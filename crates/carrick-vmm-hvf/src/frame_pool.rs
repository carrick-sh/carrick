//! Pre-mapped frame pool for zero-syscall COW and sparse fault servicing.
//!
//! Eliminates per-fault `mmap`, `hv_vm_map`, and `hv_vm_unmap` host kernel round-trips
//! by reserving a large anonymous host region and pre-mapping it into stage-2
//! once at carrier/VM bringup at a dedicated global-frame IPA range.
//!
//! Recycled frames are re-zeroed before reuse to preserve the zero-fill guarantee,
//! and fresh owner generations are allocated on checkout.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::sync::Arc;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use parking_lot::Mutex;

/// Check if the pre-mapped frame pool is enabled via environment.
///
/// Default is ON. Set `CARRICK_FRAME_POOL=0` (or `false`/`no`) as an escape hatch
/// for bisection.
pub(crate) fn is_frame_pool_enabled() -> bool {
    match std::env::var("CARRICK_FRAME_POOL") {
        Ok(val) => {
            val != "0" && !val.eq_ignore_ascii_case("false") && !val.eq_ignore_ascii_case("no")
        }
        Err(_) => true,
    }
}

/// Query the configured size of the frame pool in bytes.
///
/// Default: 1 GiB (`0x4000_0000`, 65,536 compounds of 16 KiB).
/// Override via `CARRICK_FRAME_POOL_SIZE` (in bytes, rounded up to 2 MiB alignment).
pub(crate) fn frame_pool_size() -> usize {
    if let Ok(val) = std::env::var("CARRICK_FRAME_POOL_SIZE") {
        if let Ok(size) = val.parse::<usize>() {
            const TWO_MIB: usize = 2 * 1024 * 1024;
            let aligned = (size.saturating_add(TWO_MIB - 1)) & !(TWO_MIB - 1);
            if aligned > 0 {
                return aligned;
            }
        }
    }
    // Default 1 GiB: 65,536 compounds of 16 KiB
    1024 * 1024 * 1024
}

/// A pre-mapped, carrier-scoped pool of stage-2 backed 16 KiB memory frames.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct PreMappedFramePool {
    base_ipa: u64,
    pool_size: usize,
    host_mapping: crate::host_mapping::OwnedHostMapping,
    lease: Mutex<Option<crate::trap::GlobalFrameStage2Lease>>,
    free_compounds: Mutex<Vec<u32>>,
    allocated_count: AtomicUsize,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl std::fmt::Debug for PreMappedFramePool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreMappedFramePool")
            .field("base_ipa", &format_args!("{:#x}", self.base_ipa))
            .field("pool_size", &self.pool_size)
            .field(
                "allocated_count",
                &self.allocated_count.load(Ordering::Relaxed),
            )
            .finish()
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PreMappedFramePool {
    /// Attempt to create and stage-2 map a new pre-mapped frame pool.
    pub(crate) fn try_new() -> Result<Self, crate::trap::TrapError> {
        let pool_size = frame_pool_size();
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let mut lease = crate::trap::GlobalFrameStage2Lease::reserve(pool_size as u64, TWO_MIB)?;
        let base_ipa = lease.base();
        let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            pool_size,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .map_err(|error| {
            crate::trap::TrapError::Hypervisor(format!("allocate frame pool backing: {error}"))
        })?;

        let stage2_perms = applevisor::memory::MemPerms::ReadWriteExec;
        let map_rc = unsafe {
            crate::trap::inventory_hv_vm_map(
                host_mapping.as_ptr().cast(),
                base_ipa,
                pool_size,
                u64::from(stage2_perms),
            )
        };
        if map_rc != 0 {
            return Err(crate::trap::TrapError::Hypervisor(format!(
                "map frame pool IPA 0x{base_ipa:x} size 0x{pool_size:x}: 0x{map_rc:x}"
            )));
        }
        lease.mark_mapped();

        let compound_size = crate::trap::CowArmedRanges::COMPOUND_SIZE as usize;
        let num_compounds = pool_size / compound_size;
        let mut free_compounds = Vec::with_capacity(num_compounds);
        for i in (0..num_compounds as u32).rev() {
            free_compounds.push(i);
        }

        Ok(Self {
            base_ipa,
            pool_size,
            host_mapping,
            lease: Mutex::new(Some(lease)),
            free_compounds: Mutex::new(free_compounds),
            allocated_count: AtomicUsize::new(0),
        })
    }

    #[cfg(test)]
    pub(crate) fn new_test_fixture(num_compounds: usize) -> Self {
        let compound_size = crate::trap::CowArmedRanges::COMPOUND_SIZE as usize;
        let pool_size = num_compounds * compound_size;
        let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            pool_size,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("allocate test frame pool backing");
        let base_ipa = 0x9A_1000_0000;
        let mut free_compounds = Vec::with_capacity(num_compounds);
        for i in (0..num_compounds as u32).rev() {
            free_compounds.push(i);
        }
        Self {
            base_ipa,
            pool_size,
            host_mapping,
            lease: Mutex::new(None),
            free_compounds: Mutex::new(free_compounds),
            allocated_count: AtomicUsize::new(0),
        }
    }

    /// Allocate a 16 KiB compound from the pool, if available.
    pub(crate) fn allocate_compound(self: &Arc<Self>) -> Option<PooledFrameHandle> {
        let index = self.free_compounds.lock().pop()?;
        self.allocated_count.fetch_add(1, Ordering::Relaxed);
        let compound_size = crate::trap::CowArmedRanges::COMPOUND_SIZE as usize;
        let offset = index as usize * compound_size;
        let ipa = self.base_ipa + offset as u64;
        let host_ptr = unsafe { self.host_mapping.as_ptr().add(offset) };
        Some(PooledFrameHandle {
            pool: Arc::clone(self),
            compound_index: index,
            ipa,
            host_ptr,
            len: compound_size,
        })
    }

    /// Return a compound to the pool upon final reference drop.
    /// Re-zeros the compound buffer before releasing it back to the free list.
    fn recycle(&self, compound_index: u32, host_ptr: *mut u8, len: usize) {
        // Zero-fill guarantee: scrub the recycled memory before making it available again
        unsafe {
            std::ptr::write_bytes(host_ptr, 0, len);
        }
        self.free_compounds.lock().push(compound_index);
        self.allocated_count.fetch_sub(1, Ordering::Relaxed);
    }

    /// Test whether a given IPA lies within this pool's pre-mapped extent.
    pub(crate) fn contains_ipa(&self, ipa: u64) -> bool {
        ipa >= self.base_ipa && ipa < self.base_ipa + (self.pool_size as u64)
    }

    /// The base IPA of the pool's pre-mapped extent.
    #[allow(dead_code)]
    pub(crate) fn base_ipa(&self) -> u64 {
        self.base_ipa
    }

    /// The total size of the pool in bytes.
    #[allow(dead_code)]
    pub(crate) fn pool_size(&self) -> usize {
        self.pool_size
    }

    /// The number of currently checked-out compounds.
    #[allow(dead_code)]
    pub(crate) fn allocated_count(&self) -> usize {
        self.allocated_count.load(Ordering::Relaxed)
    }

    /// Disarm the stage-2 unmap upon VM destruction.
    pub(crate) fn forget_backend_mapping(&self) {
        if let Some(mut lease) = self.lease.lock().take() {
            lease.forget_backend_mapping();
        }
    }
}

/// An exclusively checked-out 16 KiB frame compound from `PreMappedFramePool`.
///
/// On drop, the compound is automatically recycled back to the pool and wiped
/// with zeros to satisfy the zero-fill guarantee.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct PooledFrameHandle {
    pool: Arc<PreMappedFramePool>,
    compound_index: u32,
    ipa: u64,
    host_ptr: *mut u8,
    len: usize,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Send for PreMappedFramePool {}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Sync for PreMappedFramePool {}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Send for PooledFrameHandle {}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Sync for PooledFrameHandle {}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PooledFrameHandle {
    pub(crate) fn ipa(&self) -> u64 {
        self.ipa
    }

    pub(crate) fn as_mut_ptr(&self) -> *mut u8 {
        self.host_ptr
    }

    #[allow(dead_code)]
    pub(crate) fn as_ptr(&self) -> *const u8 {
        self.host_ptr
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for PooledFrameHandle {
    fn drop(&mut self) {
        self.pool
            .recycle(self.compound_index, self.host_ptr, self.len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_pool_checkout_and_zero_fill_reclaim() {
        let pool = Arc::new(PreMappedFramePool::new_test_fixture(4));
        assert_eq!(pool.allocated_count(), 0);

        // Checkout 4 compounds
        let c0 = pool.allocate_compound().expect("checkout c0");
        let c1 = pool.allocate_compound().expect("checkout c1");
        let c2 = pool.allocate_compound().expect("checkout c2");
        let c3 = pool.allocate_compound().expect("checkout c3");
        assert_eq!(pool.allocated_count(), 4);

        // Exhaustion: 5th checkout should fail
        assert!(pool.allocate_compound().is_none());

        // Check compound IPAs
        assert_eq!(c0.ipa(), pool.base_ipa());
        assert_eq!(c1.ipa(), pool.base_ipa() + 0x4000);
        assert_eq!(c2.ipa(), pool.base_ipa() + 0x8000);
        assert_eq!(c3.ipa(), pool.base_ipa() + 0xc000);

        // Dirty c1 with non-zero bytes
        unsafe {
            std::ptr::write_bytes(c1.as_mut_ptr(), 0xef, c1.len());
        }

        // Verify it is dirty
        let dirty_slice = unsafe { std::slice::from_raw_parts(c1.as_ptr(), c1.len()) };
        assert!(dirty_slice.iter().all(|&b| b == 0xef));

        // Drop c1 -> triggers recycle and zero-fill
        let dirty_ipa = c1.ipa();
        drop(c1);
        assert_eq!(pool.allocated_count(), 3);

        // Checkout again: should re-acquire the recycled compound
        let reacquired = pool.allocate_compound().expect("reacquire compound");
        assert_eq!(reacquired.ipa(), dirty_ipa);
        assert_eq!(pool.allocated_count(), 4);

        // Verify zero-fill guarantee
        let clean_slice =
            unsafe { std::slice::from_raw_parts(reacquired.as_ptr(), reacquired.len()) };
        assert!(clean_slice.iter().all(|&b| b == 0));
    }

    #[test]
    fn frame_pool_contains_ipa_predicate() {
        let pool = Arc::new(PreMappedFramePool::new_test_fixture(8));
        let base = pool.base_ipa();
        let size = pool.pool_size() as u64;

        assert!(!pool.contains_ipa(base - 1));
        assert!(pool.contains_ipa(base));
        assert!(pool.contains_ipa(base + size / 2));
        assert!(pool.contains_ipa(base + size - 1));
        assert!(!pool.contains_ipa(base + size));
    }

    #[test]
    fn frame_pool_out_of_order_drop() {
        let pool = Arc::new(PreMappedFramePool::new_test_fixture(4));
        let c0 = pool.allocate_compound().expect("c0");
        let c1 = pool.allocate_compound().expect("c1");
        let c2 = pool.allocate_compound().expect("c2");
        let c3 = pool.allocate_compound().expect("c3");
        assert_eq!(pool.allocated_count(), 4);

        // Write arbitrary byte patterns
        unsafe {
            std::ptr::write_bytes(c0.as_mut_ptr(), 0x11, c0.len());
            std::ptr::write_bytes(c1.as_mut_ptr(), 0x22, c1.len());
            std::ptr::write_bytes(c2.as_mut_ptr(), 0x33, c2.len());
            std::ptr::write_bytes(c3.as_mut_ptr(), 0x44, c3.len());
        }

        // Drop out of order: c2, then c0, then c3, then c1
        drop(c2);
        assert_eq!(pool.allocated_count(), 3);
        drop(c0);
        assert_eq!(pool.allocated_count(), 2);
        drop(c3);
        assert_eq!(pool.allocated_count(), 1);
        drop(c1);
        assert_eq!(pool.allocated_count(), 0);

        // Reallocate all 4 and assert they are all zeroed
        let mut reacquired = Vec::new();
        for _ in 0..4 {
            let handle = pool.allocate_compound().expect("reallocate");
            let slice = unsafe { std::slice::from_raw_parts(handle.as_ptr(), handle.len()) };
            assert!(slice.iter().all(|&b| b == 0));
            reacquired.push(handle);
        }
        assert_eq!(pool.allocated_count(), 4);
        assert!(pool.allocate_compound().is_none());
    }

    #[test]
    fn frame_pool_forget_backend_mapping_safe() {
        let pool = Arc::new(PreMappedFramePool::new_test_fixture(2));
        pool.forget_backend_mapping();
        // Subsequent forget call is safe and idempotent
        pool.forget_backend_mapping();
    }
}
