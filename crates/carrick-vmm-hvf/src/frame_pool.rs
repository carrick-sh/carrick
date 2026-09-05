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

/// Check if the pre-mapped root slot pool is enabled via environment.
///
/// Default is ON. Set `CARRICK_ROOT_SLOT_POOL=0` (or `false`/`no`) as an escape hatch
/// for bisection.
pub(crate) fn is_root_slot_pool_enabled() -> bool {
    match std::env::var("CARRICK_ROOT_SLOT_POOL") {
        Ok(val) => {
            val != "0" && !val.eq_ignore_ascii_case("false") && !val.eq_ignore_ascii_case("no")
        }
        Err(_) => true,
    }
}

pub(crate) const ROOT_SLOT_SIZE: usize = 2 * 1024 * 1024;

/// Query the configured size of the root slot pool in bytes.
///
/// Default: 128 MiB (64 slots of 2 MiB).
/// Override via `CARRICK_ROOT_SLOT_POOL_SIZE` (in bytes, rounded up to 2 MiB alignment).
pub(crate) fn root_slot_pool_size() -> usize {
    if let Ok(val) = std::env::var("CARRICK_ROOT_SLOT_POOL_SIZE") {
        if let Ok(size) = val.parse::<usize>() {
            let aligned = (size.saturating_add(ROOT_SLOT_SIZE - 1)) & !(ROOT_SLOT_SIZE - 1);
            if aligned > 0 {
                return aligned;
            }
        }
    }
    // Default 128 MiB: 64 slots of 2 MiB
    64 * ROOT_SLOT_SIZE
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
struct PooledRootSlotEntry {
    slot_index: u32,
    base_ipa: u64,
    host_ptr: *mut u8,
    in_use: bool,
    populated_prefix: usize,
}

/// A pre-mapped, carrier-scoped pool of stage-2 backed 2 MiB root-slot memory regions.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct PreMappedRootSlotPool {
    base_ipa: u64,
    pool_size: usize,
    _host_mapping: crate::host_mapping::OwnedHostMapping,
    lease: Mutex<Option<crate::trap::GlobalFrameStage2Lease>>,
    slots: Mutex<Vec<PooledRootSlotEntry>>,
    allocated_count: AtomicUsize,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl std::fmt::Debug for PreMappedRootSlotPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreMappedRootSlotPool")
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
unsafe impl Send for PreMappedRootSlotPool {}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Sync for PreMappedRootSlotPool {}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PreMappedRootSlotPool {
    pub(crate) fn try_new() -> Result<Self, crate::trap::TrapError> {
        let pool_size = root_slot_pool_size();
        let base_ipa = carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE;
        let mut lease = crate::trap::GlobalFrameStage2Lease::fixed(base_ipa, pool_size as u64);
        let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            pool_size,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .map_err(|error| {
            crate::trap::TrapError::Hypervisor(format!("allocate root slot pool backing: {error}"))
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
                "map root slot pool IPA 0x{base_ipa:x} size 0x{pool_size:x}: 0x{map_rc:x}"
            )));
        }
        lease.mark_mapped();

        const TWO_MIB: usize = 2 * 1024 * 1024;
        let num_slots = pool_size / TWO_MIB;
        let mut slots = Vec::with_capacity(num_slots);
        for i in 0..num_slots as u32 {
            let offset = i as usize * TWO_MIB;
            let slot_ipa = base_ipa + offset as u64;
            let host_ptr = unsafe { host_mapping.as_ptr().add(offset) };
            slots.push(PooledRootSlotEntry {
                slot_index: i,
                base_ipa: slot_ipa,
                host_ptr,
                in_use: false,
                populated_prefix: 0,
            });
        }

        Ok(Self {
            base_ipa,
            pool_size,
            _host_mapping: host_mapping,
            lease: Mutex::new(Some(lease)),
            slots: Mutex::new(slots),
            allocated_count: AtomicUsize::new(0),
        })
    }

    #[cfg(test)]
    pub(crate) fn new_test_fixture(num_slots: usize) -> Self {
        const TWO_MIB: usize = 2 * 1024 * 1024;
        let pool_size = num_slots * TWO_MIB;
        let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            pool_size,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate test root slot pool backing");
        let base_ipa = carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE;
        let mut slots = Vec::with_capacity(num_slots);
        for i in 0..num_slots as u32 {
            let offset = i as usize * TWO_MIB;
            let slot_ipa = base_ipa + offset as u64;
            let host_ptr = unsafe { host_mapping.as_ptr().add(offset) };
            slots.push(PooledRootSlotEntry {
                slot_index: i,
                base_ipa: slot_ipa,
                host_ptr,
                in_use: false,
                populated_prefix: 0,
            });
        }
        Self {
            base_ipa,
            pool_size,
            _host_mapping: host_mapping,
            lease: Mutex::new(None),
            slots: Mutex::new(slots),
            allocated_count: AtomicUsize::new(0),
        }
    }

    pub(crate) fn allocate_slot_at(
        self: &Arc<Self>,
        requested_ipa: u64,
    ) -> Option<PooledRootSlotHandle> {
        const TWO_MIB: usize = 2 * 1024 * 1024;
        if requested_ipa < self.base_ipa || requested_ipa >= self.base_ipa + self.pool_size as u64 {
            return None;
        }
        let offset = (requested_ipa - self.base_ipa) as usize;
        if !offset.is_multiple_of(TWO_MIB) {
            return None;
        }
        let slot_index = (offset / TWO_MIB) as u32;
        let mut slots = self.slots.lock();
        let slot = slots.get_mut(slot_index as usize)?;
        if slot.in_use {
            return None;
        }
        // Invariant: Zero only as far as the populated prefix on reuse.
        // A stale table beyond the prefix is unreachable from the root because the
        // stage-1 manager allocates sequentially from base, and descriptors only
        // ever reference tables within the live prefix [base, next_free).
        if slot.populated_prefix > 0 {
            unsafe {
                std::ptr::write_bytes(slot.host_ptr, 0, slot.populated_prefix);
            }
            slot.populated_prefix = 0;
        }
        slot.in_use = true;
        self.allocated_count.fetch_add(1, Ordering::Relaxed);
        Some(PooledRootSlotHandle {
            pool: Arc::clone(self),
            slot_index,
            _ipa: requested_ipa,
            host_ptr: slot.host_ptr,
            len: TWO_MIB,
            populated_prefix: AtomicUsize::new(0),
        })
    }

    #[allow(dead_code)]
    pub(crate) fn allocate_slot(self: &Arc<Self>) -> Option<PooledRootSlotHandle> {
        const TWO_MIB: usize = 2 * 1024 * 1024;
        let mut slots = self.slots.lock();
        for slot in slots.iter_mut() {
            if !slot.in_use {
                if slot.populated_prefix > 0 {
                    unsafe {
                        std::ptr::write_bytes(slot.host_ptr, 0, slot.populated_prefix);
                    }
                    slot.populated_prefix = 0;
                }
                slot.in_use = true;
                self.allocated_count.fetch_add(1, Ordering::Relaxed);
                return Some(PooledRootSlotHandle {
                    pool: Arc::clone(self),
                    slot_index: slot.slot_index,
                    _ipa: slot.base_ipa,
                    host_ptr: slot.host_ptr,
                    len: TWO_MIB,
                    populated_prefix: AtomicUsize::new(0),
                });
            }
        }
        None
    }

    fn recycle(&self, slot_index: u32, prefix: usize) {
        const TWO_MIB: usize = 2 * 1024 * 1024;
        let mut slots = self.slots.lock();
        if let Some(slot) = slots.get_mut(slot_index as usize) {
            slot.in_use = false;
            slot.populated_prefix = prefix.max(slot.populated_prefix).min(TWO_MIB);
            self.allocated_count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn contains_ipa(&self, ipa: u64) -> bool {
        ipa >= self.base_ipa && ipa < self.base_ipa + (self.pool_size as u64)
    }

    #[allow(dead_code)]
    pub(crate) fn base_ipa(&self) -> u64 {
        self.base_ipa
    }

    #[allow(dead_code)]
    pub(crate) fn pool_size(&self) -> usize {
        self.pool_size
    }

    #[allow(dead_code)]
    pub(crate) fn allocated_count(&self) -> usize {
        self.allocated_count.load(Ordering::Relaxed)
    }

    pub(crate) fn forget_backend_mapping(&self) {
        if let Some(mut lease) = self.lease.lock().take() {
            lease.forget_backend_mapping();
        }
    }
}

/// An exclusively checked-out 2 MiB root-slot backing from `PreMappedRootSlotPool`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct PooledRootSlotHandle {
    pool: Arc<PreMappedRootSlotPool>,
    slot_index: u32,
    _ipa: u64,
    host_ptr: *mut u8,
    len: usize,
    populated_prefix: AtomicUsize,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Send for PooledRootSlotHandle {}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Sync for PooledRootSlotHandle {}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PooledRootSlotHandle {
    #[allow(dead_code)]
    pub(crate) fn ipa(&self) -> u64 {
        self._ipa
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

    pub(crate) fn record_populated_prefix(&self, prefix: usize) {
        self.populated_prefix.fetch_max(prefix, Ordering::Relaxed);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for PooledRootSlotHandle {
    fn drop(&mut self) {
        self.pool.recycle(
            self.slot_index,
            self.populated_prefix.load(Ordering::Relaxed),
        );
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

    #[test]
    fn root_slot_pool_checkout_and_prefix_zeroing() {
        let pool = Arc::new(PreMappedRootSlotPool::new_test_fixture(4));
        assert_eq!(pool.allocated_count(), 0);

        let s0 = pool.allocate_slot().expect("checkout s0");
        let s1 = pool.allocate_slot().expect("checkout s1");
        assert_eq!(pool.allocated_count(), 2);

        assert_eq!(s0.ipa(), pool.base_ipa());
        assert_eq!(s1.ipa(), pool.base_ipa() + ROOT_SLOT_SIZE as u64);

        // Fill s0 entirely with 0xaa
        unsafe {
            std::ptr::write_bytes(s0.as_mut_ptr(), 0xaa, s0.len());
        }

        // Record populated prefix of 48 KiB
        let prefix = 48 * 1024;
        s0.record_populated_prefix(prefix);
        let s0_ipa = s0.ipa();
        drop(s0);
        assert_eq!(pool.allocated_count(), 1);

        // Reacquire s0 via allocate_slot_at(s0_ipa)
        let reacquired = pool
            .allocate_slot_at(s0_ipa)
            .expect("reacquire s0 at specific ipa");
        assert_eq!(reacquired.ipa(), s0_ipa);
        assert_eq!(pool.allocated_count(), 2);

        // Verify [0..prefix) was zeroed on recycle, while [prefix..len) retains 0xaa
        let slice = unsafe { std::slice::from_raw_parts(reacquired.as_ptr(), reacquired.len()) };
        assert!(slice[..prefix].iter().all(|&b| b == 0));
        assert!(slice[prefix..].iter().all(|&b| b == 0xaa));

        // Attempting to allocate at already-allocated IPA returns None
        assert!(pool.allocate_slot_at(s0_ipa).is_none());
        assert!(pool.allocate_slot_at(s1.ipa()).is_none());

        // Attempting to allocate at unmanaged IPA returns None
        assert!(pool.allocate_slot_at(pool.base_ipa() + 0x1000).is_none());
        assert!(pool.allocate_slot_at(0x1000).is_none());
    }

    #[test]
    fn root_slot_pool_contains_ipa_predicate() {
        let pool = Arc::new(PreMappedRootSlotPool::new_test_fixture(4));
        let base = pool.base_ipa();
        let size = pool.pool_size() as u64;

        assert!(!pool.contains_ipa(base - 1));
        assert!(pool.contains_ipa(base));
        assert!(pool.contains_ipa(base + ROOT_SLOT_SIZE as u64));
        assert!(pool.contains_ipa(base + size - 1));
        assert!(!pool.contains_ipa(base + size));
    }
}
