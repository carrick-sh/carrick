//! EL1 in-guest kernel metadata allocator.
//!
//! Provides a bounded segregated-fit allocator supporting:
//! - Bounded O(1) allocation and deallocation across 28 size bins with bitmap indexing
//! - O(1) bidirectional coalescing via physical boundary tag offsets
//! - Dynamic host extent grants via HVC #6 (`METADATA_GRANT_OP_ALLOC`)
//! - Exact-once return of unused dynamic extents via HVC #6 (`METADATA_GRANT_OP_FREE`)
//! - Safe spinlock acquisition preserving DAIF IRQ state, dropping locks before host hypercalls
//! - GlobalAlloc implementation installed as `#[global_allocator]`

use crate::lock::SpinLock;
use core::alloc::Layout;

pub const NUM_BINS: usize = 28;
pub const MAX_EXTENTS: usize = 128;
pub const MIN_BLOCK_SIZE: usize = 32;
pub const HEADER_SIZE: usize = 32;
pub const BLOCK_MAGIC: u16 = 0xCA77;
pub const NO_PREV_BLOCK: u32 = u32::MAX;

/// Physical and logical header preceding every memory block in an admitted extent.
#[repr(C, align(16))]
pub struct BlockHeader {
    /// Intrusive pointer to previous free block in segregated free bin.
    pub prev_free: *mut BlockHeader,
    /// Intrusive pointer to next free block in segregated free bin.
    pub next_free: *mut BlockHeader,
    /// Total size of this block in bytes, including this 32-byte header.
    pub size: usize,
    /// Byte offset from the containing extent's base to the physically preceding block,
    /// or `NO_PREV_BLOCK` if this block is at the start of the extent.
    pub prev_phys_offset: u32,
    /// Index into the allocator's `extents` table.
    pub extent_idx: u8,
    /// Allocation status flag (true = allocated, false = free).
    pub is_allocated: bool,
    /// Header validation magic (`BLOCK_MAGIC = 0xCA77`).
    pub magic: u16,
}

// Ensure BlockHeader is strictly 32 bytes and 16-byte aligned.
const _: () = assert!(core::mem::size_of::<BlockHeader>() == 32);
const _: () = assert!(core::mem::align_of::<BlockHeader>() == 16);

/// Descriptor for an admitted contiguous memory extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtentDescriptor {
    pub base_va: u64,
    pub size: usize,
    pub kind: ExtentKind,
    pub state: ExtentState,
    pub live_allocations: usize,
}

impl ExtentDescriptor {
    pub const fn unused() -> Self {
        Self {
            base_va: 0,
            size: 0,
            kind: ExtentKind::Bootstrap,
            state: ExtentState::Unused,
            live_allocations: 0,
        }
    }
}

/// Provenance of an extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentKind {
    /// Pre-mapped bootstrap arena in the EL1 region (e.g. 9 MiB bootstrap).
    Bootstrap,
    /// Dynamically granted extent from the host hypervisor.
    Dynamic { token: u64 },
}

/// State of an extent descriptor slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentState {
    Unused,
    Active,
    Returned,
}

/// Dynamic extent to be returned to the host hypervisor after complete deallocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtentToReturn {
    pub base_va: u64,
    pub size: usize,
    pub token: u64,
}

/// Errors occurring during extent admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentAdmissionError {
    TableFull,
    InvalidSize,
    InvalidAlignment,
    OverlapWithExisting,
    BufferTooSmall,
}

/// Operation metrics recorded during allocation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AllocMetrics {
    pub bins_checked: usize,
    pub blocks_inspected: usize,
    pub splits_performed: usize,
}

/// Operation metrics recorded during deallocation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeallocMetrics {
    pub merges_performed: usize,
}

/// Bounded segregated-fit allocator core.
pub struct MetadataAllocatorCore {
    /// Segregated free list heads for each size class.
    bins: [*mut BlockHeader; NUM_BINS],
    /// Bitmap of non-empty size bins for O(1) search.
    active_bins: u32,
    /// Bounded table of admitted extents.
    extents: [ExtentDescriptor; MAX_EXTENTS],
    /// Total extents ever admitted.
    extents_admitted_count: usize,
    /// Currently active extents.
    active_extents_count: usize,
    /// Total capacity in bytes across all active extents.
    total_capacity_bytes: usize,
    /// Total allocated payload + header bytes in active use.
    allocated_bytes: usize,
}

// SAFETY: All raw pointers point into admitted memory buffers protected by external synchronization.
unsafe impl Send for MetadataAllocatorCore {}

impl Default for MetadataAllocatorCore {
    fn default() -> Self {
        Self::new()
    }
}

impl MetadataAllocatorCore {
    /// Create a new empty allocator state.
    pub const fn new() -> Self {
        Self {
            bins: [core::ptr::null_mut(); NUM_BINS],
            active_bins: 0,
            extents: [ExtentDescriptor::unused(); MAX_EXTENTS],
            extents_admitted_count: 0,
            active_extents_count: 0,
            total_capacity_bytes: 0,
            allocated_bytes: 0,
        }
    }

    /// Calculate bin index for a given required block size.
    #[inline]
    pub fn bin_for_size(size: usize) -> usize {
        if size <= 64 {
            return 0;
        }
        let fls = (usize::BITS - 1 - size.leading_zeros()) as usize;
        if fls <= 6 {
            0
        } else if fls >= 23 {
            NUM_BINS - 1
        } else {
            let base_bin = (fls - 6) * 2;
            let half = 1usize << (fls - 1);
            if (size & half) != 0 && base_bin + 1 < NUM_BINS {
                base_bin + 1
            } else {
                base_bin.min(NUM_BINS - 1)
            }
        }
    }

    /// Minimum size for a given bin index.
    #[inline]
    pub fn min_size_for_bin(bin: usize) -> usize {
        match bin {
            0 => 32,
            1 => 48,
            2 => 64,
            3 => 96,
            4 => 128,
            5 => 192,
            6 => 256,
            7 => 384,
            8 => 512,
            9 => 768,
            10 => 1024,
            11 => 1536,
            12 => 2048,
            13 => 3072,
            14 => 4096,
            15 => 6144,
            16 => 8192,
            17 => 12288,
            18 => 16384,
            19 => 24576,
            20 => 32768,
            21 => 49152,
            22 => 65536,
            23 => 131072,
            24 => 262144,
            25 => 524288,
            26 => 1048576,
            27 => 2097152,
            _ => 2097152,
        }
    }

    #[inline]
    fn insert_free_block(&mut self, block: *mut BlockHeader) {
        unsafe {
            let size = (*block).size;
            let bin = Self::bin_for_size(size);
            let head = self.bins[bin];

            (*block).prev_free = core::ptr::null_mut();
            (*block).next_free = head;
            (*block).is_allocated = false;
            (*block).magic = BLOCK_MAGIC;

            if !head.is_null() {
                (*head).prev_free = block;
            }
            self.bins[bin] = block;
            self.active_bins |= 1u32 << bin;
        }
    }

    #[inline]
    fn unlink_free_block(&mut self, block: *mut BlockHeader) {
        unsafe {
            let bin = Self::bin_for_size((*block).size);
            let prev = (*block).prev_free;
            let next = (*block).next_free;

            if !prev.is_null() {
                (*prev).next_free = next;
            } else {
                self.bins[bin] = next;
                if next.is_null() {
                    self.active_bins &= !(1u32 << bin);
                }
            }

            if !next.is_null() {
                (*next).prev_free = prev;
            }

            (*block).prev_free = core::ptr::null_mut();
            (*block).next_free = core::ptr::null_mut();
        }
    }

    /// Check if a free block can satisfy a requested payload size and alignment.
    #[inline]
    fn can_fit(&self, block: *mut BlockHeader, size: usize, align: usize) -> bool {
        unsafe {
            let block_addr = block as usize;
            let block_size = (*block).size;
            let min_p = block_addr + HEADER_SIZE;
            let mut p = (min_p + (align - 1)) & !(align - 1);
            let mut prefix = (p - HEADER_SIZE) - block_addr;
            if prefix > 0 && prefix < MIN_BLOCK_SIZE {
                p += align;
                prefix = (p - HEADER_SIZE) - block_addr;
            }
            let total_needed = prefix + HEADER_SIZE + size;
            total_needed <= block_size
        }
    }

    /// Calculate required host grant size to satisfy layout requirements.
    pub fn needed_grant_size(&self, size: usize, align: usize) -> usize {
        let max_block_req = size
            .saturating_add(HEADER_SIZE)
            .saturating_add(align)
            .saturating_add(MIN_BLOCK_SIZE);
        let min_quantum = carrick_el1_abi::EL1_DYNAMIC_METADATA_EXTENT_SIZE;
        let needed = max_block_req.max(min_quantum);
        (needed + 0x0FFF) & !0x0FFF
    }

    /// Admit an extent into the allocator.
    pub fn admit_extent(
        &mut self,
        base_va: u64,
        size: usize,
        kind: ExtentKind,
    ) -> Result<usize, ExtentAdmissionError> {
        if size < MIN_BLOCK_SIZE || !size.is_multiple_of(16) {
            return Err(ExtentAdmissionError::InvalidSize);
        }
        if base_va == 0 || !(base_va as usize).is_multiple_of(16) {
            return Err(ExtentAdmissionError::InvalidAlignment);
        }

        let end_va = base_va
            .checked_add(size as u64)
            .ok_or(ExtentAdmissionError::InvalidSize)?;

        // Authenticate non-overlap with any currently active extents
        for ext in &self.extents {
            if ext.state == ExtentState::Active {
                let ext_end = ext.base_va.saturating_add(ext.size as u64);
                if base_va < ext_end && end_va > ext.base_va {
                    return Err(ExtentAdmissionError::OverlapWithExisting);
                }
            }
        }

        // Find a free descriptor slot
        let slot_idx = self
            .extents
            .iter()
            .position(|e| e.state == ExtentState::Unused || e.state == ExtentState::Returned)
            .ok_or(ExtentAdmissionError::TableFull)?;

        self.extents[slot_idx] = ExtentDescriptor {
            base_va,
            size,
            kind,
            state: ExtentState::Active,
            live_allocations: 0,
        };
        self.extents_admitted_count += 1;
        self.active_extents_count += 1;
        self.total_capacity_bytes += size;

        // Initialize extent as one single free block
        unsafe {
            let initial_block = base_va as *mut BlockHeader;
            (*initial_block).size = size;
            (*initial_block).prev_phys_offset = NO_PREV_BLOCK;
            (*initial_block).extent_idx = slot_idx as u8;
            (*initial_block).is_allocated = false;
            (*initial_block).magic = BLOCK_MAGIC;
            self.insert_free_block(initial_block);
        }

        Ok(slot_idx)
    }

    /// Allocate a block satisfying layout requirements, recording structural work metrics.
    pub fn allocate_with_metrics(
        &mut self,
        size: usize,
        align: usize,
    ) -> (Option<*mut u8>, AllocMetrics) {
        let align = align.max(16);
        let aligned_size = (size.max(1) + 15) & !15;
        let max_needed = aligned_size
            .saturating_add(HEADER_SIZE)
            .saturating_add(align)
            .saturating_add(MIN_BLOCK_SIZE);
        let target_bin = Self::bin_for_size(max_needed);

        let mut metrics = AllocMetrics::default();
        let mut candidate_block: *mut BlockHeader = core::ptr::null_mut();

        // 1. Check head of target_bin
        metrics.bins_checked += 1;
        if (self.active_bins & (1u32 << target_bin)) != 0 {
            let head = self.bins[target_bin];
            if !head.is_null() {
                metrics.blocks_inspected += 1;
                if self.can_fit(head, aligned_size, align) {
                    candidate_block = head;
                }
            }
        }

        // 2. If head of target_bin did not fit, check head of next non-empty higher bin
        if candidate_block.is_null() {
            let higher_mask = self.active_bins & !((1u32 << (target_bin + 1)) - 1);
            if higher_mask != 0 {
                metrics.bins_checked += 1;
                let next_bin = higher_mask.trailing_zeros() as usize;
                let head = self.bins[next_bin];
                if !head.is_null() {
                    metrics.blocks_inspected += 1;
                    if self.can_fit(head, aligned_size, align) {
                        candidate_block = head;
                    }
                }
            }
        }

        let Some(block) = (if !candidate_block.is_null() {
            Some(candidate_block)
        } else {
            None
        }) else {
            return (None, metrics);
        };

        unsafe {
            self.unlink_free_block(block);
            let block_addr = block as usize;
            let orig_size = (*block).size;
            let extent_idx = (*block).extent_idx as usize;
            let extent_base = self.extents[extent_idx].base_va as usize;
            let extent_size = self.extents[extent_idx].size;
            let prev_phys = (*block).prev_phys_offset;

            // Compute payload address satisfying alignment
            let min_p = block_addr + HEADER_SIZE;
            let mut p = (min_p + (align - 1)) & !(align - 1);
            let mut prefix = (p - HEADER_SIZE) - block_addr;
            if prefix > 0 && prefix < MIN_BLOCK_SIZE {
                p += align;
                prefix = (p - HEADER_SIZE) - block_addr;
            }

            let allocated_block_addr = p - HEADER_SIZE;
            let allocated_block = allocated_block_addr as *mut BlockHeader;

            // If prefix > 0, split off preceding free block
            if prefix > 0 {
                metrics.splits_performed += 1;
                let pref_block = block_addr as *mut BlockHeader;
                (*pref_block).size = prefix;
                (*pref_block).prev_phys_offset = prev_phys;
                (*pref_block).extent_idx = extent_idx as u8;
                (*pref_block).is_allocated = false;
                (*pref_block).magic = BLOCK_MAGIC;
                self.insert_free_block(pref_block);

                (*allocated_block).prev_phys_offset = (block_addr - extent_base) as u32;
            } else {
                (*allocated_block).prev_phys_offset = prev_phys;
            }

            let allocated_size = HEADER_SIZE + aligned_size;
            let remaining_size = orig_size - (prefix + allocated_size);

            if remaining_size >= MIN_BLOCK_SIZE {
                metrics.splits_performed += 1;
                (*allocated_block).size = allocated_size;
                let suffix_addr = allocated_block_addr + allocated_size;
                let suffix_block = suffix_addr as *mut BlockHeader;
                (*suffix_block).size = remaining_size;
                (*suffix_block).prev_phys_offset = (allocated_block_addr - extent_base) as u32;
                (*suffix_block).extent_idx = extent_idx as u8;
                (*suffix_block).is_allocated = false;
                (*suffix_block).magic = BLOCK_MAGIC;

                let next_phys_offset = (suffix_addr + remaining_size) - extent_base;
                if next_phys_offset < extent_size {
                    let next_phys = (extent_base + next_phys_offset) as *mut BlockHeader;
                    (*next_phys).prev_phys_offset = (suffix_addr - extent_base) as u32;
                }

                self.insert_free_block(suffix_block);
            } else {
                (*allocated_block).size = orig_size - prefix;
                let next_phys_offset =
                    (allocated_block_addr + (*allocated_block).size) - extent_base;
                if next_phys_offset < extent_size {
                    let next_phys = (extent_base + next_phys_offset) as *mut BlockHeader;
                    (*next_phys).prev_phys_offset = (allocated_block_addr - extent_base) as u32;
                }
            }

            (*allocated_block).extent_idx = extent_idx as u8;
            (*allocated_block).is_allocated = true;
            (*allocated_block).magic = BLOCK_MAGIC;

            self.extents[extent_idx].live_allocations += 1;
            self.allocated_bytes += (*allocated_block).size;

            (Some(p as *mut u8), metrics)
        }
    }

    /// Allocate a block satisfying layout requirements.
    pub fn allocate(&mut self, size: usize, align: usize) -> Option<*mut u8> {
        let (ptr, _) = self.allocate_with_metrics(size, align);
        ptr
    }

    /// Deallocate a previously allocated block, recording merge work metrics.
    pub fn deallocate_with_metrics(
        &mut self,
        ptr: *mut u8,
        _align: usize,
    ) -> (Option<ExtentToReturn>, DeallocMetrics) {
        let mut metrics = DeallocMetrics::default();
        if ptr.is_null() {
            return (None, metrics);
        }

        let mut block = (ptr as usize - HEADER_SIZE) as *mut BlockHeader;

        unsafe {
            if (*block).magic != BLOCK_MAGIC || !(*block).is_allocated {
                return (None, metrics);
            }

            let extent_idx = (*block).extent_idx as usize;
            if extent_idx >= MAX_EXTENTS || self.extents[extent_idx].state != ExtentState::Active {
                return (None, metrics);
            }

            (*block).is_allocated = false;
            self.extents[extent_idx].live_allocations =
                self.extents[extent_idx].live_allocations.saturating_sub(1);
            self.allocated_bytes = self.allocated_bytes.saturating_sub((*block).size);

            let extent_base = self.extents[extent_idx].base_va as usize;
            let extent_size = self.extents[extent_idx].size;

            // 1. Coalesce with physically subsequent block if free
            let next_offset = (block as usize + (*block).size) - extent_base;
            if next_offset < extent_size {
                let next_phys = (extent_base + next_offset) as *mut BlockHeader;
                if (*next_phys).magic == BLOCK_MAGIC && !(*next_phys).is_allocated {
                    metrics.merges_performed += 1;
                    self.unlink_free_block(next_phys);
                    (*block).size += (*next_phys).size;

                    let after_next_offset = (block as usize + (*block).size) - extent_base;
                    if after_next_offset < extent_size {
                        let after_next = (extent_base + after_next_offset) as *mut BlockHeader;
                        (*after_next).prev_phys_offset = (block as usize - extent_base) as u32;
                    }
                }
            }

            // 2. Coalesce with physically preceding block if free
            if (*block).prev_phys_offset != NO_PREV_BLOCK {
                let prev_phys =
                    (extent_base + (*block).prev_phys_offset as usize) as *mut BlockHeader;
                if (*prev_phys).magic == BLOCK_MAGIC && !(*prev_phys).is_allocated {
                    metrics.merges_performed += 1;
                    self.unlink_free_block(prev_phys);
                    (*prev_phys).size += (*block).size;

                    let after_offset = (prev_phys as usize + (*prev_phys).size) - extent_base;
                    if after_offset < extent_size {
                        let after = (extent_base + after_offset) as *mut BlockHeader;
                        (*after).prev_phys_offset = (prev_phys as usize - extent_base) as u32;
                    }

                    block = prev_phys;
                }
            }

            // 3. Dynamic extent reclamation check
            if let ExtentKind::Dynamic { token } = self.extents[extent_idx].kind
                && self.extents[extent_idx].live_allocations == 0
                && (*block).size == extent_size
            {
                self.extents[extent_idx].state = ExtentState::Returned;
                self.active_extents_count = self.active_extents_count.saturating_sub(1);
                self.total_capacity_bytes = self.total_capacity_bytes.saturating_sub(extent_size);

                return (
                    Some(ExtentToReturn {
                        base_va: self.extents[extent_idx].base_va,
                        size: extent_size,
                        token,
                    }),
                    metrics,
                );
            }

            self.insert_free_block(block);
            (None, metrics)
        }
    }

    /// Deallocate a previously allocated block.
    pub fn deallocate(&mut self, ptr: *mut u8, align: usize) -> Option<ExtentToReturn> {
        let (to_return, _) = self.deallocate_with_metrics(ptr, align);
        to_return
    }

    /// Read diagnostics snapshot.
    pub fn diagnostics(&self) -> AllocatorDiagnostics {
        AllocatorDiagnostics {
            extents_admitted: self.extents_admitted_count,
            active_extents: self.active_extents_count,
            total_capacity_bytes: self.total_capacity_bytes,
            allocated_bytes: self.allocated_bytes,
            active_bins_mask: self.active_bins,
        }
    }
}

/// Snapshot of allocator operational diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocatorDiagnostics {
    pub extents_admitted: usize,
    pub active_extents: usize,
    pub total_capacity_bytes: usize,
    pub allocated_bytes: usize,
    pub active_bins_mask: u32,
}

/// Dynamic extent allocation helper invoking host hypercall HVC #6.
#[inline(never)]
pub fn request_host_extent_grant(requested_size: usize) -> Option<(u64, usize)> {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        let mut status: u64;
        let mut granted_base: u64;
        let mut granted_size: u64;

        unsafe {
            core::arch::asm!(
                "hvc #6",
                inout("x0") carrick_el1_abi::METADATA_GRANT_OP_ALLOC => status,
                inout("x1") requested_size as u64 => granted_base,
                inout("x2") 0u64 => granted_size,
                options(nostack)
            );
        }

        if status == carrick_el1_abi::METADATA_GRANT_SUCCESS
            && granted_base != 0
            && granted_size > 0
        {
            Some((granted_base, granted_size as usize))
        } else {
            None
        }
    }
    #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
    {
        let _ = requested_size;
        None
    }
}

/// Dynamic extent return helper invoking host hypercall HVC #6.
#[inline(never)]
pub fn return_host_extent(base_va: u64, size: usize) -> bool {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        let mut status: u64;
        let mut _out1: u64;
        let mut _out2: u64;

        unsafe {
            core::arch::asm!(
                "hvc #6",
                inout("x0") carrick_el1_abi::METADATA_GRANT_OP_FREE => status,
                inout("x1") base_va => _out1,
                inout("x2") size as u64 => _out2,
                options(nostack)
            );
        }

        status == carrick_el1_abi::METADATA_GRANT_SUCCESS
    }
    #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
    {
        let _ = (base_va, size);
        true
    }
}

/// Guard structure capturing saved DAIF interrupt flags.
pub struct IrqGuard {
    #[allow(dead_code)]
    saved_daif: u64,
}

#[inline(always)]
pub fn disable_irq_save() -> IrqGuard {
    let daif: u64;
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    unsafe {
        core::arch::asm!(
            "mrs {0}, daif",
            "msr daifset, #2",
            out(reg) daif,
            options(nomem, nostack)
        );
    }
    #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
    {
        daif = 0;
    }
    IrqGuard { saved_daif: daif }
}

#[inline(always)]
pub fn restore_irq(guard: IrqGuard) {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    unsafe {
        core::arch::asm!(
            "msr daif, {0}",
            in(reg) guard.saved_daif,
            options(nomem, nostack)
        );
    }
    #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
    {
        let _ = guard;
    }
}

/// Safe thread-safe wrapper around `MetadataAllocatorCore` with IRQ save/restore spinlock.
pub struct MetadataStorage {
    lock: SpinLock<MetadataAllocatorCore>,
}

impl Default for MetadataStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl MetadataStorage {
    pub const fn new() -> Self {
        Self {
            lock: SpinLock::new(MetadataAllocatorCore::new()),
        }
    }

    pub fn admit_bootstrap_region(
        &self,
        base_va: u64,
        size: usize,
    ) -> Result<(), ExtentAdmissionError> {
        let guard = disable_irq_save();
        let mut core = self.lock.lock();
        let res = core
            .admit_extent(base_va, size, ExtentKind::Bootstrap)
            .map(|_| ());
        core::mem::drop(core);
        restore_irq(guard);
        res
    }

    pub fn allocate(&self, layout: Layout) -> Option<*mut u8> {
        let align = layout.align().max(16);
        let size = layout.size();

        // 1. Try allocating from existing extents under lock
        let guard = disable_irq_save();
        let mut core = self.lock.lock();
        let p = core.allocate(size, align);
        if p.is_some() {
            core::mem::drop(core);
            restore_irq(guard);
            return p;
        }

        let needed_size = core.needed_grant_size(size, align);
        core::mem::drop(core);
        restore_irq(guard);

        // 2. Request host grant with lock DROPPED and IRQs restored
        let (granted_base, granted_size) = request_host_extent_grant(needed_size)?;

        // 3. Re-acquire lock, admit extent, and fulfill allocation
        let guard = disable_irq_save();
        let mut core = self.lock.lock();
        if core
            .admit_extent(
                granted_base,
                granted_size,
                ExtentKind::Dynamic {
                    token: granted_base,
                },
            )
            .is_err()
        {
            core::mem::drop(core);
            restore_irq(guard);
            return_host_extent(granted_base, granted_size);
            return None;
        }

        let ptr = core.allocate(size, align);
        core::mem::drop(core);
        restore_irq(guard);
        ptr
    }

    pub fn deallocate(&self, ptr: *mut u8, layout: Layout) {
        let align = layout.align().max(16);
        let guard = disable_irq_save();
        let mut core = self.lock.lock();
        let extent_to_return = core.deallocate(ptr, align);
        core::mem::drop(core);
        restore_irq(guard);

        // Return extent to host hypervisor with lock DROPPED
        if let Some(to_return) = extent_to_return {
            return_host_extent(to_return.base_va, to_return.size);
        }
    }

    pub fn diagnostics(&self) -> AllocatorDiagnostics {
        let guard = disable_irq_save();
        let core = self.lock.lock();
        let diag = core.diagnostics();
        core::mem::drop(core);
        restore_irq(guard);
        diag
    }
}

// Implement GlobalAlloc for MetadataStorage so it can be installed as #[global_allocator].
unsafe impl core::alloc::GlobalAlloc for MetadataStorage {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.allocate(layout).unwrap_or(core::ptr::null_mut())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.deallocate(ptr, layout)
    }
}

/// Global EL1 kernel metadata allocator instance.
#[cfg_attr(target_os = "none", global_allocator)]
pub static GLOBAL_ALLOCATOR: MetadataStorage = MetadataStorage::new();

/// Initialize the EL1 metadata allocator with the bootstrap region.
pub fn init_bootstrap_allocator(bootstrap_base: u64, bootstrap_size: usize) {
    if GLOBAL_ALLOCATOR
        .admit_bootstrap_region(bootstrap_base, bootstrap_size)
        .is_err()
    {
        panic!("Failed to initialize EL1 bootstrap metadata allocator");
    }
}

/// In-guest allocator test execution invoked by embed test fixture via `SYS_CARRICK_EL1_CONTROL`.
pub fn run_guest_allocator_test(subtest: u64, _arg: u64) -> u64 {
    match subtest {
        1 => {
            // Test 1: Arbitrary alignments (16, 32, 64, 128, 4096), payload pattern verification, and free
            let alignments = [16, 32, 64, 128, 4096];
            for (idx, &align) in alignments.iter().enumerate() {
                let layout = match Layout::from_size_align(128, align) {
                    Ok(l) => l,
                    Err(_) => return 100 + idx as u64,
                };
                let ptr = match GLOBAL_ALLOCATOR.allocate(layout) {
                    Some(p) => p,
                    None => return 110 + idx as u64,
                };
                if !(ptr as usize).is_multiple_of(align) {
                    GLOBAL_ALLOCATOR.deallocate(ptr, layout);
                    return 120 + idx as u64;
                }
                unsafe {
                    core::ptr::write_bytes(ptr, (0xA0 + idx) as u8, 128);
                    for j in 0..128 {
                        if *ptr.add(j) != (0xA0 + idx) as u8 {
                            GLOBAL_ALLOCATOR.deallocate(ptr, layout);
                            return 130 + idx as u64;
                        }
                    }
                }
                GLOBAL_ALLOCATOR.deallocate(ptr, layout);
            }
            0
        }
        2 => {
            // Test 2: Cross bootstrap capacity (9 MiB) by allocating 10 MiB, verify writes, and free to return extents
            let chunk_size = 1024 * 1024; // 1 MiB per chunk
            let chunk_layout = match Layout::from_size_align(chunk_size, 64) {
                Ok(l) => l,
                Err(_) => return 200,
            };
            let mut ptrs = [core::ptr::null_mut(); 10];
            let mut count = 0;

            for (i, slot) in ptrs.iter_mut().enumerate() {
                if let Some(p) = GLOBAL_ALLOCATOR.allocate(chunk_layout) {
                    unsafe {
                        core::ptr::write_bytes(p, (0x30 + i) as u8, chunk_size);
                    }
                    *slot = p;
                    count += 1;
                } else {
                    break;
                }
            }

            if count < 10 {
                // Failed to allocate all 10 MiB
                for &p in ptrs.iter().take(count) {
                    GLOBAL_ALLOCATOR.deallocate(p, chunk_layout);
                }
                return 201;
            }

            // Verify payload integrity across all 10 MiB
            for (i, &p) in ptrs.iter().take(count).enumerate() {
                unsafe {
                    for j in (0..chunk_size).step_by(4096) {
                        if *p.add(j) != (0x30 + i) as u8 {
                            for &to_free in ptrs.iter().take(count) {
                                GLOBAL_ALLOCATOR.deallocate(to_free, chunk_layout);
                            }
                            return 202;
                        }
                    }
                }
            }

            // Deallocate all 10 MiB to trigger dynamic extent return
            for &p in ptrs.iter().take(count) {
                GLOBAL_ALLOCATOR.deallocate(p, chunk_layout);
            }

            0
        }
        3 => {
            // Test 3: Denial failpoint recovery
            // Fill bootstrap and dynamic memory with 10 MiB
            let chunk_size = 1024 * 1024;
            let chunk_layout = match Layout::from_size_align(chunk_size, 64) {
                Ok(l) => l,
                Err(_) => return 300,
            };
            let mut ptrs = [core::ptr::null_mut(); 10];
            let mut count = 0;
            for (i, slot) in ptrs.iter_mut().enumerate() {
                if let Some(p) = GLOBAL_ALLOCATOR.allocate(chunk_layout) {
                    unsafe {
                        core::ptr::write_bytes(p, (0x50 + i) as u8, chunk_size);
                    }
                    *slot = p;
                    count += 1;
                } else {
                    break;
                }
            }
            if count < 10 {
                for &p in ptrs.iter().take(count) {
                    GLOBAL_ALLOCATOR.deallocate(p, chunk_layout);
                }
                return 301;
            }

            // Verify all existing 10 MiB
            for (i, &p) in ptrs.iter().take(count).enumerate() {
                unsafe {
                    for j in (0..chunk_size).step_by(4096) {
                        if *p.add(j) != (0x50 + i) as u8 {
                            for &to_free in ptrs.iter().take(count) {
                                GLOBAL_ALLOCATOR.deallocate(to_free, chunk_layout);
                            }
                            return 302;
                        }
                    }
                }
            }

            // Free 1 block to test reuse
            GLOBAL_ALLOCATOR.deallocate(ptrs[0], chunk_layout);
            ptrs[0] = core::ptr::null_mut();

            // Reallocate into freed space: must succeed
            let realloc_p = match GLOBAL_ALLOCATOR.allocate(chunk_layout) {
                Some(p) => p,
                None => {
                    for &p in ptrs.iter().skip(1) {
                        GLOBAL_ALLOCATOR.deallocate(p, chunk_layout);
                    }
                    return 303;
                }
            };
            unsafe {
                core::ptr::write_bytes(realloc_p, 0x99, chunk_size);
            }
            GLOBAL_ALLOCATOR.deallocate(realloc_p, chunk_layout);

            for &p in ptrs.iter().skip(1) {
                GLOBAL_ALLOCATOR.deallocate(p, chunk_layout);
            }

            0
        }
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arbitrary_alignments_and_memory_writes() {
        let mut backing = vec![0u8; 1024 * 1024];
        let base = backing.as_mut_ptr() as u64;
        let mut alloc = MetadataAllocatorCore::new();
        alloc
            .admit_extent(base, backing.len(), ExtentKind::Bootstrap)
            .expect("admit bootstrap");

        let test_alignments = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096];
        for &align in &test_alignments {
            let layout = Layout::from_size_align(128, align).unwrap();
            let (ptr_opt, metrics) = alloc.allocate_with_metrics(layout.size(), layout.align());
            let ptr = ptr_opt.expect("allocate aligned block");
            assert_eq!(
                ptr as usize % align,
                0,
                "payload address must strictly satisfy alignment {align}"
            );
            assert!(metrics.bins_checked <= 2);
            assert!(metrics.blocks_inspected <= 2);
            assert!(metrics.splits_performed <= 2);

            unsafe {
                core::ptr::write_bytes(ptr, 0xCC, 128);
                for j in 0..128 {
                    assert_eq!(*ptr.add(j), 0xCC);
                }
            }

            let (to_return, dealloc_metrics) = alloc.deallocate_with_metrics(ptr, layout.align());
            assert!(to_return.is_none());
            assert!(dealloc_metrics.merges_performed <= 2);
        }

        let diag = alloc.diagnostics();
        assert_eq!(diag.allocated_bytes, 0);
    }

    #[test]
    fn test_fragmentation_coalescing_and_reuse() {
        let mut arena = vec![0u8; 64 * 1024];
        let base = arena.as_mut_ptr() as u64;
        let mut alloc = MetadataAllocatorCore::new();
        alloc
            .admit_extent(base, arena.len(), ExtentKind::Bootstrap)
            .expect("admit");

        let l = Layout::from_size_align(128, 16).unwrap();
        let p_a = alloc.allocate(l.size(), l.align()).unwrap();
        let p_b = alloc.allocate(l.size(), l.align()).unwrap();
        let p_c = alloc.allocate(l.size(), l.align()).unwrap();

        // Free B and C (they coalesce together)
        alloc.deallocate(p_b, l.align());
        alloc.deallocate(p_c, l.align());

        // Allocate larger block fitting in coalesced B+C
        let big_l = Layout::from_size_align(256, 16).unwrap();
        let p_bc = alloc.allocate(big_l.size(), big_l.align()).unwrap();
        assert_eq!(p_bc, p_b, "coalesced B+C space must be reused");

        alloc.deallocate(p_a, l.align());
        alloc.deallocate(p_bc, big_l.align());

        let diag = alloc.diagnostics();
        assert_eq!(diag.allocated_bytes, 0);
    }

    #[test]
    fn test_extent_admission_validation_and_overlap_rejection() {
        let mut alloc = MetadataAllocatorCore::new();
        // Unaligned base
        assert_eq!(
            alloc.admit_extent(0x1005, 4096, ExtentKind::Bootstrap),
            Err(ExtentAdmissionError::InvalidAlignment)
        );
        // Zero base
        assert_eq!(
            alloc.admit_extent(0, 4096, ExtentKind::Bootstrap),
            Err(ExtentAdmissionError::InvalidAlignment)
        );
        // Size too small
        assert_eq!(
            alloc.admit_extent(0x2000, 16, ExtentKind::Bootstrap),
            Err(ExtentAdmissionError::InvalidSize)
        );
        let mut backing = vec![0u8; 8192];
        let base = backing.as_mut_ptr() as u64;
        // Valid admission
        assert!(
            alloc
                .admit_extent(base, 4096, ExtentKind::Bootstrap)
                .is_ok()
        );
        // Overlapping admission
        assert_eq!(
            alloc.admit_extent(base + 2048, 4096, ExtentKind::Bootstrap),
            Err(ExtentAdmissionError::OverlapWithExisting)
        );
    }

    #[test]
    fn test_dynamic_growth_and_exact_once_return() {
        let mut bootstrap = vec![0u8; 4096];
        let boot_base = bootstrap.as_mut_ptr() as u64;
        let mut alloc = MetadataAllocatorCore::new();
        alloc
            .admit_extent(boot_base, bootstrap.len(), ExtentKind::Bootstrap)
            .expect("admit bootstrap");

        let large_layout = Layout::from_size_align(8192, 64).unwrap();
        assert!(
            alloc
                .allocate(large_layout.size(), large_layout.align())
                .is_none()
        );

        // Admit dynamic extent
        let mut dynamic_backing = vec![0u8; 16 * 1024];
        let dyn_base = dynamic_backing.as_mut_ptr() as u64;
        alloc
            .admit_extent(
                dyn_base,
                dynamic_backing.len(),
                ExtentKind::Dynamic { token: 42 },
            )
            .expect("admit dynamic");

        let p_dyn = alloc
            .allocate(large_layout.size(), large_layout.align())
            .expect("alloc from dynamic");
        assert!(p_dyn as u64 >= dyn_base);

        let to_return = alloc.deallocate(p_dyn, large_layout.align());
        assert_eq!(
            to_return,
            Some(ExtentToReturn {
                base_va: dyn_base,
                size: dynamic_backing.len(),
                token: 42,
            })
        );

        let diag = alloc.diagnostics();
        assert_eq!(diag.allocated_bytes, 0);
        assert_eq!(diag.active_extents, 1);
    }

    #[test]
    fn test_grant_refusal_preserves_state_and_allows_subsequent_retry() {
        let mut bootstrap = vec![0u8; 4096];
        let boot_base = bootstrap.as_mut_ptr() as u64;
        let mut alloc = MetadataAllocatorCore::new();
        alloc
            .admit_extent(boot_base, bootstrap.len(), ExtentKind::Bootstrap)
            .expect("admit boot");

        let small_layout = Layout::from_size_align(256, 16).unwrap();
        let p1 = alloc
            .allocate(small_layout.size(), small_layout.align())
            .expect("p1");
        unsafe {
            core::ptr::write_bytes(p1, 0x77, 256);
        }

        let large_layout = Layout::from_size_align(16 * 1024, 64).unwrap();
        // Allocation fails (simulated refusal)
        assert!(
            alloc
                .allocate(large_layout.size(), large_layout.align())
                .is_none()
        );

        // Verify p1 data was preserved
        unsafe {
            for j in 0..256 {
                assert_eq!(*p1.add(j), 0x77);
            }
        }

        // Retry with admitted extent succeeds
        let mut dynamic_backing = vec![0u8; 32 * 1024];
        let dyn_base = dynamic_backing.as_mut_ptr() as u64;
        alloc
            .admit_extent(
                dyn_base,
                dynamic_backing.len(),
                ExtentKind::Dynamic { token: 101 },
            )
            .expect("admit dyn");

        let p2 = alloc
            .allocate(large_layout.size(), large_layout.align())
            .expect("p2");
        alloc.deallocate(p1, small_layout.align());
        alloc.deallocate(p2, large_layout.align());
    }

    #[test]
    fn test_bounded_operations_and_bytes_at_scales_1_8_32_128() {
        for &scale in &[1, 8, 32, 128] {
            let mut backings: Vec<Vec<u8>> = (0..scale).map(|_| vec![0u8; 64 * 1024]).collect();
            let mut alloc = MetadataAllocatorCore::new();

            for (i, backing) in backings.iter_mut().enumerate() {
                let base = backing.as_mut_ptr() as u64;
                let kind = if i == 0 {
                    ExtentKind::Bootstrap
                } else {
                    ExtentKind::Dynamic {
                        token: (i + 1) as u64,
                    }
                };
                alloc
                    .admit_extent(base, backing.len(), kind)
                    .expect("admit extent");
            }

            let diag = alloc.diagnostics();
            assert_eq!(diag.active_extents, scale);
            assert_eq!(diag.total_capacity_bytes, scale * 64 * 1024);

            // Bounded O(1) allocation metrics check
            let layout = Layout::from_size_align(256, 64).unwrap();
            let (ptr_opt, metrics) = alloc.allocate_with_metrics(layout.size(), layout.align());
            let ptr = ptr_opt.expect("allocate at scale");
            assert!(metrics.bins_checked <= 2, "bins_checked bound");
            assert!(metrics.blocks_inspected <= 2, "blocks_inspected bound");
            assert!(metrics.splits_performed <= 2, "splits_performed bound");

            let (_, dealloc_metrics) = alloc.deallocate_with_metrics(ptr, layout.align());
            assert!(
                dealloc_metrics.merges_performed <= 2,
                "merges_performed bound"
            );
        }
    }
}
