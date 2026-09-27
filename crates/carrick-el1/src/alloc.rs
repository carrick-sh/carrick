//! Bounded segregated-fit metadata allocator for Carrick EL1 kernel.
//!
//! Provides $O(1)$ allocation, deallocation, bidirectional coalescing, and
//! dynamic extent expansion/return through the shared pending-host-work mailbox.

use crate::lock::SpinLock;
use core::alloc::Layout;

pub const MIN_BLOCK_SIZE: usize = 32;
pub const HEADER_SIZE: usize = 32;
pub const NUM_BINS: usize = 28;
pub const MAX_EXTENTS: usize = 128;
pub const BLOCK_MAGIC: u16 = 0xCA77;
pub const NO_PREV_BLOCK: u32 = 0xFFFF_FFFF;

/// Boundary tag block header preceding every allocated and free payload.
#[repr(C, align(16))]
pub struct BlockHeader {
    /// Integrity magic (`0xCA77`).
    pub magic: u16,
    /// Containing extent index in the allocator's extent table.
    pub extent_idx: u8,
    /// Allocation flag (`true` when in active use, `false` when free).
    pub is_allocated: bool,
    /// Relative offset to preceding physical block within the extent, or `NO_PREV_BLOCK`.
    pub prev_phys_offset: u32,
    /// Total block size in bytes (including this 32-byte header).
    pub size: usize,
    /// Intrusive free-list pointer to previous free block in the bin.
    pub prev_free: *mut BlockHeader,
    /// Intrusive free-list pointer to next free block in the bin.
    pub next_free: *mut BlockHeader,
}

const _: () = assert!(core::mem::size_of::<BlockHeader>() == HEADER_SIZE);
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
    PendingReturn,
    ReturnRequested,
    Returned,
}

/// Dynamic extent to be returned to the host hypervisor after complete deallocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtentToReturn {
    pub base_va: u64,
    pub size: usize,
    pub token: u64,
    pub slot_idx: usize,
}

/// Receipt for a granted host extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtentGrantReceipt {
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
    bins: [*mut BlockHeader; NUM_BINS],
    active_bins: u32,
    extents: [ExtentDescriptor; MAX_EXTENTS],
    extents_admitted_count: usize,
    active_extents_count: usize,
    total_capacity_bytes: usize,
    allocated_bytes: usize,
    #[cfg(target_os = "none")]
    grant_denied_pending: bool,
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
            #[cfg(target_os = "none")]
            grant_denied_pending: false,
        }
    }

    #[cfg(target_os = "none")]
    fn note_grant_denied(&mut self) {
        self.grant_denied_pending = true;
    }

    #[cfg(target_os = "none")]
    fn take_grant_denied(&mut self) -> bool {
        core::mem::replace(&mut self.grant_denied_pending, false)
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
            if ext.state == ExtentState::Active || ext.state == ExtentState::PendingReturn {
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
        let mut chosen_block: *mut BlockHeader = core::ptr::null_mut();

        // 1. Try head of target bin
        if (self.active_bins & (1u32 << target_bin)) != 0 {
            metrics.bins_checked += 1;
            let head = self.bins[target_bin];
            if !head.is_null() {
                metrics.blocks_inspected += 1;
                if self.can_fit(head, aligned_size, align) {
                    chosen_block = head;
                }
            }
        }

        // 2. If target bin head didn't fit, check head of next non-empty bin
        if chosen_block.is_null() && target_bin + 1 < NUM_BINS {
            let mask = !((1u32 << (target_bin + 1)) - 1);
            let next_bins = self.active_bins & mask;
            if next_bins != 0 {
                metrics.bins_checked += 1;
                let bin = next_bins.trailing_zeros() as usize;
                let head = self.bins[bin];
                if !head.is_null() {
                    metrics.blocks_inspected += 1;
                    if self.can_fit(head, aligned_size, align) {
                        chosen_block = head;
                    }
                }
            }
        }

        if chosen_block.is_null() {
            return (None, metrics);
        }

        self.unlink_free_block(chosen_block);

        unsafe {
            let block_addr = chosen_block as usize;
            let orig_block_size = (*chosen_block).size;
            let extent_idx = (*chosen_block).extent_idx as usize;
            let orig_prev_phys = (*chosen_block).prev_phys_offset;
            let extent_base = self.extents[extent_idx].base_va as usize;

            let min_p = block_addr + HEADER_SIZE;
            let mut p = (min_p + (align - 1)) & !(align - 1);
            let mut prefix_size = (p - HEADER_SIZE) - block_addr;
            if prefix_size > 0 && prefix_size < MIN_BLOCK_SIZE {
                p += align;
                prefix_size = (p - HEADER_SIZE) - block_addr;
            }

            let mut cur_block_addr = block_addr;
            let mut cur_prev_phys = orig_prev_phys;

            // Prefix split
            if prefix_size >= MIN_BLOCK_SIZE {
                metrics.splits_performed += 1;
                let prefix_block = block_addr as *mut BlockHeader;
                (*prefix_block).size = prefix_size;
                (*prefix_block).extent_idx = extent_idx as u8;
                (*prefix_block).prev_phys_offset = orig_prev_phys;
                (*prefix_block).is_allocated = false;
                (*prefix_block).magic = BLOCK_MAGIC;
                self.insert_free_block(prefix_block);

                cur_block_addr = block_addr + prefix_size;
                cur_prev_phys = (block_addr - extent_base) as u32;
            }

            let allocated_block = cur_block_addr as *mut BlockHeader;
            let remaining_from_cur = orig_block_size - prefix_size;
            let needed_for_alloc = HEADER_SIZE + aligned_size;
            let suffix_size = remaining_from_cur.saturating_sub(needed_for_alloc);

            // Suffix split
            if suffix_size >= MIN_BLOCK_SIZE {
                metrics.splits_performed += 1;
                let actual_alloc_size = remaining_from_cur - suffix_size;
                (*allocated_block).size = actual_alloc_size;

                let suffix_addr = cur_block_addr + actual_alloc_size;
                let suffix_block = suffix_addr as *mut BlockHeader;
                (*suffix_block).size = suffix_size;
                (*suffix_block).extent_idx = extent_idx as u8;
                (*suffix_block).prev_phys_offset = (cur_block_addr - extent_base) as u32;
                (*suffix_block).is_allocated = false;
                (*suffix_block).magic = BLOCK_MAGIC;

                let after_suffix_offset = (suffix_addr + suffix_size) - extent_base;
                if after_suffix_offset < self.extents[extent_idx].size {
                    let after_suffix = (extent_base + after_suffix_offset) as *mut BlockHeader;
                    (*after_suffix).prev_phys_offset = (suffix_addr - extent_base) as u32;
                }

                self.insert_free_block(suffix_block);
            } else {
                (*allocated_block).size = remaining_from_cur;
            }

            (*allocated_block).extent_idx = extent_idx as u8;
            (*allocated_block).prev_phys_offset = cur_prev_phys;
            (*allocated_block).is_allocated = true;
            (*allocated_block).magic = BLOCK_MAGIC;
            (*allocated_block).prev_free = core::ptr::null_mut();
            (*allocated_block).next_free = core::ptr::null_mut();

            self.extents[extent_idx].live_allocations += 1;
            self.allocated_bytes += (*allocated_block).size;

            let payload_ptr = (cur_block_addr + HEADER_SIZE) as *mut u8;
            (Some(payload_ptr), metrics)
        }
    }

    /// Allocate a block satisfying layout requirements.
    pub fn allocate(&mut self, size: usize, align: usize) -> Option<*mut u8> {
        let (ptr, _) = self.allocate_with_metrics(size, align);
        ptr
    }

    /// Deallocate a previously allocated block, recording structural work metrics.
    pub fn deallocate_with_metrics(
        &mut self,
        ptr: *mut u8,
        _align: usize,
    ) -> (Option<ExtentToReturn>, DeallocMetrics) {
        if ptr.is_null() || (ptr as usize) < HEADER_SIZE {
            return (None, DeallocMetrics::default());
        }

        let mut metrics = DeallocMetrics::default();
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
                self.extents[extent_idx].state = ExtentState::PendingReturn;

                return (
                    Some(ExtentToReturn {
                        base_va: self.extents[extent_idx].base_va,
                        size: extent_size,
                        token,
                        slot_idx: extent_idx,
                    }),
                    metrics,
                );
            }

            self.insert_free_block(block);
            (None, metrics)
        }
    }

    /// Prepare to deallocate a block, returning dynamic extent to return if ready.
    pub fn prepare_deallocate_extent(
        &mut self,
        ptr: *mut u8,
        align: usize,
    ) -> Option<ExtentToReturn> {
        let (to_return, _) = self.deallocate_with_metrics(ptr, align);
        to_return
    }

    /// Complete dynamic extent return after host hypercall confirmation.
    pub fn complete_extent_return(&mut self, slot_idx: usize) {
        if slot_idx < MAX_EXTENTS
            && matches!(
                self.extents[slot_idx].state,
                ExtentState::PendingReturn | ExtentState::ReturnRequested
            )
        {
            let size = self.extents[slot_idx].size;
            self.extents[slot_idx].state = ExtentState::Returned;
            self.active_extents_count = self.active_extents_count.saturating_sub(1);
            self.total_capacity_bytes = self.total_capacity_bytes.saturating_sub(size);
        }
    }

    /// Cancel dynamic extent return if host hypercall was refused or failed.
    pub fn cancel_extent_return(&mut self, slot_idx: usize) {
        if slot_idx < MAX_EXTENTS
            && matches!(
                self.extents[slot_idx].state,
                ExtentState::PendingReturn | ExtentState::ReturnRequested
            )
        {
            self.extents[slot_idx].state = ExtentState::Active;
            unsafe {
                let initial_block = self.extents[slot_idx].base_va as *mut BlockHeader;
                (*initial_block).size = self.extents[slot_idx].size;
                (*initial_block).prev_phys_offset = NO_PREV_BLOCK;
                (*initial_block).extent_idx = slot_idx as u8;
                (*initial_block).is_allocated = false;
                (*initial_block).magic = BLOCK_MAGIC;
                self.insert_free_block(initial_block);
            }
        }
    }

    /// Deallocate a previously allocated block.
    pub fn deallocate(&mut self, ptr: *mut u8, align: usize) -> Option<ExtentToReturn> {
        self.prepare_deallocate_extent(ptr, align)
    }

    #[cfg(target_os = "none")]
    fn next_pending_return(&self) -> Option<ExtentToReturn> {
        self.extents
            .iter()
            .enumerate()
            .find_map(|(slot_idx, extent)| {
                if extent.state != ExtentState::PendingReturn {
                    return None;
                }
                let ExtentKind::Dynamic { token } = extent.kind else {
                    return None;
                };
                Some(ExtentToReturn {
                    base_va: extent.base_va,
                    size: extent.size,
                    token,
                    slot_idx,
                })
            })
    }

    #[cfg(target_os = "none")]
    fn mark_return_requested(&mut self, slot_idx: usize) {
        if slot_idx < MAX_EXTENTS && self.extents[slot_idx].state == ExtentState::PendingReturn {
            self.extents[slot_idx].state = ExtentState::ReturnRequested;
        }
    }

    #[cfg(target_os = "none")]
    fn has_pending_return(&self) -> bool {
        self.extents.iter().any(|extent| {
            matches!(
                extent.state,
                ExtentState::PendingReturn | ExtentState::ReturnRequested
            )
        })
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

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
#[inline(always)]
fn current_el1_slot() -> Option<usize> {
    let sp: u64;
    unsafe {
        core::arch::asm!("mov {0}, sp", out(reg) sp, options(nomem, nostack));
    }
    let offset = sp.checked_sub(carrick_el1_abi::EL1_STACKS_BASE)?;
    if offset >= carrick_el1_abi::EL1_STACK_SLOTS * carrick_el1_abi::EL1_STACK_SIZE {
        return None;
    }
    Some((offset / carrick_el1_abi::EL1_STACK_SIZE) as usize)
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

#[cfg(target_os = "none")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MailboxSync {
    None,
    AllocReady,
    AllocDenied,
    ReturnFinished,
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

    pub fn ensure_bootstrap_admitted(&self) {
        let guard = disable_irq_save();
        let mut core = self.lock.lock();
        if core.active_extents_count == 0 {
            let _ = core.admit_extent(
                carrick_el1_abi::EL1_BOOTSTRAP_METADATA_BASE,
                carrick_el1_abi::EL1_BOOTSTRAP_METADATA_SIZE as usize,
                ExtentKind::Bootstrap,
            );
        }
        core::mem::drop(core);
        restore_irq(guard);
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

    #[cfg(target_os = "none")]
    fn mark_pending_host_work(slot: usize) {
        if let Some(task) = carrick_el1_abi::current_task_guest(slot) {
            task.mark_pending_host_work();
        }
    }

    #[cfg(target_os = "none")]
    fn publish_request(slot: usize, request: carrick_el1_abi::MetadataGrantRequest) -> bool {
        if !carrick_el1_abi::metadata_mailbox_guest().try_publish_request(request) {
            return false;
        }
        Self::mark_pending_host_work(slot);
        true
    }

    #[cfg(target_os = "none")]
    fn synchronize_response(core: &mut MetadataAllocatorCore, slot: usize) -> MailboxSync {
        let mailbox = carrick_el1_abi::metadata_mailbox_guest();
        let Some(response) = mailbox.claim_response() else {
            return MailboxSync::None;
        };
        let outcome = match response.op {
            carrick_el1_abi::METADATA_GRANT_OP_ALLOC => {
                if response.status != carrick_el1_abi::METADATA_GRANT_SUCCESS {
                    core.note_grant_denied();
                    MailboxSync::AllocDenied
                } else {
                    let receipt = ExtentGrantReceipt {
                        base_va: response.arg1,
                        size: response.arg2 as usize,
                        token: response.arg3,
                    };
                    if receipt.base_va == 0
                        || receipt.size == 0
                        || receipt.token == 0
                        || core
                            .admit_extent(
                                receipt.base_va,
                                receipt.size,
                                ExtentKind::Dynamic {
                                    token: receipt.token,
                                },
                            )
                            .is_err()
                    {
                        core.note_grant_denied();
                        mailbox.finish_response();
                        if Self::publish_request(
                            slot,
                            carrick_el1_abi::MetadataGrantRequest {
                                op: carrick_el1_abi::METADATA_GRANT_OP_FREE,
                                arg1: receipt.base_va,
                                arg2: receipt.size as u64,
                                arg3: receipt.token,
                                cookie: u64::MAX,
                            },
                        ) {
                            return MailboxSync::AllocDenied;
                        }
                        return MailboxSync::AllocDenied;
                    }
                    MailboxSync::AllocReady
                }
            }
            carrick_el1_abi::METADATA_GRANT_OP_FREE => {
                let slot_idx = response.cookie as usize;
                if slot_idx != usize::MAX {
                    if response.status == carrick_el1_abi::METADATA_GRANT_SUCCESS {
                        core.complete_extent_return(slot_idx);
                    } else {
                        core.cancel_extent_return(slot_idx);
                    }
                }
                MailboxSync::ReturnFinished
            }
            _ => MailboxSync::None,
        };
        mailbox.finish_response();
        outcome
    }

    #[cfg(target_os = "none")]
    fn publish_pending_return(core: &mut MetadataAllocatorCore, slot: usize) -> bool {
        let Some(to_return) = core.next_pending_return() else {
            return false;
        };
        if !Self::publish_request(
            slot,
            carrick_el1_abi::MetadataGrantRequest {
                op: carrick_el1_abi::METADATA_GRANT_OP_FREE,
                arg1: to_return.base_va,
                arg2: to_return.size as u64,
                arg3: to_return.token,
                cookie: to_return.slot_idx as u64,
            },
        ) {
            return false;
        }
        core.mark_return_requested(to_return.slot_idx);
        true
    }

    #[cfg(target_os = "none")]
    fn service_mailbox(core: &mut MetadataAllocatorCore, slot: usize) -> MailboxSync {
        let outcome = Self::synchronize_response(core, slot);
        Self::publish_pending_return(core, slot);
        outcome
    }

    #[cfg(target_os = "none")]
    fn host_work_pending(core: &MetadataAllocatorCore) -> bool {
        core.has_pending_return() || carrick_el1_abi::metadata_mailbox_guest().has_guest_work()
    }

    pub fn allocate(&self, layout: Layout) -> Option<*mut u8> {
        let align = layout.align().max(16);
        let size = layout.size();

        // 1. Try allocating from existing extents under lock
        let guard = disable_irq_save();
        let mut core = self.lock.lock();
        #[cfg(target_os = "none")]
        if core.active_extents_count == 0 {
            let _ = core.admit_extent(
                carrick_el1_abi::EL1_BOOTSTRAP_METADATA_BASE,
                carrick_el1_abi::EL1_BOOTSTRAP_METADATA_SIZE as usize,
                ExtentKind::Bootstrap,
            );
        }
        #[cfg(target_os = "none")]
        let _mailbox_sync = current_el1_slot()
            .map(|slot| Self::service_mailbox(&mut core, slot))
            .unwrap_or(MailboxSync::None);
        let p = core.allocate(size, align);
        if p.is_some() {
            core::mem::drop(core);
            restore_irq(guard);
            return p;
        }

        #[cfg(target_os = "none")]
        {
            // A refusal belongs to the capacity miss that required a grant,
            // not to an unrelated smaller allocation that happened to consume
            // the shared response while bootstrap capacity remained.
            if core.take_grant_denied() {
                core::mem::drop(core);
                restore_irq(guard);
                return None;
            }
            let needed_size = core.needed_grant_size(size, align);
            if let Some(slot) = current_el1_slot() {
                Self::publish_request(
                    slot,
                    carrick_el1_abi::MetadataGrantRequest {
                        op: carrick_el1_abi::METADATA_GRANT_OP_ALLOC,
                        arg1: needed_size as u64,
                        arg2: 0,
                        arg3: 0,
                        cookie: 0,
                    },
                );
            }
        }
        core::mem::drop(core);
        restore_irq(guard);
        None
    }

    pub fn deallocate(&self, ptr: *mut u8, layout: Layout) {
        let align = layout.align().max(16);
        let guard = disable_irq_save();
        let mut core = self.lock.lock();
        #[cfg(target_os = "none")]
        if let Some(slot) = current_el1_slot() {
            Self::service_mailbox(&mut core, slot);
        }
        core.prepare_deallocate_extent(ptr, align);
        #[cfg(target_os = "none")]
        if let Some(slot) = current_el1_slot() {
            Self::publish_pending_return(&mut core, slot);
        }
        core::mem::drop(core);
        restore_irq(guard);
    }

    #[cfg(all(feature = "allocator-test-control", target_os = "none"))]
    fn service_test_host_work(&self) -> bool {
        let Some(slot) = current_el1_slot() else {
            return false;
        };
        let guard = disable_irq_save();
        let mut core = self.lock.lock();
        Self::service_mailbox(&mut core, slot);
        let pending = Self::host_work_pending(&core);
        core::mem::drop(core);
        restore_irq(guard);
        pending
    }

    #[cfg(all(feature = "allocator-test-control", not(target_os = "none")))]
    fn service_test_host_work(&self) -> bool {
        false
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

/// Ensure the global metadata allocator has admitted the bootstrap region.
pub fn ensure_bootstrap_initialized() {
    #[cfg(target_os = "none")]
    {
        GLOBAL_ALLOCATOR.ensure_bootstrap_admitted();
    }
}

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
#[cfg(feature = "allocator-test-control")]
static DENIAL_TEST_STAGE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

#[cfg(feature = "allocator-test-control")]
pub fn run_guest_allocator_test(subtest: u64, _arg: u64) -> u64 {
    match subtest {
        4 => run_guest_allocator_test(2, 0),
        5 => {
            if GLOBAL_ALLOCATOR.service_test_host_work() {
                carrick_el1_abi::METADATA_GRANT_PENDING
            } else {
                0
            }
        }
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
            // Test 2: Cross the 9 MiB bootstrap with one 10 MiB allocation.
            // Keeping the operation atomic across the pending-host-work
            // boundary models the transaction preflight required by the MMU:
            // a capacity miss unwinds before partial allocator state exists.
            let allocation_size = 10 * 1024 * 1024;
            let allocation_layout = match Layout::from_size_align(allocation_size, 64) {
                Ok(l) => l,
                Err(_) => return 200,
            };
            let ptr = match GLOBAL_ALLOCATOR.allocate(allocation_layout) {
                Some(ptr) => ptr,
                None => {
                    // Another allocator user may complete the shared mailbox
                    // between this miss losing publication and this check.
                    // Either way the transaction must retry from its bounded
                    // userspace loop; only exhaustion of that bound is a
                    // terminal progress failure.
                    let _ = GLOBAL_ALLOCATOR.service_test_host_work();
                    return carrick_el1_abi::METADATA_GRANT_PENDING;
                }
            };

            unsafe {
                core::ptr::write_bytes(ptr, 0x30, allocation_size);
                for offset in (0..allocation_size).step_by(4096) {
                    if *ptr.add(offset) != 0x30 {
                        GLOBAL_ALLOCATOR.deallocate(ptr, allocation_layout);
                        return 202;
                    }
                }
            }

            GLOBAL_ALLOCATOR.deallocate(ptr, allocation_layout);
            0
        }
        3 => {
            // Test 3: Denial failpoint recovery
            // Fill bootstrap with 8 x 1 MiB chunks
            let chunk_size = 1024 * 1024;
            let chunk_layout = match Layout::from_size_align(chunk_size, 64) {
                Ok(l) => l,
                Err(_) => return 300,
            };
            let mut ptrs = [core::ptr::null_mut(); 8];
            for (i, slot) in ptrs.iter_mut().enumerate() {
                let p = match GLOBAL_ALLOCATOR.allocate(chunk_layout) {
                    Some(p) => p,
                    None => return 301,
                };
                unsafe {
                    core::ptr::write_bytes(p, (0x50 + i) as u8, chunk_size);
                }
                *slot = p;
            }

            let big_layout = match Layout::from_size_align(2 * 1024 * 1024, 64) {
                Ok(l) => l,
                Err(_) => return 302,
            };
            let stage = DENIAL_TEST_STAGE.load(core::sync::atomic::Ordering::Acquire);
            let candidate = GLOBAL_ALLOCATOR.allocate(big_layout);
            if stage == 0 && candidate.is_none() && GLOBAL_ALLOCATOR.service_test_host_work() {
                for &p in &ptrs {
                    GLOBAL_ALLOCATOR.deallocate(p, chunk_layout);
                }
                return carrick_el1_abi::METADATA_GRANT_PENDING;
            }
            if stage == 0 {
                if let Some(p) = candidate {
                    GLOBAL_ALLOCATOR.deallocate(p, big_layout);
                    for &p in &ptrs {
                        GLOBAL_ALLOCATOR.deallocate(p, chunk_layout);
                    }
                    return 303;
                }
                // The denied host response has now been consumed. Existing
                // allocations must remain intact before publishing the retry.
                for (i, &p) in ptrs.iter().enumerate() {
                    unsafe {
                        for j in (0..chunk_size).step_by(4096) {
                            if *p.add(j) != (0x50 + i) as u8 {
                                for &to_free in &ptrs {
                                    GLOBAL_ALLOCATOR.deallocate(to_free, chunk_layout);
                                }
                                return 304;
                            }
                        }
                    }
                }
                DENIAL_TEST_STAGE.store(1, core::sync::atomic::Ordering::Release);
                let retry = GLOBAL_ALLOCATOR.allocate(big_layout);
                for &p in &ptrs {
                    GLOBAL_ALLOCATOR.deallocate(p, chunk_layout);
                }
                if retry.is_none() && GLOBAL_ALLOCATOR.service_test_host_work() {
                    return carrick_el1_abi::METADATA_GRANT_PENDING;
                }
                if let Some(p) = retry {
                    GLOBAL_ALLOCATOR.deallocate(p, big_layout);
                }
                return 305;
            }

            let retry_p = match candidate {
                Some(p) => p,
                None => {
                    for &p in &ptrs {
                        GLOBAL_ALLOCATOR.deallocate(p, chunk_layout);
                    }
                    if GLOBAL_ALLOCATOR.service_test_host_work() {
                        return carrick_el1_abi::METADATA_GRANT_PENDING;
                    }
                    return 305;
                }
            };
            unsafe {
                core::ptr::write_bytes(retry_p, 0x88, 2 * 1024 * 1024);
                for j in (0..2 * 1024 * 1024).step_by(4096) {
                    if *retry_p.add(j) != 0x88 {
                        GLOBAL_ALLOCATOR.deallocate(retry_p, big_layout);
                        for &to_free in ptrs.iter() {
                            GLOBAL_ALLOCATOR.deallocate(to_free, chunk_layout);
                        }
                        return 306;
                    }
                }
            }

            // Deallocate the 2 MiB dynamic chunk (triggering extent return)
            GLOBAL_ALLOCATOR.deallocate(retry_p, big_layout);

            // Deallocate all 8 bootstrap chunks
            for &p in ptrs.iter() {
                GLOBAL_ALLOCATOR.deallocate(p, chunk_layout);
            }
            DENIAL_TEST_STAGE.store(0, core::sync::atomic::Ordering::Release);
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
                slot_idx: 1,
            })
        );
        alloc.complete_extent_return(1);

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
    fn test_extent_return_cancellation_preserves_reusable_memory() {
        let mut dynamic_backing = vec![0u8; 16 * 1024];
        let dyn_base = dynamic_backing.as_mut_ptr() as u64;
        let mut alloc = MetadataAllocatorCore::new();
        alloc
            .admit_extent(
                dyn_base,
                dynamic_backing.len(),
                ExtentKind::Dynamic { token: 88 },
            )
            .expect("admit dyn");

        let layout = Layout::from_size_align(8192, 64).unwrap();
        let p = alloc.allocate(layout.size(), layout.align()).expect("p");
        let to_return = alloc
            .prepare_deallocate_extent(p, layout.align())
            .expect("to_return");

        // Simulate host refusal: cancel return
        alloc.cancel_extent_return(to_return.slot_idx);
        let diag = alloc.diagnostics();
        assert_eq!(diag.active_extents, 1);

        // Reallocate into canceled extent must succeed
        let p2 = alloc.allocate(layout.size(), layout.align()).expect("p2");
        assert_eq!(p2, p);
        alloc.deallocate(p2, layout.align());
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
