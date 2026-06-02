//! Runtime editor for the EL1 stage-1 identity page tables.
//!
//! At boot `memory::stage1_identity_page_tables` builds a coarse identity map
//! (1 GiB / 2 MiB blocks, with the first 2 MiB fine-grained to 4 KiB pages for
//! the null guard). To give guest `mprotect`/`PROT_NONE`/`munmap` real,
//! guest-visible semantics we must edit individual page descriptors at runtime:
//! split a covering block down to 4 KiB granularity, then flip validity / AP /
//! UXN on just the target pages. This module does that purely over the bytes of
//! the page-table region; HVF observes nothing until the caller copies the
//! edited bytes back to the region's host backing and runs the EL1 TLBI
//! maintenance trampoline (see `trap.rs`).
//!
//! 4 KiB translation granule, 40-bit IPA, AArch64 long-descriptor format.

// Leaf attribute layout (must match `memory::stage1_identity_page_tables`).
const VALID: u64 = 1 << 0;
const TYPE_BITS: u64 = 0b11;
const TYPE_TABLE_OR_PAGE: u64 = 0b11; // L0..L2 table descriptor, or L3 page
const TYPE_BLOCK: u64 = 0b01; // L1/L2 block descriptor
const AP_MASK: u64 = 0b11 << 6; // AP[2:1]
const AP_RW: u64 = 0b01 << 6; // RW at EL0+EL1
const AP_RO: u64 = 0b11 << 6; // RO at EL0+EL1
// UXN (Unprivileged eXecute Never), bit 54: when set, EL0 instruction fetch
// from the page faults (instruction abort → SIGSEGV). USER_*_FLAGS leave it
// CLEAR (executable) because the boot image identity-maps code; guest `mmap`/
// `mprotect` set it per `PROT_EXEC` so a data page is non-executable (W^X / NX),
// matching Linux. PXN (bit 53, already in USER_*_FLAGS) keeps EL1 from fetching.
const UXN: u64 = 1 << 54;

// PA field masks per level (identical to memory.rs).
const PA_MASK_1GIB: u64 = 0x0000_FFFF_C000_0000;
const PA_MASK_2MIB: u64 = 0x0000_FFFF_FFE0_0000;
const PA_MASK_4KIB: u64 = 0x0000_FFFF_FFFF_F000;
const PA_MASK_TABLE: u64 = 0x0000_FFFF_FFFF_F000; // next-level table PA (bits 47:12)

// User leaf flags (must match memory.rs USER_BLOCK_FLAGS / USER_PAGE_FLAGS).
const USER_BLOCK_FLAGS: u64 = (1u64 << 53) | (1 << 10) | (0b11 << 8) | (0b01 << 6) | 0b01;
const USER_PAGE_FLAGS: u64 = USER_BLOCK_FLAGS | 0b10;

const PT_PAGE: u64 = 0x1000; // stage-1 table page size (4 KiB granule)
// The boot image lays out eight tables in the first eight 4 KiB pages:
// L0, L1A, L1B, L2A, L2B, L3A (pages 0..5), then L1_rosetta, L2_rosetta
// (pages 6..7, the high-VA Rosetta alias). Runtime-allocated sub-tables come
// from the spare tail after them.
const SPARE_START_OFFSET: u64 = 8 * PT_PAGE;

/// A protection change applied to a guest VA range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PtOp {
    /// Clear the valid bit — any access faults (SEGV_MAPERR).
    Invalidate,
    /// Valid, AP=read-only. `exec` clears UXN (PROT_EXEC); else UXN set (NX).
    ReadOnly { exec: bool },
    /// Valid, AP=read-write. `exec` clears UXN (PROT_EXEC); else UXN set (NX).
    ReadWrite { exec: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageTableError {
    /// No spare table pages left to split a block.
    OutOfTables,
    /// A guest VA whose translation path leaves the page-table region, or an
    /// intermediate descriptor is unexpectedly unmapped.
    BadAddress,
}

/// Per-level table index for `va` (4 KiB granule, 40-bit IPA).
pub fn indices(va: u64) -> [usize; 4] {
    [
        ((va >> 39) & 0x1ff) as usize,
        ((va >> 30) & 0x1ff) as usize,
        ((va >> 21) & 0x1ff) as usize,
        ((va >> 12) & 0x1ff) as usize,
    ]
}

/// Diagnostic: walk a raw stage-1 long-descriptor table image for `va`,
/// returning the descriptor read at each level `[L0, L1, L2, L3]`. A level not
/// reached (an earlier block descriptor terminated the walk, or a descriptor
/// was invalid, or the table PA fell outside the region) is left `0`. `bytes`
/// is the live page-table region, `base` the PA mapped at byte offset 0. Lets a
/// fault handler PROVE whether the leaf PTE is invalid IN MEMORY (a logic bug)
/// versus valid-in-memory but stale in the faulting vCPU's TLB (a coherence
/// bug) — the two have opposite fixes.
pub fn walk_descriptors(bytes: &[u8], base: u64, va: u64) -> [u64; 4] {
    let idx = indices(va);
    let mut out = [0u64; 4];
    let mut table_off: usize = 0; // L0 table at byte offset 0
    for level in 0..4 {
        let off = table_off + idx[level] * 8;
        if off + 8 > bytes.len() {
            break;
        }
        let mut desc = 0u64;
        for (i, b) in bytes[off..off + 8].iter().enumerate() {
            desc |= (*b as u64) << (i * 8);
        }
        out[level] = desc;
        if desc & VALID == 0 {
            break; // invalid descriptor: walk stops here
        }
        if level == 3 || desc & TYPE_BITS != TYPE_TABLE_OR_PAGE {
            break; // L3 page, or an L1/L2 block descriptor: leaf reached
        }
        let child_pa = desc & PA_MASK_TABLE;
        let Some(child_off) = child_pa.checked_sub(base) else {
            break;
        };
        table_off = child_off as usize;
    }
    out
}

/// Mutable editor over a copy of the page-table region bytes.
///
/// `Clone` is used by `fork`: the child needs its OWN manager (it gets a
/// private copy of the page-table backing) but MUST inherit the parent's
/// `next_free`/`free_tables` — a fresh manager would reset the bump cursor and
/// re-hand-out table pages already live in the copied backing, corrupting it.
#[derive(Clone)]
pub struct PageTableManager {
    bytes: Vec<u8>,
    /// PA mapped at byte offset 0 (`LINUX_PAGE_TABLES_BASE`).
    base: u64,
    /// Byte offset of the next free spare page (bump allocator).
    next_free: u64,
    /// PAs of spare sub-tables freed by coalescing, reused before bumping. Only
    /// populated while single-vCPU (coalesce is gated on that), so a reused page
    /// can never be referenced by a sibling's stale walk cache.
    free_tables: Vec<u64>,
    /// Whether more than one guest vCPU is currently live. Set per-edit by the
    /// engine from the process-wide live-vCPU count; gates coalescing (a
    /// break-before-make structural change that is unsafe without an all-vCPU
    /// TLB flush HVF can't give one vCPU).
    multi_vcpu: bool,
    /// Byte offsets edited since the last sync, in write order, tagged
    /// `is_table_pointer`. The host sync replays them as aligned atomic stores,
    /// writing a table descriptor (which exposes a sub-table to the guest's
    /// hardware walker) only AFTER its child entries are visible — the
    /// break-before-make ordering that keeps a concurrent sibling walk safe
    /// without quiescing.
    dirty: Vec<(usize, bool)>,
}

impl PageTableManager {
    pub fn new(bytes: Vec<u8>, base: u64) -> Self {
        Self {
            bytes,
            base,
            next_free: SPARE_START_OFFSET,
            free_tables: Vec::new(),
            multi_vcpu: false,
            dirty: Vec::new(),
        }
    }

    /// Tell the manager whether sibling vCPUs are live (set per-edit from the
    /// process-wide live-vCPU count). Gates coalescing.
    pub fn set_multi_vcpu(&mut self, multi: bool) {
        self.multi_vcpu = multi;
    }

    /// True iff `pa` is a runtime-allocated spare sub-table (never a boot table
    /// — the boot L0/L1/L2/L3 hold the null guard and kernel hole and must
    /// never be coalesced/freed).
    fn is_spare_table(&self, pa: u64) -> bool {
        pa >= self.base + SPARE_START_OFFSET && pa < self.base + self.bytes.len() as u64
    }

    /// Zero a freed spare sub-table and return it to the reusable free list.
    /// Only reached from `try_coalesce`, which is gated on single-vCPU, so the
    /// reused page can never be referenced by a sibling's stale walk cache.
    fn free_table(&mut self, pa: u64) {
        if let Ok(off) = self.pa_to_off(pa) {
            for b in &mut self.bytes[off..off + PT_PAGE as usize] {
                *b = 0;
            }
            self.free_tables.push(pa);
        }
    }

    #[cfg(test)]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    fn read_desc(&self, off: usize) -> u64 {
        let mut a = [0u8; 8];
        a.copy_from_slice(&self.bytes[off..off + 8]);
        u64::from_le_bytes(a)
    }

    /// Write a leaf/child descriptor (a block, page, or sub-table entry that is
    /// not itself newly pointing the walker at a fresh table).
    fn write_desc(&mut self, off: usize, desc: u64) {
        self.bytes[off..off + 8].copy_from_slice(&desc.to_le_bytes());
        self.dirty.push((off, false));
    }

    /// Write a table descriptor that exposes a (freshly populated) sub-table to
    /// the walker. Tagged so the host sync orders it AFTER the sub-table's
    /// entries are visible.
    fn write_table_desc(&mut self, off: usize, desc: u64) {
        self.bytes[off..off + 8].copy_from_slice(&desc.to_le_bytes());
        self.dirty.push((off, true));
    }

    /// Replay this edit's descriptor stores to the host page-table backing as
    /// aligned atomic 64-bit writes, with a release barrier before each
    /// table-pointer store so a concurrent sibling hardware walk never sees a
    /// table descriptor pointing at not-yet-visible child entries. Clears the
    /// dirty set. `host` is the VA of byte offset 0 of the region.
    ///
    /// # Safety
    /// `host` must point to a writable mapping of at least `self.bytes.len()`
    /// bytes that backs the live guest page tables.
    pub unsafe fn sync_to_host(&mut self, host: *mut u8) {
        use core::sync::atomic::{AtomicU64, Ordering, fence};
        for (off, is_ptr) in self.dirty.drain(..) {
            let mut a = [0u8; 8];
            a.copy_from_slice(&self.bytes[off..off + 8]);
            let v = u64::from_le_bytes(a);
            if is_ptr {
                // Ensure the child-table entries written earlier are globally
                // visible before the pointer that exposes them.
                fence(Ordering::SeqCst);
            }
            // Offsets are 8-byte aligned (index*8), so this is a single atomic
            // store the guest walker observes whole.
            unsafe {
                let slot = host.add(off) as *mut AtomicU64;
                (*slot).store(v, Ordering::SeqCst);
            }
        }
        fence(Ordering::SeqCst);
    }

    /// Byte offset of a PA known to live inside the page-table region.
    fn pa_to_off(&self, pa: u64) -> Result<usize, PageTableError> {
        let end = self.base + self.bytes.len() as u64;
        if pa < self.base || pa >= end {
            return Err(PageTableError::BadAddress);
        }
        Ok((pa - self.base) as usize)
    }

    /// Spare sub-table pool occupancy for diagnostics/tracing:
    /// `(in_use, free_list, capacity)` pages. `in_use` is bumped-minus-reclaimed
    /// (live split tables); a monotonically rising `in_use` toward `capacity`
    /// under multithreaded churn is the coalesce-disabled pool leak.
    pub fn pool_stats(&self) -> (u32, u32, u32) {
        let bumped = (self.next_free - SPARE_START_OFFSET) / PT_PAGE;
        let free = self.free_tables.len() as u64;
        let capacity = (self.bytes.len() as u64 - SPARE_START_OFFSET) / PT_PAGE;
        ((bumped - free) as u32, free as u32, capacity as u32)
    }

    /// Read-only descriptor walk for `va`, for `carrick trace` diagnostics:
    /// returns `[L0, L1, L2, L3]` descriptors as the MANAGER sees them in its
    /// own `bytes` (not the host backing), stopping (rest 0) at the first
    /// non-table or out-of-range link. Lets a trace compare the manager's view
    /// across e.g. parent vs forked child.
    pub fn debug_walk(&self, va: u64) -> [u64; 4] {
        let idx = indices(va);
        let mut out = [0u64; 4];
        let mut table_off = 0usize;
        for level in 0..4usize {
            let off = table_off + idx[level] * 8;
            if off + 8 > self.bytes.len() {
                break;
            }
            let desc = self.read_desc(off);
            out[level] = desc;
            if level == 3 {
                break;
            }
            let valid = desc & VALID != 0;
            let is_table = desc & TYPE_BITS == TYPE_TABLE_OR_PAGE;
            if !(valid && is_table) {
                break;
            }
            match self.pa_to_off(desc & PA_MASK_TABLE) {
                Ok(o) => table_off = o,
                Err(_) => break,
            }
        }
        out
    }

    /// Carve a zeroed table page: reuse a coalesced one if available, else bump
    /// the spare tail. Freed pages were zeroed on free, the tail is zero from
    /// boot, so the returned page is always all-invalid descriptors.
    fn alloc_table(&mut self) -> Result<u64, PageTableError> {
        if let Some(pa) = self.free_tables.pop() {
            return Ok(pa);
        }
        let off = self.next_free;
        if off + PT_PAGE > self.bytes.len() as u64 {
            return Err(PageTableError::OutOfTables);
        }
        self.next_free += PT_PAGE;
        Ok(self.base + off)
    }

    /// Split the block descriptor at `parent_off` (a leaf at `level`, where
    /// level 1 = 1 GiB block, level 2 = 2 MiB block) into a finer sub-table,
    /// then rewrite the parent as a table descriptor pointing at it.
    fn split_block(&mut self, parent_off: usize, level: usize) -> Result<(), PageTableError> {
        let block = self.read_desc(parent_off);
        let (parent_pa_mask, child_pa_mask, child_stride, child_is_page) = match level {
            1 => (PA_MASK_1GIB, PA_MASK_2MIB, 1u64 << 21, false),
            2 => (PA_MASK_2MIB, PA_MASK_4KIB, 1u64 << 12, true),
            _ => return Err(PageTableError::BadAddress),
        };
        let base_pa = block & parent_pa_mask;
        // Leaf attributes minus the PA and the type bits.
        let attrs = block & !parent_pa_mask & !TYPE_BITS;
        let child_type = if child_is_page {
            TYPE_TABLE_OR_PAGE
        } else {
            TYPE_BLOCK
        };
        // The children must map exactly what the parent block did. Crucially,
        // preserve the parent's VALIDITY: splitting an INVALID block (e.g. a
        // coarse PROT_NONE reservation) must yield invalid children, not valid
        // ones — `child_type` sets the valid bit, so clear it when the parent
        // was invalid. (Getting this wrong silently revalidated PROT_NONE
        // reservations and broke Go's page-summary region.)
        let parent_valid = block & VALID != 0;

        let table_pa = self.alloc_table()?;
        let table_off = self.pa_to_off(table_pa)?;
        for i in 0..512u64 {
            let child_pa = base_pa + i * child_stride;
            let mut desc = (child_pa & child_pa_mask) | attrs | child_type;
            if !parent_valid {
                desc &= !VALID;
            }
            self.write_desc(table_off + (i as usize) * 8, desc);
        }
        // Parent becomes a table descriptor — exposed to the walker only after
        // the children above are visible (enforced in sync_to_host).
        self.write_table_desc(parent_off, (table_pa & PA_MASK_TABLE) | TYPE_TABLE_OR_PAGE);
        Ok(())
    }

    /// Descend to the leaf descriptor for `va`. When `allocate`, split any
    /// covering block so the returned leaf is a 4 KiB page; otherwise stop at
    /// the first leaf (block or page) and report its level.
    fn leaf_offset(&mut self, va: u64, allocate: bool) -> Result<(usize, usize), PageTableError> {
        let idx = indices(va);
        let mut table_off = 0usize; // L0 at byte offset 0
        for level in 0..4usize {
            let off = table_off + idx[level] * 8;
            if level == 3 {
                return Ok((off, 3));
            }
            let desc = self.read_desc(off);
            let valid = desc & VALID != 0;
            let is_table = desc & TYPE_BITS == TYPE_TABLE_OR_PAGE;
            if is_table && valid {
                table_off = self.pa_to_off(desc & PA_MASK_TABLE)?;
                continue;
            }
            // A block leaf (valid, type 0b01) or an invalid descriptor.
            if !allocate {
                return Ok((off, level));
            }
            if !valid {
                // Our identity layout never leaves an intermediate unmapped on
                // a path the guest can map; refuse to fabricate one.
                return Err(PageTableError::BadAddress);
            }
            // Valid block: split to finer granularity, then descend.
            self.split_block(off, level)?;
            let desc2 = self.read_desc(off);
            table_off = self.pa_to_off(desc2 & PA_MASK_TABLE)?;
        }
        Err(PageTableError::BadAddress)
    }

    /// Next-level table PA if the entry at `off` is a valid table descriptor.
    fn child_table_pa(&self, off: usize) -> Option<u64> {
        let d = self.read_desc(off);
        if d & VALID != 0 && d & TYPE_BITS == TYPE_TABLE_OR_PAGE {
            Some(d & PA_MASK_TABLE)
        } else {
            None
        }
    }

    /// If every one of a table's 512 entries is a valid leaf of `child_type`
    /// with contiguous identity PA (`child_pa_mask`/`child_stride`) and IDENTICAL
    /// attributes — i.e. the table is exactly equivalent to one coarse block —
    /// return `(base_pa, attrs)` for that block. Otherwise `None` (don't
    /// coalesce). The strict equality is what makes coalescing safe: the block
    /// we write maps precisely what the table did.
    fn uniform_block(
        &self,
        table_off: usize,
        child_pa_mask: u64,
        child_stride: u64,
        child_type: u64,
    ) -> Option<(u64, u64)> {
        let e0 = self.read_desc(table_off);
        if e0 & VALID == 0 || e0 & TYPE_BITS != child_type {
            return None;
        }
        let base_pa = e0 & child_pa_mask;
        let attrs = e0 & !child_pa_mask & !TYPE_BITS;
        for i in 0..512u64 {
            let d = self.read_desc(table_off + (i as usize) * 8);
            if d & VALID == 0
                || d & TYPE_BITS != child_type
                || (d & child_pa_mask) != base_pa + i * child_stride
                || (d & !child_pa_mask & !TYPE_BITS) != attrs
            {
                return None;
            }
        }
        Some((base_pa, attrs))
    }

    /// Collapse fully-uniform spare sub-tables covering `va` back into a single
    /// block, reclaiming the table page. L3→L2 (2 MiB) then L2→L1 (1 GiB).
    /// Only spare tables are touched (the boot L2_A/L2_B/L3_A — null guard +
    /// kernel hole — are never uniform and never spare, so are doubly safe).
    fn try_coalesce(&mut self, va: u64) {
        // Coalescing flips a table descriptor to a block (and frees the
        // sub-table) for a live VA. That is a break-before-make structural
        // change: a sibling vCPU mid-walk through the old table-pointer can hit
        // the being-freed sub-table and fault (proven via the mmap-churn
        // reproducer + host-table walk). Correct break-before-make needs an
        // all-vCPU TLB flush, which one vCPU's `tlbi vmalle1is` does not provide
        // under HVF. So coalesce only when single-vCPU (no siblings to race);
        // when multi-vCPU the structure stays split — safe, at the cost of not
        // reclaiming until back to one vCPU.
        if self.multi_vcpu {
            return;
        }
        let idx = indices(va);
        let Some(l1_pa) = self.child_table_pa(idx[0] * 8) else {
            return;
        };
        let Ok(l1_off) = self.pa_to_off(l1_pa) else {
            return;
        };
        let l1_entry = l1_off + idx[1] * 8;

        // L3 -> L2: the L2 entry must point at a spare L3 table of uniform pages.
        if let Some(l2_pa) = self.child_table_pa(l1_entry) {
            if let Ok(l2_off) = self.pa_to_off(l2_pa) {
                let l2_entry = l2_off + idx[2] * 8;
                if let Some(l3_pa) = self.child_table_pa(l2_entry) {
                    if self.is_spare_table(l3_pa) {
                        if let Ok(l3_off) = self.pa_to_off(l3_pa) {
                            if let Some((base, attrs)) = self.uniform_block(
                                l3_off,
                                PA_MASK_4KIB,
                                1 << 12,
                                TYPE_TABLE_OR_PAGE,
                            ) {
                                self.write_desc(
                                    l2_entry,
                                    (base & PA_MASK_2MIB) | attrs | TYPE_BLOCK,
                                );
                                self.free_table(l3_pa);
                            }
                        }
                    }
                }
            }
        }

        // L2 -> L1: the L1 entry must point at a spare L2 table of uniform blocks.
        if let Some(l2_pa) = self.child_table_pa(l1_entry) {
            if self.is_spare_table(l2_pa) {
                if let Ok(l2_off) = self.pa_to_off(l2_pa) {
                    if let Some((base, attrs)) =
                        self.uniform_block(l2_off, PA_MASK_2MIB, 1 << 21, TYPE_BLOCK)
                    {
                        self.write_desc(l1_entry, (base & PA_MASK_1GIB) | attrs | TYPE_BLOCK);
                        self.free_table(l2_pa);
                    }
                }
            }
        }
    }

    /// Block size in bytes mapped by a leaf at `level` (1=1 GiB, 2=2 MiB,
    /// 3=4 KiB) and the matching PA mask.
    fn level_span(level: usize) -> (u64, u64) {
        match level {
            1 => (1 << 30, PA_MASK_1GIB),
            2 => (1 << 21, PA_MASK_2MIB),
            _ => (1 << 12, PA_MASK_4KIB),
        }
    }

    /// Build the leaf descriptor for `op` covering `base_pa` at `level`.
    fn desc_for(op: PtOp, base_pa: u64, level: usize) -> u64 {
        let (_, mask) = Self::level_span(level);
        // Block at L1/L2, page at L3 (type bit differs; USER_PAGE_FLAGS adds it).
        let flags = if level == 3 {
            USER_PAGE_FLAGS
        } else {
            USER_BLOCK_FLAGS
        };
        let base = base_pa & mask;
        // UXN (bit 54) is set for a non-exec leaf; cleared for an exec one.
        // USER_*_FLAGS start UXN-clear (executable), so OR in UXN when !exec.
        let uxn = |exec: bool| if exec { 0 } else { UXN };
        match op {
            PtOp::Invalidate => base | (flags & !VALID),
            PtOp::ReadWrite { exec } => base | flags | uxn(exec),
            PtOp::ReadOnly { exec } => base | (flags & !AP_MASK) | AP_RO | uxn(exec),
        }
    }

    /// Does a leaf with `(valid, ap, uxn_set)` already satisfy `op`? Includes the
    /// UXN (execute) bit so a re-protect that only flips PROT_EXEC still applies.
    fn satisfies(op: PtOp, valid: bool, ap: u64, uxn_set: bool) -> bool {
        match op {
            PtOp::Invalidate => !valid,
            PtOp::ReadWrite { exec } => valid && ap == AP_RW && uxn_set == !exec,
            PtOp::ReadOnly { exec } => valid && ap == AP_RO && uxn_set == !exec,
        }
    }

    /// Apply `op` to `[va, va+len)` at the COARSEST granularity possible: edit a
    /// covering block descriptor in place when the whole block lies inside the
    /// range, and split one level finer only at an unaligned range edge. This
    /// keeps the stage-1 tables sparse — a 512 MiB `PROT_NONE` reservation costs
    /// one L1→L2 split + 256 L2-block edits (1 table), not 256 L3 tables. Skips
    /// granules already at the target protection (so RW-on-already-RW is free).
    fn apply(&mut self, va: u64, len: usize, op: PtOp) -> Result<bool, PageTableError> {
        let end = va + (len as u64).div_ceil(PT_PAGE) * PT_PAGE;
        let mut cur = va;
        let mut changed = false;
        while cur < end {
            // The existing covering descriptor (block or page) for `cur`.
            let (off, level) = self.leaf_offset(cur, false)?;
            let (span, mask) = Self::level_span(level);
            let block_start = cur & mask;
            let block_end = block_start + span;
            let desc = self.read_desc(off);
            if Self::satisfies(op, desc & VALID != 0, desc & AP_MASK, desc & UXN != 0) {
                // The covering block is ALREADY at the target — skip its whole
                // span with no split (this is what keeps RW-on-already-RW, and a
                // re-protect of an unchanged range, free).
                cur = block_end;
            } else if block_start >= va && block_end <= end {
                // The whole covering block is inside the range and needs the
                // change: edit it in place at this level (no split).
                self.write_desc(off, Self::desc_for(op, block_start, level));
                changed = true;
                cur = block_end;
            } else {
                // The range edge bisects a block that needs changing: split one
                // level finer and re-examine (a 4 KiB page is never bisected —
                // len is page aligned — so `level` here is always 1 or 2). The
                // split itself mutates the tables (parent → table pointer + a
                // new sub-table), so it must be synced even if the subsequent
                // in-range edits all happen to be no-ops.
                self.split_block(off, level)?;
                changed = true;
                // `cur` unchanged; loop re-reads the now-finer covering leaf.
            }
        }
        // Reclaim any sub-table the edit left fully uniform (single-vCPU only;
        // see try_coalesce). Walk one VA per 2 MiB block touched.
        if changed {
            let mut block = va & !((1 << 21) - 1);
            while block < end {
                self.try_coalesce(block);
                block += 1 << 21;
            }
        }
        Ok(changed)
    }

    /// Mark `[va, va+len)` invalid (faults on any access → SEGV_MAPERR).
    pub fn set_prot_none(&mut self, va: u64, len: usize) -> Result<bool, PageTableError> {
        self.apply(va, len, PtOp::Invalidate)
    }

    /// Alias for `set_prot_none`, used by `munmap` (the freed range faults
    /// until reused).
    pub fn invalidate(&mut self, va: u64, len: usize) -> Result<bool, PageTableError> {
        self.set_prot_none(va, len)
    }

    /// Mark `[va, va+len)` valid read-only (AP=RO). `exec` clears UXN
    /// (executable, PROT_EXEC); otherwise UXN is set (non-executable / NX).
    pub fn set_readonly(
        &mut self,
        va: u64,
        len: usize,
        exec: bool,
    ) -> Result<bool, PageTableError> {
        self.apply(va, len, PtOp::ReadOnly { exec })
    }

    /// Restore `[va, va+len)` to a valid RW user page (identity-mapped). `exec`
    /// clears UXN (executable, PROT_EXEC); otherwise UXN is set (NX).
    pub fn set_rw(&mut self, va: u64, len: usize, exec: bool) -> Result<bool, PageTableError> {
        self.apply(va, len, PtOp::ReadWrite { exec })
    }

    /// Build a fresh VA→IPA translation for `[va, va+len)` for EL0, creating
    /// any missing L1/L2/L3 sub-tables. This is the dynamic counterpart of the
    /// boot Rosetta alias: it maps high guest VAs (which can't be
    /// identity-mapped — HVF's IPA is only 40 bits) down to a low IPA the caller
    /// has `hv_vm_map`'d. Uses 2 MiB blocks when `va`/`ipa`/`len` are 2 MiB
    /// aligned, else 4 KiB pages. The target VA range must be previously
    /// unmapped (high space the boot tables never populate). Always Ok(true).
    ///
    /// `writable`: when false the leaf is built AP=RO (read-only at EL0/EL1)
    /// while PRESERVING the IPA output address — so a guest store to a
    /// SHM_RDONLY shmat alias raises a stage-1 permission abort (SIGSEGV),
    /// matching Linux. The output address must stay the low IPA (NOT VA&mask),
    /// because an alias is non-identity (VA != IPA); set_readonly/apply would
    /// rebuild it from the VA and destroy the mapping, which is why writability
    /// is threaded in HERE instead.
    pub fn map_aliased(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        writable: bool,
    ) -> Result<bool, PageTableError> {
        const TWO_MIB: u64 = 1 << 21;
        const FOUR_KIB: u64 = 1 << 12;
        let block_flags = if writable {
            USER_BLOCK_FLAGS
        } else {
            (USER_BLOCK_FLAGS & !AP_MASK) | AP_RO
        };
        let page_flags = if writable {
            USER_PAGE_FLAGS
        } else {
            (USER_PAGE_FLAGS & !AP_MASK) | AP_RO
        };
        if va % TWO_MIB == 0 && ipa % TWO_MIB == 0 {
            // Map the 2 MiB-aligned BULK as L2 block leaves (one descriptor per
            // 2 MiB, no per-2-MiB L3 table), then the sub-2-MiB TAIL as 4 KiB
            // pages (a single L3 table). A multi-GiB alias whose length is not a
            // multiple of 2 MiB — e.g. CPython's `mmap` of a 2 GiB sparse file →
            // 2 GiB + 16 KiB — otherwise fell to the page-granular loop below for
            // the WHOLE region, allocating ~1 L3 table per 2 MiB (~1024 tables for
            // 2 GiB). That exhausts the spare pool (OutOfTables) and leaves a
            // half-built mapping the guest re-faults on forever (an apparent hang).
            let blocks = len / TWO_MIB;
            for i in 0..blocks {
                let v = va + i * TWO_MIB;
                let p = ipa + i * TWO_MIB;
                let l2_off = self.descend_creating(v, 2)?;
                let idx = indices(v);
                self.write_desc(l2_off + idx[2] * 8, (p & PA_MASK_2MIB) | block_flags);
            }
            let tail_off = blocks * TWO_MIB;
            let tail_pages = (len - tail_off).div_ceil(FOUR_KIB);
            for j in 0..tail_pages {
                let v = va + tail_off + j * FOUR_KIB;
                let p = ipa + tail_off + j * FOUR_KIB;
                let l3_off = self.descend_creating(v, 3)?;
                let idx = indices(v);
                self.write_desc(l3_off + idx[3] * 8, (p & PA_MASK_4KIB) | page_flags);
            }
            return Ok(true);
        }
        // va/ipa not 2 MiB-aligned (no caller does this for aliases today, but
        // keep a correct fallback): page-granular throughout.
        let pages = len.div_ceil(FOUR_KIB);
        for i in 0..pages {
            let v = va + i * FOUR_KIB;
            let p = ipa + i * FOUR_KIB;
            let l3_off = self.descend_creating(v, 3)?;
            let idx = indices(v);
            self.write_desc(l3_off + idx[3] * 8, (p & PA_MASK_4KIB) | page_flags);
        }
        Ok(true)
    }

    /// Descend from L0 to the table at `target_level` (1, 2, or 3), allocating
    /// any missing intermediate table from the spare pool. Returns the byte
    /// offset of that table within the region. Errors if an existing block sits
    /// on the path (never the case for the high alias space).
    fn descend_creating(&mut self, va: u64, target_level: usize) -> Result<usize, PageTableError> {
        let idx = indices(va);
        let mut table_off = 0usize; // L0 at byte offset 0
        for level in 0..target_level {
            let off = table_off + idx[level] * 8;
            let desc = self.read_desc(off);
            let valid = desc & VALID != 0;
            let is_table = desc & TYPE_BITS == TYPE_TABLE_OR_PAGE;
            if valid && is_table {
                table_off = self.pa_to_off(desc & PA_MASK_TABLE)?;
                continue;
            }
            if valid {
                // A valid BLOCK leaf covering this VA. Split it into a finer
                // sub-table (preserving its mapping + validity) so we can
                // descend and install a sub-range — e.g. a finer mapping inside
                // a 2 MiB block an earlier alias mapping created (the case a
                // forked child hits when it maps inside a block its parent's
                // cloned tables already established). Mirrors `leaf_offset`.
                self.split_block(off, level)?;
                let desc2 = self.read_desc(off);
                table_off = self.pa_to_off(desc2 & PA_MASK_TABLE)?;
                continue;
            }
            let pa = self.alloc_table()?;
            table_off = self.pa_to_off(pa)?;
            self.write_table_desc(off, (pa & PA_MASK_TABLE) | TYPE_TABLE_OR_PAGE);
        }
        Ok(table_off)
    }

    /// True iff the leaf for `va` (block or page) is valid. Test/diagnostic.
    #[cfg(test)]
    pub fn is_valid(&mut self, va: u64) -> bool {
        match self.leaf_offset(va, false) {
            Ok((off, _)) => self.read_desc(off) & VALID != 0,
            Err(_) => false,
        }
    }

    /// AP[2:1] of the leaf for `va`. Test/diagnostic.
    #[cfg(test)]
    pub fn ap_bits(&mut self, va: u64) -> u64 {
        match self.leaf_offset(va, false) {
            Ok((off, _)) => self.read_desc(off) & AP_MASK,
            Err(_) => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{
        LINUX_ALIAS_IPA_BASE, LINUX_HIGH_VA_THRESHOLD, LINUX_MMAP_BASE, LINUX_PAGE_TABLES_BASE,
        stage1_identity_page_tables,
    };

    fn manager() -> PageTableManager {
        // Pad with spare table pages so split has room (mirrors Phase C1).
        let mut bytes = stage1_identity_page_tables();
        bytes.resize(0x40000, 0);
        PageTableManager::new(bytes, LINUX_PAGE_TABLES_BASE)
    }

    #[test]
    fn indices_decompose_va() {
        let i = indices(LINUX_MMAP_BASE); // 0x60_0000_0000
        assert_eq!(i[0], 0);
        assert_eq!(i[1], (LINUX_MMAP_BASE >> 30 & 0x1ff) as usize);
    }

    #[test]
    fn rosetta_alias_vas_avoid_boot_identity_l0_slots() {
        // The boot identity map covers 0..1 TiB, occupying L0 slots [0, 1].
        // TTBR1 shares the TTBR0 root, so an aliased upper-half VA is correct
        // only if it indexes a DISJOINT L0 slot. Every is_high_va VA (>= the
        // 1 TiB threshold) does by construction; spot-check the VAs Rosetta
        // actually uses — the stripped translated-ELF mmap and the 240 TiB arena.
        assert_eq!(indices(LINUX_HIGH_VA_THRESHOLD - 1)[0], 1); // last identity slot
        // Stripped x86-64 high-half ELF mmap (0xffff_ffff_ffff_4000 & 48-bit mask).
        let elf_va = 0xffff_ffff_ffff_4000u64 & 0x0000_FFFF_FFFF_FFFF;
        assert!(
            indices(elf_va)[0] >= 2,
            "ELF alias collides with identity L0[0..1]"
        );
        // Rosetta's ~240 TiB translation arena.
        let arena_va = 240u64 * (1 << 40);
        assert!(
            indices(arena_va)[0] >= 2,
            "arena alias collides with identity L0[0..1]"
        );
    }

    #[test]
    fn user_block_flags_match_boot_image() {
        // Drift guard: L1B[0] (offset 0x2000) maps 512 GiB as a USER block.
        let bytes = stage1_identity_page_tables();
        let mut a = [0u8; 8];
        a.copy_from_slice(&bytes[0x2000..0x2008]);
        let desc = u64::from_le_bytes(a);
        assert_eq!(desc & !PA_MASK_1GIB, USER_BLOCK_FLAGS);
    }

    #[test]
    fn set_prot_none_splits_block_and_invalidates_only_target() {
        let mut mgr = manager();
        let va = LINUX_MMAP_BASE + 0x10_0000; // inside a 1 GiB block
        assert!(mgr.is_valid(va), "arena starts mapped");
        mgr.set_prot_none(va, 0x1000).expect("split + invalidate");
        assert!(!mgr.is_valid(va), "target page now faults");
        assert!(mgr.is_valid(va + 0x1000), "next page stays mapped");
        assert!(
            mgr.is_valid(va.wrapping_sub(0x1000)),
            "prev page stays mapped"
        );
    }

    #[test]
    fn set_readonly_then_rw_round_trips() {
        let mut mgr = manager();
        let va = LINUX_MMAP_BASE + 0x20_0000;
        mgr.set_readonly(va, 0x1000, true).expect("ro");
        assert_eq!(mgr.ap_bits(va), AP_RO);
        assert!(mgr.is_valid(va));
        mgr.set_rw(va, 0x1000, true).expect("rw");
        assert_eq!(mgr.ap_bits(va), AP_RW);
        assert!(mgr.is_valid(va));
    }

    #[test]
    fn prot_none_then_rw_remaps() {
        let mut mgr = manager();
        let va = LINUX_MMAP_BASE + 0x30_0000;
        mgr.set_prot_none(va, 0x2000).expect("none");
        assert!(!mgr.is_valid(va));
        assert!(!mgr.is_valid(va + 0x1000));
        mgr.set_rw(va, 0x2000, true).expect("rw");
        assert!(mgr.is_valid(va));
        assert!(mgr.is_valid(va + 0x1000));
    }

    #[test]
    fn map_aliased_large_unaligned_len_does_not_exhaust_table_pool() {
        // A large file-backed alias whose length is NOT a multiple of 2 MiB (e.g.
        // CPython's `mmap(2GB-sparse-file)` → 2 GiB + 16 KiB) must map its
        // 2 MiB-aligned bulk as BLOCKS (L2 leaves, no L3 table per 2 MiB) and only
        // the sub-2 MiB tail as 4 KiB pages. The old code fell to a fully
        // page-granular loop for the WHOLE region, allocating one L3 table per
        // 2 MiB — ~1024 tables for 2 GiB — which exhausts the spare pool, returns
        // OutOfTables, and (in the runtime) leaves a half-built mapping the guest
        // re-faults on forever. 128 MiB + 16 KiB needs ~66 L3 tables page-granular
        // (> the 56-page test pool) but only ~3 tables block+tail.
        let mut mgr = manager();
        let va = LINUX_HIGH_VA_THRESHOLD; // 1 TiB, 2 MiB-aligned (alias VA base)
        let ipa = LINUX_ALIAS_IPA_BASE; // 96 GiB, 2 MiB-aligned
        let bulk = 128 * (1u64 << 20); // 128 MiB (64 blocks)
        let len = bulk + 0x4000; // + 16 KiB tail → not 2 MiB-aligned
        let ok = mgr
            .map_aliased(va, ipa, len, true)
            .expect("large unaligned alias must not exhaust the table pool");
        assert!(ok);
        assert!(mgr.is_valid(va), "first block of the bulk is mapped");
        assert!(
            mgr.is_valid(va + bulk - 0x1000),
            "last page of the bulk is mapped"
        );
        assert!(
            mgr.is_valid(va + bulk),
            "first tail page (past the 2 MiB-aligned bulk) is mapped"
        );
        assert!(mgr.is_valid(va + len - 0x1000), "last tail page is mapped");
        assert!(
            !mgr.is_valid(va + len),
            "one page past the mapping is NOT mapped"
        );
    }

    #[test]
    fn clone_preserves_bump_cursor_so_fork_child_does_not_realloc_live_tables() {
        // Regression for the cross-test TestUserArenaNew SIGSEGV: fork rebuilt
        // the child (and, before the fix, the PARENT) with a FRESH manager,
        // resetting `next_free` to the first spare while the copied backing
        // already had that page live as an L2 table. The next split then
        // re-handed-out the in-use page and wrote L3 entries over the live L2
        // table. fork must CLONE the manager (preserving the cursor), not reset.
        let mut parent = manager();
        // Split two distinct 1 GiB regions → two live spare sub-tables.
        parent
            .set_prot_none(LINUX_MMAP_BASE + 0x10_0000, 0x1000)
            .unwrap();
        parent
            .set_prot_none(LINUX_MMAP_BASE + 0x4080_0000, 0x1000)
            .unwrap();
        let (parent_in_use, _, _) = parent.pool_stats();
        assert!(parent_in_use >= 2, "two splits allocated >=2 tables");

        // The child inherits a CLONE — cursor and live tables intact.
        let mut child = parent.clone();
        assert_eq!(child.pool_stats(), parent.pool_stats(), "cursor preserved");
        // The parent's splits are visible (and correct) in the child.
        assert!(!child.is_valid(LINUX_MMAP_BASE + 0x10_0000));
        assert!(child.is_valid(LINUX_MMAP_BASE + 0x10_0000 + 0x1000));

        // A NEW split in the child must allocate a FRESH page (in_use grows),
        // never re-use a live table — and must not disturb the parent's edits.
        child
            .set_prot_none(LINUX_MMAP_BASE + 0x8080_0000, 0x1000)
            .unwrap();
        let (child_in_use, _, _) = child.pool_stats();
        assert!(child_in_use > parent_in_use, "fresh table, no re-handout");
        // The first split's neighborhood is still a correctly-mapped page (the
        // bug clobbered exactly this L2 table with an L3 page descriptor).
        assert!(child.is_valid(LINUX_MMAP_BASE + 0x10_0000 + 0x1000));
    }

    #[test]
    fn exhausting_spare_tables_errors() {
        // Truncate to exactly the six boot tables (no spare pool), so the very
        // first block split has nowhere to allocate and surfaces OutOfTables.
        let mut bytes = stage1_identity_page_tables();
        bytes.truncate(6 * 0x1000);
        let mut mgr = PageTableManager::new(bytes, LINUX_PAGE_TABLES_BASE);
        assert_eq!(
            mgr.set_prot_none(LINUX_MMAP_BASE + 0x10_0000, 0x1000),
            Err(PageTableError::OutOfTables),
        );
    }

    #[test]
    fn set_rw_on_default_rw_block_does_not_split() {
        // No spare pages: setting RW-non-exec on the already-RW-non-exec arena
        // must skip (no split) and succeed, rather than exhaust the pool. The
        // arena's boot blocks default UXN=1 (NX), so a non-exec mmap matches the
        // existing leaf — the common case must stay a no-op (no dense split).
        let mut bytes = stage1_identity_page_tables();
        bytes.truncate(6 * 0x1000);
        let mut mgr = PageTableManager::new(bytes, LINUX_PAGE_TABLES_BASE);
        // Already RW + non-exec → no change, no split, no allocation.
        assert_eq!(
            mgr.set_rw(LINUX_MMAP_BASE + 0x10_0000, 0x4000, false),
            Ok(false)
        );
    }

    #[test]
    fn full_block_restore_coalesces_and_reclaims_table() {
        // Split a 2 MiB block (set one page PROT_NONE), then restore the WHOLE
        // 2 MiB to RW: the sub-table becomes uniform and is reclaimed, so the
        // spare cursor/free-list returns to its pre-split capacity.
        let mut mgr = manager();
        let block = LINUX_MMAP_BASE + 0x20_0000; // 2 MiB-aligned arena block
        mgr.set_prot_none(block, 0x1000).expect("split");
        let after_split = mgr.next_free;
        assert!(
            after_split > SPARE_START_OFFSET,
            "split consumed spare pages"
        );
        // Restore the entire 2 MiB block to RW -> uniform -> coalesce.
        mgr.set_rw(block, 1 << 21, true).expect("restore");
        assert!(mgr.is_valid(block));
        assert!(
            !mgr.free_tables.is_empty(),
            "coalesce reclaimed a sub-table"
        );
    }

    #[test]
    fn large_aligned_prot_none_is_coarse_not_dense() {
        // A 512 MiB PROT_NONE on the (1 GiB-aligned) arena base must cost ONE
        // L1->L2 split (then 256 in-place L2-block edits), NOT 256 L3 tables.
        // This is the Go page-summary-reservation regression fix.
        let mut mgr = manager();
        assert_eq!(
            LINUX_MMAP_BASE % (1 << 30),
            0,
            "arena base is 1 GiB-aligned"
        );
        let before = mgr.next_free;
        mgr.set_prot_none(LINUX_MMAP_BASE, 512 << 20)
            .expect("coarse prot_none");
        let pages_used = (mgr.next_free - before) / 0x1000;
        assert_eq!(
            pages_used, 1,
            "512 MiB PROT_NONE used {pages_used} tables, want 1"
        );
        assert!(!mgr.is_valid(LINUX_MMAP_BASE));
        assert!(!mgr.is_valid(LINUX_MMAP_BASE + (512 << 20) - 0x1000));
        // Just past the range stays valid.
        assert!(mgr.is_valid(LINUX_MMAP_BASE + (512 << 20)));
    }

    #[test]
    fn rw_commit_into_prot_none_block_keeps_neighbors_invalid() {
        // Go's page allocator shape: reserve a region PROT_NONE (coarse,
        // invalid block), then RW-commit a single page inside it (MAP_FIXED).
        // The committed page must become RW; the rest of the (split) block must
        // STAY invalid — splitting an invalid block must not revalidate it.
        let mut mgr = manager();
        let block = LINUX_MMAP_BASE; // 2 MiB-aligned
        mgr.set_prot_none(block, 1 << 21)
            .expect("reserve PROT_NONE");
        assert!(!mgr.is_valid(block));
        assert!(!mgr.is_valid(block + 0x1000));
        // Commit one page RW (splits the invalid 2 MiB block to L3).
        mgr.set_rw(block + 0x10000, 0x1000, true)
            .expect("RW commit");
        assert!(mgr.is_valid(block + 0x10000), "committed page is RW");
        assert_eq!(mgr.ap_bits(block + 0x10000), AP_RW);
        assert!(!mgr.is_valid(block), "neighbor page 0 stays invalid");
        assert!(
            !mgr.is_valid(block + 0x1000),
            "neighbor page 1 stays invalid"
        );
        assert!(
            !mgr.is_valid(block + 0x1ff000),
            "last page of the 2 MiB block stays invalid"
        );
    }

    #[test]
    fn full_1gib_prot_none_edits_block_with_no_split() {
        // A whole 1 GiB-aligned 1 GiB PROT_NONE flips the L1 block in place — 0
        // splits — so it works even with no spare pages.
        let mut bytes = stage1_identity_page_tables();
        bytes.truncate(6 * 0x1000);
        let mut mgr = PageTableManager::new(bytes, LINUX_PAGE_TABLES_BASE);
        assert_eq!(mgr.set_prot_none(LINUX_MMAP_BASE, 1 << 30), Ok(true));
        assert!(!mgr.is_valid(LINUX_MMAP_BASE));
        assert!(!mgr.is_valid(LINUX_MMAP_BASE + (1 << 30) - 0x1000));
    }

    #[test]
    fn multi_vcpu_does_not_coalesce() {
        // With sibling vCPUs live, a full-block restore must NOT coalesce
        // (coalesce is a break-before-make change unsafe without an all-vCPU
        // flush). The structure stays split; no table is reclaimed.
        let mut mgr = manager();
        mgr.set_multi_vcpu(true);
        let block = LINUX_MMAP_BASE + 0x60_0000;
        mgr.set_prot_none(block, 0x1000).expect("split");
        mgr.set_rw(block, 1 << 21, true).expect("restore");
        assert!(mgr.is_valid(block));
        assert!(
            mgr.free_tables.is_empty(),
            "multi-vCPU must NOT coalesce/reclaim"
        );
        // Back to single-vCPU, a subsequent full-block restore coalesces again.
        mgr.set_multi_vcpu(false);
        mgr.set_prot_none(block, 0x1000).expect("split");
        mgr.set_rw(block, 1 << 21, true).expect("restore");
        assert!(
            !mgr.free_tables.is_empty(),
            "single-vCPU coalesces/reclaims"
        );
    }

    #[test]
    fn partial_protection_does_not_coalesce() {
        // One page RO, the rest RW: NOT uniform -> must keep the sub-table.
        let mut mgr = manager();
        let block = LINUX_MMAP_BASE + 0x40_0000;
        mgr.set_readonly(block, 0x1000, true).expect("ro one page");
        mgr.set_rw(block, 1 << 21, true).expect("rw the rest");
        // The RO page was overwritten to RW by the full-block set_rw, so it WILL
        // coalesce; instead verify a genuinely-mixed state is preserved:
        let mut mgr2 = manager();
        mgr2.set_readonly(block, 0x1000, true).expect("ro one page");
        mgr2.set_rw(block + 0x1000, 0x1000, true)
            .expect("rw next page");
        assert_eq!(mgr2.ap_bits(block), AP_RO, "mixed block keeps RO page");
        assert_eq!(mgr2.ap_bits(block + 0x1000), AP_RW);
        assert!(mgr2.free_tables.is_empty(), "mixed block must not coalesce");
    }

    #[test]
    fn into_bytes_preserves_edits() {
        let mut mgr = manager();
        let va = LINUX_MMAP_BASE + 0x40_0000;
        mgr.set_prot_none(va, 0x1000).unwrap();
        let bytes = mgr.into_bytes();
        let mut mgr2 = PageTableManager::new(bytes, LINUX_PAGE_TABLES_BASE);
        assert!(!mgr2.is_valid(va), "edit survived round-trip through bytes");
    }
}
