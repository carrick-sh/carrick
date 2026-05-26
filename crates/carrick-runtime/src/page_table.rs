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

// The editor is consumed by the syscall path in Phase D of this plan
// (mprotect/PROT_NONE/munmap wiring); until then only the unit tests exercise
// it. Remove this allow when `trap.rs` calls `protect_range`/`unmap_range`.
#![allow(dead_code)]

// Leaf attribute layout (must match `memory::stage1_identity_page_tables`).
const VALID: u64 = 1 << 0;
const TYPE_BITS: u64 = 0b11;
const TYPE_TABLE_OR_PAGE: u64 = 0b11; // L0..L2 table descriptor, or L3 page
const TYPE_BLOCK: u64 = 0b01; // L1/L2 block descriptor
const AP_MASK: u64 = 0b11 << 6; // AP[2:1]
const AP_RW: u64 = 0b01 << 6; // RW at EL0+EL1
const AP_RO: u64 = 0b11 << 6; // RO at EL0+EL1

// PA field masks per level (identical to memory.rs).
const PA_MASK_1GIB: u64 = 0x0000_FFFF_C000_0000;
const PA_MASK_2MIB: u64 = 0x0000_FFFF_FFE0_0000;
const PA_MASK_4KIB: u64 = 0x0000_FFFF_FFFF_F000;
const PA_MASK_TABLE: u64 = 0x0000_FFFF_FFFF_F000; // next-level table PA (bits 47:12)

// User leaf flags (must match memory.rs USER_BLOCK_FLAGS / USER_PAGE_FLAGS).
const USER_BLOCK_FLAGS: u64 = (1u64 << 53) | (1 << 10) | (0b11 << 8) | (0b01 << 6) | 0b01;
const USER_PAGE_FLAGS: u64 = USER_BLOCK_FLAGS | 0b10;

const PT_PAGE: u64 = 0x1000; // stage-1 table page size (4 KiB granule)
// The boot image lays out six tables (L0, L1A, L1B, L2A, L2B, L3A) in the
// first six 4 KiB pages; runtime-allocated sub-tables come from the spare tail.
const SPARE_START_OFFSET: u64 = 6 * PT_PAGE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PageTableError {
    /// No spare table pages left to split a block.
    OutOfTables,
    /// A guest VA whose translation path leaves the page-table region, or an
    /// intermediate descriptor is unexpectedly unmapped.
    BadAddress,
}

/// Per-level table index for `va` (4 KiB granule, 40-bit IPA).
pub(crate) fn indices(va: u64) -> [usize; 4] {
    [
        ((va >> 39) & 0x1ff) as usize,
        ((va >> 30) & 0x1ff) as usize,
        ((va >> 21) & 0x1ff) as usize,
        ((va >> 12) & 0x1ff) as usize,
    ]
}

/// Mutable editor over a copy of the page-table region bytes.
pub(crate) struct PageTableManager {
    bytes: Vec<u8>,
    /// PA mapped at byte offset 0 (`LINUX_PAGE_TABLES_BASE`).
    base: u64,
    /// Byte offset of the next free spare page (bump allocator).
    next_free: u64,
}

impl PageTableManager {
    pub(crate) fn new(bytes: Vec<u8>, base: u64) -> Self {
        Self {
            bytes,
            base,
            next_free: SPARE_START_OFFSET,
        }
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    fn read_desc(&self, off: usize) -> u64 {
        let mut a = [0u8; 8];
        a.copy_from_slice(&self.bytes[off..off + 8]);
        u64::from_le_bytes(a)
    }

    fn write_desc(&mut self, off: usize, desc: u64) {
        self.bytes[off..off + 8].copy_from_slice(&desc.to_le_bytes());
    }

    /// Byte offset of a PA known to live inside the page-table region.
    fn pa_to_off(&self, pa: u64) -> Result<usize, PageTableError> {
        let end = self.base + self.bytes.len() as u64;
        if pa < self.base || pa >= end {
            return Err(PageTableError::BadAddress);
        }
        Ok((pa - self.base) as usize)
    }

    /// Carve a fresh zeroed table page from the spare tail; returns its PA.
    fn alloc_table(&mut self) -> Result<u64, PageTableError> {
        let off = self.next_free;
        if off + PT_PAGE > self.bytes.len() as u64 {
            return Err(PageTableError::OutOfTables);
        }
        self.next_free += PT_PAGE;
        // Bytes are already zero (invalid descriptors) from boot zero-fill.
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

        let table_pa = self.alloc_table()?;
        let table_off = self.pa_to_off(table_pa)?;
        for i in 0..512u64 {
            let child_pa = base_pa + i * child_stride;
            let desc = (child_pa & child_pa_mask) | attrs | child_type;
            self.write_desc(table_off + (i as usize) * 8, desc);
        }
        // Parent becomes a table descriptor.
        self.write_desc(parent_off, (table_pa & PA_MASK_TABLE) | TYPE_TABLE_OR_PAGE);
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

    /// Run `edit` on the 4 KiB leaf descriptor of every page in `[va, va+len)`,
    /// splitting covering blocks as needed.
    fn edit_pages(
        &mut self,
        va: u64,
        len: usize,
        edit: impl Fn(u64, u64) -> u64,
    ) -> Result<(), PageTableError> {
        let pages = (len as u64).div_ceil(PT_PAGE);
        for p in 0..pages {
            let page_va = va + p * PT_PAGE;
            let (off, _level) = self.leaf_offset(page_va, true)?;
            let desc = self.read_desc(off);
            self.write_desc(off, edit(desc, page_va));
        }
        Ok(())
    }

    /// Mark `[va, va+len)` invalid (faults on any access → SEGV_MAPERR).
    pub(crate) fn set_prot_none(&mut self, va: u64, len: usize) -> Result<(), PageTableError> {
        self.edit_pages(va, len, |desc, _| desc & !VALID)
    }

    /// Alias for `set_prot_none`, used by `munmap` (the freed range faults
    /// until reused). Kept distinct for call-site clarity; the caller lands in
    /// Phase D (dispatcher wiring).
    pub(crate) fn invalidate(&mut self, va: u64, len: usize) -> Result<(), PageTableError> {
        self.set_prot_none(va, len)
    }

    /// Mark `[va, va+len)` read-only (valid, AP=RO). Clears UXN unchanged.
    pub(crate) fn set_readonly(&mut self, va: u64, len: usize) -> Result<(), PageTableError> {
        self.edit_pages(va, len, |desc, _| (desc & !AP_MASK) | AP_RO | VALID)
    }

    /// Restore `[va, va+len)` to a valid RW user page (identity-mapped).
    pub(crate) fn set_rw(&mut self, va: u64, len: usize) -> Result<(), PageTableError> {
        self.edit_pages(va, len, |_desc, page_va| {
            (page_va & PA_MASK_4KIB) | USER_PAGE_FLAGS
        })
    }

    /// True iff the leaf for `va` (block or page) is valid. Test/diagnostic.
    #[cfg(test)]
    pub(crate) fn is_valid(&mut self, va: u64) -> bool {
        match self.leaf_offset(va, false) {
            Ok((off, _)) => self.read_desc(off) & VALID != 0,
            Err(_) => false,
        }
    }

    /// AP[2:1] of the leaf for `va`. Test/diagnostic.
    #[cfg(test)]
    pub(crate) fn ap_bits(&mut self, va: u64) -> u64 {
        match self.leaf_offset(va, false) {
            Ok((off, _)) => self.read_desc(off) & AP_MASK,
            Err(_) => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{LINUX_MMAP_BASE, LINUX_PAGE_TABLES_BASE, stage1_identity_page_tables};

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
        mgr.set_readonly(va, 0x1000).expect("ro");
        assert_eq!(mgr.ap_bits(va), AP_RO);
        assert!(mgr.is_valid(va));
        mgr.set_rw(va, 0x1000).expect("rw");
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
        mgr.set_rw(va, 0x2000).expect("rw");
        assert!(mgr.is_valid(va));
        assert!(mgr.is_valid(va + 0x1000));
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
    fn into_bytes_preserves_edits() {
        let mut mgr = manager();
        let va = LINUX_MMAP_BASE + 0x40_0000;
        mgr.set_prot_none(va, 0x1000).unwrap();
        let bytes = mgr.into_bytes();
        let mut mgr2 = PageTableManager::new(bytes, LINUX_PAGE_TABLES_BASE);
        assert!(!mgr2.is_valid(va), "edit survived round-trip through bytes");
    }
}
