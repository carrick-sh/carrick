//! Per-CPU direct-mapped L1 software TLB (`read`, `write`, `exec` planes).
//!
//! Each plane holds `1024` 16-byte [`SoftTlbEntry`] records indexed by `(va >> 12) & 0x3ff`.

use core::mem::size_of;

use crate::domains::{
    Access, Cpl, CpuAccessMode, GuestVa, PAGE_BASE_MASK_4K, PAGE_SHIFT_4K, PAGE_SIZE_4K,
};
use crate::placement::HostVa;

pub const SOFT_TLB_BITS: u32 = 10;
pub const SOFT_TLB_ENTRIES: usize = 1 << SOFT_TLB_BITS;
pub const SOFT_TLB_INDEX_MASK: usize = SOFT_TLB_ENTRIES - 1;
pub const TLB_TAG_INVALID: u64 = u64::MAX;
pub const TLB_TAG_CPL3_BIT: u64 = 1 << 0;
pub const TLB_TAG_AC_BIT: u64 = 1 << 1;
pub const TLB_TAG_WP_OFF_BIT: u64 = 1 << 2;
pub const TLB_TAG_SMEP_OFF_BIT: u64 = 1 << 3;
pub const TLB_TAG_SMAP_OFF_BIT: u64 = 1 << 4;
pub const TLB_TAG_NXE_OFF_BIT: u64 = 1 << 5;
pub const TLB_TAG_MODE_MASK: u64 = TLB_TAG_CPL3_BIT
    | TLB_TAG_AC_BIT
    | TLB_TAG_WP_OFF_BIT
    | TLB_TAG_SMEP_OFF_BIT
    | TLB_TAG_SMAP_OFF_BIT
    | TLB_TAG_NXE_OFF_BIT;

/// Single 16-byte direct-mapped software TLB entry.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SoftTlbEntry {
    pub tag: u64,
    pub addend: u64,
}

impl SoftTlbEntry {
    pub const SIZE: usize = size_of::<Self>();
    pub const TAG_OFFSET: usize = 0;
    pub const ADDEND_OFFSET: usize = size_of::<u64>();
    pub const INVALID: Self = Self {
        tag: TLB_TAG_INVALID,
        addend: 0,
    };
    pub const fn is_valid(self) -> bool {
        self.tag != TLB_TAG_INVALID
    }
    pub const fn va_page(self) -> u64 {
        self.tag & PAGE_BASE_MASK_4K
    }
    pub const fn translate(self, va: GuestVa) -> usize {
        va.raw().wrapping_add(self.addend) as usize
    }
}

impl Default for SoftTlbEntry {
    fn default() -> Self {
        Self::INVALID
    }
}

/// One 1024-entry direct-mapped TLB plane (`16 KiB`).
#[repr(C, align(64))]
#[derive(Clone, Debug)]
pub struct SoftTlbPlane {
    pub(crate) entries: [SoftTlbEntry; SOFT_TLB_ENTRIES],
}

impl SoftTlbPlane {
    pub const BYTE_SIZE: usize = size_of::<Self>();
    pub const fn new() -> Self {
        Self {
            entries: [SoftTlbEntry::INVALID; SOFT_TLB_ENTRIES],
        }
    }
    pub const fn entries(&self) -> &[SoftTlbEntry; SOFT_TLB_ENTRIES] {
        &self.entries
    }
    pub const fn entry(&self, index: usize) -> SoftTlbEntry {
        self.entries[index]
    }
    pub(crate) fn flush_all(&mut self) {
        self.entries.fill(SoftTlbEntry::INVALID);
    }
}

impl Default for SoftTlbPlane {
    fn default() -> Self {
        Self::new()
    }
}

/// Deterministic structural work counters for [`SoftTlb`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SoftTlbStats {
    pub hits: u64,
    pub misses: u64,
    pub full_flushes: u64,
    pub va_evictions: u64,
    pub write_evictions: u64,
}

/// Per-CPU software TLB with separate `read`, `write`, and `exec` planes.
#[repr(C, align(64))]
#[derive(Clone, Debug)]
pub struct SoftTlb {
    pub(crate) read: SoftTlbPlane,
    pub(crate) write: SoftTlbPlane,
    pub(crate) exec: SoftTlbPlane,
    leaf_shifts: [[u8; SOFT_TLB_ENTRIES]; 3],
    large_page_entries: u32,
    stats: SoftTlbStats,
}

const _: () = {
    assert!(SoftTlbEntry::SIZE == 16);
    assert!(SoftTlbEntry::TAG_OFFSET == 0);
    assert!(SoftTlbEntry::ADDEND_OFFSET == 8);
    assert!(SoftTlbPlane::BYTE_SIZE == 16 * 1024);
};

impl SoftTlb {
    pub const READ_PLANE_OFFSET: usize = 0;
    pub const WRITE_PLANE_OFFSET: usize = SoftTlbPlane::BYTE_SIZE;
    pub const EXEC_PLANE_OFFSET: usize = 2 * SoftTlbPlane::BYTE_SIZE;

    /// Construct an empty [`SoftTlb`] with all entries marked [`TLB_TAG_INVALID`].
    pub const fn new() -> Self {
        Self {
            read: SoftTlbPlane::new(),
            write: SoftTlbPlane::new(),
            exec: SoftTlbPlane::new(),
            leaf_shifts: [[0u8; SOFT_TLB_ENTRIES]; 3],
            large_page_entries: 0,
            stats: SoftTlbStats {
                hits: 0,
                misses: 0,
                full_flushes: 0,
                va_evictions: 0,
                write_evictions: 0,
            },
        }
    }
    const fn plane_index(access: Access) -> usize {
        match access {
            Access::Read => 0,
            Access::Write => 1,
            Access::Execute => 2,
        }
    }
    const fn shift_for_leaf_size(leaf_size_bytes: u64) -> u8 {
        if leaf_size_bytes >= (1 << 30) {
            30
        } else if leaf_size_bytes >= (1 << 21) {
            21
        } else {
            12
        }
    }
    const fn plane_by_index(&self, p: usize) -> &SoftTlbPlane {
        match p {
            0 => &self.read,
            1 => &self.write,
            _ => &self.exec,
        }
    }
    const fn plane_by_index_mut(&mut self, p: usize) -> &mut SoftTlbPlane {
        match p {
            0 => &mut self.read,
            1 => &mut self.write,
            _ => &mut self.exec,
        }
    }
    /// Compute the direct-mapped slot index `((va >> 12) & 0x3ff)` for `va`.
    pub const fn index_for(va: GuestVa) -> usize {
        ((va.raw() >> PAGE_SHIFT_4K) as usize) & SOFT_TLB_INDEX_MASK
    }
    /// Encode the low mode bits for `mode`.
    pub const fn mode_tag_bits(mode: CpuAccessMode) -> u64 {
        let mut bits = match mode.cpl {
            Cpl::Ring3 => TLB_TAG_CPL3_BIT,
            Cpl::Ring0 => {
                let mut r0 = 0u64;
                if mode.ac && mode.cr4_smap {
                    r0 |= TLB_TAG_AC_BIT;
                }
                if !mode.cr0_wp {
                    r0 |= TLB_TAG_WP_OFF_BIT;
                }
                if !mode.cr4_smep {
                    r0 |= TLB_TAG_SMEP_OFF_BIT;
                }
                if !mode.cr4_smap {
                    r0 |= TLB_TAG_SMAP_OFF_BIT;
                }
                r0
            }
        };
        if !mode.efer_nxe {
            bits |= TLB_TAG_NXE_OFF_BIT;
        }
        bits
    }
    pub const fn tag_for(va: GuestVa, mode: CpuAccessMode) -> u64 {
        va.page_base() | Self::mode_tag_bits(mode)
    }
    pub const fn addend_for(va: GuestVa, host_page: HostVa) -> u64 {
        (host_page.page_base() as u64).wrapping_sub(va.page_base())
    }
    pub const fn read(&self) -> &SoftTlbPlane {
        &self.read
    }
    pub const fn write(&self) -> &SoftTlbPlane {
        &self.write
    }
    pub const fn exec(&self) -> &SoftTlbPlane {
        &self.exec
    }
    pub const fn plane(&self, access: Access) -> &SoftTlbPlane {
        self.plane_by_index(Self::plane_index(access))
    }

    /// Probe the TLB without mutating counters (returns `None` on page crossing or tag miss).
    pub const fn probe_readonly(
        &self,
        va: GuestVa,
        len: usize,
        access: Access,
        mode: CpuAccessMode,
    ) -> Option<usize> {
        if va.crosses_page(len) {
            return None;
        }
        let entry = self.plane(access).entries[Self::index_for(va)];
        if entry.tag == Self::tag_for(va, mode) {
            Some(entry.translate(va))
        } else {
            None
        }
    }

    /// Probe the TLB for an access of `len` bytes at `va`, updating hit/miss counters.
    pub fn probe(
        &mut self,
        va: GuestVa,
        len: usize,
        access: Access,
        mode: CpuAccessMode,
    ) -> Option<usize> {
        if let Some(host_addr) = self.probe_readonly(va, len, access, mode) {
            self.stats.hits += 1;
            Some(host_addr)
        } else {
            self.stats.misses += 1;
            None
        }
    }

    #[allow(dead_code)]
    pub(crate) fn fill_plane(
        &mut self,
        access: Access,
        va: GuestVa,
        mode: CpuAccessMode,
        host_page: HostVa,
    ) -> SoftTlbEntry {
        self.fill_plane_with_leaf_size(access, va, mode, host_page, PAGE_SIZE_4K)
    }

    pub(crate) fn fill_plane_with_leaf_size(
        &mut self,
        access: Access,
        va: GuestVa,
        mode: CpuAccessMode,
        host_page: HostVa,
        leaf_size_bytes: u64,
    ) -> SoftTlbEntry {
        let p = Self::plane_index(access);
        let idx = Self::index_for(va);
        if self.leaf_shifts[p][idx] > 12 {
            self.large_page_entries = self.large_page_entries.saturating_sub(1);
        }
        let new_shift = Self::shift_for_leaf_size(leaf_size_bytes);
        if new_shift > 12 {
            self.large_page_entries = self.large_page_entries.saturating_add(1);
        }
        self.leaf_shifts[p][idx] = new_shift;

        let entry = SoftTlbEntry {
            tag: Self::tag_for(va, mode),
            addend: Self::addend_for(va, host_page),
        };
        self.plane_by_index_mut(p).entries[idx] = entry;
        entry
    }

    /// Flush all entries in `read`, `write`, and `exec` (`mov cr3` semantics).
    pub fn flush_all(&mut self) {
        self.read.flush_all();
        self.write.flush_all();
        self.exec.flush_all();
        self.leaf_shifts = [[0u8; SOFT_TLB_ENTRIES]; 3];
        self.large_page_entries = 0;
        self.stats.full_flushes += 1;
    }

    /// Flush the entire `write` plane across all 1024 entries.
    pub fn flush_write_plane(&mut self) {
        for shift in &mut self.leaf_shifts[1] {
            if *shift > 12 {
                self.large_page_entries = self.large_page_entries.saturating_sub(1);
            }
            *shift = 0;
        }
        self.write.flush_all();
        self.stats.write_evictions += 1;
    }

    fn clear_slot_in_plane(&mut self, p: usize, idx: usize) {
        if self.leaf_shifts[p][idx] > 12 {
            self.large_page_entries = self.large_page_entries.saturating_sub(1);
        }
        self.leaf_shifts[p][idx] = 0;
        self.plane_by_index_mut(p).entries[idx] = SoftTlbEntry::INVALID;
    }

    fn evict_in_plane(&mut self, p: usize, va: GuestVa) -> bool {
        let idx = Self::index_for(va);
        let page_base = va.page_base();
        let mut evicted = false;
        let entry = self.plane_by_index(p).entries[idx];
        if entry.is_valid() && entry.va_page() == page_base {
            self.clear_slot_in_plane(p, idx);
            evicted = true;
        }
        if self.large_page_entries > 0 {
            let target_raw = va.raw();
            for slot in 0..SOFT_TLB_ENTRIES {
                let shift = self.leaf_shifts[p][slot];
                if shift > 12 {
                    let e = self.plane_by_index(p).entries[slot];
                    if e.is_valid() {
                        let mask = !((1u64 << shift) - 1);
                        if (e.va_page() & mask) == (target_raw & mask) {
                            self.clear_slot_in_plane(p, slot);
                            evicted = true;
                        }
                    } else {
                        self.leaf_shifts[p][slot] = 0;
                        self.large_page_entries = self.large_page_entries.saturating_sub(1);
                    }
                }
            }
        }
        evicted
    }

    /// Evict `va` (and any sibling slots of a 2 MiB / 1 GiB leaf covering `va`) across all planes (`invlpg`).
    pub fn evict_va(&mut self, va: GuestVa) {
        for p in 0..3 {
            let _ = self.evict_in_plane(p, va);
        }
        self.stats.va_evictions += 1;
    }

    /// Evict every 4 KiB or large-page entry overlapping `[start_va, start_va + len_bytes)`.
    pub fn evict_range(&mut self, start_va: GuestVa, len_bytes: u64) {
        if len_bytes == 0 {
            self.evict_va(start_va);
            return;
        }
        let first_page = start_va.page_base();
        let last_page =
            start_va.raw().saturating_add(len_bytes.saturating_sub(1)) & PAGE_BASE_MASK_4K;
        let page_count =
            ((last_page.saturating_sub(first_page)) >> PAGE_SHIFT_4K).saturating_add(1);
        if page_count > (SOFT_TLB_ENTRIES as u64) {
            self.flush_all();
            return;
        }
        let mut page = first_page;
        loop {
            self.evict_va(GuestVa::new(page));
            if page == last_page {
                break;
            }
            let Some(next) = page.checked_add(PAGE_SIZE_4K) else {
                break;
            };
            page = next;
        }
    }

    /// Evict `va`'s 4 KiB page (and any large-page sibling covering `va`) from the `write` plane only.
    pub fn evict_write_va(&mut self, va: GuestVa) -> bool {
        let evicted = self.evict_in_plane(1, va);
        self.stats.write_evictions += 1;
        evicted
    }

    /// Snapshot deterministic structural counters.
    pub const fn stats(&self) -> SoftTlbStats {
        self.stats
    }

    /// Reset structural counters to zero without altering cached entries.
    pub fn reset_stats(&mut self) {
        self.stats = SoftTlbStats::default();
    }
}

impl Default for SoftTlb {
    fn default() -> Self {
        Self::new()
    }
}
