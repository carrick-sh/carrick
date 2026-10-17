//! Per-CPU direct-mapped L1 software TLB (`read`, `write`, `exec` planes).
//!
//! Each plane holds `1024` 16-byte [`SoftTlbEntry`] records indexed by
//! `(va >> 12) & 0x3ff`:
//!
//! ```text
//! tag    : u64 = va_page | cpl_bit | ac_bit   (u64::MAX = invalid)
//! addend : u64 = host_page - va_page          (host = va + addend)
//! ```
//!
//! - `mov cr3` calls [`SoftTlb::flush_all`] (hardware semantics without PCID).
//! - `invlpg` calls [`SoftTlb::evict_va`] (evicts the slot for that 4 KiB page
//!   across all three planes regardless of the cached `cpl_bit` or `ac_bit`).
//! - Installing a translated block on an executable page calls
//!   [`SoftTlb::evict_write_va`] so subsequent guest writes trap into the slow
//!   path and bump the page's code generation before writing.
//! - Page-crossing accesses (`va.crosses_page(len)`) never hit [`SoftTlb`].

use core::mem::size_of;

use crate::domains::{
    Access, Cpl, CpuAccessMode, GuestVa, PAGE_BASE_MASK_4K, PAGE_SHIFT_4K, PAGE_SIZE_4K,
};
use crate::placement::HostVa;

/// Base-2 logarithm of the number of entries per [`SoftTlbPlane`] (`10` -> `1024` entries).
pub const SOFT_TLB_BITS: u32 = 10;

/// Number of direct-mapped entries per [`SoftTlbPlane`] (`1024`).
pub const SOFT_TLB_ENTRIES: usize = 1 << SOFT_TLB_BITS;

/// Index mask applied to `(va >> 12)` (`0x3ff`).
pub const SOFT_TLB_INDEX_MASK: usize = SOFT_TLB_ENTRIES - 1;

/// Invalid tag sentinel (`u64::MAX`).
///
/// Valid tags have bits `2..12` clear, so a valid tag is never equal to `u64::MAX`.
pub const TLB_TAG_INVALID: u64 = u64::MAX;

/// Tag bit 0: set when the entry was filled for user mode (`CPL == 3`).
pub const TLB_TAG_CPL3_BIT: u64 = 1 << 0;

/// Tag bit 1: set when the entry was filled for supervisor mode (`CPL == 0`) with `RFLAGS.AC == 1`.
pub const TLB_TAG_AC_BIT: u64 = 1 << 1;

/// Mask of the mode bits stored in the low 12 bits of a valid TLB tag.
pub const TLB_TAG_MODE_MASK: u64 = TLB_TAG_CPL3_BIT | TLB_TAG_AC_BIT;

/// Single 16-byte direct-mapped software TLB entry.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SoftTlbEntry {
    /// `va_page | cpl_bit | ac_bit`, or [`TLB_TAG_INVALID`] (`u64::MAX`) when empty.
    pub tag: u64,
    /// Wrapping `host_page - va_page` addend so `host_addr = va.wrapping_add(addend)`.
    pub addend: u64,
}

impl SoftTlbEntry {
    /// Byte size of one [`SoftTlbEntry`] (`16`).
    pub const SIZE: usize = size_of::<Self>();

    /// Byte offset of `tag` within `#[repr(C)]` [`SoftTlbEntry`] (`0`).
    pub const TAG_OFFSET: usize = 0;

    /// Byte offset of `addend` within `#[repr(C)]` [`SoftTlbEntry`] (`8`).
    pub const ADDEND_OFFSET: usize = size_of::<u64>();

    /// An invalidated [`SoftTlbEntry`].
    pub const INVALID: Self = Self {
        tag: TLB_TAG_INVALID,
        addend: 0,
    };

    /// Return `true` if this slot is currently valid.
    #[inline]
    pub const fn is_valid(self) -> bool {
        self.tag != TLB_TAG_INVALID
    }

    /// Return the 4 KiB guest virtual page base encoded in a valid tag.
    #[inline]
    pub const fn va_page(self) -> u64 {
        self.tag & PAGE_BASE_MASK_4K
    }

    /// Translate `va` using this entry's precomputed `host_page - va_page` addend.
    #[inline]
    pub const fn translate(self, va: GuestVa) -> usize {
        va.raw().wrapping_add(self.addend) as usize
    }
}

impl Default for SoftTlbEntry {
    #[inline]
    fn default() -> Self {
        Self::INVALID
    }
}

/// One 1024-entry direct-mapped TLB plane (`16 KiB`).
#[repr(C, align(64))]
#[derive(Clone, Debug)]
pub struct SoftTlbPlane {
    /// Direct-mapped entries indexed by `(va >> 12) & 0x3ff`.
    pub entries: [SoftTlbEntry; SOFT_TLB_ENTRIES],
}

impl SoftTlbPlane {
    /// Byte size of one [`SoftTlbPlane`] (`16384`).
    pub const BYTE_SIZE: usize = size_of::<Self>();

    /// Create an all-invalid TLB plane.
    #[inline]
    pub const fn new() -> Self {
        Self {
            entries: [SoftTlbEntry::INVALID; SOFT_TLB_ENTRIES],
        }
    }

    /// Invalidate all 1024 entries in this plane.
    #[inline]
    pub fn flush_all(&mut self) {
        self.entries.fill(SoftTlbEntry::INVALID);
    }

    /// Evict the entry at `va`'s index if it currently maps `va.page_base()` (under any CPL/AC tag).
    ///
    /// Returns `true` if a valid matching entry was evicted.
    #[inline]
    pub fn evict_va(&mut self, va: GuestVa) -> bool {
        let idx = SoftTlb::index_for(va);
        let entry = self.entries[idx];
        if entry.is_valid() && entry.va_page() == va.page_base() {
            self.entries[idx] = SoftTlbEntry::INVALID;
            true
        } else {
            false
        }
    }
}

impl Default for SoftTlbPlane {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// Deterministic structural work counters for [`SoftTlb`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SoftTlbStats {
    /// Fast-path probe hits across all three planes.
    pub hits: u64,
    /// Probe misses (including page-crossing rejections) across all three planes.
    pub misses: u64,
    /// Full TLB flushes (`mov cr3`).
    pub full_flushes: u64,
    /// Single-page VA evictions (`invlpg`).
    pub va_evictions: u64,
    /// Write-plane invalidations for pages holding translated code.
    pub write_evictions: u64,
}

/// Per-CPU software TLB with separate `read`, `write`, and `exec` planes.
#[repr(C, align(64))]
#[derive(Clone, Debug)]
pub struct SoftTlb {
    /// Data-read plane.
    pub read: SoftTlbPlane,
    /// Data-write plane (kept invalid for read-only, COW-armed, and translated-code pages).
    pub write: SoftTlbPlane,
    /// Instruction-fetch plane (filled only when `NX == 0` at all paging levels and SMEP passes).
    pub exec: SoftTlbPlane,
    /// Deterministic structural counters.
    stats: SoftTlbStats,
}

const _: () = {
    assert!(SoftTlbEntry::SIZE == 16);
    assert!(SoftTlbEntry::TAG_OFFSET == 0);
    assert!(SoftTlbEntry::ADDEND_OFFSET == 8);
    assert!(SoftTlbPlane::BYTE_SIZE == 16 * 1024);
};

impl SoftTlb {
    /// Byte offset of the `read` plane within `#[repr(C)]` [`SoftTlb`] (`0`).
    pub const READ_PLANE_OFFSET: usize = 0;

    /// Byte offset of the `write` plane within `#[repr(C)]` [`SoftTlb`] (`16384`).
    pub const WRITE_PLANE_OFFSET: usize = SoftTlbPlane::BYTE_SIZE;

    /// Byte offset of the `exec` plane within `#[repr(C)]` [`SoftTlb`] (`32768`).
    pub const EXEC_PLANE_OFFSET: usize = 2 * SoftTlbPlane::BYTE_SIZE;

    /// Construct an empty [`SoftTlb`] with all entries marked [`TLB_TAG_INVALID`].
    #[inline]
    pub const fn new() -> Self {
        Self {
            read: SoftTlbPlane::new(),
            write: SoftTlbPlane::new(),
            exec: SoftTlbPlane::new(),
            stats: SoftTlbStats {
                hits: 0,
                misses: 0,
                full_flushes: 0,
                va_evictions: 0,
                write_evictions: 0,
            },
        }
    }

    /// Compute the direct-mapped slot index `((va >> 12) & 0x3ff)` for `va`.
    #[inline]
    pub const fn index_for(va: GuestVa) -> usize {
        ((va.raw() >> PAGE_SHIFT_4K) as usize) & SOFT_TLB_INDEX_MASK
    }

    /// Encode the low mode bits (`cpl_bit | ac_bit`) for `mode`.
    ///
    /// - `Cpl::Ring3`: `TLB_TAG_CPL3_BIT` (`ac_bit` is 0 because SMAP only applies to CPL < 3).
    /// - `Cpl::Ring0` with `ac == false`: `0`.
    /// - `Cpl::Ring0` with `ac == true`: `TLB_TAG_AC_BIT`.
    #[inline]
    pub const fn mode_tag_bits(mode: CpuAccessMode) -> u64 {
        match mode.cpl {
            Cpl::Ring3 => TLB_TAG_CPL3_BIT,
            Cpl::Ring0 => {
                if mode.ac {
                    TLB_TAG_AC_BIT
                } else {
                    0
                }
            }
        }
    }

    /// Compute the exact 64-bit TLB tag `va_page | cpl_bit | ac_bit` for `(va, mode)`.
    #[inline]
    pub const fn tag_for(va: GuestVa, mode: CpuAccessMode) -> u64 {
        va.page_base() | Self::mode_tag_bits(mode)
    }

    /// Compute the wrapping 64-bit addend `host_page - va_page`.
    #[inline]
    pub const fn addend_for(va: GuestVa, host_page: HostVa) -> u64 {
        (host_page.page_base() as u64).wrapping_sub(va.page_base())
    }

    /// Return the plane corresponding to `access`.
    #[inline]
    pub const fn plane(&self, access: Access) -> &SoftTlbPlane {
        match access {
            Access::Read => &self.read,
            Access::Write => &self.write,
            Access::Execute => &self.exec,
        }
    }

    /// Return the mutable plane corresponding to `access`.
    #[inline]
    pub const fn plane_mut(&mut self, access: Access) -> &mut SoftTlbPlane {
        match access {
            Access::Read => &mut self.read,
            Access::Write => &mut self.write,
            Access::Execute => &mut self.exec,
        }
    }

    /// Probe the TLB without mutating counters.
    ///
    /// Returns `None` when `len == 0` is false and the access crosses a 4 KiB page boundary, or
    /// when the direct-mapped slot's tag does not match `Self::tag_for(va, mode)`.
    #[inline]
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
        let idx = Self::index_for(va);
        let expected_tag = Self::tag_for(va, mode);
        let entry = self.plane(access).entries[idx];
        if entry.tag == expected_tag {
            Some(entry.translate(va))
        } else {
            None
        }
    }

    /// Probe the TLB for an access of `len` bytes at `va`, updating hit/miss counters.
    ///
    /// Page-crossing accesses (`(va & 0xfff) + len > 4096`) always miss and return `None`.
    #[inline]
    pub fn probe(
        &mut self,
        va: GuestVa,
        len: usize,
        access: Access,
        mode: CpuAccessMode,
    ) -> Option<usize> {
        match self.probe_readonly(va, len, access, mode) {
            Some(host_addr) => {
                self.stats.hits = self.stats.hits.saturating_add(1);
                Some(host_addr)
            }
            None => {
                self.stats.misses = self.stats.misses.saturating_add(1);
                None
            }
        }
    }

    /// Fill a single plane's slot for `(va, mode)` with the resolved `host_page`.
    #[inline]
    pub fn fill_plane(
        &mut self,
        access: Access,
        va: GuestVa,
        mode: CpuAccessMode,
        host_page: HostVa,
    ) -> SoftTlbEntry {
        let idx = Self::index_for(va);
        let entry = SoftTlbEntry {
            tag: Self::tag_for(va, mode),
            addend: Self::addend_for(va, host_page),
        };
        self.plane_mut(access).entries[idx] = entry;
        entry
    }

    /// Flush all entries in `read`, `write`, and `exec` (`mov cr3` semantics).
    #[inline]
    pub fn flush_all(&mut self) {
        self.read.flush_all();
        self.write.flush_all();
        self.exec.flush_all();
        self.stats.full_flushes = self.stats.full_flushes.saturating_add(1);
    }

    /// Evict `va`'s 4 KiB page from `read`, `write`, and `exec` (`invlpg` semantics).
    ///
    /// Because the direct-mapped index depends only on `va.page_base()`, this evicts any cached
    /// entry for `va`'s page regardless of the CPL or AC bits it was filled under.
    #[inline]
    pub fn evict_va(&mut self, va: GuestVa) {
        let _ = self.read.evict_va(va);
        let _ = self.write.evict_va(va);
        let _ = self.exec.evict_va(va);
        self.stats.va_evictions = self.stats.va_evictions.saturating_add(1);
    }

    /// Evict every 4 KiB page overlapping `[start_va, start_va + len_bytes)`.
    pub fn evict_range(&mut self, start_va: GuestVa, len_bytes: u64) {
        if len_bytes == 0 {
            self.evict_va(start_va);
            return;
        }
        let first_page = start_va.page_base();
        let last_byte = start_va.raw().saturating_add(len_bytes.saturating_sub(1));
        let last_page = last_byte & PAGE_BASE_MASK_4K;
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
            match page.checked_add(PAGE_SIZE_4K) {
                Some(next) => page = next,
                None => break,
            }
        }
    }

    /// Evict `va`'s 4 KiB page from the `write` plane only.
    ///
    /// Called when the translator caches a block for the page backing `va` so any subsequent write
    /// misses the `write` TLB and takes the slow path to invalidate cached translations.
    #[inline]
    pub fn evict_write_va(&mut self, va: GuestVa) -> bool {
        let evicted = self.write.evict_va(va);
        self.stats.write_evictions = self.stats.write_evictions.saturating_add(1);
        evicted
    }

    /// Snapshot deterministic structural counters.
    #[inline]
    pub const fn stats(&self) -> SoftTlbStats {
        self.stats
    }

    /// Reset structural counters to zero without altering cached entries.
    #[inline]
    pub fn reset_stats(&mut self) {
        self.stats = SoftTlbStats {
            hits: 0,
            misses: 0,
            full_flushes: 0,
            va_evictions: 0,
            write_evictions: 0,
        };
    }
}

impl Default for SoftTlb {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
