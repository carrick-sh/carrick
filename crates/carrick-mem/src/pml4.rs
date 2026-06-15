//! x86-64 4-level (PML4) page-table codec. 4 KiB pages, 4 levels
//! (PML4→PDPT→PD→PT), 9 index bits/level, 48-bit VA — the same granule shape
//! as the aarch64 stage-1 tables ([`crate::page_table`]); only the descriptor
//! bit layout differs. Descriptor bits per OSDev "Paging" / Intel SDM vol. 3
//! (ISA references — NOT kernel source): P=bit0 (present), R/W=bit1 (needs
//! CR0.WP for ring-0 honoring), U/S=bit2 (must be set at EVERY level of a
//! user walk), PS=bit7 (large leaf at PDPT/PD; carrick builds 4 KiB leaves
//! only), NX=bit63 (needs EFER.NXE), physical address bits 51:12.
//!
//! Deliberately absent vs the aarch64 sibling (`page_table.rs`):
//! `map_aliased`, block split/coalesce, the spare-table pool bookkeeping, and
//! the multi-vCPU gating — all M3-era machinery (fork/shared-aperture). The
//! Phase 2 bring-up builds every leaf at 4 KiB up front via [`pml4_tables`],
//! so the runtime editor ([`Pml4Manager`]) only ever flips bits on existing
//! leaves and never allocates.

// ─── Granule (the spec §4.4 symmetry: identical to aarch64 stage-1) ─────────

/// log2 of the page size (4 KiB pages).
pub const PML4_PAGE_SHIFT: u32 = 12;
/// Translation levels walked (PML4 → PDPT → PD → PT).
pub const PML4_LEVELS: u8 = 4;
/// Index bits consumed per level (512 entries × 8 bytes = one 4 KiB table).
pub const PML4_INDEX_BITS: u32 = 9;

// ─── Descriptor bits (OSDev "Paging" / Intel SDM vol. 3, §4.5 4-level) ──────

/// P (present), bit 0. Clear ⇒ any access faults (#PF).
pub const PML4_P: u64 = 1 << 0;
/// R/W, bit 1. Write allowed only if set at EVERY level of the walk (and
/// CR0.WP makes ring 0 honor it too).
pub const PML4_RW: u64 = 1 << 1;
/// U/S (user/supervisor), bit 2. A ring-3 access requires it set at EVERY
/// level of the walk.
pub const PML4_US: u64 = 1 << 2;
/// PS (page size), bit 7: a large leaf at PDPT (1 GiB) / PD (2 MiB). carrick
/// builds 4 KiB leaves only; the walkers still recognize PS defensively.
pub const PML4_PS: u64 = 1 << 7;
/// NX/XD (no-execute), bit 63. Effective only with EFER.NXE; NX at ANY level
/// makes the whole subtree non-executable, so intermediates keep it clear and
/// the leaf restricts.
pub const PML4_NX: u64 = 1 << 63;
/// Physical-address field, bits 51:12 (the architectural maximum; MAXPHYADDR
/// only narrows what the hardware accepts).
pub const PML4_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

const PT_PAGE: usize = 1 << PML4_PAGE_SHIFT; // 4 KiB
const PAGE_MASK: u64 = (PT_PAGE as u64) - 1;
/// carrick's guest layout is low-half canonical: every VA sits below 2^47
/// (x86-64 canonical-address rule; the high half is sign-extended kernel
/// space carrick never maps).
const VA_LIMIT: u64 = 1 << 47;
/// One past the top of the physical-address field (bits 51:12 ⇒ 2^52).
const PA_LIMIT: u64 = 1 << 52;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pml4Error {
    /// A VA at or above 2^47 (carrick's layout is low-half canonical).
    NonCanonical,
    /// A VA/GPA/length not 4 KiB-aligned, or a GPA past bits 51:12.
    Misaligned,
    /// The table region has no free page left for a needed table.
    OutOfTables,
    /// A walk left the table region, hit a non-present intermediate, or a
    /// leaf with no recorded GPA to restore.
    BadAddress,
}

/// Per-level table index for `va`: `[PML4, PDPT, PD, PT]` (9 bits each above
/// the 12-bit page offset — the same decomposition as the aarch64 4 KiB
/// granule).
pub fn indices(va: u64) -> [usize; 4] {
    [
        ((va >> 39) & 0x1ff) as usize,
        ((va >> 30) & 0x1ff) as usize,
        ((va >> 21) & 0x1ff) as usize,
        ((va >> 12) & 0x1ff) as usize,
    ]
}

/// One VA→GPA mapping request for [`pml4_tables`]. The PML4 decouples VA from
/// GPA (unlike the aarch64 identity bring-up) — the high-GPA fallback lever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pml4MapSpec {
    pub va: u64,
    pub gpa: u64,
    pub len: u64,
    /// U/S on the leaf (intermediate levels get U/S if ANY user mapping
    /// passes through them — the every-level rule).
    pub user: bool,
    /// R/W on the leaf.
    pub write: bool,
    /// Executable: clear ⇒ NX set on the leaf.
    pub exec: bool,
}

fn read_desc(bytes: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&bytes[off..off + 8]);
    u64::from_le_bytes(a)
}

fn write_desc(bytes: &mut [u8], off: usize, desc: u64) {
    bytes[off..off + 8].copy_from_slice(&desc.to_le_bytes());
}

/// Build a complete 4-level table image for `maps`, rooted at `base` (the
/// table pages are allocated sequentially from `base`; the root PML4 is the
/// first page). Returns exactly `capacity` bytes (unused tail pages stay
/// zero, i.e. all-non-present). Mirrors the aarch64
/// `stage1_identity_page_tables` role but takes explicit VA→GPA pairs.
/// Every leaf is a 4 KiB PT entry (no PS large pages), so the runtime editor
/// never needs to split.
pub fn pml4_tables(maps: &[Pml4MapSpec], base: u64, capacity: usize) -> Result<Vec<u8>, Pml4Error> {
    if base & PAGE_MASK != 0 || !capacity.is_multiple_of(PT_PAGE) || capacity == 0 {
        return Err(Pml4Error::Misaligned);
    }
    if base
        .checked_add(capacity as u64)
        .is_none_or(|e| e > PA_LIMIT)
    {
        return Err(Pml4Error::BadAddress);
    }
    let mut bytes = vec![0u8; capacity];
    // Bump allocator: page 0 is the root PML4; tables follow sequentially.
    let mut next_free = PT_PAGE;
    for m in maps {
        if m.va & PAGE_MASK != 0 || m.gpa & PAGE_MASK != 0 || m.len & PAGE_MASK != 0 {
            return Err(Pml4Error::Misaligned);
        }
        let va_end = m.va.checked_add(m.len).ok_or(Pml4Error::NonCanonical)?;
        if va_end > VA_LIMIT {
            return Err(Pml4Error::NonCanonical);
        }
        if m.gpa.checked_add(m.len).is_none_or(|e| e > PA_LIMIT) {
            return Err(Pml4Error::Misaligned);
        }
        let leaf_bits = PML4_P
            | if m.write { PML4_RW } else { 0 }
            | if m.user { PML4_US } else { 0 }
            | if m.exec { 0 } else { PML4_NX };
        let pages = m.len / PT_PAGE as u64;
        for i in 0..pages {
            let va = m.va + i * PT_PAGE as u64;
            let gpa = m.gpa + i * PT_PAGE as u64;
            let pt_off = descend_creating(&mut bytes, &mut next_free, base, va, m.user)?;
            let leaf_off = pt_off + indices(va)[3] * 8;
            write_desc(&mut bytes, leaf_off, (gpa & PML4_ADDR_MASK) | leaf_bits);
        }
    }
    Ok(bytes)
}

/// Descend PML4→PDPT→PD for `va`, creating any missing intermediate table
/// from the sequential allocator. Returns the byte offset of the PT (level-3
/// table). Intermediates are written P|R/W (permissive — the LEAF restricts
/// writability/NX, per the every-level conjunction rule) and pick up U/S as
/// soon as any user mapping passes through.
fn descend_creating(
    bytes: &mut [u8],
    next_free: &mut usize,
    base: u64,
    va: u64,
    user: bool,
) -> Result<usize, Pml4Error> {
    let idx = indices(va);
    let mut table_off = 0usize; // root PML4 at byte offset 0
    for &slot in idx.iter().take(3) {
        let off = table_off + slot * 8;
        let desc = read_desc(bytes, off);
        if desc & PML4_P != 0 {
            if user && desc & PML4_US == 0 {
                // Upgrade: a user walk now passes through this intermediate.
                write_desc(bytes, off, desc | PML4_US);
            }
            let child = desc & PML4_ADDR_MASK;
            let child_off = child.checked_sub(base).ok_or(Pml4Error::BadAddress)? as usize;
            if child_off + PT_PAGE > bytes.len() {
                return Err(Pml4Error::BadAddress);
            }
            table_off = child_off;
            continue;
        }
        // Allocate the next table page (zero from the builder ⇒ all-non-present).
        let new_off = *next_free;
        if new_off + PT_PAGE > bytes.len() {
            return Err(Pml4Error::OutOfTables);
        }
        *next_free += PT_PAGE;
        let child_gpa = base + new_off as u64;
        let inter =
            (child_gpa & PML4_ADDR_MASK) | PML4_P | PML4_RW | if user { PML4_US } else { 0 };
        write_desc(bytes, off, inter);
        table_off = new_off;
    }
    Ok(table_off)
}

/// Diagnostic: walk a raw PML4 table image for `va`, returning the descriptor
/// read at each level `[PML4, PDPT, PD, PT]`. A level not reached (an earlier
/// non-present descriptor, a PS large leaf, or a table pointer outside the
/// region) is left `0`. `bytes` is the table region, `base` the GPA mapped at
/// byte offset 0. The aarch64 `page_table::walk_descriptors` sibling — lets a
/// fault handler prove whether a leaf is non-present IN MEMORY versus a
/// stale-TLB coherence problem.
pub fn walk_descriptors(bytes: &[u8], base: u64, va: u64) -> [u64; 4] {
    let idx = indices(va);
    let mut out = [0u64; 4];
    let mut table_off = 0usize;
    for (level, &slot) in idx.iter().enumerate() {
        let off = table_off + slot * 8;
        if off + 8 > bytes.len() {
            break;
        }
        let desc = read_desc(bytes, off);
        out[level] = desc;
        if desc & PML4_P == 0 || level == 3 {
            break; // non-present, or the PT leaf: walk ends here
        }
        if desc & PML4_PS != 0 {
            break; // PS large leaf at PDPT/PD (carrick never builds one)
        }
        let Some(child_off) = (desc & PML4_ADDR_MASK).checked_sub(base) else {
            break;
        };
        table_off = child_off as usize;
    }
    out
}

/// Runtime editor over a byte image of the PML4 tables rooted at `base` —
/// the x86-64 sibling of [`crate::page_table::PageTableManager`], minus the
/// M3-era machinery (see the module docs). Every leaf is a 4 KiB PT entry
/// built by [`pml4_tables`], so edits only flip P/R\/W/NX bits in place;
/// `set_prot_none` PRESERVES the recorded GPA in the non-present descriptor
/// so `set_rw` can restore the same (possibly non-identity) mapping.
pub struct Pml4Manager {
    bytes: Vec<u8>,
    /// GPA mapped at byte offset 0 (the CR3 target).
    base: u64,
}

impl Pml4Manager {
    pub fn new(bytes: Vec<u8>, base: u64) -> Self {
        Self { bytes, base }
    }

    /// The live table image (e.g. for the backend's host write-back or a
    /// stateless [`walk_descriptors`] diagnostic).
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Byte offset of a GPA known to live inside the table region.
    fn pa_to_off(&self, pa: u64) -> Result<usize, Pml4Error> {
        let end = self.base + self.bytes.len() as u64;
        if pa < self.base || pa >= end {
            return Err(Pml4Error::BadAddress);
        }
        Ok((pa - self.base) as usize)
    }

    fn read_desc(&self, off: usize) -> u64 {
        read_desc(&self.bytes, off)
    }

    /// Byte offset of the PT (level-3) leaf descriptor for `va`. Errors if an
    /// intermediate is non-present or points outside the region, or if a PS
    /// large leaf terminates the walk early (carrick never builds one).
    fn leaf_offset(&self, va: u64) -> Result<usize, Pml4Error> {
        let idx = indices(va);
        let mut table_off = 0usize;
        for &slot in idx.iter().take(3) {
            let off = table_off + slot * 8;
            if off + 8 > self.bytes.len() {
                return Err(Pml4Error::BadAddress);
            }
            let desc = self.read_desc(off);
            if desc & PML4_P == 0 || desc & PML4_PS != 0 {
                return Err(Pml4Error::BadAddress);
            }
            table_off = self.pa_to_off(desc & PML4_ADDR_MASK)?;
        }
        let off = table_off + idx[3] * 8;
        if off + 8 > self.bytes.len() {
            return Err(Pml4Error::BadAddress);
        }
        Ok(off)
    }

    /// Translate a guest VA to its GPA, walking the descriptors exactly as
    /// the hardware would (modulo access checks). `None` if any level is
    /// non-present/out-of-range or the VA is non-canonical. PS large leaves
    /// at PDPT/PD are handled defensively even though [`pml4_tables`] never
    /// builds them.
    pub fn translate(&self, va: u64) -> Option<u64> {
        if va >= VA_LIMIT {
            return None;
        }
        let idx = indices(va);
        let mut table_off = 0usize;
        for (level, &slot) in idx.iter().enumerate() {
            let off = table_off + slot * 8;
            if off + 8 > self.bytes.len() {
                return None;
            }
            let desc = self.read_desc(off);
            if desc & PML4_P == 0 {
                return None;
            }
            if level == 3 {
                return Some((desc & PML4_ADDR_MASK) | (va & PAGE_MASK));
            }
            if desc & PML4_PS != 0 {
                // 1 GiB (PDPT) / 2 MiB (PD) large leaf.
                return match level {
                    1 => Some((desc & PML4_ADDR_MASK & !((1 << 30) - 1)) | (va & ((1 << 30) - 1))),
                    2 => Some((desc & PML4_ADDR_MASK & !((1 << 21) - 1)) | (va & ((1 << 21) - 1))),
                    _ => None, // PS at PML4 level is reserved
                };
            }
            table_off = self.pa_to_off(desc & PML4_ADDR_MASK).ok()?;
        }
        None
    }

    /// Apply `edit` to every 4 KiB leaf in `[va, va+len)` (len rounded up to
    /// pages). Returns whether any descriptor changed.
    fn apply(
        &mut self,
        va: u64,
        len: usize,
        edit: impl Fn(u64) -> Result<u64, Pml4Error>,
    ) -> Result<bool, Pml4Error> {
        if va & PAGE_MASK != 0 {
            return Err(Pml4Error::Misaligned);
        }
        let end = va
            .checked_add((len as u64).div_ceil(PT_PAGE as u64) * PT_PAGE as u64)
            .ok_or(Pml4Error::NonCanonical)?;
        if end > VA_LIMIT {
            return Err(Pml4Error::NonCanonical);
        }
        let mut changed = false;
        let mut cur = va;
        while cur < end {
            let off = self.leaf_offset(cur)?;
            let desc = self.read_desc(off);
            let new = edit(desc)?;
            if new != desc {
                write_desc(&mut self.bytes, off, new);
                changed = true;
            }
            cur += PT_PAGE as u64;
        }
        Ok(changed)
    }

    /// Mark `[va, va+len)` non-present (any access faults — the guest-visible
    /// `PROT_NONE`/`munmap` semantic). Clears ONLY the P bit: the GPA and
    /// permission bits stay recorded so [`Pml4Manager::set_rw`] can restore
    /// the same mapping (the PML4 is non-identity-capable; the VA cannot
    /// reconstruct the GPA the way the aarch64 identity editor does).
    pub fn set_prot_none(&mut self, va: u64, len: usize) -> Result<bool, Pml4Error> {
        self.apply(va, len, |desc| Ok(desc & !PML4_P))
    }

    /// Mark `[va, va+len)` present read-only, with NX per `exec`. This is the
    /// x86 sibling of `PageTableManager::set_readonly`: stores should raise a
    /// present-page protection fault (#PF with PFEC.P=1), while reads remain
    /// allowed.
    pub fn set_readonly(&mut self, va: u64, len: usize, exec: bool) -> Result<bool, Pml4Error> {
        self.apply(va, len, |desc| {
            if desc == 0 {
                return Err(Pml4Error::BadAddress);
            }
            let mut new = (desc | PML4_P) & !PML4_RW;
            if exec {
                new &= !PML4_NX;
            } else {
                new |= PML4_NX;
            }
            Ok(new)
        })
    }

    /// Restore `[va, va+len)` to present read-write, with NX per `exec`
    /// (`exec=true` clears NX — PROT_EXEC; else NX set, the W^X default).
    /// Errors `BadAddress` on a leaf that never had a mapping recorded (an
    /// all-zero descriptor has no GPA to restore).
    pub fn set_rw(&mut self, va: u64, len: usize, exec: bool) -> Result<bool, Pml4Error> {
        self.apply(va, len, |desc| {
            if desc == 0 {
                return Err(Pml4Error::BadAddress);
            }
            let mut new = desc | PML4_P | PML4_RW;
            if exec {
                new &= !PML4_NX;
            } else {
                new |= PML4_NX;
            }
            Ok(new)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GPA of the table region root (arbitrary but kernel-region-shaped, like
    /// the aarch64 `LINUX_PAGE_TABLES_BASE` role).
    const BASE: u64 = 0x20_0000;
    /// 16 table pages: plenty for the handful of maps the tests build.
    const CAP: usize = 16 * 0x1000;

    fn build(maps: &[Pml4MapSpec]) -> Vec<u8> {
        pml4_tables(maps, BASE, CAP).expect("table build")
    }

    fn user_rw_nx(va: u64, gpa: u64, len: u64) -> Pml4MapSpec {
        Pml4MapSpec {
            va,
            gpa,
            len,
            user: true,
            write: true,
            exec: false,
        }
    }

    #[test]
    fn granule_matches_aarch64_shape() {
        // The spec §4.4 symmetry: same PtGranule as aarch64; only the
        // descriptor bits differ.
        assert_eq!(PML4_PAGE_SHIFT, 12);
        assert_eq!(PML4_LEVELS, 4);
        assert_eq!(PML4_INDEX_BITS, 9);
    }

    #[test]
    fn nx_bit_is_bit_63() {
        assert_eq!(PML4_NX, 1u64 << 63);
    }

    #[test]
    fn phys_mask_is_bits_51_12() {
        assert_eq!(PML4_ADDR_MASK, 0x000F_FFFF_FFFF_F000);
    }

    #[test]
    fn identity_map_encodes_and_walks_round_trip() {
        // map 0x40_0000 → 0x40_0000 user-RW-NX: translate returns the GPA;
        // walk_descriptors shows P|U/S at every level and NX on the leaf.
        let va = 0x40_0000;
        let bytes = build(&[user_rw_nx(va, va, 0x1000)]);
        let mgr = Pml4Manager::new(bytes.clone(), BASE);
        assert_eq!(mgr.translate(va), Some(va));
        assert_eq!(mgr.translate(va + 0xabc), Some(va + 0xabc));
        assert_eq!(mgr.translate(va + 0x1000), None, "past the mapping");

        let walk = walk_descriptors(&bytes, BASE, va);
        for (level, desc) in walk.iter().enumerate() {
            assert_ne!(desc & PML4_P, 0, "P set at level {level}");
            assert_ne!(desc & PML4_US, 0, "U/S set at level {level} (user walk)");
        }
        // NX restricts on the LEAF; intermediates stay NX-clear (NX at any
        // level poisons the whole subtree).
        assert_ne!(walk[3] & PML4_NX, 0, "leaf NX set (non-exec map)");
        for (level, desc) in walk.iter().enumerate().take(3) {
            assert_eq!(desc & PML4_NX, 0, "intermediate level {level} NX clear");
        }
        assert_ne!(walk[3] & PML4_RW, 0, "leaf R/W set (writable map)");
        assert_eq!(walk[3] & PML4_ADDR_MASK, va, "leaf phys = GPA");
    }

    #[test]
    fn supervisor_map_keeps_us_clear_at_every_level() {
        // A supervisor-only path (its own PDPT subtree) must have U/S clear at
        // every level — the ring-3 protection story for the kernel region.
        let va = 0x8000_0000; // second GiB: distinct PDPT entry from the tests above
        let bytes = build(&[Pml4MapSpec {
            va,
            gpa: va,
            len: 0x1000,
            user: false,
            write: true,
            exec: true,
        }]);
        let walk = walk_descriptors(&bytes, BASE, va);
        for (level, desc) in walk.iter().enumerate() {
            assert_ne!(desc & PML4_P, 0, "P set at level {level}");
            assert_eq!(
                desc & PML4_US,
                0,
                "U/S clear at level {level} (supervisor walk)"
            );
        }
        assert_eq!(walk[3] & PML4_NX, 0, "exec leaf has NX clear");
    }

    #[test]
    fn intermediates_get_us_when_any_user_mapping_passes_through() {
        // Supervisor map first, then a user map sharing the same PD: the
        // shared intermediates must be upgraded to U/S (any-user rule); the
        // supervisor LEAF stays U/S-clear.
        let sup_va = 0x40_0000;
        let usr_va = 0x40_1000;
        let bytes = build(&[
            Pml4MapSpec {
                va: sup_va,
                gpa: sup_va,
                len: 0x1000,
                user: false,
                write: true,
                exec: false,
            },
            user_rw_nx(usr_va, usr_va, 0x1000),
        ]);
        let usr_walk = walk_descriptors(&bytes, BASE, usr_va);
        for (level, desc) in usr_walk.iter().enumerate() {
            assert_ne!(desc & PML4_US, 0, "user walk level {level} has U/S");
        }
        let sup_walk = walk_descriptors(&bytes, BASE, sup_va);
        assert_eq!(sup_walk[3] & PML4_US, 0, "supervisor leaf keeps U/S clear");
    }

    #[test]
    fn non_identity_map_translates() {
        // The PML4 decouples VA from GPA (the high-GPA fallback lever).
        let va = 0x40_0000;
        let gpa = 0x9_0000_0000; // 36 GiB — nowhere near the VA
        let bytes = build(&[user_rw_nx(va, gpa, 0x2000)]);
        let mgr = Pml4Manager::new(bytes, BASE);
        assert_eq!(mgr.translate(va), Some(gpa));
        assert_eq!(mgr.translate(va + 0x1234), Some(gpa + 0x1234));
        assert_eq!(mgr.translate(va + 0x1000), Some(gpa + 0x1000));
        assert_eq!(mgr.translate(va + 0x2000), None);
    }

    #[test]
    fn set_prot_none_clears_p_and_set_rw_restores() {
        let va = 0x40_0000;
        let bytes = build(&[user_rw_nx(va, va, 0x3000)]);
        let mut mgr = Pml4Manager::new(bytes, BASE);
        assert_eq!(mgr.set_prot_none(va, 0x1000), Ok(true));
        assert_eq!(mgr.translate(va), None, "P cleared: no translation");
        assert_eq!(
            mgr.translate(va + 0x1000),
            Some(va + 0x1000),
            "neighbor page untouched"
        );
        // The GPA is preserved in the non-present descriptor, so RW restores
        // the SAME mapping (PML4 is non-identity-capable: the VA can't
        // reconstruct the GPA, unlike the aarch64 identity editor).
        assert_eq!(mgr.set_rw(va, 0x1000, false), Ok(true));
        assert_eq!(mgr.translate(va), Some(va));
        // Idempotence: re-applying is a no-op.
        assert_eq!(mgr.set_rw(va, 0x1000, false), Ok(false));
        assert_eq!(mgr.set_prot_none(va, 0x1000), Ok(true));
        assert_eq!(mgr.set_prot_none(va, 0x1000), Ok(false));
    }

    #[test]
    fn set_rw_exec_toggles_nx() {
        let va = 0x40_0000;
        let bytes = build(&[user_rw_nx(va, va, 0x1000)]); // built NX
        let mut mgr = Pml4Manager::new(bytes, BASE);
        assert_eq!(mgr.set_rw(va, 0x1000, true), Ok(true), "exec=true edits");
        let walk = walk_descriptors(mgr.bytes(), BASE, va);
        assert_eq!(walk[3] & PML4_NX, 0, "exec=true cleared NX");
        assert_eq!(mgr.set_rw(va, 0x1000, false), Ok(true));
        let walk = walk_descriptors(mgr.bytes(), BASE, va);
        assert_ne!(walk[3] & PML4_NX, 0, "exec=false set NX");
    }

    #[test]
    fn set_readonly_clears_rw_and_preserves_present_mapping() {
        let va = 0x40_0000;
        let bytes = build(&[user_rw_nx(va, va, 0x1000)]);
        let mut mgr = Pml4Manager::new(bytes, BASE);

        assert_eq!(mgr.set_readonly(va, 0x1000, false), Ok(true));

        assert_eq!(mgr.translate(va), Some(va), "RO page stays present");
        let walk = walk_descriptors(mgr.bytes(), BASE, va);
        assert_eq!(walk[3] & PML4_RW, 0, "leaf R/W cleared");
        assert_ne!(walk[3] & PML4_NX, 0, "non-exec RO page remains NX");
        assert_eq!(
            mgr.set_readonly(va, 0x1000, false),
            Ok(false),
            "idempotent RO"
        );
    }

    #[test]
    fn set_rw_on_never_mapped_leaf_errors() {
        // No GPA was ever recorded for this page: nothing to restore.
        let va = 0x40_0000;
        let bytes = build(&[user_rw_nx(va, va, 0x1000)]);
        let mut mgr = Pml4Manager::new(bytes, BASE);
        assert_eq!(
            mgr.set_rw(va + 0x1000, 0x1000, false),
            Err(Pml4Error::BadAddress)
        );
    }

    #[test]
    fn set_ops_on_unmapped_subtree_error() {
        let va = 0x40_0000;
        let bytes = build(&[user_rw_nx(va, va, 0x1000)]);
        let mut mgr = Pml4Manager::new(bytes, BASE);
        // A VA whose PDPT/PD path was never built.
        assert_eq!(
            mgr.set_prot_none(0x70_0000_0000, 0x1000),
            Err(Pml4Error::BadAddress)
        );
    }

    #[test]
    fn non_canonical_va_rejected() {
        // carrick's layout is low-half canonical: VAs must sit below 1 << 47.
        let high = 1u64 << 47;
        assert_eq!(
            pml4_tables(&[user_rw_nx(high, 0x1000, 0x1000)], BASE, CAP),
            Err(Pml4Error::NonCanonical)
        );
        // A range that CROSSES the boundary is rejected too.
        assert_eq!(
            pml4_tables(&[user_rw_nx(high - 0x1000, 0x1000, 0x2000)], BASE, CAP),
            Err(Pml4Error::NonCanonical)
        );
        let bytes = build(&[user_rw_nx(0x40_0000, 0x40_0000, 0x1000)]);
        let mut mgr = Pml4Manager::new(bytes, BASE);
        assert_eq!(mgr.translate(high), None);
        assert_eq!(
            mgr.set_prot_none(high, 0x1000),
            Err(Pml4Error::NonCanonical)
        );
        assert_eq!(
            mgr.set_rw(high, 0x1000, false),
            Err(Pml4Error::NonCanonical)
        );
    }

    #[test]
    fn misaligned_spec_rejected() {
        assert_eq!(
            pml4_tables(&[user_rw_nx(0x40_0800, 0x40_0000, 0x1000)], BASE, CAP),
            Err(Pml4Error::Misaligned),
            "unaligned VA"
        );
        assert_eq!(
            pml4_tables(&[user_rw_nx(0x40_0000, 0x40_0800, 0x1000)], BASE, CAP),
            Err(Pml4Error::Misaligned),
            "unaligned GPA"
        );
        assert_eq!(
            pml4_tables(&[user_rw_nx(0x40_0000, 0x40_0000, 0x800)], BASE, CAP),
            Err(Pml4Error::Misaligned),
            "unaligned length"
        );
    }

    #[test]
    fn exhausting_table_capacity_errors() {
        // Root + PDPT + PD + PT = 4 pages minimum; 2 pages can't hold a map.
        assert_eq!(
            pml4_tables(
                &[user_rw_nx(0x40_0000, 0x40_0000, 0x1000)],
                BASE,
                2 * 0x1000
            ),
            Err(Pml4Error::OutOfTables)
        );
    }

    #[test]
    fn into_bytes_preserves_edits() {
        let va = 0x40_0000;
        let bytes = build(&[user_rw_nx(va, va, 0x1000)]);
        let mut mgr = Pml4Manager::new(bytes, BASE);
        mgr.set_prot_none(va, 0x1000).expect("edit");
        let bytes = mgr.into_bytes();
        let mgr2 = Pml4Manager::new(bytes, BASE);
        assert_eq!(mgr2.translate(va), None, "edit survived the round-trip");
    }

    #[test]
    fn indices_decompose_va() {
        // 9 bits per level, page offset 12: same decomposition as aarch64.
        let va = (3u64 << 39) | (5 << 30) | (7 << 21) | (9 << 12);
        assert_eq!(indices(va), [3, 5, 7, 9]);
    }
}
