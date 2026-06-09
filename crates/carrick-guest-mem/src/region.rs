//! Neutral guest-memory region lookup + the combined PROT_NONE/region access
//! gate, shared by every hypervisor backend.
//!
//! WHY THIS EXISTS
//!
//! Every backend's hot `read_bytes`/`write_bytes` must do the SAME two-step
//! guard before touching a syscall buffer:
//!
//!  1. the PROT_NONE check — a buffer overlapping a guest `mprotect(PROT_NONE)`
//!     range must fault with `EFAULT` even though the host backing is physically
//!     accessible (the host-side check; see
//!     [`carrick_mem::protections::MemoryProtections`]); and
//!  2. the region lookup + bounds — resolve the guest address to the single
//!     host-backed region that wholly contains it, or fail out-of-bounds.
//!
//! The PROT_NONE *primitive* is already shared (`MemoryProtections`). What was
//! NOT shared is the COMBINATION — find-region-then-gate — which each backend
//! re-implemented inline. This module hoists that combination so a NEW backend
//! (bhyve) cannot wire up one half and forget the other.
//!
//! THIS IS A RECURRENCE GUARD, NOT A FEATURE. It deliberately models the
//! SIMPLE, single-region, whole-range, forward-first-match lookup that a flat
//! identity-mapped window list uses (the KVM `Window` shape, the bhyve shape).
//! A backend whose region selection is richer than first-match — e.g. HVF,
//! which chunks per stage-1 page, strips pointer tags, walks the guest stage-1
//! tables (`translate_va`) to disambiguate overlapping high-VA aliases, and
//! prefers the NEWEST region — keeps that selection as its own glue and does
//! NOT route through [`find_region_for_gpa`] (which would change which region a
//! syscall buffer copy lands in). It may still reuse [`GuestAccessError`] and
//! the gate ORDERING for parity.
//!
//! DEPENDENCY NOTE: the PROT_NONE primitive
//! (`carrick_mem::protections::MemoryProtections`) lives in `carrick-mem`, which
//! already depends on THIS crate — so this crate cannot depend back on it
//! without a cycle (and this crate is deliberately the dependency-light leaf;
//! see the crate docs). [`safe_guest_access`] therefore takes the PROT_NONE
//! check as a `no_access` predicate closure (`|gpa, len| -> bool`); the backend
//! supplies `|g, l| self.protections.range_no_access(g, l)`. Zero-cost (it
//! monomorphizes) and keeps the leaf crate clean.

use crate::MemoryError;

/// The minimal neutral projection of one host-backed guest-memory region: the
/// base guest address the lookup keys on, the length, and the host backing
/// pointer. A backend builds (or borrows) this from its own container
/// (`Window`, `HvfMappedRegion`, …) at the lookup boundary — the per-backend
/// glue (KVM's `slot_gpa` <1 TiB alias, HVF's high-VA `translate_va`) decides
/// WHICH `base`/`gpa` is fed in; this struct stays neutral.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestMemoryRegion {
    /// The guest address (GPA == VA under identity mapping) at which this
    /// region's backing starts — the key the lookup matches against. For KVM
    /// this is the `Window::base` the host syscall path uses (NOT `slot_gpa`).
    pub base: u64,
    /// Length of the region in bytes.
    pub len: usize,
    /// Host virtual address backing `base`. The byte at guest `base + off`
    /// lives at `host_addr + off`.
    pub host_addr: *mut u8,
}

/// Why a guarded guest access was refused. Each backend maps these to its own
/// [`MemoryError`] variant so the wire-visible errno is unchanged: today both
/// backends return [`MemoryError::OutOfBounds`] for BOTH the PROT_NONE reject
/// and the lookup miss, so [`map_to_memory_error`] does the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestAccessError {
    /// `[gpa, gpa+len)` overlaps a PROT_NONE range — the buffer must `EFAULT`.
    NoAccess,
    /// No single host-backed region wholly contains `[gpa, gpa+len)`.
    OutOfBounds,
}

impl GuestAccessError {
    /// The [`MemoryError`] a backend surfaces for this access failure. Both the
    /// PROT_NONE reject and the lookup miss currently map to
    /// [`MemoryError::OutOfBounds`] (which the dispatcher turns into `EFAULT`),
    /// so this preserves the existing wire behavior exactly.
    pub fn map_to_memory_error(self, address: u64, length: usize) -> MemoryError {
        MemoryError::OutOfBounds { address, length }
    }
}

/// Find the single region whose `[base, base+len)` wholly contains
/// `[gpa, gpa+len)`, returning that region and the byte offset of `gpa` within
/// it. Forward FIRST-match (mirrors KVM `GuestRam::locate`). The bounds are the
/// SAME whole-range containment both flat-window backends use:
/// `off = gpa - base` must be `Some` (gpa ≥ base) AND `off + len ≤ region.len`
/// (the whole span fits), with checked arithmetic so a wrapping length can't
/// alias a valid region.
///
/// `len == 0` is treated EXACTLY as KVM's `locate(gpa, 0)`: it still requires
/// `gpa` to fall inside a region (`off ≤ region.len`), so a zero-length access
/// to an unmapped address is `None`. (HVF's `read_bytes` short-circuits a
/// zero-length copy BEFORE any region lookup — that divergence is preserved by
/// HVF NOT routing through this helper.)
pub fn find_region_for_gpa(
    regions: &[GuestMemoryRegion],
    gpa: u64,
    len: usize,
) -> Option<(&GuestMemoryRegion, usize)> {
    regions
        .iter()
        .find_map(|r| r.offset_of(gpa, len).map(|off| (r, off)))
}

/// Iterator form of [`find_region_for_gpa`] for a backend that does NOT keep its
/// regions as a `&[GuestMemoryRegion]` but can cheaply PROJECT its own container
/// (`Window`, …) into a `GuestMemoryRegion` per element — yielding the located
/// region BY VALUE so no intermediate `Vec` is allocated on the hot path. The
/// containment/bounds/first-match semantics are identical to the slice form
/// (both go through [`GuestMemoryRegion::offset_of`], so they can't drift).
pub fn find_region_in(
    regions: impl IntoIterator<Item = GuestMemoryRegion>,
    gpa: u64,
    len: usize,
) -> Option<(GuestMemoryRegion, usize)> {
    regions
        .into_iter()
        .find_map(|r| r.offset_of(gpa, len).map(|off| (r, off)))
}

impl GuestMemoryRegion {
    /// Byte offset of `gpa` within this region IFF the whole `[gpa, gpa+len)`
    /// span lies inside `[base, base+len)`, else `None`. The neutral
    /// whole-range, single-region containment+bounds primitive: `gpa ≥ base` and
    /// `(gpa - base) + len ≤ region.len`, with checked arithmetic so a wrapping
    /// length can't alias a valid region. A backend whose region SELECTION is
    /// richer than first-match (HVF: newest-first + stage-1-IPA, chunked) keeps
    /// that selection as glue but can still source this exact bounds test here so
    /// the containment math can't drift across backends.
    #[inline]
    pub fn offset_of(&self, gpa: u64, len: usize) -> Option<usize> {
        let off = gpa.checked_sub(self.base)?;
        ((off as usize).checked_add(len)? <= self.len).then_some(off as usize)
    }

    /// Whether `[gpa, gpa+len)` lies wholly within this region (the boolean form
    /// of [`Self::offset_of`]).
    #[inline]
    pub fn contains_range(&self, gpa: u64, len: usize) -> bool {
        self.offset_of(gpa, len).is_some()
    }
}

/// The COMBINED gate: the PROT_NONE check THEN the region lookup, in that exact
/// order (so a PROT_NONE buffer faults `NoAccess` even if it also happens to
/// fall in a backed region — matching both backends today). Returns the host
/// pointer to the first byte (`gpa`) on success.
///
/// `no_access` is the PROT_NONE predicate — the backend passes
/// `|g, l| self.protections.range_no_access(g, l)` (a closure rather than a
/// `&MemoryProtections` so this leaf crate need not depend on `carrick-mem`,
/// which already depends on it; see the module docs). For a zero-length span
/// `range_no_access` returns `false`, so the gate falls through to
/// [`find_region_for_gpa`], which requires `gpa` to be in a region — matching
/// KVM's current `read_bytes(addr, 0)` behavior.
///
/// # Safety
/// The returned pointer is `host_addr + off` of the located region and is valid
/// for at least `len` bytes by the bounds [`find_region_for_gpa`] proved. It is
/// only valid for the current dispatch (the same lifetime the backend's inline
/// code relied on).
pub fn safe_guest_access(
    no_access: impl FnOnce(u64, usize) -> bool,
    regions: &[GuestMemoryRegion],
    gpa: u64,
    len: usize,
) -> Result<*mut u8, GuestAccessError> {
    if no_access(gpa, len) {
        return Err(GuestAccessError::NoAccess);
    }
    find_region_for_gpa(regions, gpa, len)
        // SAFETY: `find_region_for_gpa` proved `[gpa, gpa+len) ⊆ region`, so
        // `host_addr + off` points at `len` valid bytes of that region.
        .map(|(r, off)| unsafe { r.host_addr.add(off) })
        .ok_or(GuestAccessError::OutOfBounds)
}

/// Iterator form of [`safe_guest_access`]: the same PROT_NONE-then-lookup gate,
/// but over a projected-on-the-fly region iterator (see [`find_region_in`]), so
/// a backend whose container is not a `&[GuestMemoryRegion]` pays NO hot-path
/// allocation. Identical ordering and semantics.
pub fn safe_guest_access_in(
    no_access: impl FnOnce(u64, usize) -> bool,
    regions: impl IntoIterator<Item = GuestMemoryRegion>,
    gpa: u64,
    len: usize,
) -> Result<*mut u8, GuestAccessError> {
    safe_guest_access_translated_in(no_access, regions, gpa, gpa, len)
}

/// Like [`safe_guest_access_in`], but the PROT_NONE check and the region lookup
/// use SEPARATE guest addresses: `va` for the PROT_NONE gate, `ipa` for the
/// backing lookup. This is the recurrence guard for the `repoint_private`
/// (MAP_FIXED|MAP_PRIVATE over a shared-aperture VA) and high-VA-alias cases,
/// where the guest's syscall pointer is NON-identity to its IPA: the syscall
/// copy must land in the backing the guest's OWN EL0 accesses hit (the
/// translated `ipa`), while `mprotect(PROT_NONE)` — which records the guest VA —
/// must still fault EFAULT (keyed on `va`). For an identity VA the backend
/// passes `ipa == va` and this is byte-identical to [`safe_guest_access_in`].
pub fn safe_guest_access_translated_in(
    no_access: impl FnOnce(u64, usize) -> bool,
    regions: impl IntoIterator<Item = GuestMemoryRegion>,
    va: u64,
    ipa: u64,
    len: usize,
) -> Result<*mut u8, GuestAccessError> {
    // PROT_NONE is recorded on the guest VA (mprotect's address), so gate on `va`.
    if no_access(va, len) {
        return Err(GuestAccessError::NoAccess);
    }
    // The host backing the guest actually reads/writes is keyed on the IPA.
    find_region_in(regions, ipa, len)
        // SAFETY: `find_region_in` proved `[ipa, ipa+len) ⊆ region`, so
        // `host_addr + off` points at `len` valid bytes of that region.
        .map(|(r, off)| unsafe { r.host_addr.add(off) })
        .ok_or(GuestAccessError::OutOfBounds)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A backing buffer big enough that `host_addr.add(off)` stays in-bounds for
    // the offsets the tests probe. We never deref it; we only compare pointers.
    fn region(base: u64, len: usize, host: &mut [u8]) -> GuestMemoryRegion {
        GuestMemoryRegion {
            base,
            len,
            host_addr: host.as_mut_ptr(),
        }
    }

    /// A standalone PROT_NONE predicate over `ranges` ([start, end) pairs),
    /// modelling `MemoryProtections::range_no_access` WITHOUT pulling
    /// `carrick-mem` into this leaf crate's deps. Same semantics: a zero-length
    /// span never overlaps; any byte-overlap with a protected range faults.
    fn no_access_over(ranges: &[(u64, u64)]) -> impl Fn(u64, usize) -> bool + '_ {
        move |addr: u64, len: usize| {
            let end = addr.saturating_add(len as u64);
            if end <= addr {
                return false;
            }
            ranges.iter().any(|&(s, e)| addr < e && s < end)
        }
    }

    #[test]
    fn in_range_hit_returns_region_and_offset() {
        let mut buf = vec![0u8; 0x1000];
        let regions = [region(0x4000, 0x1000, &mut buf)];
        let (r, off) = find_region_for_gpa(&regions, 0x4010, 0x20).expect("hit");
        assert_eq!(r.base, 0x4000);
        assert_eq!(off, 0x10);
    }

    #[test]
    fn exact_full_span_fits() {
        let mut buf = vec![0u8; 0x1000];
        let regions = [region(0x4000, 0x1000, &mut buf)];
        // gpa+len lands exactly on the region end — must still fit.
        assert!(find_region_for_gpa(&regions, 0x4000, 0x1000).is_some());
        // One byte past the end does not fit.
        assert!(find_region_for_gpa(&regions, 0x4000, 0x1001).is_none());
        // A span starting inside but ending past the region is out of bounds.
        assert!(find_region_for_gpa(&regions, 0x4ff0, 0x20).is_none());
    }

    #[test]
    fn below_base_is_miss() {
        let mut buf = vec![0u8; 0x1000];
        let regions = [region(0x4000, 0x1000, &mut buf)];
        assert!(find_region_for_gpa(&regions, 0x3fff, 0x1).is_none());
    }

    #[test]
    fn multi_region_picks_the_containing_one() {
        let mut a = vec![0u8; 0x1000];
        let mut b = vec![0u8; 0x1000];
        let pa = a.as_mut_ptr();
        let pb = b.as_mut_ptr();
        let regions = [
            GuestMemoryRegion { base: 0x4000, len: 0x1000, host_addr: pa },
            GuestMemoryRegion { base: 0x9000, len: 0x1000, host_addr: pb },
        ];
        let (r, off) = find_region_for_gpa(&regions, 0x9100, 0x10).expect("hit b");
        assert_eq!(r.base, 0x9000);
        assert_eq!(off, 0x100);
        assert_eq!(r.host_addr, pb);
    }

    #[test]
    fn cross_region_span_is_out_of_bounds() {
        let mut a = vec![0u8; 0x1000];
        let mut b = vec![0u8; 0x1000];
        // Two ADJACENT regions (contiguous gpa, separate backings): a span
        // straddling the boundary fits NEITHER region wholly → miss. (Whole-range
        // single-region containment, the flat-window invariant.)
        let regions = [
            GuestMemoryRegion { base: 0x4000, len: 0x1000, host_addr: a.as_mut_ptr() },
            GuestMemoryRegion { base: 0x5000, len: 0x1000, host_addr: b.as_mut_ptr() },
        ];
        assert!(find_region_for_gpa(&regions, 0x4ff0, 0x20).is_none());
    }

    #[test]
    fn zero_length_requires_region_membership() {
        let mut buf = vec![0u8; 0x1000];
        let regions = [region(0x4000, 0x1000, &mut buf)];
        // Inside a region: a zero-length access resolves (off ≤ len).
        assert!(find_region_for_gpa(&regions, 0x4010, 0).is_some());
        // At the exact end: off == len, 0 fits → resolves (matches KVM locate).
        assert!(find_region_for_gpa(&regions, 0x5000, 0).is_some());
        // Outside every region: a zero-length access is still a miss.
        assert!(find_region_for_gpa(&regions, 0x9999, 0).is_none());
    }

    #[test]
    fn safe_access_returns_correct_host_ptr() {
        let mut buf = vec![0u8; 0x1000];
        let base_ptr = buf.as_mut_ptr();
        let regions = [region(0x4000, 0x1000, &mut buf)];
        let p = safe_guest_access(no_access_over(&[]), &regions, 0x4040, 0x10).expect("ok");
        assert_eq!(p, unsafe { base_ptr.add(0x40) });
    }

    #[test]
    fn safe_access_out_of_bounds_when_no_region() {
        let mut buf = vec![0u8; 0x1000];
        let regions = [region(0x4000, 0x1000, &mut buf)];
        assert_eq!(
            safe_guest_access(no_access_over(&[]), &regions, 0x8000, 0x10),
            Err(GuestAccessError::OutOfBounds)
        );
    }

    #[test]
    fn safe_access_prot_none_rejects_before_lookup() {
        let mut buf = vec![0u8; 0x1000];
        let regions = [region(0x4000, 0x1000, &mut buf)];
        // PROT_NONE the whole region: an overlapping access faults NoAccess even
        // though the region is backed (the gate ordering — PROT_NONE first).
        let prot = no_access_over(&[(0x4000, 0x5000)]);
        assert_eq!(
            safe_guest_access(&prot, &regions, 0x4040, 0x10),
            Err(GuestAccessError::NoAccess)
        );
        // A partial overlap still rejects (any overlap → NoAccess).
        assert_eq!(
            safe_guest_access(&prot, &regions, 0x3ff0, 0x20),
            Err(GuestAccessError::NoAccess)
        );
    }

    #[test]
    fn translated_access_gates_va_but_looks_up_ipa() {
        // Model the repoint_private case: a "shared" region at the VA (0x4000)
        // and a private "overlay" region at a different IPA (0x9000). The guest
        // VA 0x4040 is repointed (stage-1) to overlay IPA 0x9040.
        let mut shared = vec![0xAAu8; 0x1000];
        let mut overlay = vec![0xBBu8; 0x1000];
        let shared_ptr = shared.as_mut_ptr();
        let overlay_ptr = overlay.as_mut_ptr();
        let regions = [
            GuestMemoryRegion { base: 0x4000, len: 0x1000, host_addr: shared_ptr },
            GuestMemoryRegion { base: 0x9000, len: 0x1000, host_addr: overlay_ptr },
        ];
        // The lookup follows the IPA (0x9040 -> overlay backing), NOT the VA.
        let p = safe_guest_access_translated_in(
            no_access_over(&[]),
            regions,
            0x4040, // va
            0x9040, // ipa
            0x10,
        )
        .expect("ok");
        assert_eq!(p, unsafe { overlay_ptr.add(0x40) });
        // PROT_NONE is keyed on the VA: mprotect(PROT_NONE) on the VA range must
        // fault EVEN THOUGH the overlay IPA itself is accessible.
        assert_eq!(
            safe_guest_access_translated_in(
                no_access_over(&[(0x4000, 0x5000)]),
                regions,
                0x4040, // va is PROT_NONE
                0x9040, // ipa is fine
                0x10,
            ),
            Err(GuestAccessError::NoAccess)
        );
        // A PROT_NONE recorded on the IPA must NOT affect a non-PROT_NONE VA.
        let p2 = safe_guest_access_translated_in(
            no_access_over(&[(0x9000, 0xa000)]),
            regions,
            0x4040, // va not protected
            0x9040, // ipa "protected" but irrelevant — gate is VA-keyed
            0x10,
        )
        .expect("ok: gate is keyed on the va, not the ipa");
        assert_eq!(p2, unsafe { overlay_ptr.add(0x40) });
    }

    #[test]
    fn safe_access_zero_length_in_region_ok_prot_none_passes() {
        let mut buf = vec![0u8; 0x1000];
        let regions = [region(0x4000, 0x1000, &mut buf)];
        // range_no_access(_, 0) is false, so even a PROT_NONE region lets a
        // zero-length access through the gate to the lookup (which resolves).
        let prot = no_access_over(&[(0x4000, 0x5000)]);
        assert!(safe_guest_access(&prot, &regions, 0x4010, 0).is_ok());
    }

    #[test]
    fn iterator_form_matches_slice_form() {
        let mut a = vec![0u8; 0x1000];
        let mut b = vec![0u8; 0x1000];
        let regions = [
            GuestMemoryRegion { base: 0x4000, len: 0x1000, host_addr: a.as_mut_ptr() },
            GuestMemoryRegion { base: 0x9000, len: 0x1000, host_addr: b.as_mut_ptr() },
        ];
        // find_region_in (projected by value) agrees with find_region_for_gpa.
        let by_slice = find_region_for_gpa(&regions, 0x9100, 0x10);
        let by_iter = find_region_in(regions.iter().copied(), 0x9100, 0x10);
        assert_eq!(by_slice.map(|(r, o)| (*r, o)), by_iter);
        // safe_guest_access_in agrees with safe_guest_access (host ptr + gate).
        let p_slice = safe_guest_access(no_access_over(&[]), &regions, 0x9100, 0x10);
        let p_iter =
            safe_guest_access_in(no_access_over(&[]), regions.iter().copied(), 0x9100, 0x10);
        assert_eq!(p_slice, p_iter);
        // PROT_NONE rejects identically through the iterator form.
        let prot = no_access_over(&[(0x9000, 0xa000)]);
        assert_eq!(
            safe_guest_access_in(&prot, regions.iter().copied(), 0x9100, 0x10),
            Err(GuestAccessError::NoAccess)
        );
    }

    #[test]
    fn error_maps_to_out_of_bounds_memory_error() {
        let e = GuestAccessError::NoAccess.map_to_memory_error(0x1234, 8);
        assert_eq!(e, MemoryError::OutOfBounds { address: 0x1234, length: 8 });
        let e = GuestAccessError::OutOfBounds.map_to_memory_error(0x1234, 8);
        assert_eq!(e, MemoryError::OutOfBounds { address: 0x1234, length: 8 });
    }
}
