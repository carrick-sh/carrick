//! Soft-MMU binding and frame-keyed code-page invalidation for `carrick-softcpu-x86`.
//!
//! `carrick-softcpu-x86` consumes [`carrick_softmmu::SoftMmuMemory`], [`carrick_softmmu::SoftWalker`],
//! and [`carrick_softmmu::SoftTlb`] directly (one memory trait, one TLB, no test double in the lib).
//!
//! Host memory requires an explicit unsafe commitment, including through these re-exports.
//! These witnesses run in the softcpu CI doctest gate.
//!
//! ```compile_fail,E0133
//! use carrick_softcpu_x86::{LinearPlacement, MmioHoles};
//! let _ = LinearPlacement::new(0x1000, 4096, MmioHoles::empty());
//! ```
//!
//! ```compile_fail,E0133
//! use carrick_softcpu_x86::LinearPlacement;
//! let _ = LinearPlacement::with_x86_defaults(0x1000, 4096);
//! ```
//!
//! ```compile_fail,E0200
//! use carrick_softcpu_x86::{ExtentTable, LinearPlacement, SoftMmuMemory};
//! struct ArbitraryMemory;
//! impl SoftMmuMemory for ArbitraryMemory {
//!     fn placement(&self) -> &LinearPlacement { unimplemented!() }
//!     fn extents(&self) -> &ExtentTable { unimplemented!() }
//!     fn extents_mut(&mut self) -> &mut ExtentTable { unimplemented!() }
//! }
//! ```

pub use carrick_softmmu::{
    Access as SoftAccessKind, Access, AuthenticatedDescriptorWords, AuthenticatedGpa, Cpl,
    CpuAccessMode, DescriptorRefusal, ExtentRecord, ExtentTable, FrameGpa, GuestVa, HostVa,
    LinearPlacement, LiveDescriptorWords, MmioHoles, OwnerGeneration,
    PAGE_BASE_MASK_4K as SOFT_TLB_PAGE_MASK, PAGE_OFFSET_MASK_4K as SOFT_TLB_OFFSET_MASK,
    PAGE_SHIFT_4K as SOFT_TLB_PAGE_SHIFT, PAGE_SIZE_4K as SOFT_TLB_PAGE_SIZE, PageFaultErrorCode,
    PageFaultInfo, PlacementError, ResolvedAccess, ResolvedSpan, RootGpa, SOFT_TLB_BITS,
    SOFT_TLB_ENTRIES, SOFT_TLB_INDEX_MASK, SoftCpuException, SoftFaultClass, SoftMmuMemory,
    SoftTlb, SoftTlbEntry, SoftTlbPlane, SoftTlbStats, SoftTranslationError, SoftWalker, Stage1Gpa,
    TLB_TAG_AC_BIT as SOFT_TLB_TAG_AC_BIT, TLB_TAG_CPL3_BIT as SOFT_TLB_TAG_CPL3_BIT,
    TLB_TAG_INVALID as SOFT_TLB_INVALID_TAG, WalkOutcome,
};

/// Hardware x86 `#PF` error-code bits.
pub const PF_ERR_PRESENT: u32 = PageFaultErrorCode::PRESENT;
pub const PF_ERR_WRITE: u32 = PageFaultErrorCode::WRITE;
pub const PF_ERR_USER: u32 = PageFaultErrorCode::USER;
pub const PF_ERR_RSVD: u32 = PageFaultErrorCode::RESERVED_WRITE;
pub const PF_ERR_INSTR: u32 = PageFaultErrorCode::INSTRUCTION_FETCH;

/// Check whether `va` is a canonical 48-bit x86_64 virtual address.
#[inline]
#[must_use]
pub const fn is_canonical_va(va: u64) -> bool {
    ((va as i64) << 16 >> 16) as u64 == va
}

/// Convert `(cpl, ac)` into [`carrick_softmmu::CpuAccessMode`].
#[inline]
#[must_use]
pub const fn cpu_access_mode(cpl: u8, ac: bool) -> CpuAccessMode {
    if cpl == 0 {
        CpuAccessMode::ring0(ac)
    } else {
        CpuAccessMode::ring3_with_ac(ac)
    }
}

/// Compute the low tag bits for [`SoftTlbEntry::tag`] via [`SoftTlb`].
#[inline]
#[must_use]
pub const fn tlb_tag_mode_bits(cpl: u8, ac: bool) -> u64 {
    SoftTlb::mode_tag_bits(cpu_access_mode(cpl, ac))
}

/// Hardware `#PF` details surfaced by [`SoftWalker`] on a translation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SoftPageFault {
    pub cr2: u64,
    pub error_code: u32,
}

impl SoftPageFault {
    #[must_use]
    pub const fn new(cr2: u64, error_code: u32) -> Self {
        Self { cr2, error_code }
    }

    #[must_use]
    pub const fn from_info(info: PageFaultInfo) -> Self {
        Self::new(info.va.raw(), info.error_code.bits())
    }
}

use crate::context::SoftCpuContext;

/// Walk `va` through `ctx.walker` and `mem`, filling `ctx.tlb` and returning the host byte pointer
/// and authenticated [`AuthenticatedGpa`] of the resolved 4 KiB frame.
pub fn translate_with_frame<M: SoftMmuMemory>(
    ctx: &mut SoftCpuContext,
    mem: &mut M,
    va: u64,
    kind: SoftAccessKind,
) -> Result<(*mut u8, AuthenticatedGpa), SoftPageFault> {
    let root = ctx.root_gpa().ok_or(SoftPageFault::new(va, 0))?;
    let mode = ctx.access_mode();
    match ctx
        .walker
        .walk_and_fill(mem, &mut ctx.tlb, root, GuestVa::new(va), kind, mode)
    {
        Ok(WalkOutcome::Ram(resolved)) => Ok((resolved.host_addr as *mut u8, resolved.frame_gpa)),
        Err(SoftTranslationError::CpuException(SoftCpuException::PageFault(info))) => {
            Err(SoftPageFault::from_info(info))
        }
        Ok(WalkOutcome::Mmio { .. }) | Err(_) => {
            let mut bits = if mode.cpl == Cpl::Ring3 {
                PF_ERR_USER
            } else {
                0
            };
            if kind == SoftAccessKind::Write {
                bits |= PF_ERR_WRITE;
            } else if kind == SoftAccessKind::Execute {
                bits |= PF_ERR_INSTR;
            }
            Err(SoftPageFault::new(va, bits))
        }
    }
}

/// Translate `va` using `ctx.tlb` as a front cache, falling back to `ctx.walker` on a miss.
pub fn translate_va<M: SoftMmuMemory>(
    ctx: &mut SoftCpuContext,
    mem: &mut M,
    va: u64,
    kind: SoftAccessKind,
) -> Result<*mut u8, SoftPageFault> {
    if let Some(host_addr) = ctx.tlb.probe(GuestVa::new(va), 1, kind, ctx.access_mode()) {
        return Ok(host_addr as *mut u8);
    }
    translate_with_frame(ctx, mem, va, kind).map(|(ptr, _)| ptr)
}

/// Read `dst.len()` bytes starting at guest `va`, pre-validating all spanned pages.
pub fn read_guest_bytes<M: SoftMmuMemory>(
    ctx: &mut SoftCpuContext,
    mem: &mut M,
    va: u64,
    dst: &mut [u8],
    kind: SoftAccessKind,
) -> Result<(), SoftPageFault> {
    walk_span(ctx, mem, va, dst.len(), kind, |off, ptr, chunk| {
        // SAFETY: `ptr` has at least `chunk` valid bytes within its 4 KiB page.
        unsafe { std::ptr::copy_nonoverlapping(ptr, dst[off..].as_mut_ptr(), chunk) };
    })
}

/// Write `src` to guest `va`, pre-validating all spanned pages before writing any byte.
pub fn write_guest_bytes<M: SoftMmuMemory>(
    ctx: &mut SoftCpuContext,
    mem: &mut M,
    va: u64,
    src: &[u8],
) -> Result<(), SoftPageFault> {
    let w = SoftAccessKind::Write;
    walk_span(ctx, mem, va, src.len(), w, |off, ptr, chunk| {
        // SAFETY: `ptr` has at least `chunk` writable bytes within its 4 KiB page.
        unsafe { std::ptr::copy_nonoverlapping(src[off..].as_ptr(), ptr, chunk) };
    })
}

fn walk_span<M: SoftMmuMemory>(
    ctx: &mut SoftCpuContext,
    mem: &mut M,
    va: u64,
    len: usize,
    kind: SoftAccessKind,
    mut commit: impl FnMut(usize, *mut u8, usize),
) -> Result<(), SoftPageFault> {
    for pass in [false, true] {
        let (mut cur, mut off) = (va, 0usize);
        while off < len {
            let chunk =
                (len - off).min((SOFT_TLB_PAGE_SIZE - (cur & SOFT_TLB_OFFSET_MASK)) as usize);
            let ptr = translate_va(ctx, mem, cur, kind)?;
            if pass {
                commit(off, ptr, chunk);
            }
            cur = cur.wrapping_add(chunk as u64);
            off += chunk;
        }
    }
    Ok(())
}

/// Check a guest data operand's alignment without extra walks on the aligned
/// path. If #AC is pending, authenticate every page first: #PF has priority.
/// Callers validate canonicality and select the architectural alignment.
pub(crate) fn check_guest_alignment<M: SoftMmuMemory>(
    ctx: &mut SoftCpuContext,
    mem: &mut M,
    va: u64,
    len: usize,
    alignment: usize,
    kind: SoftAccessKind,
    rip: u64,
) -> Result<(), crate::context::X86Exception> {
    let Err(exc) = ctx.check_alignment(va, alignment, rip) else {
        return Ok(());
    };
    let mut offset = 0;
    while offset < len {
        let current = va.wrapping_add(offset as u64);
        translate_va(ctx, mem, current, kind)
            .map_err(|pf| crate::context::X86Exception::page_fault(rip, pf.error_code, pf.cr2))?;
        offset +=
            (len - offset).min((SOFT_TLB_PAGE_SIZE - (current & SOFT_TLB_OFFSET_MASK)) as usize);
    }
    Err(exc)
}
