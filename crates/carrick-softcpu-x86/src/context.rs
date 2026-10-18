//! Per-vCPU execution context (`SoftCpuContext`), gateway machine-code trampolines,
//! slow-path soft-TLB/bounce helpers, and checked complex instruction helpers.

use std::collections::HashMap;
use std::mem::offset_of;
use std::ptr::NonNull;
use std::sync::OnceLock;

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use crate::cflow::compute_effective_va;
use crate::decode::gpr_index;
use crate::mmu::{
    Cpl, CpuAccessMode, FrameGpa, RootGpa, SOFT_TLB_OFFSET_MASK, SOFT_TLB_PAGE_MASK,
    SOFT_TLB_PAGE_SIZE, SoftAccessKind, SoftMmuMemory, SoftPageFault, SoftTlb, SoftWalker,
    is_canonical_va, translate_va,
};

/// Monomorphized translation callback for active [`SoftMmuMemory`] during block execution.
type ActiveTranslateFn =
    unsafe fn(&mut SoftCpuContext, u64, SoftAccessKind) -> Result<*mut u8, SoftPageFault>;

/// Monomorphized [`ActiveTranslateFn`] adapter for any `M: SoftMmuMemory`.
///
/// # Safety
///
/// `ctx.active_mem_ptr` must point to a valid, exclusively borrowed `M` for the call duration.
unsafe fn translate_for_mem<M: SoftMmuMemory>(
    ctx: &mut SoftCpuContext,
    va: u64,
    kind: SoftAccessKind,
) -> Result<*mut u8, SoftPageFault> {
    let mem_ptr = ctx.active_mem_ptr.ok_or(SoftPageFault::new(va, 0))?;
    let mem = unsafe { mem_ptr.cast::<M>().as_mut() };
    translate_va(ctx, mem, va, kind)
}

/// Architectural x86_64 general-purpose register indices in [`SoftCpuContext::gpr`].
pub mod reg {
    pub const RAX: usize = 0;
    pub const RCX: usize = 1;
    pub const RDX: usize = 2;
    pub const RBX: usize = 3;
    pub const RSP: usize = 4;
    pub const RBP: usize = 5;
    pub const RSI: usize = 6;
    pub const RDI: usize = 7;
    pub const R8: usize = 8;
    pub const R9: usize = 9;
    pub const R10: usize = 10;
    pub const R11: usize = 11;
    pub const R12: usize = 12;
    pub const R13: usize = 13;
    pub const R14: usize = 14;
    pub const R15: usize = 15;
}

pub const EXIT_REASON_CONTINUE: u64 = 0;
pub const EXIT_REASON_SYSCALL: u64 = 1;
pub const EXIT_REASON_CFLOW: u64 = 2;
pub const EXIT_REASON_SENSITIVE: u64 = 3;
pub const EXIT_REASON_EXCEPTION: u64 = 4;

pub const CTX_GPR_R14_OFF: usize = 0x70;
pub const CTX_GPR_R15_OFF: usize = 0x78;
pub const CTX_RIP_OFF: usize = 0x80;
pub const CTX_FS_BASE_OFF: usize = 0x90;
pub const CTX_GS_BASE_OFF: usize = 0x98;
pub const CTX_TLB_TAG_BITS_OFF: usize = 0xA8;
pub const CTX_EXIT_REASON_OFF: usize = 0xC0;
pub const CTX_EXIT_INSN_VA_OFF: usize = 0xC8;
pub const CTX_PROBE_SPILL0_OFF: usize = 0xD0;
pub const CTX_PROBE_SPILL1_OFF: usize = 0xD8;
pub const CTX_VIRT_SPILL0_OFF: usize = 0xE0;
pub const CTX_VIRT_SPILL1_OFF: usize = 0xE8;
pub const CTX_SAVED_LAHF_OFF: usize = 0xF0;
pub const CTX_SLOW_PATH_FN_OFF: usize = 0xF8;
pub const CTX_BOUNCE_COMMIT_FN_OFF: usize = 0x100;
pub const CTX_COMPLEX_STEP_FN_OFF: usize = 0x108;
pub const CTX_EXIT_TRAMPOLINE_FN_OFF: usize = 0x110;
pub(crate) const CTX_VIRT_RSP_SPILL_OFF: usize = offset_of!(SoftCpuContext, virt_rsp_spill);
pub const CTX_FXSAVE_OFF: usize = 0x160;
pub const CTX_TLB_READ_OFF: usize = 0x380;
pub const CTX_TLB_WRITE_OFF: usize = CTX_TLB_READ_OFF + SoftTlb::WRITE_PLANE_OFFSET;

/// Architectural x86_64 exception vectors surfaced by `carrick-softcpu-x86`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum X86ExceptionVector {
    DivideError = 0,
    Breakpoint = 3,
    SimdFloatingPoint = 19,
    X87FloatingPoint = 16,
    InvalidOpcode = 6,
    GeneralProtection = 13,
    PageFault = 14,
}

/// Typed architectural exception raised by guest execution without host signals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86Exception {
    pub vector: X86ExceptionVector,
    pub rip: u64,
    pub error_code: Option<u32>,
    pub cr2: Option<u64>,
}

impl X86Exception {
    #[must_use]
    pub const fn new(
        vector: X86ExceptionVector,
        rip: u64,
        error_code: Option<u32>,
        cr2: Option<u64>,
    ) -> Self {
        Self {
            vector,
            rip,
            error_code,
            cr2,
        }
    }
    #[must_use]
    pub const fn divide_error(rip: u64) -> Self {
        Self::new(X86ExceptionVector::DivideError, rip, None, None)
    }
    #[must_use]
    pub const fn invalid_opcode(rip: u64) -> Self {
        Self::new(X86ExceptionVector::InvalidOpcode, rip, None, None)
    }
    #[must_use]
    pub const fn general_protection(rip: u64, code: u32) -> Self {
        Self::new(X86ExceptionVector::GeneralProtection, rip, Some(code), None)
    }
    #[must_use]
    pub const fn page_fault(rip: u64, code: u32, cr2: u64) -> Self {
        Self::new(X86ExceptionVector::PageFault, rip, Some(code), Some(cr2))
    }
}

/// Bounce-buffer writeback descriptors populated when a writable operand straddles two 4 KiB pages.
#[derive(Clone, Copy, Debug, Default)]
struct BounceWriteback {
    pub host_ptr0: *mut u8,
    pub len0: usize,
    pub host_ptr1: *mut u8,
    pub len1: usize,
}

/// Fixed architectural MXCSR mask: DAZ is optional on x86_64 and is not exposed.
pub const GUEST_MXCSR_MASK: u32 = 0x0000_ffbf;

/// Aligned 512-byte FXSAVE area (`fxsave64`/`fxrstor64` require 16-byte alignment).
#[repr(C, align(16))]
#[derive(Clone, Debug)]
pub struct FxsaveArea(pub [u8; 512]);

impl Default for FxsaveArea {
    fn default() -> Self {
        let mut bytes = [0u8; 512];
        bytes[0..2].copy_from_slice(&0x037Fu16.to_le_bytes());
        bytes[24..28].copy_from_slice(&0x1F80u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&GUEST_MXCSR_MASK.to_le_bytes());
        Self(bytes)
    }
}

/// Per-CPU architectural and runtime context pointed to by `%r15` during block execution.
///
/// ```compile_fail
/// use carrick_softcpu_x86::context::{SoftCpuContext, softcpu_mem_slow_path};
/// softcpu_mem_slow_path(&mut SoftCpuContext::new(), 0, 0);
/// ```
///
/// ```compile_fail
/// use carrick_softcpu_x86::context::{SoftCpuContext, softcpu_commit_bounce};
/// softcpu_commit_bounce(&mut SoftCpuContext::new());
/// ```
///
/// ```compile_fail
/// use carrick_softcpu_x86::context::{SoftCpuContext, softcpu_step_complex};
/// softcpu_step_complex(&mut SoftCpuContext::new(), 0);
/// ```
#[repr(C, align(64))]
/// The raw translated entry is internal even for callers using unsafe Rust.
/// ```compile_fail
/// use carrick_softcpu_x86::context::softcpu_enter_translated;
/// let _ = softcpu_enter_translated;
/// ```
pub struct SoftCpuContext {
    pub gpr: [u64; 16],
    pub rip: u64,
    pub rflags: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub kernel_gs_base: u64,
    pub tlb_tag_bits: u64,
    host_rsp: u64,
    entry_exec_addr: u64,
    pub exit_reason: u64,
    pub exit_insn_va: u64,
    probe_spill: [u64; 2],
    virt_spill: [u64; 2],
    saved_lahf: u64,
    slow_path_fn: u64,
    bounce_commit_fn: u64,
    complex_step_fn: u64,
    exit_trampoline_fn: u64,
    bounce_active: u64,
    bounce_buf: [u8; 64],
    pub fxsave: FxsaveArea,
    pub tlb: SoftTlb,
    pub walker: SoftWalker,
    pub cpl: u8,
    pub pkru: u32,
    pub xcr0: u64,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
    pub block_start_va: u64,
    pub pending_exception: Option<X86Exception>,
    bounce_writeback: BounceWriteback,
    active_mem_ptr: Option<NonNull<()>>,
    active_translate_fn: Option<ActiveTranslateFn>,
    active_block_insns: Vec<(u64, Instruction, Option<FpLeafFn>)>,
    fp_leaves: HashMap<Vec<u8>, FpLeaf>,
    host_fxsave: FxsaveArea,
    helper_resume: u64,
    virt_rsp_spill: u64,
    pub x87_code_selector: u16,
    pub x87_data_selector: u16,
}

const _: () = {
    assert!(offset_of!(SoftCpuContext, rip) == CTX_RIP_OFF);
    assert!(offset_of!(SoftCpuContext, fs_base) == CTX_FS_BASE_OFF);
    assert!(offset_of!(SoftCpuContext, gs_base) == CTX_GS_BASE_OFF);
    assert!(offset_of!(SoftCpuContext, tlb_tag_bits) == CTX_TLB_TAG_BITS_OFF);
    assert!(offset_of!(SoftCpuContext, exit_reason) == CTX_EXIT_REASON_OFF);
    assert!(offset_of!(SoftCpuContext, exit_insn_va) == CTX_EXIT_INSN_VA_OFF);
    assert!(offset_of!(SoftCpuContext, probe_spill) == CTX_PROBE_SPILL0_OFF);
    assert!(offset_of!(SoftCpuContext, virt_spill) == CTX_VIRT_SPILL0_OFF);
    assert!(offset_of!(SoftCpuContext, saved_lahf) == CTX_SAVED_LAHF_OFF);
    assert!(offset_of!(SoftCpuContext, slow_path_fn) == CTX_SLOW_PATH_FN_OFF);
    assert!(offset_of!(SoftCpuContext, bounce_commit_fn) == CTX_BOUNCE_COMMIT_FN_OFF);
    assert!(offset_of!(SoftCpuContext, complex_step_fn) == CTX_COMPLEX_STEP_FN_OFF);
    assert!(offset_of!(SoftCpuContext, exit_trampoline_fn) == CTX_EXIT_TRAMPOLINE_FN_OFF);
    assert!(offset_of!(SoftCpuContext, fxsave) == CTX_FXSAVE_OFF);
    assert!(offset_of!(SoftCpuContext, tlb) == CTX_TLB_READ_OFF);
};

impl Default for SoftCpuContext {
    fn default() -> Self {
        Self::new()
    }
}

impl SoftCpuContext {
    #[must_use]
    pub fn new() -> Self {
        let gw = gateway_trampolines();
        let mut ctx = Self {
            gpr: [0; 16],
            rip: 0,
            rflags: 0x202,
            fs_base: 0,
            gs_base: 0,
            kernel_gs_base: 0,
            tlb_tag_bits: 0,
            host_rsp: 0,
            entry_exec_addr: 0,
            exit_reason: 0,
            exit_insn_va: 0,
            probe_spill: [0; 2],
            virt_spill: [0; 2],
            saved_lahf: 0,
            slow_path_fn: gw.map_or(0, |g| g.slow_path_shim),
            bounce_commit_fn: gw.map_or(0, |g| g.bounce_commit_shim),
            complex_step_fn: gw.map_or(0, |g| g.complex_step_shim),
            exit_trampoline_fn: gw.map_or(0, |g| g.exit_trampoline),
            bounce_active: 0,
            bounce_buf: [0; 64],
            fxsave: FxsaveArea::default(),
            tlb: SoftTlb::new(),
            walker: SoftWalker::new(),
            cpl: 3,
            pkru: 0,
            xcr0: 0x3,
            // EM stays clear for SSE data operations. CPUID.FPU remains clear:
            // x87 instructions are refused independently of this control bit.
            cr0: 0x8005_0033,
            cr2: 0,
            cr3: 0,
            cr4: 0x0034_06f0,
            efer: 0x0d01,
            block_start_va: 0,
            pending_exception: None,
            bounce_writeback: BounceWriteback::default(),
            active_mem_ptr: None,
            active_translate_fn: None,
            active_block_insns: Vec::new(),
            fp_leaves: HashMap::new(),
            host_fxsave: FxsaveArea::default(),
            helper_resume: 0,
            virt_rsp_spill: 0,
            x87_code_selector: 0,
            x87_data_selector: 0,
        };
        ctx.sync_tlb_tag_bits();
        ctx
    }

    pub(crate) fn prepare_block(
        &mut self,
        planned: &crate::block::PlannedBlock,
    ) -> Result<(), crate::emit::EmitError> {
        use crate::emit::{EmitError, JitStage};
        self.active_block_insns.clear();
        for d in &planned.insns {
            let leaf = if crate::decode::supported_body(&d.raw)
                && crate::decode::is_fp_arithmetic(&d.raw)
            {
                let bytes = native_fp_bytes(&d.raw)
                    .map_err(|detail| EmitError::EncodeFailed { va: d.va, detail })?;
                let entry = self.fp_leaves.entry(bytes);
                let leaf = match entry {
                    std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        let code = fp_leaf_image(entry.key());
                        let mut buffer = crate::cpu::JitCodeBuffer::new(code.len()).ok_or(
                            EmitError::HostJit {
                                va: d.va,
                                stage: JitStage::Allocate,
                            },
                        )?;
                        let addr = buffer.publish(&code).ok_or(EmitError::HostJit {
                            va: d.va,
                            stage: JitStage::Publish,
                        })?;
                        // SAFETY: this RX leaf has the FpRun ABI and buffer owns it until CPU drop.
                        let execute =
                            unsafe { std::mem::transmute::<usize, FpLeafFn>(addr as usize) };
                        entry.insert(FpLeaf {
                            _buffer: buffer,
                            execute,
                        })
                    }
                };
                Some(leaf.execute)
            } else {
                None
            };
            self.active_block_insns.push((d.va, d.raw, leaf));
        }
        Ok(())
    }

    pub(crate) fn reset_bounce(&mut self) {
        self.bounce_active = 0;
    }

    // Only the CPU's freshly published JIT entry may enter this binding.
    pub(crate) unsafe fn execute<M: SoftMmuMemory>(
        &mut self,
        mem: &mut M,
        entry: u64,
        planned: &crate::block::PlannedBlock,
    ) -> u64 {
        struct Guard<'a>(&'a mut SoftCpuContext);
        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                self.0.active_mem_ptr = None;
                self.0.active_translate_fn = None;
                self.0.bounce_active = 0;
            }
        }
        self.block_start_va = planned.start;
        self.entry_exec_addr = entry;
        self.exit_reason = 0;
        self.pending_exception = None;
        self.active_mem_ptr = Some(NonNull::from(mem).cast());
        self.active_translate_fn = Some(translate_for_mem::<M>);
        let guard = Guard(self);
        // SAFETY: the CPU owns entry and mem stays exclusively borrowed through return.
        unsafe { softcpu_enter_translated((guard.0 as *mut SoftCpuContext).cast()) }
    }

    #[inline]
    #[must_use]
    pub const fn ac(&self) -> bool {
        (self.rflags & (1 << 18)) != 0
    }

    #[inline]
    #[must_use]
    pub const fn root_gpa(&self) -> Option<RootGpa> {
        RootGpa::page_aligned(FrameGpa::new(self.cr3 & SOFT_TLB_PAGE_MASK))
    }

    #[inline]
    #[must_use]
    pub const fn access_mode(&self) -> CpuAccessMode {
        let cpl = if self.cpl == 0 {
            Cpl::Ring0
        } else {
            Cpl::Ring3
        };
        CpuAccessMode {
            cpl,
            ac: self.ac(),
            cr0_wp: (self.cr0 & (1 << 16)) != 0,
            cr4_smep: (self.cr4 & (1 << 20)) != 0,
            cr4_smap: (self.cr4 & (1 << 21)) != 0,
            efer_nxe: (self.efer & (1 << 11)) != 0,
            stack_access: false,
        }
    }

    #[inline]
    pub fn set_smap_enabled(&mut self, enabled: bool) {
        self.cr4 = if enabled {
            self.cr4 | (1 << 21)
        } else {
            self.cr4 & !(1 << 21)
        };
        self.sync_tlb_tag_bits();
    }

    #[inline]
    pub fn sync_tlb_tag_bits(&mut self) {
        self.tlb_tag_bits = SoftTlb::mode_tag_bits(self.access_mode());
    }

    #[inline]
    pub fn set_cpl(&mut self, cpl: u8) {
        self.cpl = cpl;
        self.sync_tlb_tag_bits();
    }

    #[must_use]
    pub fn read_xmm(&self, index: usize) -> u128 {
        let off = 160 + index.min(15) * 16;
        if index >= 16 {
            0
        } else {
            u128::from_le_bytes(self.fxsave.0[off..off + 16].try_into().unwrap_or([0; 16]))
        }
    }

    pub fn write_xmm(&mut self, index: usize, val: u128) {
        if index < 16 {
            let off = 160 + index * 16;
            self.fxsave.0[off..off + 16].copy_from_slice(&val.to_le_bytes());
        }
    }
}

#[inline]
#[must_use]
pub const fn pack_slow_path_meta(insn_off: u32, size: u8, kind: u8, align16: bool) -> u64 {
    (insn_off as u64)
        | ((size as u64) << 32)
        | (((kind & 3) as u64) << 40)
        | (if align16 { 1u64 << 42 } else { 0 })
}

#[inline]
const fn unpack_slow_path_meta(meta: u64) -> (u32, usize, u8, bool) {
    (
        meta as u32,
        ((meta >> 32) & 0xff) as usize,
        ((meta >> 40) & 3) as u8,
        ((meta >> 42) & 1) != 0,
    )
}

fn translate_active(
    ctx: &mut SoftCpuContext,
    va: u64,
    kind: SoftAccessKind,
) -> Result<*mut u8, SoftPageFault> {
    let translate_fn = ctx.active_translate_fn.ok_or(SoftPageFault::new(va, 0))?;
    // SAFETY: `active_mem_ptr` and `active_translate_fn` are paired by `SoftCpu::execute_planned_block`.
    unsafe { translate_fn(ctx, va, kind) }
}

fn translate_or_record(
    ctx: &mut SoftCpuContext,
    va: u64,
    kind: SoftAccessKind,
    insn_va: u64,
) -> Option<*mut u8> {
    match translate_active(ctx, va, kind) {
        Ok(ptr) => Some(ptr),
        Err(pf) => {
            ctx.cr2 = pf.cr2;
            record_exception(
                ctx,
                X86Exception::page_fault(insn_va, pf.error_code, pf.cr2),
            );
            None
        }
    }
}

/// Slow-path memory translation and page-crossing bounce-buffer setup.
#[unsafe(no_mangle)]
extern "sysv64" fn softcpu_mem_slow_path(
    ctx: &mut SoftCpuContext,
    guest_va: u64,
    meta: u64,
) -> u64 {
    let (insn_offset, size, access_code, align16) = unpack_slow_path_meta(meta);
    let insn_va = ctx.block_start_va.wrapping_add(u64::from(insn_offset));
    ctx.bounce_active = 0;

    if size == 0 || size > ctx.bounce_buf.len() {
        record_exception(ctx, X86Exception::invalid_opcode(insn_va));
        return 0;
    }
    let last_va = guest_va.wrapping_add((size - 1) as u64);
    if !is_canonical_va(guest_va)
        || !is_canonical_va(last_va)
        || (align16 && (guest_va & 0xf) != 0)
        || ctx.active_mem_ptr.is_none()
        || ctx.active_translate_fn.is_none()
    {
        record_exception(ctx, X86Exception::general_protection(insn_va, 0));
        return 0;
    }

    let page_off = (guest_va & SOFT_TLB_OFFSET_MASK) as usize;
    if page_off + size <= SOFT_TLB_PAGE_SIZE as usize {
        let ptr = match access_code {
            0 => translate_or_record(ctx, guest_va, SoftAccessKind::Read, insn_va),
            1 => translate_or_record(ctx, guest_va, SoftAccessKind::Write, insn_va),
            _ => translate_or_record(ctx, guest_va, SoftAccessKind::Read, insn_va)
                .and_then(|_| translate_or_record(ctx, guest_va, SoftAccessKind::Write, insn_va)),
        };
        return ptr.map_or(0, |p| p as u64);
    }

    let (len0, len1) = (
        (SOFT_TLB_PAGE_SIZE as usize) - page_off,
        size - ((SOFT_TLB_PAGE_SIZE as usize) - page_off),
    );
    let page1_va = (guest_va & SOFT_TLB_PAGE_MASK).wrapping_add(SOFT_TLB_PAGE_SIZE);
    let (needs_read, needs_write) = (access_code != 1, access_code != 0);

    let mut read_ptrs = (std::ptr::null_mut(), std::ptr::null_mut());
    if needs_read {
        let (Some(p0), Some(p1)) = (
            translate_or_record(ctx, guest_va, SoftAccessKind::Read, insn_va),
            translate_or_record(ctx, page1_va, SoftAccessKind::Read, insn_va),
        ) else {
            return 0;
        };
        read_ptrs = (p0, p1);
    }

    if needs_write {
        let (Some(w0), Some(w1)) = (
            translate_or_record(ctx, guest_va, SoftAccessKind::Write, insn_va),
            translate_or_record(ctx, page1_va, SoftAccessKind::Write, insn_va),
        ) else {
            return 0;
        };
        ctx.bounce_writeback = BounceWriteback {
            host_ptr0: w0,
            len0,
            host_ptr1: w1,
            len1,
        };
        ctx.bounce_active = 1;
        if !needs_read {
            read_ptrs = (w0, w1);
        }
    }

    {
        // SAFETY: `read_ptrs.0` has `len0` valid bytes and `read_ptrs.1` has `len1` valid bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(read_ptrs.0, ctx.bounce_buf.as_mut_ptr(), len0);
            std::ptr::copy_nonoverlapping(read_ptrs.1, ctx.bounce_buf.as_mut_ptr().add(len0), len1);
        }
    }
    ctx.bounce_buf.as_mut_ptr() as u64
}

/// Commit the per-CPU bounce buffer back to the two pre-validated guest pages.
#[unsafe(no_mangle)]
extern "sysv64" fn softcpu_commit_bounce(ctx: &mut SoftCpuContext) {
    if ctx.bounce_active != 0 {
        let wb = ctx.bounce_writeback;
        // SAFETY: `wb.host_ptr0` and `wb.host_ptr1` were validated by `softcpu_mem_slow_path`.
        unsafe {
            std::ptr::copy_nonoverlapping(ctx.bounce_buf.as_ptr(), wb.host_ptr0, wb.len0);
            std::ptr::copy_nonoverlapping(
                ctx.bounce_buf.as_ptr().add(wb.len0),
                wb.host_ptr1,
                wb.len1,
            );
        }
        ctx.bounce_active = 0;
    }
}

fn record_exception(ctx: &mut SoftCpuContext, exc: X86Exception) {
    ctx.rip = exc.rip;
    ctx.exit_insn_va = exc.rip;
    ctx.exit_reason = EXIT_REASON_EXCEPTION;
    ctx.pending_exception = Some(exc);
}

/// Execute a complex body instruction (`div`/`idiv`, string ops, `push`/`pop`, etc.).
#[unsafe(no_mangle)]
extern "sysv64" fn softcpu_step_complex(ctx: &mut SoftCpuContext, insn_idx: u64) -> u64 {
    let Some(&(insn_va, insn, fp_leaf)) = ctx.active_block_insns.get(insn_idx as usize) else {
        record_exception(ctx, X86Exception::invalid_opcode(ctx.rip));
        return 0;
    };
    ctx.fxsave.0[28..32].copy_from_slice(&GUEST_MXCSR_MASK.to_le_bytes());
    match step_complex_inner(ctx, &insn, insn_va, fp_leaf) {
        Ok(()) => 1,
        Err(exc) => {
            if let Some(cr2) = exc.cr2 {
                ctx.cr2 = cr2;
            }
            record_exception(ctx, exc);
            0
        }
    }
}

fn step_complex_inner(
    ctx: &mut SoftCpuContext,
    insn: &Instruction,
    insn_va: u64,
    fp_leaf: Option<FpLeafFn>,
) -> Result<(), X86Exception> {
    match insn.mnemonic() {
        _ if crate::decode::is_fp_arithmetic(insn) => {
            let entry = fp_leaf.ok_or_else(|| X86Exception::invalid_opcode(insn_va))?;
            step_fp(ctx, insn, insn_va, entry)
        }
        Mnemonic::Div => step_div(ctx, insn, insn_va, false),
        Mnemonic::Idiv => step_div(ctx, insn, insn_va, true),
        Mnemonic::Push => step_push(ctx, insn, insn_va),
        Mnemonic::Pop => step_pop(ctx, insn, insn_va),
        Mnemonic::Pushfq | Mnemonic::Pushf => {
            let width = if insn.mnemonic() == Mnemonic::Pushfq {
                8
            } else {
                2
            };
            let new_rsp = ctx.gpr[reg::RSP].wrapping_sub(width as u64);
            write_int(
                ctx,
                new_rsp,
                (ctx.rflags & 0x0025_7fd5) | 0x2,
                width,
                insn_va,
            )?;
            ctx.gpr[reg::RSP] = new_rsp;
            Ok(())
        }
        Mnemonic::Popfq | Mnemonic::Popf => {
            let is_64 = insn.mnemonic() == Mnemonic::Popfq;
            let (width, old_rsp) = (if is_64 { 8 } else { 2 }, ctx.gpr[reg::RSP]);
            let popped = read_int(ctx, old_rsp, width, insn_va)?;
            let mask: u64 = match (is_64, ctx.cpl == 0) {
                (true, true) => 0x0025_7fd5,
                (true, false) => 0x0024_0dd5,
                (false, true) => 0x7fd5,
                (false, false) => 0x0dd5,
            };
            ctx.rflags = ((ctx.rflags & !mask) | (popped & mask) | 0x2) & !(1 << 16);
            ctx.sync_tlb_tag_bits();
            ctx.gpr[reg::RSP] = old_rsp.wrapping_add(width as u64);
            Ok(())
        }
        Mnemonic::Leave => {
            let rbp = ctx.gpr[reg::RBP];
            ctx.gpr[reg::RBP] = read_int(ctx, rbp, 8, insn_va)?;
            ctx.gpr[reg::RSP] = rbp.wrapping_add(8);
            Ok(())
        }
        Mnemonic::Enter => {
            let (alloc, nesting) = (u64::from(insn.immediate16()), insn.immediate8_2nd() & 0x1f);
            let (mut rsp, old_rbp) = (ctx.gpr[reg::RSP].wrapping_sub(8), ctx.gpr[reg::RBP]);
            write_int(ctx, rsp, old_rbp, 8, insn_va)?;
            let frame_temp = rsp;
            if nesting > 0 {
                let mut rbp_cur = old_rbp;
                for _ in 1..nesting {
                    rbp_cur = rbp_cur.wrapping_sub(8);
                    let slot = read_int(ctx, rbp_cur, 8, insn_va)?;
                    rsp = rsp.wrapping_sub(8);
                    write_int(ctx, rsp, slot, 8, insn_va)?;
                }
                rsp = rsp.wrapping_sub(8);
                write_int(ctx, rsp, frame_temp, 8, insn_va)?;
            }
            ctx.gpr[reg::RBP] = frame_temp;
            ctx.gpr[reg::RSP] = rsp.wrapping_sub(alloc);
            Ok(())
        }
        Mnemonic::Maskmovdqu => step_maskmov(ctx, insn, insn_va),
        Mnemonic::Xlatb => {
            let addr = ctx.gpr[reg::RBX].wrapping_add(ctx.gpr[reg::RAX] & 0xff);
            let b = read_int(ctx, addr, 1, insn_va)?;
            ctx.gpr[reg::RAX] = (ctx.gpr[reg::RAX] & !0xff) | (b & 0xff);
            Ok(())
        }
        m if insn.is_string_instruction() => step_string_op(ctx, insn, m, insn_va),
        _ => Err(X86Exception::invalid_opcode(insn_va)),
    }
}

// An SSE instruction cannot fault natively: all memory is copied into aligned
// host-owned storage first, and every MXCSR exception is masked during execution.
// Guest status and destination commit only after checking the guest mask bits.
#[repr(C, align(16))]
struct FpRun {
    working: FxsaveArea,
    host: FxsaveArea,
    operand: [u8; 16],
}

type FpLeafFn = unsafe extern "sysv64" fn(*mut FpRun);
struct FpLeaf {
    _buffer: crate::cpu::JitCodeBuffer,
    execute: FpLeafFn,
}

fn native_fp_bytes(insn: &Instruction) -> Result<Vec<u8>, String> {
    let mut native = *insn;
    if insn.op_kinds().any(|kind| kind == OpKind::Memory) {
        native.set_segment_prefix(Register::None);
        native.set_memory_base(Register::RAX);
        native.set_memory_index(Register::None);
        native.set_memory_index_scale(1);
        native.set_memory_displacement64(0);
        native.set_memory_displ_size(0);
    }
    let mut encoder = iced_x86::Encoder::new(64);
    encoder.encode(&native, 0).map_err(|e| e.to_string())?;
    Ok(encoder.take_buffer())
}

fn fp_leaf_image(native: &[u8]) -> Vec<u8> {
    // fxsave64 [rdi+512]; fxrstor64 [rdi]; lea rax,[rdi+1024]
    let mut code = vec![
        0x48, 0x0f, 0xae, 0x87, 0, 2, 0, 0, 0x48, 0x0f, 0xae, 0x0f, 0x48, 0x8d, 0x87, 0, 4, 0, 0,
    ];
    code.extend_from_slice(native);
    // fxsave64 [rdi]; fxrstor64 [rdi+512]; ret
    code.extend_from_slice(&[
        0x48, 0x0f, 0xae, 0x07, 0x48, 0x0f, 0xae, 0x8f, 0, 2, 0, 0, 0xc3,
    ]);
    code
}

fn step_fp(
    ctx: &mut SoftCpuContext,
    insn: &Instruction,
    ip: u64,
    execute: FpLeafFn,
) -> Result<(), X86Exception> {
    let mut run = FpRun {
        working: ctx.fxsave.clone(),
        host: FxsaveArea::default(),
        operand: [0; 16],
    };
    let original = u32::from_le_bytes(
        ctx.fxsave.0[24..28]
            .try_into()
            .map_err(|_| X86Exception::invalid_opcode(ip))?,
    );
    let mut masked = (original | 0x1f80) & !0x3f;
    // SDM Vol. 1 11.5.2.5: FTZ applies only when UM is masked. Preserve
    // tiny results so unmasked underflow can be detected even when exact.
    if original & (1 << 11) == 0 {
        masked &= !(1 << 15);
    }
    run.working.0[24..28].copy_from_slice(&masked.to_le_bytes());
    if (0..insn.op_count()).any(|i| insn.op_kind(i) == OpKind::Memory) {
        let va = compute_effective_va(insn, ctx);
        let size = insn.memory_size().size();
        if size == 16 && va & 15 != 0 {
            return Err(X86Exception::general_protection(ip, 0));
        }
        walk_active_span(ctx, va, size, SoftAccessKind::Read, ip, |off, ptr, n| {
            // SAFETY: the walker authenticated this readable span; operand fits 16 bytes.
            unsafe {
                std::ptr::copy_nonoverlapping(ptr, run.operand[off..].as_mut_ptr(), n);
            }
        })?;
    }
    // SAFETY: prepare_block admitted and published this immutable leaf for this
    // exact instruction; it touches only aligned FpRun storage and restores host FP state.
    unsafe {
        execute(&mut run);
    }
    let mut status = u32::from_le_bytes(
        run.working.0[24..28]
            .try_into()
            .map_err(|_| X86Exception::invalid_opcode(ip))?,
    ) & 0x3f;
    if original & (1 << 11) == 0 && tiny_arithmetic_result(insn, &run.working) {
        status |= 1 << 4;
    }
    let guest_mxcsr = original | status;
    if status & !(original >> 7) & 0x3f != 0 {
        ctx.fxsave.0[24..28].copy_from_slice(&guest_mxcsr.to_le_bytes());
        return Err(if ctx.cr4 & (1 << 10) != 0 {
            X86Exception::new(X86ExceptionVector::SimdFloatingPoint, ip, None, None)
        } else {
            X86Exception::invalid_opcode(ip)
        });
    }
    run.working.0[24..28].copy_from_slice(&guest_mxcsr.to_le_bytes());
    // x87 state belongs to the virtual context. No admitted native instruction
    // modifies it; hardware FXSAVE may discard its pointer metadata.
    ctx.fxsave.0[160..416].copy_from_slice(&run.working.0[160..416]);
    ctx.fxsave.0[24..28].copy_from_slice(&guest_mxcsr.to_le_bytes());
    Ok(())
}

// Only arithmetic instructions generate underflow. MIN/MAX select an input;
// comparisons and unchanged scalar upper lanes cannot cause this exception.
fn tiny_arithmetic_result(insn: &Instruction, state: &FxsaveArea) -> bool {
    let (width, lanes) = match insn.mnemonic() {
        Mnemonic::Addss | Mnemonic::Subss | Mnemonic::Mulss | Mnemonic::Divss => (4, 1),
        Mnemonic::Addsd | Mnemonic::Subsd | Mnemonic::Mulsd | Mnemonic::Divsd => (8, 1),
        Mnemonic::Addps | Mnemonic::Subps | Mnemonic::Mulps | Mnemonic::Divps => (4, 4),
        Mnemonic::Addpd | Mnemonic::Subpd | Mnemonic::Mulpd | Mnemonic::Divpd => (8, 2),
        _ => return false,
    };
    let start = 160 + insn.op0_register().number() * 16;
    state.0[start..start + width * lanes]
        .chunks_exact(width)
        .any(|lane| {
            let mut bytes = [0; 8];
            bytes[..width].copy_from_slice(lane);
            let bits = u64::from_le_bytes(bytes);
            let (significand, exponent) = if width == 4 {
                (0x007f_ffff, 0x7f80_0000)
            } else {
                (0x000f_ffff_ffff_ffff, 0x7ff0_0000_0000_0000)
            };
            bits & exponent == 0 && bits & significand != 0
        })
}

fn step_maskmov(ctx: &mut SoftCpuContext, insn: &Instruction, ip: u64) -> Result<(), X86Exception> {
    let regs: Vec<_> = (0..insn.op_count())
        .filter(|&i| insn.op_kind(i) == OpKind::Register)
        .map(|i| insn.op_register(i))
        .collect();
    let [data_reg, mask_reg] = regs.as_slice() else {
        return Err(X86Exception::invalid_opcode(ip));
    };
    if !data_reg.is_xmm() || !mask_reg.is_xmm() {
        return Err(X86Exception::invalid_opcode(ip));
    }
    let width = 16;
    let read_vector = |r: Register| ctx.read_xmm(r.number()).to_le_bytes();
    let (data, mask) = (read_vector(*data_reg), read_vector(*mask_reg));
    let mut addr = if (0..insn.op_count()).any(|i| insn.op_kind(i) == OpKind::MemorySegEDI) {
        ctx.gpr[reg::RDI] as u32 as u64
    } else {
        ctx.gpr[reg::RDI]
    };
    addr = addr.wrapping_add(match insn.segment_prefix() {
        Register::FS => ctx.fs_base,
        Register::GS => ctx.gs_base,
        _ => 0,
    });
    let mut destinations = [std::ptr::null_mut(); 16];
    for i in 0..width {
        if mask[i] & 0x80 != 0 {
            let va = addr.wrapping_add(i as u64);
            if !is_canonical_va(va) {
                return Err(X86Exception::general_protection(ip, 0));
            }
            destinations[i] = translate_active(ctx, va, SoftAccessKind::Write)
                .map_err(|pf| X86Exception::page_fault(ip, pf.error_code, pf.cr2))?;
        }
    }
    for i in 0..width {
        if !destinations[i].is_null() {
            // SAFETY: each selected byte was authenticated for writing above.
            unsafe {
                destinations[i].write(data[i]);
            }
        }
    }
    Ok(())
}

fn walk_active_span(
    ctx: &mut SoftCpuContext,
    va: u64,
    len: usize,
    kind: SoftAccessKind,
    insn_va: u64,
    mut commit: impl FnMut(usize, *mut u8, usize),
) -> Result<(), X86Exception> {
    if len == 0 {
        return Ok(());
    }
    if !is_canonical_va(va)
        || !is_canonical_va(va.wrapping_add((len - 1) as u64))
        || ctx.active_mem_ptr.is_none()
        || ctx.active_translate_fn.is_none()
    {
        return Err(X86Exception::general_protection(insn_va, 0));
    }
    for pass in [false, true] {
        let (mut cur, mut off) = (va, 0usize);
        while off < len {
            let chunk =
                (len - off).min((SOFT_TLB_PAGE_SIZE - (cur & SOFT_TLB_OFFSET_MASK)) as usize);
            let ptr = translate_active(ctx, cur, kind)
                .map_err(|pf| X86Exception::page_fault(insn_va, pf.error_code, pf.cr2))?;
            if pass {
                commit(off, ptr, chunk);
            }
            cur = cur.wrapping_add(chunk as u64);
            off += chunk;
        }
    }
    Ok(())
}

fn read_int(
    ctx: &mut SoftCpuContext,
    va: u64,
    w: usize,
    insn_va: u64,
) -> Result<u64, X86Exception> {
    let mut buf = [0u8; 8];
    walk_active_span(ctx, va, w, SoftAccessKind::Read, insn_va, |off, ptr, n| {
        // SAFETY: `ptr` has at least `n` readable bytes within its 4 KiB page.
        unsafe { std::ptr::copy_nonoverlapping(ptr, buf[off..].as_mut_ptr(), n) };
    })?;
    Ok(u64::from_le_bytes(buf))
}

fn write_int(
    ctx: &mut SoftCpuContext,
    va: u64,
    val: u64,
    w: usize,
    insn_va: u64,
) -> Result<(), X86Exception> {
    let bytes = val.to_le_bytes();
    walk_active_span(ctx, va, w, SoftAccessKind::Write, insn_va, |off, ptr, n| {
        // SAFETY: `ptr` has at least `n` writable bytes within its 4 KiB page.
        unsafe { std::ptr::copy_nonoverlapping(bytes[off..].as_ptr(), ptr, n) };
    })
}

pub(crate) fn read_reg_sized(ctx: &SoftCpuContext, r: Register) -> (u64, usize) {
    let Some(idx) = gpr_index(r) else {
        return (0, 8);
    };
    let val = ctx.gpr[idx];
    if matches!(r, Register::AH | Register::CH | Register::DH | Register::BH) {
        return ((val >> 8) & 0xff, 1);
    }
    let w = r.size();
    let mask = if w >= 8 {
        u64::MAX
    } else {
        (1u64 << (w * 8)) - 1
    };
    (val & mask, w)
}

pub(crate) fn write_reg_sized(ctx: &mut SoftCpuContext, r: Register, v: u64) {
    let Some(idx) = gpr_index(r) else { return };
    if matches!(r, Register::AH | Register::CH | Register::DH | Register::BH) {
        ctx.gpr[idx] = (ctx.gpr[idx] & !0xff00) | ((v & 0xff) << 8);
        return;
    }
    match r.size() {
        1 => ctx.gpr[idx] = (ctx.gpr[idx] & !0xff) | (v & 0xff),
        2 => ctx.gpr[idx] = (ctx.gpr[idx] & !0xffff) | (v & 0xffff),
        4 => ctx.gpr[idx] = v & 0xffff_ffff,
        _ => ctx.gpr[idx] = v,
    }
}

fn read_op0_val(
    ctx: &mut SoftCpuContext,
    insn: &Instruction,
    insn_va: u64,
) -> Result<(u64, usize), X86Exception> {
    match insn.op0_kind() {
        OpKind::Register => Ok(read_reg_sized(ctx, insn.op0_register())),
        OpKind::Memory => {
            let (ea, w) = (compute_effective_va(insn, ctx), insn.memory_size().size());
            Ok((read_int(ctx, ea, w, insn_va)?, w))
        }
        _ => Err(X86Exception::invalid_opcode(insn_va)),
    }
}

fn step_div(
    ctx: &mut SoftCpuContext,
    insn: &Instruction,
    insn_va: u64,
    signed: bool,
) -> Result<(), X86Exception> {
    let (divisor, width) = read_op0_val(ctx, insn, insn_va)?;
    if divisor == 0 || !matches!(width, 1 | 2 | 4 | 8) {
        return Err(if divisor == 0 {
            X86Exception::divide_error(insn_va)
        } else {
            X86Exception::invalid_opcode(insn_va)
        });
    }

    let bits = (width * 8) as u32;
    let mask = if bits == 64 {
        u128::from(u64::MAX)
    } else {
        (1u128 << bits) - 1
    };
    let raw_dividend: u128 = if width == 1 {
        u128::from(ctx.gpr[reg::RAX] & 0xffff)
    } else {
        ((u128::from(ctx.gpr[reg::RDX]) & mask) << bits) | (u128::from(ctx.gpr[reg::RAX]) & mask)
    };

    let (q_u64, r_u64) = if !signed {
        let d = u128::from(divisor) & mask;
        let (q, r) = (raw_dividend / d, raw_dividend % d);
        if q > mask {
            return Err(X86Exception::divide_error(insn_va));
        }
        (q as u64, r as u64)
    } else {
        let (shift, d_shift) = (128 - bits * 2, 128 - bits);
        let dividend = ((raw_dividend << shift) as i128) >> shift;
        let d = (((u128::from(divisor) & mask) << d_shift) as i128) >> d_shift;
        let (min_q, max_q) = (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1);
        if dividend == i128::MIN && d == -1 {
            return Err(X86Exception::divide_error(insn_va));
        }
        let (q, r) = (dividend / d, dividend % d);
        if q < min_q || q > max_q {
            return Err(X86Exception::divide_error(insn_va));
        }
        ((q as u128 & mask) as u64, (r as u128 & mask) as u64)
    };

    match width {
        1 => ctx.gpr[reg::RAX] = (ctx.gpr[reg::RAX] & !0xffff) | (r_u64 << 8) | q_u64,
        2 => {
            ctx.gpr[reg::RAX] = (ctx.gpr[reg::RAX] & !0xffff) | q_u64;
            ctx.gpr[reg::RDX] = (ctx.gpr[reg::RDX] & !0xffff) | r_u64;
        }
        _ => {
            ctx.gpr[reg::RAX] = q_u64;
            ctx.gpr[reg::RDX] = r_u64;
        }
    }
    Ok(())
}

fn step_push(
    ctx: &mut SoftCpuContext,
    insn: &Instruction,
    insn_va: u64,
) -> Result<(), X86Exception> {
    let (val, width) = match insn.op0_kind() {
        OpKind::Register | OpKind::Memory => read_op0_val(ctx, insn, insn_va)?,
        OpKind::Immediate8to16 => (insn.immediate8to16() as u16 as u64, 2),
        OpKind::Immediate16 => (u64::from(insn.immediate16()), 2),
        OpKind::Immediate8to64 => (insn.immediate8to64() as u64, 8),
        OpKind::Immediate32to64 => (insn.immediate32to64() as u64, 8),
        _ => return Err(X86Exception::invalid_opcode(insn_va)),
    };
    let width = if width == 2 { 2 } else { 8 };
    let new_rsp = ctx.gpr[reg::RSP].wrapping_sub(width as u64);
    write_int(ctx, new_rsp, val, width, insn_va)?;
    ctx.gpr[reg::RSP] = new_rsp;
    Ok(())
}

fn step_pop(
    ctx: &mut SoftCpuContext,
    insn: &Instruction,
    insn_va: u64,
) -> Result<(), X86Exception> {
    let is_16 = match insn.op0_kind() {
        OpKind::Register => read_reg_sized(ctx, insn.op0_register()).1 == 2,
        OpKind::Memory => insn.memory_size().size() == 2,
        _ => return Err(X86Exception::invalid_opcode(insn_va)),
    };
    let (width, old_rsp) = (if is_16 { 2 } else { 8 }, ctx.gpr[reg::RSP]);
    let popped = read_int(ctx, old_rsp, width, insn_va)?;
    ctx.gpr[reg::RSP] = old_rsp.wrapping_add(width as u64);
    match insn.op0_kind() {
        OpKind::Register => write_reg_sized(ctx, insn.op0_register(), popped),
        OpKind::Memory => {
            if let Err(e) = write_int(ctx, compute_effective_va(insn, ctx), popped, width, insn_va)
            {
                ctx.gpr[reg::RSP] = old_rsp;
                return Err(e);
            }
        }
        _ => return Err(X86Exception::invalid_opcode(insn_va)),
    }
    Ok(())
}

fn step_string_op(
    ctx: &mut SoftCpuContext,
    insn: &Instruction,
    mnemonic: Mnemonic,
    insn_va: u64,
) -> Result<(), X86Exception> {
    let width = insn.memory_size().size();
    let kind: u8 = match mnemonic {
        Mnemonic::Movsb | Mnemonic::Movsw | Mnemonic::Movsd | Mnemonic::Movsq => 0,
        Mnemonic::Stosb | Mnemonic::Stosw | Mnemonic::Stosd | Mnemonic::Stosq => 1,
        Mnemonic::Lodsb | Mnemonic::Lodsw | Mnemonic::Lodsd | Mnemonic::Lodsq => 2,
        Mnemonic::Cmpsb | Mnemonic::Cmpsw | Mnemonic::Cmpsd | Mnemonic::Cmpsq => 3,
        Mnemonic::Scasb | Mnemonic::Scasw | Mnemonic::Scasd | Mnemonic::Scasq => 4,
        _ => return Err(X86Exception::invalid_opcode(insn_va)),
    };
    let delta = if (ctx.rflags & (1 << 10)) != 0 {
        (width as u64).wrapping_neg()
    } else {
        width as u64
    };
    let has_rep = insn.has_rep_prefix() || insn.has_repe_prefix() || insn.has_repne_prefix();

    while !has_rep || ctx.gpr[reg::RCX] != 0 {
        let (rsi, rdi) = (ctx.gpr[reg::RSI], ctx.gpr[reg::RDI]);
        match kind {
            0 => {
                let v = read_int(ctx, rsi, width, insn_va)?;
                write_int(ctx, rdi, v, width, insn_va)?;
                ctx.gpr[reg::RSI] = rsi.wrapping_add(delta);
                ctx.gpr[reg::RDI] = rdi.wrapping_add(delta);
            }
            1 => {
                write_int(ctx, rdi, ctx.gpr[reg::RAX], width, insn_va)?;
                ctx.gpr[reg::RDI] = rdi.wrapping_add(delta);
            }
            2 => {
                let val = read_int(ctx, rsi, width, insn_va)?;
                let r = match width {
                    1 => Register::AL,
                    2 => Register::AX,
                    4 => Register::EAX,
                    _ => Register::RAX,
                };
                write_reg_sized(ctx, r, val);
                ctx.gpr[reg::RSI] = rsi.wrapping_add(delta);
            }
            3 => {
                let (a, b) = (
                    read_int(ctx, rsi, width, insn_va)?,
                    read_int(ctx, rdi, width, insn_va)?,
                );
                ctx.rflags = sub_flags(ctx.rflags, a, b, width);
                ctx.gpr[reg::RSI] = rsi.wrapping_add(delta);
                ctx.gpr[reg::RDI] = rdi.wrapping_add(delta);
            }
            _ => {
                let b = read_int(ctx, rdi, width, insn_va)?;
                ctx.rflags = sub_flags(ctx.rflags, ctx.gpr[reg::RAX], b, width);
                ctx.gpr[reg::RDI] = rdi.wrapping_add(delta);
            }
        }
        if !has_rep {
            break;
        }
        ctx.gpr[reg::RCX] = ctx.gpr[reg::RCX].wrapping_sub(1);
        let zf = (ctx.rflags & (1 << 6)) != 0;
        if kind >= 3 && ((insn.has_repe_prefix() && !zf) || (insn.has_repne_prefix() && zf)) {
            break;
        }
    }
    Ok(())
}

fn sub_flags(old_rflags: u64, a: u64, b: u64, width: usize) -> u64 {
    let bits = (width * 8) as u32;
    let mask = if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let (sign_bit, ua, ub) = (1u64 << (bits - 1), a & mask, b & mask);
    let res = ua.wrapping_sub(ub) & mask;
    let cf = u64::from(ua < ub);
    let pf = u64::from((res as u8).count_ones().is_multiple_of(2));
    let af = u64::from(((ua ^ ub ^ res) & 0x10) != 0);
    let zf = u64::from(res == 0);
    let sf = u64::from((res & sign_bit) != 0);
    let of = u64::from((((ua ^ ub) & (ua ^ res)) & sign_bit) != 0);
    const ARITH_MASK: u64 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);
    (old_rflags & !ARITH_MASK) | cf | (pf << 2) | (af << 4) | (zf << 6) | (sf << 7) | (of << 11)
}

/// Enter the translated block at `ctx.entry_exec_addr`, returning `ctx.exit_reason`.
///
/// # Safety
///
/// `ctx` must point to a valid, initialized [`SoftCpuContext`] whose `entry_exec_addr`
/// points to a translated block emitted by [`crate::emit::emit_block`].
pub(crate) unsafe fn softcpu_enter_translated(ctx: *mut u8) -> u64 {
    let Some(gw) = gateway_trampolines() else {
        return EXIT_REASON_EXCEPTION;
    };
    // SAFETY: `gw.enter_translated` points to the entry gateway in the executable page.
    let enter: unsafe extern "sysv64" fn(*mut u8) -> u64 =
        unsafe { std::mem::transmute(gw.enter_translated as usize) };
    unsafe { enter(ctx) }
}

struct GatewayTrampolines {
    enter_translated: u64,
    exit_trampoline: u64,
    slow_path_shim: u64,
    bounce_commit_shim: u64,
    complex_step_shim: u64,
}

// Gateway code is built with named context offsets and branch relocations, so
// changing the ABI cannot silently leave stale offsets inside an opaque blob.
// RSP always belongs to the host. Guest RSP lives only in ctx.gpr[RSP] and is
// virtualized by the emitter; asynchronous host signals can use the host stack.
fn gateway_image() -> (Vec<u8>, [usize; 5]) {
    let mut code = Vec::new();
    let mut offsets = [0; 5];
    code.extend_from_slice(&[
        0x55, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xec, 8,
    ]);
    code.extend_from_slice(&[0x49, 0x89, 0xff]); // r15 = ctx
    gw_store(&mut code, 4, offset_of!(SoftCpuContext, host_rsp));
    gw_fx(&mut code, false, offset_of!(SoftCpuContext, host_fxsave));
    gw_restore_guest(&mut code);
    gw_jump_ctx(&mut code, offset_of!(SoftCpuContext, entry_exec_addr));

    offsets[1] = code.len();
    gw_save_guest(&mut code, false, false);
    gw_restore_host(&mut code);
    let host_return = code.len();
    gw_load(&mut code, 0, CTX_EXIT_REASON_OFF);
    code.extend_from_slice(&[
        0x48, 0x83, 0xc4, 8, 0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x5b, 0x5d, 0xc3,
    ]);

    for (slot, helper, from_probe, from_lahf) in [
        (
            2,
            softcpu_mem_slow_path as *const () as usize as u64,
            true,
            true,
        ),
        (
            3,
            softcpu_commit_bounce as *const () as usize as u64,
            true,
            false,
        ),
        (
            4,
            softcpu_step_complex as *const () as usize as u64,
            true,
            true,
        ),
    ] {
        offsets[slot] = code.len();
        // Resume is in RCX and the helper argument (meta or index) is in RAX.
        gw_store(&mut code, 1, offset_of!(SoftCpuContext, helper_resume));
        gw_store(&mut code, 3, 3 * 8);
        code.extend_from_slice(&[0x48, 0x89, 0xc3]); // rbx = helper argument
        gw_save_guest(&mut code, from_probe, from_lahf);
        gw_restore_host(&mut code);
        code.extend_from_slice(&[0x4c, 0x89, 0xff]); // rdi = ctx
        if slot == 2 {
            code.extend_from_slice(&[0x4c, 0x89, 0xf6, 0x48, 0x89, 0xda]); // rsi = guest EA; rdx = meta
        } else if slot == 4 {
            code.extend_from_slice(&[0x48, 0x89, 0xde]); // rsi = index
        }
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&helper.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0]);
        if slot != 3 {
            code.extend_from_slice(&[0x48, 0x85, 0xc0, 0x0f, 0x84]);
            let patch = code.len();
            let rel = (host_return as isize - (patch + 4) as isize) as i32;
            code.extend_from_slice(&rel.to_le_bytes());
        }
        if slot == 2 {
            code.extend_from_slice(&[0x49, 0x89, 0xc6]);
        } // translated pointer in r14
        gw_restore_guest(&mut code);
        gw_jump_ctx(&mut code, offset_of!(SoftCpuContext, helper_resume));
    }
    (code, offsets)
}

fn gw_store(code: &mut Vec<u8>, gpr: usize, offset: usize) {
    code.extend_from_slice(&[
        0x49 | if gpr >= 8 { 4 } else { 0 },
        0x89,
        0x87 | (((gpr as u8) & 7) << 3),
    ]);
    code.extend_from_slice(&(offset as i32).to_le_bytes());
}

fn gw_load(code: &mut Vec<u8>, gpr: usize, offset: usize) {
    code.extend_from_slice(&[
        0x49 | if gpr >= 8 { 4 } else { 0 },
        0x8b,
        0x87 | (((gpr as u8) & 7) << 3),
    ]);
    code.extend_from_slice(&(offset as i32).to_le_bytes());
}

fn gw_fx(code: &mut Vec<u8>, restore: bool, offset: usize) {
    code.extend_from_slice(&[0x49, 0x0f, 0xae, if restore { 0x8f } else { 0x87 }]);
    code.extend_from_slice(&(offset as i32).to_le_bytes());
}

fn gw_jump_ctx(code: &mut Vec<u8>, offset: usize) {
    code.extend_from_slice(&[0x41, 0xff, 0xa7]);
    code.extend_from_slice(&(offset as i32).to_le_bytes());
}

fn gw_save_guest(code: &mut Vec<u8>, from_probe: bool, from_lahf: bool) {
    for gpr in 0..14 {
        if gpr == reg::RSP || (from_probe && gpr < 2) {
            continue;
        }
        // RBX holds the helper argument on helper transitions. Save its guest
        // value before repurposing it (the caller does that below).
        if from_probe && gpr == reg::RBX {
            continue;
        }
        gw_store(code, gpr, gpr * 8);
    }
    if from_probe {
        for (gpr, off) in [(0, CTX_PROBE_SPILL0_OFF), (1, CTX_PROBE_SPILL1_OFF)] {
            gw_load(code, 2, off);
            gw_store(code, 2, gpr * 8);
        }
    }
    if from_lahf {
        code.extend_from_slice(&[0x41, 0x8b, 0x87]);
        code.extend_from_slice(&(CTX_SAVED_LAHF_OFF as i32).to_le_bytes());
        code.extend_from_slice(&[0x04, 0x7f, 0x9e]);
    }
    code.extend_from_slice(&[0x9c, 0x58]); // pushfq; pop rax on the host stack
    gw_load(code, 1, offset_of!(SoftCpuContext, rflags));
    code.extend_from_slice(&[
        0x48, 0x81, 0xe1, 0x00, 0x02, 0x04, 0x00, 0x48, 0x25, 0xff, 0xfd, 0xfb, 0xff, 0x48, 0x09,
        0xc8,
    ]);
    gw_store(code, 0, offset_of!(SoftCpuContext, rflags));
    gw_save_guest_simd(code);
}

fn gw_save_guest_simd(code: &mut Vec<u8>) {
    // Native bodies can modify XMM/MXCSR only. Keep the emulated x87 image,
    // including FIP/FDP, under context ownership across every block/helper.
    // STMXCSR [r15+fxsave+24]
    code.extend_from_slice(&[0x41, 0x0f, 0xae, 0x9f]);
    code.extend_from_slice(&((CTX_FXSAVE_OFF + 24) as i32).to_le_bytes());
    for xmm in 0..16u8 {
        // MOVDQU [r15+fxsave+160+xmm*16],xmm
        code.extend_from_slice(&[
            0xf3,
            0x41 | if xmm >= 8 { 4 } else { 0 },
            0x0f,
            0x7f,
            0x87 | ((xmm & 7) << 3),
        ]);
        code.extend_from_slice(
            &((CTX_FXSAVE_OFF + 160 + usize::from(xmm) * 16) as i32).to_le_bytes(),
        );
    }
}

fn gw_restore_host(code: &mut Vec<u8>) {
    code.push(0xfc); // CLD before every Rust call and host return
    gw_fx(code, true, offset_of!(SoftCpuContext, host_fxsave));
}

fn gw_restore_guest(code: &mut Vec<u8>) {
    gw_fx(code, true, CTX_FXSAVE_OFF);
    gw_load(code, 0, offset_of!(SoftCpuContext, rflags));
    code.extend_from_slice(&[0x48, 0x25, 0xff, 0xfe, 0xfb, 0xff, 0x50, 0x9d]);
    for gpr in 0..14 {
        if gpr != reg::RSP {
            gw_load(code, gpr, gpr * 8);
        }
    }
}

fn gateway_trampolines() -> Option<&'static GatewayTrampolines> {
    static GATEWAY: OnceLock<Option<GatewayTrampolines>> = OnceLock::new();
    GATEWAY
        .get_or_init(|| {
            let (image, offsets) = gateway_image();
            let mut buffer = Box::new(crate::cpu::JitCodeBuffer::new(image.len())?);
            let b = buffer.publish(&image)?;
            let _ = Box::leak(buffer); // one immutable gateway for the process lifetime
            Some(GatewayTrampolines {
                enter_translated: b + offsets[0] as u64,
                exit_trampoline: b + offsets[1] as u64,
                slow_path_shim: b + offsets[2] as u64,
                bounce_commit_shim: b + offsets[3] as u64,
                complex_step_shim: b + offsets[4] as u64,
            })
        })
        .as_ref()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::JitCodeBuffer;
    #[test]
    fn gateway_returns_with_host_df_and_fp_controls_restored() {
        // Capture DF in a native wrapper immediately after the translated exit,
        // then restore host DF/FP controls before Rust even on the broken gateway.
        use crate::cpu::JitCodeBuffer;
        let mut ctx = SoftCpuContext::new();
        let mut block_jit = JitCodeBuffer::new(4096).unwrap();
        // std; jmp [r15 + exit trampoline] exercises the gateway's host return.
        let mut code = vec![0xfd, 0x41, 0xff, 0xa7];
        code.extend_from_slice(&(CTX_EXIT_TRAMPOLINE_FN_OFF as i32).to_le_bytes());
        ctx.entry_exec_addr = block_jit.publish(&code).unwrap();
        ctx.fxsave.0[..2].copy_from_slice(&0x027fu16.to_le_bytes());
        ctx.fxsave.0[24..28].copy_from_slice(&0x5f80u32.to_le_bytes());
        let mut snapshots = [0u8; 16];
        let mut wrapper = vec![
            0x53, 0x48, 0x89, 0xf3, 0x0f, 0xae, 0x1b, 0xd9, 0x7b, 4, 0x48, 0xb8,
        ];
        wrapper.extend_from_slice(
            &(softcpu_enter_translated as *const () as usize as u64).to_le_bytes(),
        );
        wrapper.extend_from_slice(&[
            0xff, 0xd0, 0x9c, 0x58, 0xfc, 0x0f, 0xae, 0x5b, 8, 0xd9, 0x7b, 12, 0x0f, 0xae, 0x13,
            0xd9, 0x6b, 4, 0x5b, 0xc3,
        ]);
        let mut wrapper_jit = JitCodeBuffer::new(4096).unwrap();
        let entry = wrapper_jit.publish(&wrapper).unwrap();
        let run: unsafe extern "sysv64" fn(*mut SoftCpuContext, *mut u8) -> u64 =
            unsafe { std::mem::transmute(entry as usize) };
        let flags = unsafe { run(&mut ctx, snapshots.as_mut_ptr()) };
        assert_eq!(
            &snapshots[..6],
            &snapshots[8..14],
            "guest MXCSR/FCW reached host ABI"
        );
        assert_eq!(flags & (1 << 10), 0, "guest DF reached the host ABI");
        assert_ne!(ctx.rflags & (1 << 10), 0, "guest DF was lost");
        assert_eq!(&ctx.fxsave.0[..2], &0x027fu16.to_le_bytes());
        assert_eq!(&ctx.fxsave.0[24..28], &0x5f80u32.to_le_bytes());
    }

    #[test]
    fn crossing_conditional_write_preserves_untouched_bounce_bytes() {
        use crate::mmu::{ExtentRecord, ExtentTable, LinearPlacement, MmioHoles, OwnerGeneration};
        struct Memory(LinearPlacement, ExtentTable);
        impl SoftMmuMemory for Memory {
            fn placement(&self) -> &LinearPlacement {
                &self.0
            }
            fn extents(&self) -> &ExtentTable {
                &self.1
            }
            fn extents_mut(&mut self) -> &mut ExtentTable {
                &mut self.1
            }
        }
        #[repr(align(4096))]
        struct Pages([u64; 3072]);
        let mut pages = Box::new(Pages([0; 3072]));
        // Four live table levels map two adjacent user pages to frames 4 and 5.
        for (slot, frame) in [(0, 1), (512, 2), (1024, 3), (1536, 4), (1537, 5)] {
            pages.0[slot] = (frame << 12) | 7;
        }
        let host_base = pages.0.as_mut_ptr().cast::<u8>();
        let placement =
            LinearPlacement::new(host_base as usize, 6 * 4096, MmioHoles::empty()).unwrap();
        let mut extents = ExtentTable::new();
        let generation = OwnerGeneration::new(1);
        assert!(extents.install(ExtentRecord::new(FrameGpa::new(0), 6 * 4096, generation)));
        extents.set_root_generation(RootGpa::page_aligned(FrameGpa::new(0)).unwrap(), generation);
        let mut memory = Memory(placement, extents);
        // SAFETY: the 16 bytes span the last eight bytes of frame 4 and the first eight of frame 5.
        unsafe {
            std::ptr::write_bytes(host_base.add(0x4ff8), 0x55, 16);
        }
        let mut ctx = SoftCpuContext::new();
        ctx.bounce_buf.fill(0xcc);
        ctx.active_mem_ptr = Some(NonNull::from(&mut memory).cast());
        ctx.active_translate_fn = Some(translate_for_mem::<Memory>);
        assert_ne!(
            softcpu_mem_slow_path(&mut ctx, 0xff8, pack_slow_path_meta(0, 16, 1, false)),
            0
        );
        ctx.bounce_buf[0] = 0xaa;
        ctx.bounce_buf[15] = 0xaa;
        softcpu_commit_bounce(&mut ctx);
        // SAFETY: the same owned data pages remain live; all writes have finished.
        let bytes = unsafe { std::slice::from_raw_parts(host_base.add(0x4ff8), 16) };
        assert_eq!(
            bytes,
            [
                0xaa, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
                0x55, 0xaa
            ]
        );
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn published_blocks_and_gateways_are_rx_and_never_writable() {
        fn permissions(addr: u64) -> String {
            std::fs::read_to_string("/proc/self/maps")
                .unwrap()
                .lines()
                .find_map(|line| {
                    let mut fields = line.split_whitespace();
                    let (start, end) = fields.next()?.split_once('-')?;
                    let start = u64::from_str_radix(start, 16).ok()?;
                    let end = u64::from_str_radix(end, 16).ok()?;
                    let perms = fields.next()?;
                    (start <= addr && addr < end).then(|| perms.to_owned())
                })
                .unwrap()
        }
        let mut jit = JitCodeBuffer::new(4096).unwrap();
        for _ in 0..2 {
            let addr = jit.publish(&[0xc3]).unwrap();
            assert_eq!(permissions(addr), "r-xp");
        }
        let ctx = SoftCpuContext::new();
        for addr in [
            ctx.slow_path_fn,
            ctx.bounce_commit_fn,
            ctx.complex_step_fn,
            ctx.exit_trampoline_fn,
        ] {
            assert_eq!(permissions(addr), "r-xp");
        }
    }
    struct NoMemory;
    impl SoftMmuMemory for NoMemory {
        fn placement(&self) -> &crate::mmu::LinearPlacement {
            panic!("register-only fixture touched memory")
        }
        fn extents(&self) -> &crate::mmu::ExtentTable {
            panic!("register-only fixture touched memory")
        }
        fn extents_mut(&mut self) -> &mut crate::mmu::ExtentTable {
            panic!("register-only fixture touched memory")
        }
    }

    fn fp_block() -> crate::block::PlannedBlock {
        let ip = 0x400000;
        let mut bytes = [0; 15];
        bytes[..4].copy_from_slice(&[0xf3, 0x0f, 0x59, 0xc1]); // mulss xmm0,xmm1
        crate::block::PlannedBlock {
            start: ip,
            end: ip + 4,
            insns: vec![crate::decode::classify(&bytes[..4], ip).unwrap()],
            insn_bytes: vec![bytes],
            exit: crate::block::BlockExit::Syscall {
                va: ip + 4,
                resume: ip + 6,
            },
        }
    }

    #[test]
    fn fp_leaf_allocation_is_once_across_repeated_blocks() {
        let mut cpu = crate::SoftCpu::new().unwrap();
        let planned = fp_block();
        crate::cpu::JIT_ALLOCATIONS.with(|count| count.set(0));
        for _ in 0..3 {
            cpu.execute_planned_block(&planned, &mut NoMemory).unwrap();
        }
        crate::cpu::JIT_ALLOCATIONS.with(|count| assert_eq!(count.get(), 1));
    }

    fn fp_host_failure(publish: bool) {
        let mut cpu = crate::SoftCpu::new().unwrap();
        let planned = fp_block();
        crate::cpu::FAIL_SMALL_JIT.with(|fault| fault.set(Some(publish)));
        let result = cpu.execute_planned_block(&planned, &mut NoMemory);
        assert_eq!(
            result,
            Err(crate::EmitError::HostJit {
                va: planned.start,
                stage: if publish {
                    crate::JitStage::Publish
                } else {
                    crate::JitStage::Allocate
                },
            })
        );
        assert_eq!(cpu.context().pending_exception, None);
    }

    #[test]
    fn fp_allocation_failure_is_a_host_error() {
        fp_host_failure(false);
    }

    #[test]
    fn fp_publication_failure_is_a_host_error() {
        fp_host_failure(true);
    }
}
