//! Per-vCPU execution context (`SoftCpuContext`), gateway machine-code trampolines,
//! slow-path soft-TLB/bounce helpers, and checked complex instruction helpers.

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
pub type ActiveTranslateFn =
    unsafe fn(&mut SoftCpuContext, u64, SoftAccessKind) -> Result<*mut u8, SoftPageFault>;

/// Monomorphized [`ActiveTranslateFn`] adapter for any `M: SoftMmuMemory`.
///
/// # Safety
///
/// `ctx.active_mem_ptr` must point to a valid, exclusively borrowed `M` for the call duration.
pub unsafe fn translate_for_mem<M: SoftMmuMemory>(
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
pub const CTX_FXSAVE_OFF: usize = 0x160;
pub const CTX_TLB_READ_OFF: usize = 0x380;
pub const CTX_TLB_WRITE_OFF: usize = CTX_TLB_READ_OFF + SoftTlb::WRITE_PLANE_OFFSET;

/// Architectural x86_64 exception vectors surfaced by `carrick-softcpu-x86`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum X86ExceptionVector {
    DivideError = 0,
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
pub struct BounceWriteback {
    pub host_ptr0: *mut u8,
    pub len0: usize,
    pub host_ptr1: *mut u8,
    pub len1: usize,
}

/// Aligned 512-byte FXSAVE area (`fxsave64`/`fxrstor64` require 16-byte alignment).
#[repr(C, align(16))]
#[derive(Clone, Debug)]
pub struct FxsaveArea(pub [u8; 512]);

impl Default for FxsaveArea {
    fn default() -> Self {
        let mut bytes = [0u8; 512];
        bytes[0..2].copy_from_slice(&0x037Fu16.to_le_bytes());
        bytes[24..28].copy_from_slice(&0x1F80u32.to_le_bytes());
        Self(bytes)
    }
}

/// Per-CPU architectural and runtime context pointed to by `%r15` during block execution.
#[repr(C, align(64))]
pub struct SoftCpuContext {
    pub gpr: [u64; 16],
    pub rip: u64,
    pub rflags: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub kernel_gs_base: u64,
    pub tlb_tag_bits: u64,
    pub host_rsp: u64,
    pub entry_exec_addr: u64,
    pub exit_reason: u64,
    pub exit_insn_va: u64,
    pub probe_spill: [u64; 2],
    pub virt_spill: [u64; 2],
    pub saved_lahf: u64,
    pub slow_path_fn: u64,
    pub bounce_commit_fn: u64,
    pub complex_step_fn: u64,
    pub exit_trampoline_fn: u64,
    pub bounce_active: u64,
    pub bounce_buf: [u8; 64],
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
    pub bounce_writeback: BounceWriteback,
    pub active_mem_ptr: Option<NonNull<()>>,
    pub active_translate_fn: Option<ActiveTranslateFn>,
    pub active_block_insns: Vec<(u64, Instruction)>,
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
            xcr0: 0x7,
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
        };
        ctx.sync_tlb_tag_bits();
        ctx
    }

    #[inline]
    #[must_use]
    pub const fn ac(&self) -> bool {
        (self.rflags & (1 << 18)) != 0
    }

    #[inline]
    #[must_use]
    pub const fn root_gpa(&self) -> RootGpa {
        match RootGpa::page_aligned(FrameGpa::new(self.cr3 & SOFT_TLB_PAGE_MASK)) {
            Some(root) => root,
            None => unreachable!(),
        }
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
pub extern "sysv64" fn softcpu_mem_slow_path(
    ctx: &mut SoftCpuContext,
    guest_va: u64,
    meta: u64,
) -> u64 {
    let (insn_offset, size, access_code, align16) = unpack_slow_path_meta(meta);
    let insn_va = ctx.block_start_va.wrapping_add(u64::from(insn_offset));
    ctx.bounce_active = 0;

    let size = size.clamp(1, 64);
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
    }

    if needs_read {
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
pub extern "sysv64" fn softcpu_commit_bounce(ctx: &mut SoftCpuContext) {
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
pub extern "sysv64" fn softcpu_step_complex(ctx: &mut SoftCpuContext, insn_idx: u64) -> u64 {
    let Some(&(insn_va, insn)) = ctx.active_block_insns.get(insn_idx as usize) else {
        record_exception(ctx, X86Exception::invalid_opcode(ctx.rip));
        return 0;
    };
    match step_complex_inner(ctx, &insn, insn_va) {
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
) -> Result<(), X86Exception> {
    match insn.mnemonic() {
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
pub unsafe fn softcpu_enter_translated(ctx: *mut u8) -> u64 {
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

const GATEWAY_TEMPLATE: &[u8; 916] = b"\
\x55\x53\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x08\x49\x89\xFF\x49\x89\xA7\xB0\x00\x00\x00\x49\x0F\xAE\x8F\x60\x01\x00\x00\x49\x8B\x87\x88\x00\x00\x00\x48\x25\xFF\xFE\xFB\xFF\x50\x9D\x49\x8B\x07\x49\x8B\x4F\x08\x49\x8B\x57\x10\x49\x8B\x5F\x18\x49\x8B\x67\x20\x49\x8B\x6F\x28\x49\x8B\x77\x30\x49\x8B\x7F\x38\x4D\x8B\x47\x40\x4D\x8B\x4F\x48\x4D\x8B\x57\x50\x4D\x8B\x5F\x58\x4D\x8B\
\x67\x60\x4D\x8B\x6F\x68\x41\xFF\xA7\xB8\x00\x00\x00\x49\x89\x07\x49\x89\x4F\x08\x49\x89\x57\x10\x49\x89\x5F\x18\x49\x89\x67\x20\x49\x89\x6F\x28\x49\x89\x77\x30\x49\x89\x7F\x38\x4D\x89\x47\x40\x4D\x89\x4F\x48\x4D\x89\x57\x50\x4D\x89\x5F\x58\x4D\x89\x67\x60\x4D\x89\x6F\x68\x49\x8B\xA7\xB0\x00\x00\x00\x9C\x58\x49\x8B\x8F\x88\x00\x00\x00\x48\x81\xE1\x00\x02\x04\x00\x48\x25\xFF\xFD\xFB\
\xFF\x48\x09\xC8\x49\x89\x87\x88\x00\x00\x00\x49\x0F\xAE\x87\x60\x01\x00\x00\x49\x8B\x87\xC0\x00\x00\x00\x48\x83\xC4\x08\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x5B\x5D\xC3\x49\x89\x57\x10\x49\x89\x5F\x18\x49\x89\x67\x20\x49\x89\x6F\x28\x49\x89\x77\x30\x49\x89\x7F\x38\x4D\x89\x47\x40\x4D\x89\x4F\x48\x4D\x89\x57\x50\x4D\x89\x5F\x58\x4D\x89\x67\x60\x4D\x89\x6F\x68\x49\x8B\x97\xD0\x00\x00\x00\
\x49\x89\x17\x49\x8B\x97\xD8\x00\x00\x00\x49\x89\x57\x08\x49\x8B\xA7\xB0\x00\x00\x00\x4C\x89\xFF\x4C\x89\xF6\x48\x89\xC2\x48\x89\xCB\x41\x8B\x87\xF0\x00\x00\x00\x04\x7F\x9E\x9C\x58\x49\x8B\x8F\x88\x00\x00\x00\x48\x81\xE1\x00\x02\x04\x00\x48\x25\xFF\xFD\xFB\xFF\x48\x09\xC8\x49\x89\x87\x88\x00\x00\x00\x49\x0F\xAE\x87\x60\x01\x00\x00\x48\xB8\x11\x11\x11\x11\x11\x11\x11\x11\xFF\xD0\x48\
\x85\xC0\x0F\x84\x4B\xFF\xFF\xFF\x49\x89\xC6\x49\x0F\xAE\x8F\x60\x01\x00\x00\x48\x89\xD9\x49\x8B\x57\x10\x49\x8B\x5F\x18\x49\x8B\x67\x20\x49\x8B\x6F\x28\x49\x8B\x77\x30\x49\x8B\x7F\x38\x4D\x8B\x47\x40\x4D\x8B\x4F\x48\x4D\x8B\x57\x50\x4D\x8B\x5F\x58\x4D\x8B\x67\x60\x4D\x8B\x6F\x68\xFF\xE1\x49\x89\x57\x10\x49\x89\x5F\x18\x49\x89\x67\x20\x49\x89\x6F\x28\x49\x89\x77\x30\x49\x89\x7F\x38\
\x4D\x89\x47\x40\x4D\x89\x4F\x48\x4D\x89\x57\x50\x4D\x89\x5F\x58\x4D\x89\x67\x60\x4D\x89\x6F\x68\x49\x8B\xA7\xB0\x00\x00\x00\x9C\x58\x49\x8B\x97\x88\x00\x00\x00\x48\x81\xE2\x00\x02\x04\x00\x48\x25\xFF\xFD\xFB\xFF\x48\x09\xD0\x49\x89\x87\x88\x00\x00\x00\x48\x89\xCB\x49\x0F\xAE\x87\x60\x01\x00\x00\x4C\x89\xFF\x48\xB8\x22\x22\x22\x22\x22\x22\x22\x22\xFF\xD0\x49\x0F\xAE\x8F\x60\x01\x00\
\x00\x49\x89\x9F\xE8\x00\x00\x00\x49\x8B\x87\x88\x00\x00\x00\x48\x25\xFF\xFE\xFB\xFF\x50\x9D\x49\x8B\x87\xD0\x00\x00\x00\x49\x8B\x8F\xD8\x00\x00\x00\x49\x8B\x57\x10\x49\x8B\x5F\x18\x49\x8B\x67\x20\x49\x8B\x6F\x28\x49\x8B\x77\x30\x49\x8B\x7F\x38\x4D\x8B\x47\x40\x4D\x8B\x4F\x48\x4D\x8B\x57\x50\x4D\x8B\x5F\x58\x4D\x8B\x67\x60\x4D\x8B\x6F\x68\x41\xFF\xA7\xE8\x00\x00\x00\x49\x89\x57\x10\
\x49\x89\x5F\x18\x49\x89\x67\x20\x49\x89\x6F\x28\x49\x89\x77\x30\x49\x89\x7F\x38\x4D\x89\x47\x40\x4D\x89\x4F\x48\x4D\x89\x57\x50\x4D\x89\x5F\x58\x4D\x89\x67\x60\x4D\x89\x6F\x68\x49\x8B\x97\xD0\x00\x00\x00\x49\x89\x17\x49\x8B\x97\xD8\x00\x00\x00\x49\x89\x57\x08\x49\x8B\xA7\xB0\x00\x00\x00\x4C\x89\xFF\x48\x89\xC6\x48\x89\xCB\x41\x8B\x87\xF0\x00\x00\x00\x04\x7F\x9E\x9C\x58\x49\x8B\x8F\
\x88\x00\x00\x00\x48\x81\xE1\x00\x02\x04\x00\x48\x25\xFF\xFD\xFB\xFF\x48\x09\xC8\x49\x89\x87\x88\x00\x00\x00\x49\x0F\xAE\x87\x60\x01\x00\x00\x48\xB8\x33\x33\x33\x33\x33\x33\x33\x33\xFF\xD0\x48\x85\xC0\x0F\x84\x9B\xFD\xFF\xFF\x49\x0F\xAE\x8F\x60\x01\x00\x00\x49\x89\x9F\xE8\x00\x00\x00\x49\x8B\x87\x88\x00\x00\x00\x48\x25\xFF\xFE\xFB\xFF\x50\x9D\x49\x8B\x07\x49\x8B\x4F\x08\x49\x8B\x57\
\x10\x49\x8B\x5F\x18\x49\x8B\x67\x20\x49\x8B\x6F\x28\x49\x8B\x77\x30\x49\x8B\x7F\x38\x4D\x8B\x47\x40\x4D\x8B\x4F\x48\x4D\x8B\x57\x50\x4D\x8B\x5F\x58\x4D\x8B\x67\x60\x4D\x8B\x6F\x68\x41\xFF\xA7\xE8\x00\x00\x00";

fn gateway_trampolines() -> Option<&'static GatewayTrampolines> {
    static GATEWAY: OnceLock<Option<GatewayTrampolines>> = OnceLock::new();
    GATEWAY
        .get_or_init(|| {
            let mut image = *GATEWAY_TEMPLATE;
            for (off, f) in [
                (373usize, softcpu_mem_slow_path as *const () as usize as u64),
                (559, softcpu_commit_bounce as *const () as usize as u64),
                (805, softcpu_step_complex as *const () as usize as u64),
            ] {
                image[off..off + 8].copy_from_slice(&f.to_le_bytes());
            }
            let b = Box::leak(Box::new(crate::cpu::JitCodeBuffer::new(4096)?)).publish(&image)?;
            Some(GatewayTrampolines {
                enter_translated: b,
                exit_trampoline: b + 0x06d,
                slow_path_shim: b + 0x0e9,
                bounce_commit_shim: b + 0x1c8,
                complex_step_shim: b + 0x29c,
            })
        })
        .as_ref()
}
