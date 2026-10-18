//! Control-flow resolution (`jmp`, `jcc`, `loop*`, `call`, `ret`) over [`SoftMmuMemory`].

use iced_x86::{Code, ConditionCode, Instruction, OpKind, Register};

use crate::context::{SoftCpuContext, X86Exception, reg};
use crate::decode::{CflowKind, gpr_index};
use crate::mmu::{
    SoftAccessKind, SoftMmuMemory, is_canonical_va, read_guest_bytes, write_guest_bytes,
};

const ZF: u64 = 1 << 6;

/// Evaluate an `iced_x86::ConditionCode` against `rflags`.
#[must_use]
pub const fn eval_cc(cc: ConditionCode, rflags: u64) -> bool {
    let (cf, pf, zf, sf, of) = (
        (rflags & 1) != 0,
        (rflags & 4) != 0,
        (rflags & ZF) != 0,
        (rflags & 128) != 0,
        (rflags & 2048) != 0,
    );
    match cc {
        ConditionCode::None => true,
        ConditionCode::o => of,
        ConditionCode::no => !of,
        ConditionCode::b => cf,
        ConditionCode::ae => !cf,
        ConditionCode::e => zf,
        ConditionCode::ne => !zf,
        ConditionCode::be => cf || zf,
        ConditionCode::a => !cf && !zf,
        ConditionCode::s => sf,
        ConditionCode::ns => !sf,
        ConditionCode::p => pf,
        ConditionCode::np => !pf,
        ConditionCode::l => sf != of,
        ConditionCode::ge => sf == of,
        ConditionCode::le => zf || (sf != of),
        ConditionCode::g => !zf && (sf == of),
    }
}

/// Compute the effective 64-bit guest virtual address of `insn`'s memory operand.
#[must_use]
pub fn compute_effective_va(insn: &Instruction, ctx: &SoftCpuContext) -> u64 {
    let mut addr = if insn.is_ip_rel_memory_operand() {
        insn.ip_rel_memory_address()
    } else {
        let (base_reg, index_reg) = (insn.memory_base(), insn.memory_index());
        let base_val = read_addr_reg(base_reg, ctx);
        let index_val =
            read_addr_reg(index_reg, ctx).wrapping_mul(u64::from(insn.memory_index_scale()));
        let raw = base_val
            .wrapping_add(index_val)
            .wrapping_add(insn.memory_displacement64());
        if base_reg.size() == 4 || index_reg.size() == 4 {
            raw & 0xffff_ffff
        } else {
            raw
        }
    };
    match insn.segment_prefix() {
        Register::FS => addr = addr.wrapping_add(ctx.fs_base),
        Register::GS => addr = addr.wrapping_add(ctx.gs_base),
        _ => {}
    }
    addr
}

fn read_addr_reg(r: Register, ctx: &SoftCpuContext) -> u64 {
    gpr_index(r).map_or(0, |idx| {
        if r.size() == 4 {
            ctx.gpr[idx] & 0xffff_ffff
        } else {
            ctx.gpr[idx]
        }
    })
}

fn read_u64_checked<M: SoftMmuMemory>(
    va: u64,
    insn_va: u64,
    ctx: &mut SoftCpuContext,
    mem: &mut M,
) -> Result<u64, X86Exception> {
    if !is_canonical_va(va) || !is_canonical_va(va.wrapping_add(7)) {
        return Err(X86Exception::general_protection(insn_va, 0));
    }
    let mut buf = [0u8; 8];
    read_guest_bytes(ctx, mem, va, &mut buf, SoftAccessKind::Read)
        .map_err(|pf| X86Exception::page_fault(insn_va, pf.error_code, pf.cr2))?;
    ctx.check_alignment(va, 8, insn_va)?;
    Ok(u64::from_le_bytes(buf))
}

fn write_u64_checked<M: SoftMmuMemory>(
    va: u64,
    val: u64,
    insn_va: u64,
    ctx: &mut SoftCpuContext,
    mem: &mut M,
) -> Result<(), X86Exception> {
    if !is_canonical_va(va) || !is_canonical_va(va.wrapping_add(7)) {
        return Err(X86Exception::general_protection(insn_va, 0));
    }
    crate::mmu::check_guest_alignment(ctx, mem, va, 8, 8, SoftAccessKind::Write, insn_va)?;
    write_guest_bytes(ctx, mem, va, &val.to_le_bytes())
        .map_err(|pf| X86Exception::page_fault(insn_va, pf.error_code, pf.cr2))
}

fn read_indirect_target<M: SoftMmuMemory>(
    insn: &Instruction,
    insn_va: u64,
    ctx: &mut SoftCpuContext,
    mem: &mut M,
) -> Result<u64, X86Exception> {
    match insn.op0_kind() {
        OpKind::Register => gpr_index(insn.op0_register())
            .map(|idx| ctx.gpr[idx])
            .ok_or_else(|| X86Exception::invalid_opcode(insn_va)),
        OpKind::Memory => read_u64_checked(compute_effective_va(insn, ctx), insn_va, ctx, mem),
        _ => Err(X86Exception::invalid_opcode(insn_va)),
    }
}

/// Resolve a control-flow terminator at `insn_va`, updating `ctx.rip` (and `RSP`/`RCX`)
/// or returning a typed [`X86Exception`].
pub fn resolve_cflow<M: SoftMmuMemory>(
    insn: &Instruction,
    insn_va: u64,
    kind: CflowKind,
    ctx: &mut SoftCpuContext,
    mem: &mut M,
) -> Result<u64, X86Exception> {
    match kind {
        CflowKind::DirectJump { .. } | CflowKind::IndirectJump => {
            let dest = match kind {
                CflowKind::DirectJump { target } => target,
                _ => read_indirect_target(insn, insn_va, ctx, mem)?,
            };
            if !is_canonical_va(dest) {
                return Err(X86Exception::general_protection(insn_va, 0));
            }
            ctx.rip = dest;
            Ok(dest)
        }
        CflowKind::ConditionalBranch {
            target,
            fallthrough,
        } => {
            let (taken, new_rcx) = eval_conditional_branch(insn, ctx);
            let dest = if taken { target } else { fallthrough };
            if !is_canonical_va(dest) {
                return Err(X86Exception::general_protection(insn_va, 0));
            }
            if let Some(rcx) = new_rcx {
                ctx.gpr[reg::RCX] = rcx;
            }
            ctx.rip = dest;
            Ok(dest)
        }
        CflowKind::DirectCall { return_va, .. } | CflowKind::IndirectCall { return_va } => {
            let dest = match kind {
                CflowKind::DirectCall { target, .. } => target,
                _ => read_indirect_target(insn, insn_va, ctx, mem)?,
            };
            if !is_canonical_va(dest) {
                return Err(X86Exception::general_protection(insn_va, 0));
            }
            let new_rsp = ctx.gpr[reg::RSP].wrapping_sub(8);
            write_u64_checked(new_rsp, return_va, insn_va, ctx, mem)?;
            ctx.gpr[reg::RSP] = new_rsp;
            ctx.rip = dest;
            Ok(dest)
        }
        CflowKind::Return { pop_bytes } => {
            let old_rsp = ctx.gpr[reg::RSP];
            let target = read_u64_checked(old_rsp, insn_va, ctx, mem)?;
            if !is_canonical_va(target) {
                return Err(X86Exception::general_protection(insn_va, 0));
            }
            ctx.gpr[reg::RSP] = old_rsp.wrapping_add(8).wrapping_add(u64::from(pop_bytes));
            ctx.rip = target;
            Ok(target)
        }
    }
}

fn eval_conditional_branch(insn: &Instruction, ctx: &SoftCpuContext) -> (bool, Option<u64>) {
    let (zf, rcx_in) = ((ctx.rflags & ZF) != 0, ctx.gpr[reg::RCX]);
    match insn.code() {
        Code::Jrcxz_rel8_64 => (rcx_in == 0, None),
        Code::Jecxz_rel8_64 => ((rcx_in as u32) == 0, None),
        Code::Loop_rel8_64_RCX
        | Code::Loope_rel8_64_RCX
        | Code::Loopne_rel8_64_RCX
        | Code::Loop_rel8_64_ECX
        | Code::Loope_rel8_64_ECX
        | Code::Loopne_rel8_64_ECX => {
            let is_32 = matches!(
                insn.code(),
                Code::Loop_rel8_64_ECX | Code::Loope_rel8_64_ECX | Code::Loopne_rel8_64_ECX
            );
            let (rcx, nz) = if is_32 {
                let ecx = (rcx_in as u32).wrapping_sub(1);
                ((rcx_in & !0xffff_ffff) | u64::from(ecx), ecx != 0)
            } else {
                let r = rcx_in.wrapping_sub(1);
                (r, r != 0)
            };
            let cond = match insn.code() {
                Code::Loope_rel8_64_RCX | Code::Loope_rel8_64_ECX => zf,
                Code::Loopne_rel8_64_RCX | Code::Loopne_rel8_64_ECX => !zf,
                _ => true,
            };
            (nz && cond, Some(rcx))
        }
        _ => (eval_cc(insn.condition_code(), ctx.rflags), None),
    }
}
