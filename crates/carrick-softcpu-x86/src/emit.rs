//! Level 0 x86_64 block translator and soft-TLB probe emitter.

use iced_x86::{
    Code, Encoder, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register,
};

use crate::block::{BlockExit, PlannedBlock};
use crate::context::{
    CTX_BOUNCE_COMMIT_FN_OFF, CTX_COMPLEX_STEP_FN_OFF, CTX_EXIT_INSN_VA_OFF, CTX_EXIT_REASON_OFF,
    CTX_EXIT_TRAMPOLINE_FN_OFF, CTX_FS_BASE_OFF, CTX_GPR_R14_OFF, CTX_GPR_R15_OFF, CTX_GS_BASE_OFF,
    CTX_PROBE_SPILL0_OFF, CTX_PROBE_SPILL1_OFF, CTX_RIP_OFF, CTX_SAVED_LAHF_OFF,
    CTX_SLOW_PATH_FN_OFF, CTX_TLB_READ_OFF, CTX_TLB_TAG_BITS_OFF, CTX_TLB_WRITE_OFF,
    CTX_VIRT_SPILL0_OFF, CTX_VIRT_SPILL1_OFF, EXIT_REASON_CFLOW, EXIT_REASON_CONTINUE,
    EXIT_REASON_EXCEPTION, EXIT_REASON_SENSITIVE, EXIT_REASON_SYSCALL, pack_slow_path_meta,
};
use crate::decode::{gpr_index, is_fp_arithmetic, is_memory_kind, supported_body};

/// Failed host JIT operation, distinct from a guest architectural exception.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JitStage {
    Allocate,
    Publish,
}

/// Error returned if a block cannot be emitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EmitError {
    EncodeFailed { va: u64, detail: String },
    HostJit { va: u64, stage: JitStage },
}

/// Output of [`emit_block`].
#[derive(Clone, Debug)]
pub struct EmittedBlock {
    pub code: Vec<u8>,
}

struct ColdSlowPath {
    branch_patch_offsets: Vec<usize>,
    resume_offset: usize,
    meta: u64,
    write_exec_bytes: Option<Vec<u8>>,
}

/// Translate `block` into Level 0 x86_64 machine code.
pub fn emit_block(block: &PlannedBlock) -> Result<EmittedBlock, EmitError> {
    let mut code = Vec::with_capacity(block.insns.len() * 64 + 64);
    let mut info_factory = InstructionInfoFactory::new();
    let mut cold_paths: Vec<ColdSlowPath> = Vec::new();

    for (idx, decoded) in block.insns.iter().enumerate() {
        let insn = &decoded.raw;
        if !supported_body(insn) {
            emit_exit_stub(&mut code, decoded.va, decoded.va, EXIT_REASON_EXCEPTION);
            break;
        }
        let raw_bytes = &block.insn_bytes[idx][..decoded.len];
        if is_routed_to_complex_helper(insn) {
            emit_complex_call(&mut code, idx as u32);
        } else if matches!(
            insn.mnemonic(),
            Mnemonic::Nop | Mnemonic::Endbr64 | Mnemonic::Endbr32
        ) || is_prefetch_mnemonic(insn.mnemonic())
        {
            code.push(0x90);
        } else if insn.mnemonic() == Mnemonic::Lea {
            emit_lea(&mut code, insn, decoded.va, &mut info_factory)?;
        } else if !(0..insn.op_count()).any(|i| is_memory_kind(insn.op_kind(i)))
            && info_factory.info(insn).used_memory().is_empty()
        {
            emit_reg_only_insn(&mut code, insn, raw_bytes, decoded.va, &mut info_factory)?;
        } else {
            emit_mem_insn(
                &mut code,
                insn,
                decoded.va,
                block.start,
                &mut info_factory,
                &mut cold_paths,
            )?;
        }
    }

    let (next_rip, insn_va, reason) = match &block.exit {
        BlockExit::Syscall { va, resume, .. } => (*resume, *va, EXIT_REASON_SYSCALL),
        BlockExit::ControlFlow { va, .. } => (*va, *va, EXIT_REASON_CFLOW),
        BlockExit::Sensitive { va, resume, .. } => (*resume, *va, EXIT_REASON_SENSITIVE),
        BlockExit::Continue { target } => (*target, *target, EXIT_REASON_CONTINUE),
        BlockExit::InvalidOpcode { va } => (*va, *va, EXIT_REASON_EXCEPTION),
    };
    emit_exit_stub(&mut code, next_rip, insn_va, reason);

    for cold in cold_paths {
        let slow_entry = code.len();
        for patch_off in cold.branch_patch_offsets {
            patch_rel32(&mut code, patch_off, slow_entry);
        }
        emit_movabs(&mut code, 0x48, 0xB8, cold.meta);
        let lea_patch = emit_lea_rcx_rip_rel(&mut code);
        emit_jmp_r15_disp32(&mut code, CTX_SLOW_PATH_FN_OFF as i32);

        if let Some(write_bytes) = cold.write_exec_bytes {
            let slow_exec_off = code.len();
            patch_rel32(&mut code, lea_patch, slow_exec_off);
            emit_restore_flags_and_rax_rcx(&mut code);
            code.extend_from_slice(&write_bytes);
            emit_mov_r15_disp32_from_gpr(&mut code, CTX_PROBE_SPILL0_OFF as i32, 0);
            emit_mov_r15_disp32_from_gpr(&mut code, CTX_PROBE_SPILL1_OFF as i32, 1);
            let commit_lea = emit_lea_rcx_rip_rel(&mut code);
            patch_rel32(&mut code, commit_lea, cold.resume_offset);
            emit_jmp_r15_disp32(&mut code, CTX_BOUNCE_COMMIT_FN_OFF as i32);
        } else {
            patch_rel32(&mut code, lea_patch, cold.resume_offset);
        }
    }
    Ok(EmittedBlock { code })
}

fn is_routed_to_complex_helper(insn: &Instruction) -> bool {
    is_fp_arithmetic(insn)
        || insn.is_string_instruction()
        || matches!(
            insn.mnemonic(),
            Mnemonic::Maskmovdqu
                | Mnemonic::Div
                | Mnemonic::Idiv
                | Mnemonic::Push
                | Mnemonic::Pop
                | Mnemonic::Pushfq
                | Mnemonic::Popfq
                | Mnemonic::Pushf
                | Mnemonic::Popf
                | Mnemonic::Leave
                | Mnemonic::Enter
                | Mnemonic::Xlatb
        )
}

const fn is_prefetch_mnemonic(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Prefetchnta
            | Mnemonic::Prefetcht0
            | Mnemonic::Prefetcht1
            | Mnemonic::Prefetcht2
            | Mnemonic::Prefetchw
            | Mnemonic::Prefetchwt1
    )
}

fn emit_complex_call(code: &mut Vec<u8>, insn_idx: u32) {
    emit_mov_r15_disp32_from_gpr(code, CTX_PROBE_SPILL0_OFF as i32, 0);
    emit_mov_r15_disp32_from_gpr(code, CTX_PROBE_SPILL1_OFF as i32, 1);
    emit_save_flags_into_ctx(code);
    code.push(0xB8);
    code.extend_from_slice(&insn_idx.to_le_bytes());
    let lea_patch = emit_lea_rcx_rip_rel(code);
    emit_jmp_r15_disp32(code, CTX_COMPLEX_STEP_FN_OFF as i32);
    let after_off = code.len();
    patch_rel32(code, lea_patch, after_off);
}

fn emit_lea(
    code: &mut Vec<u8>,
    insn: &Instruction,
    va: u64,
    info_factory: &mut InstructionInfoFactory,
) -> Result<(), EmitError> {
    if insn.is_ip_rel_memory_operand() {
        let target = insn.ip_rel_memory_address();
        let mut temp_insn = *insn;
        let virt = begin_virt_r14_r15(code, &mut temp_insn, info_factory, false);
        let reg_idx = gpr_index(temp_insn.op0_register()).unwrap_or(0) as u8;
        match insn.op0_register().size() {
            8 => emit_movabs(
                code,
                0x48 | if reg_idx >= 8 { 1 } else { 0 },
                0xB8 + (reg_idx & 7),
                target,
            ),
            4 => {
                if reg_idx >= 8 {
                    code.push(0x41);
                }
                code.push(0xB8 + (reg_idx & 7));
                code.extend_from_slice(&(target as u32).to_le_bytes());
            }
            2 => {
                code.push(0x66);
                if reg_idx >= 8 {
                    code.push(0x41);
                }
                code.push(0xB8 + (reg_idx & 7));
                code.extend_from_slice(&(target as u16).to_le_bytes());
            }
            _ => {
                return Err(EmitError::EncodeFailed {
                    va,
                    detail: "invalid LEA destination".to_string(),
                });
            }
        }
        end_virt_r14_r15(code, &virt);
        return Ok(());
    }
    let mut rewritten = *insn;
    let virt = begin_virt_r14_r15(code, &mut rewritten, info_factory, true);
    encode_one(code, &rewritten, va)?;
    end_virt_r14_r15(code, &virt);
    Ok(())
}

fn emit_reg_only_insn(
    code: &mut Vec<u8>,
    insn: &Instruction,
    raw_bytes: &[u8],
    va: u64,
    info_factory: &mut InstructionInfoFactory,
) -> Result<(), EmitError> {
    if !mentions_r14_or_r15(insn, true) {
        code.extend_from_slice(raw_bytes);
        return Ok(());
    }
    let mut rewritten = *insn;
    let virt = begin_virt_r14_r15(code, &mut rewritten, info_factory, true);
    encode_one(code, &rewritten, va)?;
    end_virt_r14_r15(code, &virt);
    Ok(())
}

fn emit_mem_insn(
    code: &mut Vec<u8>,
    insn: &Instruction,
    va: u64,
    block_start: u64,
    info_factory: &mut InstructionInfoFactory,
    cold_paths: &mut Vec<ColdSlowPath>,
) -> Result<(), EmitError> {
    if !(0..insn.op_count()).any(|i| insn.op_kind(i) == OpKind::Memory) {
        emit_exit_stub(code, va, va, EXIT_REASON_EXCEPTION);
        return Ok(());
    }
    let used_mem = info_factory.info(insn).used_memory();
    if used_mem.is_empty() {
        code.push(0x90);
        return Ok(());
    }

    let mem_info = used_mem[0];
    let operand_size = mem_info.memory_size().size();
    if !(1..=64).contains(&operand_size) {
        emit_exit_stub(code, va, va, EXIT_REASON_EXCEPTION);
        return Ok(());
    }
    let size = operand_size as u8;
    let access_code: u8 = match mem_info.access() {
        OpAccess::Write | OpAccess::CondWrite => 1,
        OpAccess::ReadWrite | OpAccess::ReadCondWrite => 2,
        _ => 0,
    };
    let align16 = requires_16byte_alignment(insn, size);
    let meta = pack_slow_path_meta(
        va.wrapping_sub(block_start) as u32,
        size,
        access_code,
        align16,
    );

    emit_mov_r15_disp32_from_gpr(code, CTX_PROBE_SPILL0_OFF as i32, 0);
    emit_mov_r15_disp32_from_gpr(code, CTX_PROBE_SPILL1_OFF as i32, 1);
    emit_save_flags_into_ctx(code);
    emit_effective_address_into_r14(code, insn);

    let mut branch_patches = Vec::with_capacity(3);
    if align16 {
        code.extend_from_slice(&[0x41, 0xF6, 0xC6, 0x0F]);
        branch_patches.push(emit_jcc_rel32(code, 0x85));
    }
    if size > 1 {
        code.extend_from_slice(&[
            0x44, 0x89, 0xF1, 0x81, 0xE1, 0xFF, 0x0F, 0x00, 0x00, 0x81, 0xF9,
        ]);
        code.extend_from_slice(&(4096u32 - u32::from(size)).to_le_bytes());
        branch_patches.push(emit_jcc_rel32(code, 0x87));
    }

    code.extend_from_slice(&[
        0x4C, 0x89, 0xF0, 0x48, 0xC1, 0xE8, 0x0C, 0x25, 0xFF, 0x03, 0x00, 0x00, 0xC1, 0xE0, 0x04,
        0x4C, 0x89, 0xF1, 0x48, 0x81, 0xE1, 0x00, 0xF0, 0xFF, 0xFF, 0x49, 0x0B, 0x8F,
    ]);
    code.extend_from_slice(&(CTX_TLB_TAG_BITS_OFF as i32).to_le_bytes());

    let tlb_off = if access_code == 0 {
        CTX_TLB_READ_OFF as i32
    } else {
        CTX_TLB_WRITE_OFF as i32
    };
    code.extend_from_slice(&[0x49, 0x3B, 0x8C, 0x07]);
    code.extend_from_slice(&tlb_off.to_le_bytes());
    branch_patches.push(emit_jcc_rel32(code, 0x85));

    code.extend_from_slice(&[0x4D, 0x03, 0xB4, 0x07]);
    code.extend_from_slice(&(tlb_off + 8).to_le_bytes());

    let probe_done_off = code.len();
    emit_restore_flags_and_rax_rcx(code);

    let mut exec_bytes = Vec::with_capacity(32);
    emit_rewritten_mem_op(&mut exec_bytes, insn, va, info_factory)?;
    code.extend_from_slice(&exec_bytes);
    let after_insn_off = code.len();

    cold_paths.push(ColdSlowPath {
        branch_patch_offsets: branch_patches,
        resume_offset: if access_code == 0 {
            probe_done_off
        } else {
            after_insn_off
        },
        meta,
        write_exec_bytes: (access_code != 0).then_some(exec_bytes),
    });
    Ok(())
}

fn emit_rewritten_mem_op(
    out: &mut Vec<u8>,
    insn: &Instruction,
    va: u64,
    info_factory: &mut InstructionInfoFactory,
) -> Result<(), EmitError> {
    let mut rewritten = *insn;
    match rewritten.code() {
        Code::Mov_AL_moffs8 => rewritten.set_code(Code::Mov_r8_rm8),
        Code::Mov_AX_moffs16 => rewritten.set_code(Code::Mov_r16_rm16),
        Code::Mov_EAX_moffs32 => rewritten.set_code(Code::Mov_r32_rm32),
        Code::Mov_RAX_moffs64 => rewritten.set_code(Code::Mov_r64_rm64),
        Code::Mov_moffs8_AL => rewritten.set_code(Code::Mov_rm8_r8),
        Code::Mov_moffs16_AX => rewritten.set_code(Code::Mov_rm16_r16),
        Code::Mov_moffs32_EAX => rewritten.set_code(Code::Mov_rm32_r32),
        Code::Mov_moffs64_RAX => rewritten.set_code(Code::Mov_rm64_r64),
        _ => {}
    }

    let virt = begin_virt_r14_r15(out, &mut rewritten, info_factory, false);
    rewritten.set_segment_prefix(Register::None);
    rewritten.set_memory_base(Register::R14);
    rewritten.set_memory_index(Register::None);
    rewritten.set_memory_index_scale(1);
    rewritten.set_memory_displacement64(0);
    rewritten.set_memory_displ_size(0);

    encode_one(out, &rewritten, va)?;
    end_virt_r14_r15(out, &virt);
    Ok(())
}

fn encode_one(out: &mut Vec<u8>, insn: &Instruction, va: u64) -> Result<(), EmitError> {
    let mut encoder = Encoder::new(64);
    encoder
        .encode(insn, va)
        .map_err(|e| EmitError::EncodeFailed {
            va,
            detail: e.to_string(),
        })?;
    out.extend_from_slice(&encoder.take_buffer());
    Ok(())
}

struct VirtSpillState {
    rsp_host: Option<usize>,
    r14_host: Option<usize>,
    r15_host: Option<usize>,
}

fn mentions_r14_or_r15(insn: &Instruction, include_mem: bool) -> bool {
    (0..insn.op_count()).any(|i| {
        insn.op_kind(i) == OpKind::Register
            && matches!(gpr_index(insn.op_register(i)), Some(4 | 14 | 15))
    }) || (include_mem
        && (matches!(gpr_index(insn.memory_base()), Some(4 | 14 | 15))
            || matches!(gpr_index(insn.memory_index()), Some(4 | 14 | 15))))
}

fn begin_virt_r14_r15(
    out: &mut Vec<u8>,
    insn: &mut Instruction,
    info_factory: &mut InstructionInfoFactory,
    rewrite_mem: bool,
) -> VirtSpillState {
    if !mentions_r14_or_r15(insn, rewrite_mem) {
        return VirtSpillState {
            rsp_host: None,
            r14_host: None,
            r15_host: None,
        };
    }

    let mut used_mask =
        (1u16 << 0) | (1u16 << 1) | (1u16 << 2) | (1u16 << 4) | (1u16 << 14) | (1u16 << 15);
    for r in info_factory.info(insn).used_registers() {
        if let Some(idx) = gpr_index(r.register()) {
            used_mask |= 1u16 << idx;
        }
    }

    let mut pick_free = || -> usize {
        for cand in [8usize, 9, 10, 11, 12, 13, 3, 5, 6, 7] {
            if (used_mask & (1u16 << cand)) == 0 {
                used_mask |= 1u16 << cand;
                return cand;
            }
        }
        8
    };

    let (mut need_rsp, mut need_r14, mut need_r15) = (false, false, false);
    for i in 0..insn.op_count() {
        if insn.op_kind(i) == OpKind::Register {
            need_rsp |= gpr_index(insn.op_register(i)) == Some(4);
            need_r14 |= gpr_index(insn.op_register(i)) == Some(14);
            need_r15 |= gpr_index(insn.op_register(i)) == Some(15);
        }
    }
    if rewrite_mem {
        for r in [insn.memory_base(), insn.memory_index()] {
            need_rsp |= gpr_index(r) == Some(4);
            need_r14 |= gpr_index(r) == Some(14);
            need_r15 |= gpr_index(r) == Some(15);
        }
    }

    let rsp_host = need_rsp.then(&mut pick_free);
    let r14_host = need_r14.then(&mut pick_free);
    let r15_host = need_r15.then(&mut pick_free);
    if let Some(h) = rsp_host {
        emit_mov_r15_disp32_from_gpr(out, crate::context::CTX_VIRT_RSP_SPILL_OFF as i32, h);
        emit_mov_gpr_from_r15_disp32(out, h, 4 * 8);
    }
    if let Some(h) = r14_host {
        emit_mov_r15_disp32_from_gpr(out, CTX_VIRT_SPILL0_OFF as i32, h);
        emit_mov_gpr_from_r15_disp32(out, h, CTX_GPR_R14_OFF as i32);
    }
    if let Some(h) = r15_host {
        emit_mov_r15_disp32_from_gpr(out, CTX_VIRT_SPILL1_OFF as i32, h);
        emit_mov_gpr_from_r15_disp32(out, h, CTX_GPR_R15_OFF as i32);
    }

    let remap = |r: Register| match gpr_index(r) {
        Some(4) => rsp_host.map(|h| map_reg_width(r, h)),
        Some(14) => r14_host.map(|h| map_reg_width(r, h)),
        Some(15) => r15_host.map(|h| map_reg_width(r, h)),
        _ => None,
    };

    for i in 0..insn.op_count() {
        if insn.op_kind(i) == OpKind::Register
            && let Some(nr) = remap(insn.op_register(i))
        {
            insn.set_op_register(i, nr);
        }
    }
    if rewrite_mem {
        if let Some(nb) = remap(insn.memory_base()) {
            insn.set_memory_base(nb);
        }
        if let Some(ni) = remap(insn.memory_index()) {
            insn.set_memory_index(ni);
        }
    }

    VirtSpillState {
        rsp_host,
        r14_host,
        r15_host,
    }
}

fn end_virt_r14_r15(out: &mut Vec<u8>, state: &VirtSpillState) {
    if let Some(h) = state.rsp_host {
        emit_mov_r15_disp32_from_gpr(out, 4 * 8, h);
        emit_mov_gpr_from_r15_disp32(out, h, crate::context::CTX_VIRT_RSP_SPILL_OFF as i32);
    }
    if let Some(h) = state.r14_host {
        emit_mov_r15_disp32_from_gpr(out, CTX_GPR_R14_OFF as i32, h);
        emit_mov_gpr_from_r15_disp32(out, h, CTX_VIRT_SPILL0_OFF as i32);
    }
    if let Some(h) = state.r15_host {
        emit_mov_r15_disp32_from_gpr(out, CTX_GPR_R15_OFF as i32, h);
        emit_mov_gpr_from_r15_disp32(out, h, CTX_VIRT_SPILL1_OFF as i32);
    }
}

fn map_reg_width(orig: Register, new_gpr: usize) -> Register {
    let number = match orig.size() {
        1 if new_gpr < 4 => Register::AL as usize + new_gpr,
        1 => Register::SPL as usize + new_gpr - 4,
        2 => Register::AX as usize + new_gpr,
        4 => Register::EAX as usize + new_gpr,
        8 => Register::RAX as usize + new_gpr,
        _ => return Register::None,
    };
    match Register::try_from(number) {
        Ok(r) => r,
        Err(_) => Register::None,
    }
}

fn emit_effective_address_into_r14(code: &mut Vec<u8>, insn: &Instruction) {
    if insn.is_ip_rel_memory_operand() {
        emit_movabs(code, 0x49, 0xBE, insn.ip_rel_memory_address());
    } else {
        emit_movabs(code, 0x49, 0xBE, insn.memory_displacement64());
        let (base, index) = (insn.memory_base(), insn.memory_index());
        if base != Register::None {
            emit_load_addr_reg_into_rax(code, base);
            code.extend_from_slice(&[0x49, 0x01, 0xC6]);
        }
        if index != Register::None {
            emit_load_addr_reg_into_rax(code, index);
            let scale_shift: u8 = match insn.memory_index_scale() {
                2 => 1,
                4 => 2,
                8 => 3,
                _ => 0,
            };
            if scale_shift > 0 {
                code.extend_from_slice(&[0x48, 0xC1, 0xE0, scale_shift]);
            }
            code.extend_from_slice(&[0x49, 0x01, 0xC6]);
        }
        if base.size() == 4 || index.size() == 4 {
            code.extend_from_slice(&[0x45, 0x89, 0xF6]);
        }
    }

    let seg_disp = match insn.segment_prefix() {
        Register::FS => Some(CTX_FS_BASE_OFF as i32),
        Register::GS => Some(CTX_GS_BASE_OFF as i32),
        _ => None,
    };
    if let Some(disp) = seg_disp {
        code.extend_from_slice(&[0x4D, 0x03, 0xB7]);
        code.extend_from_slice(&disp.to_le_bytes());
    }
}

fn emit_load_addr_reg_into_rax(code: &mut Vec<u8>, r: Register) {
    match gpr_index(r).unwrap_or(0) {
        0 => emit_mov_gpr_from_r15_disp32(code, 0, CTX_PROBE_SPILL0_OFF as i32),
        1 => emit_mov_gpr_from_r15_disp32(code, 0, CTX_PROBE_SPILL1_OFF as i32),
        4 => emit_mov_gpr_from_r15_disp32(code, 0, 4 * 8),
        14 => emit_mov_gpr_from_r15_disp32(code, 0, CTX_GPR_R14_OFF as i32),
        15 => emit_mov_gpr_from_r15_disp32(code, 0, CTX_GPR_R15_OFF as i32),
        other => {
            let rex = 0x48 | if other >= 8 { 0x04 } else { 0 };
            code.extend_from_slice(&[rex, 0x89, 0xC0 | (((other as u8) & 7) << 3)]);
        }
    }
    if r.size() == 4 {
        code.extend_from_slice(&[0x89, 0xC0]);
    }
}

fn requires_16byte_alignment(insn: &Instruction, size: u8) -> bool {
    if matches!(
        insn.mnemonic(),
        Mnemonic::Movaps
            | Mnemonic::Movapd
            | Mnemonic::Movdqa
            | Mnemonic::Movntps
            | Mnemonic::Movntpd
            | Mnemonic::Movntdq
            | Mnemonic::Movntdqa
    ) {
        return true;
    }
    if size != 16
        || matches!(
            insn.mnemonic(),
            Mnemonic::Movups | Mnemonic::Movupd | Mnemonic::Movdqu | Mnemonic::Lddqu
        )
    {
        return false;
    }
    (0..insn.op_count())
        .any(|i| insn.op_kind(i) == OpKind::Register && insn.op_register(i).is_xmm())
        && matches!(insn.encoding(), iced_x86::EncodingKind::Legacy)
}

fn emit_save_flags_into_ctx(code: &mut Vec<u8>) {
    code.extend_from_slice(&[0x9F, 0x0F, 0x90, 0xC0, 0x41, 0x89, 0x87]);
    code.extend_from_slice(&(CTX_SAVED_LAHF_OFF as i32).to_le_bytes());
}

fn emit_restore_flags_and_rax_rcx(code: &mut Vec<u8>) {
    code.extend_from_slice(&[0x41, 0x8B, 0x87]);
    code.extend_from_slice(&(CTX_SAVED_LAHF_OFF as i32).to_le_bytes());
    code.extend_from_slice(&[0x04, 0x7F, 0x9E]);
    emit_mov_gpr_from_r15_disp32(code, 0, CTX_PROBE_SPILL0_OFF as i32);
    emit_mov_gpr_from_r15_disp32(code, 1, CTX_PROBE_SPILL1_OFF as i32);
}

fn emit_exit_stub(code: &mut Vec<u8>, next_rip: u64, insn_va: u64, reason: u64) {
    for (val, disp) in [
        (next_rip, CTX_RIP_OFF as i32),
        (insn_va, CTX_EXIT_INSN_VA_OFF as i32),
        (reason, CTX_EXIT_REASON_OFF as i32),
    ] {
        emit_movabs(code, 0x49, 0xBE, val);
        emit_mov_r15_disp32_from_gpr(code, disp, 14);
    }
    emit_jmp_r15_disp32(code, CTX_EXIT_TRAMPOLINE_FN_OFF as i32);
}

fn emit_movabs(code: &mut Vec<u8>, rex: u8, op: u8, val: u64) {
    code.extend_from_slice(&[rex, op]);
    code.extend_from_slice(&val.to_le_bytes());
}

fn emit_mov_r15_disp32_from_gpr(code: &mut Vec<u8>, disp: i32, gpr: usize) {
    let rex = 0x49 | if gpr >= 8 { 0x04 } else { 0 };
    code.extend_from_slice(&[rex, 0x89, 0x87 | (((gpr as u8) & 7) << 3)]);
    code.extend_from_slice(&disp.to_le_bytes());
}

fn emit_mov_gpr_from_r15_disp32(code: &mut Vec<u8>, gpr: usize, disp: i32) {
    let rex = 0x49 | if gpr >= 8 { 0x04 } else { 0 };
    code.extend_from_slice(&[rex, 0x8B, 0x87 | (((gpr as u8) & 7) << 3)]);
    code.extend_from_slice(&disp.to_le_bytes());
}

fn emit_jmp_r15_disp32(code: &mut Vec<u8>, disp: i32) {
    code.extend_from_slice(&[0x41, 0xFF, 0xA7]);
    code.extend_from_slice(&disp.to_le_bytes());
}

fn emit_jcc_rel32(code: &mut Vec<u8>, opcode2: u8) -> usize {
    code.extend_from_slice(&[0x0F, opcode2, 0, 0, 0, 0]);
    code.len() - 4
}

fn emit_lea_rcx_rip_rel(code: &mut Vec<u8>) -> usize {
    code.extend_from_slice(&[0x48, 0x8D, 0x0D, 0, 0, 0, 0]);
    code.len() - 4
}

fn patch_rel32(code: &mut [u8], patch_off: usize, target_off: usize) {
    let rel = (target_off as isize - (patch_off + 4) as isize) as i32;
    code[patch_off..patch_off + 4].copy_from_slice(&rel.to_le_bytes());
}
