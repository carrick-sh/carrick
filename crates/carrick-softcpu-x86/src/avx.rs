//! Checked VEX execution. The native leaf sees only private, aligned operands;
//! guest addresses and masked/VSIB accesses are resolved by the software MMU.

use std::mem::offset_of;

use iced_x86::{
    Code, CpuidFeature, Encoder, EncodingKind, Instruction, InstructionInfoFactory, MemoryOperand,
    Mnemonic, OpAccess, OpKind, Register,
};

use crate::context::{
    FxsaveArea, SoftCpuContext, X86Exception, X86ExceptionVector, walk_active_span_aligned,
};
use crate::mmu::{SoftAccessKind, TranslatedTarget};

pub(crate) fn supported(insn: &Instruction) -> bool {
    insn.encoding() == EncodingKind::VEX
        && insn
            .cpuid_features()
            .iter()
            .all(|f| matches!(f, CpuidFeature::AVX | CpuidFeature::AVX2))
        && !matches!(insn.mnemonic(), Mnemonic::Vldmxcsr | Mnemonic::Vstmxcsr)
}

fn masked(insn: &Instruction) -> bool {
    matches!(
        insn.mnemonic(),
        Mnemonic::Vmaskmovps | Mnemonic::Vmaskmovpd | Mnemonic::Vpmaskmovd | Mnemonic::Vpmaskmovq
    )
}

pub(crate) fn needs_leaf(insn: &Instruction) -> bool {
    supported(insn) && !masked(insn) && !insn.is_vsib() && insn.mnemonic() != Mnemonic::Vmaskmovdqu
}

#[repr(C, align(32))]
#[derive(Clone)]
pub(crate) struct Run {
    working: FxsaveArea,
    host: FxsaveArea,
    vectors: [[u8; 32]; 16],
    host_vectors: [[u8; 32]; 16],
    operand: [u8; 32],
    gpr: [u64; 4],
    flags: u64,
    implicit_gprs: [u64; 3],
}

pub(crate) type LeafFn = unsafe extern "sysv64" fn(*mut Run);
pub(crate) struct Leaf {
    pub(crate) _buffer: crate::cpu::JitCodeBuffer,
    pub(crate) execute: LeafFn,
}

pub(crate) fn key(insn: &Instruction) -> Result<Vec<u8>, String> {
    let mut normalized = *insn;
    if insn.op_kinds().any(|k| k == OpKind::Memory) {
        normalized.set_segment_prefix(Register::None);
        normalized.set_memory_base(Register::RSI);
        normalized.set_memory_index(Register::None);
        normalized.set_memory_index_scale(1);
        normalized.set_memory_displacement64(0);
        normalized.set_memory_displ_size(0);
    }
    let mut encoder = Encoder::new(64);
    encoder.encode(&normalized, 0).map_err(|e| e.to_string())?;
    Ok(encoder.take_buffer())
}

fn slot(offset: usize) -> MemoryOperand {
    MemoryOperand::with_base_displ(Register::RDI, offset as i64)
}

/// Immutable, per-encoding leaf; no guest register can name the host stack or
/// the leaf's context pointer. AVX GPR operands are explicit and remapped.
pub(crate) fn image(insn: &Instruction) -> Result<Vec<u8>, String> {
    if !std::is_x86_feature_detected!("avx2") {
        return Err("AVX execution needs an AVX2-capable same-ISA host".into());
    }
    let mut encoder = Encoder::new(64);
    let mut emit = |instruction: Result<Instruction, iced_x86::IcedError>| -> Result<(), String> {
        encoder
            .encode(&instruction.map_err(|e| e.to_string())?, 0)
            .map_err(|e| e.to_string())?;
        Ok(())
    };
    emit(Instruction::with1(
        Code::Fxsave64_m512byte,
        slot(offset_of!(Run, host)),
    ))?;
    for i in 0..16 {
        emit(Instruction::with2(
            Code::VEX_Vmovdqu_ymmm256_ymm,
            slot(offset_of!(Run, host_vectors) + i * 32),
            Register::YMM0 + i as u32,
        ))?;
    }
    emit(Instruction::with1(
        Code::Fxrstor64_m512byte,
        slot(offset_of!(Run, working)),
    ))?;
    for i in 0..16 {
        emit(Instruction::with2(
            Code::VEX_Vmovdqu_ymm_ymmm256,
            Register::YMM0 + i as u32,
            slot(offset_of!(Run, vectors) + i * 32),
        ))?;
    }
    emit(Instruction::with2(
        Code::Lea_r64_m,
        Register::RSI,
        slot(offset_of!(Run, operand)),
    ))?;
    let mut native = *insn;
    for i in 0..insn.op_count() {
        if insn.op_kind(i) == OpKind::Memory {
            native.set_segment_prefix(Register::None);
            native.set_memory_base(Register::RSI);
            native.set_memory_index(Register::None);
            native.set_memory_displacement64(0);
            native.set_memory_displ_size(0);
        } else if insn.op_kind(i) == OpKind::Register && insn.op_register(i).is_gpr() {
            emit(Instruction::with2(
                Code::Mov_r64_rm64,
                Register::R8 + i,
                slot(offset_of!(Run, gpr) + i as usize * 8),
            ))?;
            native.set_op_register(
                i,
                if insn.op_register(i).is_gpr64() {
                    Register::R8 + i
                } else {
                    Register::R8D + i
                },
            );
        }
    }
    for (i, reg) in [Register::RAX, Register::RCX, Register::RDX]
        .into_iter()
        .enumerate()
    {
        emit(Instruction::with2(
            Code::Mov_r64_rm64,
            reg,
            slot(offset_of!(Run, implicit_gprs) + i * 8),
        ))?;
    }
    emit(Ok(native))?;
    if matches!(
        insn.mnemonic(),
        Mnemonic::Vmovntps | Mnemonic::Vmovntpd | Mnemonic::Vmovntdq
    ) {
        emit(Ok(Instruction::with(Code::Sfence)))?;
    }
    for (i, reg) in [Register::RAX, Register::RCX, Register::RDX]
        .into_iter()
        .enumerate()
    {
        emit(Instruction::with2(
            Code::Mov_rm64_r64,
            slot(offset_of!(Run, implicit_gprs) + i * 8),
            reg,
        ))?;
    }
    emit(Ok(Instruction::with(Code::Pushfq)))?;
    emit(Instruction::with1(
        Code::Pop_rm64,
        slot(offset_of!(Run, flags)),
    ))?;
    for i in 0..insn.op_count() {
        if insn.op_kind(i) == OpKind::Register && insn.op_register(i).is_gpr() {
            emit(Instruction::with2(
                Code::Mov_rm64_r64,
                slot(offset_of!(Run, gpr) + i as usize * 8),
                Register::R8 + i,
            ))?;
        }
    }
    for i in 0..16 {
        emit(Instruction::with2(
            Code::VEX_Vmovdqu_ymmm256_ymm,
            slot(offset_of!(Run, vectors) + i * 32),
            Register::YMM0 + i as u32,
        ))?;
    }
    emit(Instruction::with1(
        Code::Fxsave64_m512byte,
        slot(offset_of!(Run, working)),
    ))?;
    emit(Instruction::with1(
        Code::Fxrstor64_m512byte,
        slot(offset_of!(Run, host)),
    ))?;
    for i in 0..16 {
        emit(Instruction::with2(
            Code::VEX_Vmovdqu_ymm_ymmm256,
            Register::YMM0 + i as u32,
            slot(offset_of!(Run, host_vectors) + i * 32),
        ))?;
    }
    emit(Ok(Instruction::with(Code::Retnq)))?;
    Ok(encoder.take_buffer())
}

fn vector(ctx: &SoftCpuContext, index: usize) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..16].copy_from_slice(&ctx.read_xmm(index).to_le_bytes());
    bytes[16..].copy_from_slice(&ctx.ymm_hi128[index * 16..index * 16 + 16]);
    bytes
}

fn set_vector(ctx: &mut SoftCpuContext, index: usize, bytes: &[u8; 32]) {
    let mut lo = [0; 16];
    lo.copy_from_slice(&bytes[..16]);
    ctx.write_xmm(index, u128::from_le_bytes(lo));
    ctx.ymm_hi128[index * 16..index * 16 + 16].copy_from_slice(&bytes[16..]);
}

pub(crate) fn step(
    ctx: &mut SoftCpuContext,
    insn: &Instruction,
    ip: u64,
    leaf: Option<LeafFn>,
) -> Result<(), X86Exception> {
    // SDM Vol. 2 AVX exception class: #UD controls precede #NM and memory.
    if ctx.cr4 & (1 << 18) == 0 || ctx.xcr0 & 6 != 6 {
        return Err(X86Exception::invalid_opcode(ip));
    }
    if ctx.cr0 & 8 != 0 {
        return Err(X86Exception::device_not_available(ip));
    }
    if insn.mnemonic() == Mnemonic::Vmaskmovdqu {
        return crate::context::step_maskmov(ctx, insn, ip);
    }
    if masked(insn) {
        return step_masked(ctx, insn, ip);
    }
    if insn.is_vsib() {
        return step_gather(ctx, insn, ip);
    }
    let leaf = leaf.ok_or_else(|| X86Exception::invalid_opcode(ip))?;
    let mut run = Run {
        working: ctx.fxsave.clone(),
        host: FxsaveArea::default(),
        vectors: std::array::from_fn(|i| vector(ctx, i)),
        host_vectors: [[0; 32]; 16],
        operand: [0; 32],
        gpr: [0; 4],
        flags: 0,
        implicit_gprs: [ctx.gpr[0], ctx.gpr[1], ctx.gpr[2]],
    };
    let original = u32::from_le_bytes(
        ctx.fxsave.0[24..28]
            .try_into()
            .map_err(|_| X86Exception::invalid_opcode(ip))?,
    );
    let mut masked_mxcsr = (original | 0x1f80) & !0x3f;
    if original & (1 << 11) == 0 {
        masked_mxcsr &= !(1 << 15);
    }
    run.working.0[24..28].copy_from_slice(&masked_mxcsr.to_le_bytes());
    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(insn);
    let mut memory = None;
    for i in 0..insn.op_count() {
        if insn.op_kind(i) == OpKind::Register && insn.op_register(i).is_gpr() {
            run.gpr[i as usize] = crate::context::read_reg_sized(ctx, insn.op_register(i)).0;
        }
        if insn.op_kind(i) == OpKind::Memory {
            let va = crate::cflow::compute_effective_va(insn, ctx);
            let size = insn.memory_size().size();
            if size > 32 {
                return Err(X86Exception::invalid_opcode(ip));
            }
            if matches!(
                insn.mnemonic(),
                Mnemonic::Vmovaps
                    | Mnemonic::Vmovapd
                    | Mnemonic::Vmovdqa
                    | Mnemonic::Vmovntps
                    | Mnemonic::Vmovntpd
                    | Mnemonic::Vmovntdq
                    | Mnemonic::Vmovntdqa
            ) && va & (size as u64 - 1) != 0
            {
                return Err(X86Exception::general_protection(ip, 0));
            }
            let write = info.op_access(i) == OpAccess::Write;
            transfer(
                ctx,
                va,
                &mut run.operand[..size],
                write,
                false,
                ip,
                size <= 8,
            )?;
            memory = Some((va, size, write));
        }
    }
    // FTZ changes the masked response to *all* tiny arithmetic results,
    // including exact intermediate products in DPPS/DPPD. A second private
    // evaluation supplies UE when guest UM is unmasked; it publishes no data.
    // Unlike inspecting final lanes, this also detects cancellation to zero.
    let mut underflow_probe = if original & (1 << 11) == 0 {
        Some(run.clone())
    } else {
        None
    };
    // SAFETY: image remaps every explicit address/GPR, masks FP exceptions,
    // saves/restores host vectors and publishes a leaf only on an AVX2 host.
    unsafe {
        leaf(&mut run);
    }
    let mut status = u32::from_le_bytes(
        run.working.0[24..28]
            .try_into()
            .map_err(|_| X86Exception::invalid_opcode(ip))?,
    ) & 0x3f;
    if let Some(probe) = &mut underflow_probe {
        probe.working.0[24..28].copy_from_slice(&(masked_mxcsr | (1 << 15)).to_le_bytes());
        // SAFETY: same admitted leaf and private operand storage as above.
        unsafe {
            leaf(probe);
        }
        status |= u32::from(probe.working.0[24] & (1 << 4));
    }
    let mxcsr = original | status;
    if status & !(original >> 7) & 0x3f != 0 {
        ctx.fxsave.0[24..28].copy_from_slice(&mxcsr.to_le_bytes());
        return Err(if ctx.cr4 & (1 << 10) != 0 {
            X86Exception::new(X86ExceptionVector::SimdFloatingPoint, ip, None, None)
        } else {
            X86Exception::invalid_opcode(ip)
        });
    }
    if let Some((va, size, true)) = memory {
        transfer(ctx, va, &mut run.operand[..size], true, true, ip, size <= 8)?;
    }
    for i in 0..16 {
        set_vector(ctx, i, &run.vectors[i]);
    }
    for i in 0..insn.op_count() {
        if insn.op_kind(i) == OpKind::Register
            && insn.op_register(i).is_gpr()
            && matches!(info.op_access(i), OpAccess::Write | OpAccess::ReadWrite)
        {
            crate::context::write_reg_sized(ctx, insn.op_register(i), run.gpr[i as usize]);
        }
    }
    if matches!(
        insn.mnemonic(),
        Mnemonic::Vpcmpestri | Mnemonic::Vpcmpestri64 | Mnemonic::Vpcmpistri
    ) {
        ctx.gpr[crate::context::reg::RCX] = run.implicit_gprs[1];
    }
    // V(U)COMI and VTEST/VPTEST define the six arithmetic flags.
    let flags = if insn.rflags_modified() != 0 {
        0x8d5
    } else {
        0
    };
    ctx.rflags = (ctx.rflags & !flags) | (run.flags & flags);
    ctx.fxsave.0[24..28].copy_from_slice(&mxcsr.to_le_bytes());
    Ok(())
}

fn transfer(
    ctx: &mut SoftCpuContext,
    va: u64,
    bytes: &mut [u8],
    write: bool,
    commit: bool,
    ip: u64,
    alignment_check: bool,
) -> Result<(), X86Exception> {
    walk_active_span_aligned(
        ctx,
        va,
        bytes.len(),
        if write {
            SoftAccessKind::Write
        } else {
            SoftAccessKind::Read
        },
        ip,
        alignment_check,
        |ctx, off, target, n| {
            if write && !commit {
                return;
            }
            match target {
                TranslatedTarget::Ram(ptr) => {
                    // SAFETY: walk_active_span authenticated the entire operand before this pass.
                    unsafe {
                        if write {
                            std::ptr::copy_nonoverlapping(bytes[off..].as_ptr(), ptr, n);
                        } else {
                            std::ptr::copy_nonoverlapping(ptr, bytes[off..].as_mut_ptr(), n);
                        }
                    }
                }
                TranslatedTarget::LapicMmio { offset } => {
                    if write {
                        ctx.lapic_mmio_write(offset, &bytes[off..off + n]);
                    } else {
                        bytes[off..off + n].copy_from_slice(&ctx.lapic_mmio_read(offset, n)[..n]);
                    }
                }
            }
        },
    )
}

fn step_masked(ctx: &mut SoftCpuContext, insn: &Instruction, ip: u64) -> Result<(), X86Exception> {
    let store = insn.op0_kind() == OpKind::Memory;
    let data_reg = if store {
        insn.op2_register()
    } else {
        insn.op0_register()
    };
    let size = data_reg.size();
    let width = if matches!(insn.mnemonic(), Mnemonic::Vmaskmovpd | Mnemonic::Vpmaskmovq) {
        8
    } else {
        4
    };
    let mask = vector(ctx, insn.op1_register().number());
    let mut data = if store {
        vector(ctx, data_reg.number())
    } else {
        [0; 32]
    };
    let base = crate::cflow::compute_effective_va(insn, ctx);
    // Validate all selected lanes before a store. Masked-off lanes have no
    // address access, including at noncanonical/unmapped page boundaries.
    for commit in [false, true] {
        for off in (0..size).step_by(width) {
            if mask[off + width - 1] & 0x80 != 0 {
                transfer(
                    ctx,
                    base.wrapping_add(off as u64),
                    &mut data[off..off + width],
                    store,
                    commit,
                    ip,
                    false,
                )?;
            }
        }
        if !store {
            break;
        }
    }
    if !store {
        set_vector(ctx, data_reg.number(), &data);
    }
    Ok(())
}

fn step_gather(ctx: &mut SoftCpuContext, insn: &Instruction, ip: u64) -> Result<(), X86Exception> {
    let dest = insn.op0_register();
    let mask_reg = insn.op2_register();
    let index_reg = insn.memory_index();
    let index_width = if insn.is_vsib64() { 8 } else { 4 };
    let width = insn.memory_size().size();
    let lanes = (dest.size() / width).min(index_reg.size() / index_width);
    let indices = vector(ctx, index_reg.number());
    let mut data = vector(ctx, dest.number());
    let mut mask = vector(ctx, mask_reg.number());
    let mut address = *insn;
    address.set_memory_index(Register::None);
    address.set_segment_prefix(Register::None);
    let base = crate::cflow::compute_effective_va(&address, ctx);
    // SDM VGATHER: completed lanes and mask progress survive a later fault.
    // The excess destination and mask lanes are zeroed even on partial completion.
    data[lanes * width..].fill(0);
    mask[lanes * width..].fill(0);
    for lane in mask[..lanes * width].chunks_exact_mut(width) {
        lane.fill(if lane[width - 1] & 0x80 != 0 { 0xff } else { 0 });
    }
    set_vector(ctx, dest.number(), &data);
    set_vector(ctx, mask_reg.number(), &mask);
    for lane in 0..lanes {
        let off = lane * width;
        if mask[off + width - 1] & 0x80 == 0 {
            continue;
        }
        let mut raw = [0; 8];
        raw[..index_width].copy_from_slice(&indices[lane * index_width..(lane + 1) * index_width]);
        let index = if index_width == 4 {
            i64::from(i32::from_le_bytes(
                raw[..4]
                    .try_into()
                    .map_err(|_| X86Exception::invalid_opcode(ip))?,
            )) as u64
        } else {
            u64::from_le_bytes(raw)
        };
        let mut va = base.wrapping_add(index.wrapping_mul(u64::from(insn.memory_index_scale())));
        if insn.memory_base().is_gpr32()
            || (insn.memory_base() == Register::None && insn.memory_displ_size() == 4)
        {
            va = u64::from(va as u32);
        }
        va = va.wrapping_add(match insn.segment_prefix() {
            Register::FS => ctx.fs_base(),
            Register::GS => ctx.gs_base(),
            _ => 0,
        });
        transfer(
            ctx,
            va,
            &mut data[off..off + width],
            false,
            false,
            ip,
            false,
        )?;
        mask[off..off + width].fill(0);
        set_vector(ctx, dest.number(), &data);
        set_vector(ctx, mask_reg.number(), &mask);
    }
    // On successful completion all mask bits are cleared, including inactive lanes.
    mask.fill(0);
    set_vector(ctx, mask_reg.number(), &mask);
    Ok(())
}
