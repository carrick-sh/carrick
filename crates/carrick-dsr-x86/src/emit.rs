//! Minimal x86_64 block emitter: copy-through + RIP-relative rewrite + typed
//! exit branches.
//!
//! For a translated block, the Copy-class instructions are emitted VERBATIM
//! and the terminator is replaced by an indirect branch to the matching
//! gateway exit stub — `jmp *disp(%r15)` where `disp` is the stub's address
//! offset in the [`X86DsrContext`](crate::gateway::X86DsrContext) (r15 is the
//! context pointer during translated execution). The indirect-through-context
//! form is used because the JIT region and the gateway `.text` can be more
//! than 2 GiB apart (a `rel32` branch cannot reach) and it clobbers no guest
//! register.
//!
//! Two instruction shapes cannot copy through, and both rewrite against the
//! context using the same scratch-spill machinery (placement-independent by
//! design — the JIT cache may sit anywhere; emitted bytes never depend on
//! where the block lands):
//!
//! - **RIP-relative operands** would compute their address against the
//!   JIT-cache RIP, not the guest VA. In the native model a guest VA IS a
//!   host VA, so the rewrite materializes the ABSOLUTE target:
//!   `lea r64/r32, [rip+disp]` becomes `mov r, imm` of the VA; anything else
//!   spills a free GPR to the context
//!   [`scratch`](crate::gateway::X86DsrContext::scratch) slot, materializes
//!   the target in it, and re-encodes the instruction with it as base.
//! - **Guest `%r15`** is virtualized (the live r15 is the context pointer).
//!   An instruction touching it gets r15 RENAMED to a spilled scratch GPR
//!   that is loaded from the snapshot's r15 slot first and stored back if
//!   the instruction writes it.
//!
//! One instruction can need both (e.g. `mov r15, [rip+d]`) — then two
//! scratches spill to the two context slots. Every bracketing operation is a
//! `mov`, so guest rflags pass through untouched; the rewritten
//! instruction's own flag effects are exactly the guest's.

use iced_x86::{
    Code, Decoder, DecoderOptions, Encoder, Instruction, InstructionInfoFactory, MemoryOperand,
    Mnemonic, OpAccess, OpKind, Register,
};

use crate::block::{X86Block, X86Exit};
use crate::gateway::{
    CTX_EXIT_INDIRECT_ADDR, CTX_EXIT_SENSITIVE_ADDR, CTX_EXIT_SYSCALL_ADDR, CTX_SCRATCH,
    CTX_SCRATCH2, SNAP_GUEST_R15,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EmitError {
    #[error("x86 emit: source block bytes ({got}) shorter than the copy-through region ({need})")]
    ShortSource { need: usize, got: usize },
    #[error("x86 emit: terminator {0} is not lowered yet")]
    Unsupported(&'static str),
    #[error("x86 emit: planned instruction at guest VA 0x{va:x} no longer decodes")]
    Undecodable { va: u64 },
    #[error("x86 emit: no free scratch GPR for the rewrite at guest VA 0x{va:x}")]
    NoScratch { va: u64 },
    #[error("x86 emit: re-encoding the rewritten instruction at guest VA 0x{va:x} failed")]
    Reencode { va: u64 },
}

/// The `jmp *disp32(%r15)` encoding for an exit stub whose address lives at
/// `disp` bytes into the context: REX.B (0x41) + FF /4 + ModRM(mod=10,
/// reg=100, rm=111=r15) + disp32 (little-endian).
fn jmp_indirect_r15(disp: i32) -> [u8; 7] {
    let d = disp.to_le_bytes();
    [0x41, 0xFF, 0xA7, d[0], d[1], d[2], d[3]]
}

/// Emit the translated bytes for `block`. `source` is the guest bytes for
/// `[block.start, block.end)`. Returns the JIT-ready byte sequence: the
/// caller copies it through the JIT region's RW alias and sets the context's
/// `entry` to the corresponding exec VA. The bytes are placement-independent
/// (no field depends on where in the cache they land).
pub fn emit_block(source: &[u8], block: &X86Block) -> Result<Vec<u8>, EmitError> {
    match block.exit {
        X86Exit::Syscall { va, .. } => {
            let mut out = emit_copy_body(source, block, va)?;
            out.extend_from_slice(&jmp_indirect_r15(CTX_EXIT_SYSCALL_ADDR));
            Ok(out)
        }
        X86Exit::ControlFlow { va, .. } => {
            // Copy the straight-line body up to (not including) the branch,
            // then exit to Rust, which resolves the target from the captured
            // guest state (see `cflow::resolve`). The branch itself is not
            // executed on the host — its semantics are applied in Rust.
            let mut out = emit_copy_body(source, block, va)?;
            out.extend_from_slice(&jmp_indirect_r15(CTX_EXIT_INDIRECT_ADDR));
            Ok(out)
        }
        X86Exit::Sensitive { va, .. } => {
            // The sensitive instruction itself is NOT emitted: the body runs,
            // then the sensitive stub returns to Rust, which services the
            // instruction from the block's typed `kind` (rdtsc/cpuid/
            // fsgsbase/gs-access) against the snapshot and re-enters after
            // it. The caller pre-fills `exit_resume` with the instruction's
            // VA so the run loop knows where servicing starts.
            let mut out = emit_copy_body(source, block, va)?;
            out.extend_from_slice(&jmp_indirect_r15(CTX_EXIT_SENSITIVE_ADDR));
            Ok(out)
        }
        X86Exit::Unsupported { .. } => Err(EmitError::Unsupported("unsupported-instruction")),
        X86Exit::Continue { target, .. } => {
            // A structural boundary (page end / instruction cap), not a real
            // terminator: every planned instruction emits, then execution
            // exits through the indirect stub. The caller pre-fills
            // `exit_resume` with `target`, so the captured snapshot resumes
            // at the continuation VA.
            let mut out = emit_copy_body(source, block, target)?;
            out.extend_from_slice(&jmp_indirect_r15(CTX_EXIT_INDIRECT_ADDR));
            Ok(out)
        }
    }
}

/// Emit every planned Copy instruction of `block` whose VA precedes
/// `terminator_va`: verbatim copy for position-independent instructions,
/// absolute-address rewrite for RIP-relative ones.
fn emit_copy_body(
    source: &[u8],
    block: &X86Block,
    terminator_va: u64,
) -> Result<Vec<u8>, EmitError> {
    let copy_len = (terminator_va - block.start) as usize;
    if source.len() < copy_len {
        return Err(EmitError::ShortSource {
            need: copy_len,
            got: source.len(),
        });
    }
    let mut out = Vec::with_capacity(copy_len + 7);
    for planned in &block.instructions {
        let off = (planned.va - block.start) as usize;
        let bytes = &source[off..off + planned.len as usize];
        emit_one(bytes, planned.va, &mut out)?;
    }
    Ok(out)
}

/// How one instruction touches virtualized guest `%r15`.
struct R15Use {
    written: bool,
}

/// Emit one Copy-class instruction: verbatim unless it has a RIP-relative
/// memory operand (rewrite against the absolute guest VA) or touches
/// virtualized guest r15 (rename it to a scratch backed by the snapshot).
fn emit_one(bytes: &[u8], va: u64, out: &mut Vec<u8>) -> Result<(), EmitError> {
    let mut decoder = Decoder::with_ip(64, bytes, va, DecoderOptions::NONE);
    let inst: Instruction = decoder.decode();
    if inst.is_invalid() {
        return Err(EmitError::Undecodable { va });
    }
    let ip_rel = inst.is_ip_rel_memory_operand();
    let r15_use = r15_usage(&inst);
    if !ip_rel && r15_use.is_none() {
        out.extend_from_slice(bytes);
        return Ok(());
    }

    // `lea` (not involving r15) never touches memory or flags — it IS an
    // address computation, so it lowers to a plain immediate load of the
    // absolute VA the access resolves to (guest VA == host VA natively).
    if ip_rel && r15_use.is_none() && inst.mnemonic() == Mnemonic::Lea {
        let target = inst.ip_rel_memory_address();
        let dst = inst.op0_register();
        if dst.size() == 8 {
            let mov = Instruction::with2(Code::Mov_r64_imm64, dst, target)
                .map_err(|_| EmitError::Reencode { va })?;
            return encode_into(&mov, va, out);
        }
        if dst.size() == 4 {
            // 32-bit lea truncates the address; mov r32, imm32 matches that
            // (and zero-extends to 64 bits, exactly like lea r32 does).
            let mov = Instruction::with2(Code::Mov_r32_imm32, dst, target as u32)
                .map_err(|_| EmitError::Reencode { va })?;
            return encode_into(&mov, va, out);
        }
        // 16-bit lea is exotic; the generic rewrite below handles it (the
        // re-encoded `lea r16, [scratch]` keeps the truncation semantics).
    }

    // Generic rewrite. Spill up to two scratch GPRs the instruction does not
    // use: `rename` stands in for guest r15 (loaded from the snapshot slot,
    // stored back if written), `base` holds the materialized RIP-relative
    // target. All bracketing operations are `mov`s — guest rflags pass
    // through untouched; the instruction's own flag writes are guest
    // semantics.
    let mut scratches = ScratchAllocator::for_instruction(&inst);
    let spill_slots = [CTX_SCRATCH, CTX_SCRATCH2];
    let mut spilled: Vec<(Register, i32)> = Vec::new();
    let mut rewritten = inst;

    let rename = if r15_use.is_some() {
        let s = scratches.take().ok_or(EmitError::NoScratch { va })?;
        let slot = spill_slots[spilled.len()];
        spilled.push((s, slot));
        Some(s)
    } else {
        None
    };
    let base = if ip_rel {
        let s = scratches.take().ok_or(EmitError::NoScratch { va })?;
        let slot = spill_slots[spilled.len()];
        spilled.push((s, slot));
        Some(s)
    } else {
        None
    };

    // Saves (and loads) in allocation order.
    for &(reg, slot) in &spilled {
        let spill = MemoryOperand::with_base_displ(Register::R15, i64::from(slot));
        let save = Instruction::with2(Code::Mov_rm64_r64, spill, reg)
            .map_err(|_| EmitError::Reencode { va })?;
        encode_into(&save, va, out)?;
    }
    if let Some(rename) = rename {
        let snap = MemoryOperand::with_base_displ(Register::R15, i64::from(SNAP_GUEST_R15));
        let load = Instruction::with2(Code::Mov_r64_rm64, rename, snap)
            .map_err(|_| EmitError::Reencode { va })?;
        encode_into(&load, va, out)?;
        rename_r15(&mut rewritten, rename);
    }
    if let Some(base) = base {
        let target = inst.ip_rel_memory_address();
        let load = Instruction::with2(Code::Mov_r64_imm64, base, target)
            .map_err(|_| EmitError::Reencode { va })?;
        encode_into(&load, va, out)?;
        rewritten.set_memory_base(base);
        rewritten.set_memory_displ_size(0);
        rewritten.set_memory_displacement64(0);
    }

    encode_into(&rewritten, va, out)?;

    if let (Some(rename), Some(R15Use { written: true })) = (rename, &r15_use) {
        let snap = MemoryOperand::with_base_displ(Register::R15, i64::from(SNAP_GUEST_R15));
        let store = Instruction::with2(Code::Mov_rm64_r64, snap, rename)
            .map_err(|_| EmitError::Reencode { va })?;
        encode_into(&store, va, out)?;
    }
    // Restores in reverse allocation order.
    for &(reg, slot) in spilled.iter().rev() {
        let spill = MemoryOperand::with_base_displ(Register::R15, i64::from(slot));
        let restore = Instruction::with2(Code::Mov_r64_rm64, reg, spill)
            .map_err(|_| EmitError::Reencode { va })?;
        encode_into(&restore, va, out)?;
    }
    Ok(())
}

/// Replace every appearance of (any width of) r15 in the instruction's
/// operands with the same-width form of `scratch`: explicit register
/// operands, and the memory base/index registers.
fn rename_r15(inst: &mut Instruction, scratch: Register) {
    for i in 0..inst.op_count() {
        if inst.op_kind(i) == OpKind::Register {
            let r = inst.op_register(i);
            if r.full_register() == Register::R15 {
                inst.set_op_register(i, sized_gpr(scratch, r.size()));
            }
        }
    }
    if inst.memory_base().full_register() == Register::R15 {
        inst.set_memory_base(sized_gpr(scratch, inst.memory_base().size()));
    }
    if inst.memory_index().full_register() == Register::R15 {
        inst.set_memory_index(sized_gpr(scratch, inst.memory_index().size()));
    }
}

fn encode_into(inst: &Instruction, va: u64, out: &mut Vec<u8>) -> Result<(), EmitError> {
    let mut encoder = Encoder::new(64);
    // Every instruction encoded here is position-independent (no RIP-relative
    // operands remain), so the IP argument is immaterial; 0 keeps that honest.
    encoder
        .encode(inst, 0)
        .map_err(|_| EmitError::Reencode { va })?;
    out.extend_from_slice(&encoder.take_buffer());
    Ok(())
}

/// How the instruction touches (any width of) virtualized guest `%r15` —
/// `None` when it doesn't. Implicit uses are included via
/// `InstructionInfoFactory` (no x86 instruction uses r15 implicitly today,
/// but the factory keeps that assumption honest).
fn r15_usage(inst: &Instruction) -> Option<R15Use> {
    let mut info = InstructionInfoFactory::new();
    let mut found = false;
    let mut written = false;
    for r in info.info(inst).used_registers() {
        if r.register().full_register() == Register::R15 {
            found = true;
            written |= matches!(
                r.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            );
        }
    }
    found.then_some(R15Use { written })
}

/// The scratch candidates for rewrites. `rsp`/`rbp` are excluded
/// (frame/stack semantics and ModRM special cases buy nothing); `r15` is the
/// context register. Any instruction references at most a handful of GPRs,
/// so enough free candidates always exist in practice.
const SCRATCH_CANDIDATES: [Register; 13] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RBX,
    Register::RSI,
    Register::RDI,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
    Register::R12,
    Register::R13,
    Register::R14,
];

/// Hands out scratch GPRs the instruction does not reference (implicit
/// registers included), each at most once.
struct ScratchAllocator {
    used: Vec<Register>,
    next: usize,
}

impl ScratchAllocator {
    fn for_instruction(inst: &Instruction) -> Self {
        let mut info = InstructionInfoFactory::new();
        let used = info
            .info(inst)
            .used_registers()
            .iter()
            .map(|r| r.register().full_register())
            .collect();
        Self { used, next: 0 }
    }

    fn take(&mut self) -> Option<Register> {
        while self.next < SCRATCH_CANDIDATES.len() {
            let candidate = SCRATCH_CANDIDATES[self.next];
            self.next += 1;
            if !self.used.contains(&candidate) {
                return Some(candidate);
            }
        }
        None
    }
}

/// The `size`-byte form of a 64-bit scratch candidate (e.g. RCX → ECX/CX/CL).
/// Only the low 8-bit forms appear (r15's 8-bit form is low, so a rename
/// never needs AH-class registers).
fn sized_gpr(full: Register, size: usize) -> Register {
    use Register::*;
    let row: [Register; 4] = match full {
        RAX => [RAX, EAX, AX, AL],
        RCX => [RCX, ECX, CX, CL],
        RDX => [RDX, EDX, DX, DL],
        RBX => [RBX, EBX, BX, BL],
        RSI => [RSI, ESI, SI, SIL],
        RDI => [RDI, EDI, DI, DIL],
        R8 => [R8, R8D, R8W, R8L],
        R9 => [R9, R9D, R9W, R9L],
        R10 => [R10, R10D, R10W, R10L],
        R11 => [R11, R11D, R11W, R11L],
        R12 => [R12, R12D, R12W, R12L],
        R13 => [R13, R13D, R13W, R13L],
        R14 => [R14, R14D, R14W, R14L],
        other => return other,
    };
    match size {
        8 => row[0],
        4 => row[1],
        2 => row[2],
        1 => row[3],
        _ => row[0],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::plan_block;

    const BASE: u64 = 0x40_0000;

    fn plan_and_emit(img: &[u8]) -> Vec<u8> {
        let reader = |va: u64| {
            let off = (va - BASE) as usize;
            img.get(off..).map(|s| s.to_vec()).unwrap_or_default()
        };
        let block = plan_block(BASE, 256, 4096, reader).expect("plan");
        emit_block(img, &block).expect("emit")
    }

    #[test]
    fn syscall_block_copies_body_then_branches() {
        // mov eax,60 (b8 3c 00 00 00); syscall (0f 05)
        static IMG: &[u8] = &[0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05];
        let out = plan_and_emit(IMG);
        // 5 body bytes + 7-byte indirect jmp; the syscall (0f 05) is dropped.
        assert_eq!(&out[..5], &IMG[..5]);
        assert_eq!(out.len(), 5 + 7);
        assert_eq!(out[5], 0x41, "REX.B prefix of the exit jmp");
        assert_eq!(out[6], 0xFF, "jmp near indirect opcode");
    }

    #[test]
    fn control_flow_lowers_to_the_indirect_exit() {
        // nop (90); jmp +0 (eb 00) — one copy byte, then the branch exit.
        static IMG: &[u8] = &[0x90, 0xeb, 0x00];
        let out = plan_and_emit(IMG);
        // 1 copied body byte (the nop) + the 7-byte indirect exit; the branch
        // (eb 00) is dropped — Rust resolves the target.
        assert_eq!(&out[..1], &[0x90]);
        assert_eq!(out.len(), 1 + 7);
        assert_eq!(out[1], 0x41, "REX.B prefix of the exit jmp");
    }

    #[test]
    fn rip_relative_lea_becomes_absolute_mov() {
        // lea rsi, [rip+0x10] (48 8d 35 10 00 00 00); syscall
        static IMG: &[u8] = &[0x48, 0x8d, 0x35, 0x10, 0x00, 0x00, 0x00, 0x0f, 0x05];
        let out = plan_and_emit(IMG);
        // movabs rsi, imm64 (48 be + 8 bytes) replaces the 7-byte lea.
        assert_eq!(&out[..2], &[0x48, 0xbe], "movabs rsi opcode");
        let target = BASE + 7 + 0x10; // rip after the lea + disp
        assert_eq!(&out[2..10], &target.to_le_bytes(), "absolute guest VA");
        assert_eq!(out.len(), 10 + 7, "movabs + exit jmp only");
    }

    #[test]
    fn rip_relative_lea32_becomes_absolute_mov32() {
        // lea esi, [rip+0x10] (8d 35 10 00 00 00); syscall
        static IMG: &[u8] = &[0x8d, 0x35, 0x10, 0x00, 0x00, 0x00, 0x0f, 0x05];
        let out = plan_and_emit(IMG);
        // mov esi, imm32 (be + 4 bytes): lea r32 truncates; so does this.
        assert_eq!(out[0], 0xbe, "mov esi, imm32 opcode");
        let target = (BASE + 6 + 0x10) as u32;
        assert_eq!(&out[1..5], &target.to_le_bytes(), "truncated guest VA");
    }

    #[test]
    fn rip_relative_load_rewrites_through_a_scratch_register() {
        // mov edx, [rip+0x20] (8b 15 20 00 00 00); syscall
        static IMG: &[u8] = &[0x8b, 0x15, 0x20, 0x00, 0x00, 0x00, 0x0f, 0x05];
        let out = plan_and_emit(IMG);
        let target = BASE + 6 + 0x20;
        // Expected shape (scratch = rax, first candidate not used by the mov):
        //   49 89 87 f8 02 00 00   mov [r15+CTX_SCRATCH], rax
        //   48 b8 <target>         movabs rax, target
        //   8b 10                  mov edx, [rax]
        //   49 8b 87 f8 02 00 00   mov rax, [r15+CTX_SCRATCH]
        let spill_disp = (CTX_SCRATCH as u32).to_le_bytes();
        assert_eq!(&out[..3], &[0x49, 0x89, 0x87], "spill rax to ctx scratch");
        assert_eq!(&out[3..7], &spill_disp, "scratch slot displacement");
        assert_eq!(&out[7..9], &[0x48, 0xb8], "movabs rax, target");
        assert_eq!(&out[9..17], &target.to_le_bytes());
        assert_eq!(&out[17..19], &[0x8b, 0x10], "mov edx, [rax]");
        assert_eq!(&out[19..22], &[0x49, 0x8b, 0x87], "restore rax");
        assert_eq!(&out[22..26], &spill_disp);
        assert_eq!(out.len(), 26 + 7, "rewrite + exit jmp");
    }

    #[test]
    fn scratch_selection_avoids_registers_the_instruction_uses() {
        // mov eax, [rip+0x20] (8b 05 20 00 00 00) — rax is the destination,
        // so the scratch must skip it (rcx is next); syscall terminator.
        static IMG: &[u8] = &[0x8b, 0x05, 0x20, 0x00, 0x00, 0x00, 0x0f, 0x05];
        let out = plan_and_emit(IMG);
        // 49 89 8f — mov [r15+disp32], rcx (ModRM reg=001).
        assert_eq!(&out[..3], &[0x49, 0x89, 0x8f], "spills rcx, not rax");
        // Rewritten load: mov eax, [rcx] = 8b 01.
        assert_eq!(&out[17..19], &[0x8b, 0x01]);
    }

    #[test]
    fn rip_relative_store_and_rmw_rewrite_too() {
        // add dword [rip+0x30], 1 (83 05 30 00 00 00 01) — a memory RMW whose
        // own flag writes are guest semantics; the bracketing movs must not
        // add any. syscall terminator.
        static IMG: &[u8] = &[0x83, 0x05, 0x30, 0x00, 0x00, 0x00, 0x01, 0x0f, 0x05];
        let out = plan_and_emit(IMG);
        let target = BASE + 7 + 0x30;
        // movabs rax, target present with the absolute VA.
        let needle = {
            let mut v = vec![0x48, 0xb8];
            v.extend_from_slice(&target.to_le_bytes());
            v
        };
        assert!(
            out.windows(needle.len()).any(|w| w == needle),
            "materializes the absolute target"
        );
        // Rewritten RMW: add dword [rax], 1 = 83 00 01.
        assert!(
            out.windows(3).any(|w| w == [0x83, 0x00, 0x01]),
            "re-encoded RMW against the scratch base"
        );
    }

    #[test]
    fn continue_exit_emits_body_and_indirect_exit() {
        // Three nops with a 2-instruction cap: a structural Continue, not a
        // terminator. The body emits and control exits via the indirect stub
        // (exit_resume carries the continuation VA at run time).
        static IMG: &[u8] = &[0x90, 0x90, 0x90];
        let reader = |va: u64| {
            let off = (va - BASE) as usize;
            IMG.get(off..).map(|s| s.to_vec()).unwrap_or_default()
        };
        let block = plan_block(BASE, 2, 4096, reader).expect("plan");
        assert!(matches!(block.exit, X86Exit::Continue { .. }));
        let out = emit_block(IMG, &block).expect("emit");
        assert_eq!(&out[..2], &[0x90, 0x90], "both capped instructions emit");
        assert_eq!(out.len(), 2 + 7);
        assert_eq!(out[2], 0x41, "REX.B prefix of the indirect exit jmp");
    }

    #[test]
    fn r15_read_renames_to_a_scratch_loaded_from_the_snapshot() {
        // mov rax, r15 (4c 89 f8); syscall — reads guest r15 only.
        static IMG: &[u8] = &[0x4c, 0x89, 0xf8, 0x0f, 0x05];
        let out = plan_and_emit(IMG);
        let spill = (CTX_SCRATCH as u32).to_le_bytes();
        // Scratch skips rax (used) -> rcx. The snapshot r15 slot (offset 120)
        // fits a disp8, so the encoder uses the short form there.
        //   49 89 8f <CTX_SCRATCH>   mov [r15+scratch], rcx   (disp32)
        //   49 8b 4f 78              mov rcx, [r15+gpr15]     (guest r15)
        //   48 89 c8                 mov rax, rcx             (renamed)
        //   49 8b 8f <CTX_SCRATCH>   mov rcx, [r15+scratch]   (restore)
        assert_eq!(&out[..3], &[0x49, 0x89, 0x8f], "spill rcx");
        assert_eq!(&out[3..7], &spill);
        assert_eq!(
            &out[7..11],
            &[0x49, 0x8b, 0x4f, SNAP_GUEST_R15 as u8],
            "load guest r15"
        );
        assert_eq!(&out[11..14], &[0x48, 0x89, 0xc8], "mov rax, rcx");
        assert_eq!(&out[14..17], &[0x49, 0x8b, 0x8f], "restore rcx");
        assert_eq!(&out[17..21], &spill);
        assert_eq!(out.len(), 21 + 7, "no store-back for a pure read");
    }

    #[test]
    fn r15_write_stores_back_to_the_snapshot() {
        // mov r15, rax (49 89 c7); syscall — writes guest r15.
        static IMG: &[u8] = &[0x49, 0x89, 0xc7, 0x0f, 0x05];
        let out = plan_and_emit(IMG);
        // rcx is the rename; after `mov rcx, rax` the result goes back:
        //   49 89 4f 78    mov [r15+gpr15], rcx   (disp8 — slot 120)
        let needle = vec![0x49, 0x89, 0x4f, SNAP_GUEST_R15 as u8];
        // The store-back must appear AFTER the renamed mov (48 89 c1).
        let renamed_at = out
            .windows(3)
            .position(|w| w == [0x48, 0x89, 0xc1])
            .expect("renamed mov rcx, rax present");
        let store_at = out
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("store-back to the snapshot r15 slot present");
        assert!(store_at > renamed_at, "store-back follows the instruction");
    }

    #[test]
    fn r15_and_rip_relative_in_one_instruction_use_two_scratches() {
        // mov r15, [rip+0x40] (4c 8b 3d 40 00 00 00); syscall
        static IMG: &[u8] = &[0x4c, 0x8b, 0x3d, 0x40, 0x00, 0x00, 0x00, 0x0f, 0x05];
        let out = plan_and_emit(IMG);
        let target = BASE + 7 + 0x40;
        // The instruction leaves rax/rcx free, so rename = rax (CTX_SCRATCH)
        // and base = rcx (CTX_SCRATCH2) — both spill slots in play.
        let spill2 = (CTX_SCRATCH2 as u32).to_le_bytes();
        assert!(
            out.windows(7)
                .any(|w| w[..3] == [0x49, 0x89, 0x8f] && w[3..] == spill2),
            "second scratch (rcx) spills to CTX_SCRATCH2"
        );
        // movabs rcx, target materializes the absolute VA in the base scratch.
        let mut movabs = vec![0x48, 0xb9];
        movabs.extend_from_slice(&target.to_le_bytes());
        assert!(
            out.windows(movabs.len()).any(|w| w == movabs),
            "absolute target lands in the base scratch"
        );
        // The renamed, rebased load: mov rax, [rcx] = 48 8b 01.
        assert!(
            out.windows(3).any(|w| w == [0x48, 0x8b, 0x01]),
            "rewritten load uses rename dest + scratch base"
        );
        // And the guest-r15 store-back exists (disp8 form of slot 120,
        // rename scratch rax).
        let store = vec![0x49, 0x89, 0x47, SNAP_GUEST_R15 as u8];
        assert!(out.windows(store.len()).any(|w| w == store));
    }

    #[test]
    fn r15_subregister_widths_rename_to_matching_scratch_forms() {
        // add r15d, 1 (41 83 c7 01); syscall — 32-bit form must become
        // add eax, 1 (83 c0 01; rax is the free rename), not a 64-bit add.
        static IMG: &[u8] = &[0x41, 0x83, 0xc7, 0x01, 0x0f, 0x05];
        let out = plan_and_emit(IMG);
        assert!(
            out.windows(3).any(|w| w == [0x83, 0xc0, 0x01]),
            "renamed 32-bit add against eax"
        );
        // RMW ⇒ store-back present (disp8 form of slot 120, rename rax).
        let store = vec![0x49, 0x89, 0x47, SNAP_GUEST_R15 as u8];
        assert!(out.windows(store.len()).any(|w| w == store));
    }

    #[test]
    fn r15_as_memory_base_renames_too() {
        // mov rax, [r15+8] (49 8b 47 08); syscall — guest r15 is an address.
        static IMG: &[u8] = &[0x49, 0x8b, 0x47, 0x08, 0x0f, 0x05];
        let out = plan_and_emit(IMG);
        // Renamed: mov rax, [rcx+8] = 48 8b 41 08.
        assert!(
            out.windows(4).any(|w| w == [0x48, 0x8b, 0x41, 0x08]),
            "base register renamed from r15 to the scratch"
        );
    }

    #[test]
    fn fs_prefixed_access_copies_through_verbatim() {
        // mov rax, fs:[0x28] (64 48 8b 04 25 28 00 00 00); syscall — the
        // gateway's fsbase swap makes the raw copy correct.
        static IMG: &[u8] = &[
            0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, 0x0f, 0x05,
        ];
        let out = plan_and_emit(IMG);
        assert_eq!(&out[..9], &IMG[..9], "verbatim fs-prefixed copy");
        assert_eq!(out.len(), 9 + 7);
    }
}
