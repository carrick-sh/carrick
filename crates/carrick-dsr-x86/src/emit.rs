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
//! RIP-relative operands cannot copy through: the copied instruction would
//! compute its address against the JIT-cache RIP, not the guest VA. In the
//! native model a guest VA IS a host VA, so the fix materializes the ABSOLUTE
//! target instead — placement-independent by design (the JIT cache may sit
//! anywhere; no disp32 recompute against an unknown distance, and emitted
//! bytes never depend on where the block lands):
//! - `lea r64/r32, [rip+disp]` becomes `mov r, imm` of the absolute VA (same
//!   result, no memory access, flags untouched by both).
//! - any other RIP-relative access spills one free guest GPR to the context
//!   [`scratch`](crate::gateway::X86DsrContext::scratch) slot, materializes
//!   the target in it, re-encodes the instruction with the scratch as base,
//!   and restores the GPR. The bracketing `mov`s preserve guest rflags; the
//!   rewritten instruction's own flag effects are exactly the guest's.
//!
//! Anything touching virtualized `%r15` fails closed (typed) until the
//! register-virtualization rung lands.

use iced_x86::{
    Code, Decoder, DecoderOptions, Encoder, Instruction, InstructionInfoFactory, MemoryOperand,
    Mnemonic, Register,
};

use crate::block::{X86Block, X86Exit};
use crate::gateway::{CTX_EXIT_INDIRECT_ADDR, CTX_EXIT_SYSCALL_ADDR, CTX_SCRATCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EmitError {
    #[error("x86 emit: source block bytes ({got}) shorter than the copy-through region ({need})")]
    ShortSource { need: usize, got: usize },
    #[error("x86 emit: terminator {0} is not lowered yet")]
    Unsupported(&'static str),
    #[error("x86 emit: planned instruction at guest VA 0x{va:x} no longer decodes")]
    Undecodable { va: u64 },
    #[error(
        "x86 emit: instruction at guest VA 0x{va:x} touches virtualized r15 (register virtualization not landed)"
    )]
    R15Virtualized { va: u64 },
    #[error("x86 emit: no free scratch GPR for the RIP-relative rewrite at guest VA 0x{va:x}")]
    NoScratch { va: u64 },
    #[error("x86 emit: re-encoding the RIP-relative instruction at guest VA 0x{va:x} failed")]
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
        X86Exit::Sensitive { .. } => Err(EmitError::Unsupported("sensitive")),
        X86Exit::Unsupported { .. } => Err(EmitError::Unsupported("unsupported-instruction")),
        X86Exit::Continue { .. } => Err(EmitError::Unsupported("continue")),
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

/// Emit one Copy-class instruction: verbatim unless it has a RIP-relative
/// memory operand, in which case rewrite it against the absolute guest VA.
fn emit_one(bytes: &[u8], va: u64, out: &mut Vec<u8>) -> Result<(), EmitError> {
    let mut decoder = Decoder::with_ip(64, bytes, va, DecoderOptions::NONE);
    let inst: Instruction = decoder.decode();
    if inst.is_invalid() {
        return Err(EmitError::Undecodable { va });
    }
    if !inst.is_ip_rel_memory_operand() {
        out.extend_from_slice(bytes);
        return Ok(());
    }

    // The absolute guest VA the access resolves to (guest VA == host VA in
    // the native mapping model, so materializing it is the whole fix).
    let target = inst.ip_rel_memory_address();

    if uses_r15(&inst) {
        return Err(EmitError::R15Virtualized { va });
    }

    // `lea` never touches memory or flags — it IS an address computation, so
    // it lowers to a plain immediate load of the absolute VA.
    if inst.mnemonic() == Mnemonic::Lea {
        let dst = inst.op0_register();
        let full = dst.full_register();
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
        let _ = full;
    }

    // Generic rewrite: spill a scratch GPR the instruction does not use,
    // point it at the target, re-encode the instruction with the scratch as
    // its base register, restore the scratch. All bracketing `mov`s — guest
    // rflags pass through untouched.
    let scratch = pick_scratch(&inst).ok_or(EmitError::NoScratch { va })?;
    let spill = MemoryOperand::with_base_displ(Register::R15, i64::from(CTX_SCRATCH));

    let save = Instruction::with2(Code::Mov_rm64_r64, spill, scratch)
        .map_err(|_| EmitError::Reencode { va })?;
    let load = Instruction::with2(Code::Mov_r64_imm64, scratch, target)
        .map_err(|_| EmitError::Reencode { va })?;
    let mut rewritten = inst;
    rewritten.set_memory_base(scratch);
    rewritten.set_memory_displ_size(0);
    rewritten.set_memory_displacement64(0);
    let restore = Instruction::with2(Code::Mov_r64_rm64, scratch, spill)
        .map_err(|_| EmitError::Reencode { va })?;

    encode_into(&save, va, out)?;
    encode_into(&load, va, out)?;
    encode_into(&rewritten, va, out)?;
    encode_into(&restore, va, out)
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

/// Whether the instruction reads or writes (any width of) `%r15`, the pinned
/// context register.
fn uses_r15(inst: &Instruction) -> bool {
    let mut info = InstructionInfoFactory::new();
    info.info(inst)
        .used_registers()
        .iter()
        .any(|r| r.register().full_register() == Register::R15)
}

/// The scratch candidates for the RIP-relative rewrite. `rsp`/`rbp` are
/// excluded (frame/stack semantics and ModRM special cases buy nothing);
/// `r15` is the context register. Any instruction references at most a
/// handful of GPRs, so a free candidate always exists in practice.
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

fn pick_scratch(inst: &Instruction) -> Option<Register> {
    let mut info = InstructionInfoFactory::new();
    let used: Vec<Register> = info
        .info(inst)
        .used_registers()
        .iter()
        .map(|r| r.register().full_register())
        .collect();
    SCRATCH_CANDIDATES
        .into_iter()
        .find(|candidate| !used.contains(candidate))
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
    fn rip_relative_touching_r15_fails_closed() {
        // lea r15, [rip+0x10] (4c 8d 3d 10 00 00 00); syscall
        static IMG: &[u8] = &[0x4c, 0x8d, 0x3d, 0x10, 0x00, 0x00, 0x00, 0x0f, 0x05];
        let reader = |va: u64| {
            let off = (va - BASE) as usize;
            IMG.get(off..).map(|s| s.to_vec()).unwrap_or_default()
        };
        let block = plan_block(BASE, 256, 4096, reader).expect("plan");
        assert_eq!(
            emit_block(IMG, &block),
            Err(EmitError::R15Virtualized { va: BASE })
        );
    }
}
