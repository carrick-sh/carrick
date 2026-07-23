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
    Code, ConditionCode, CpuidFeature, Decoder, DecoderOptions, Encoder, FlowControl, Instruction,
    InstructionInfoFactory, MemoryOperand, Mnemonic, OpAccess, OpKind, Register,
};

use crate::block::{X86Block, X86Exit};
use crate::gateway::{
    CTX_CHAIN_PATCH, CTX_EXECUTABLE_STOP_WORD, CTX_EXIT_INDIRECT_ADDR, CTX_EXIT_KICKED_ADDR,
    CTX_EXIT_RESUME, CTX_EXIT_SENSITIVE_ADDR, CTX_EXIT_SYSCALL_ADDR, CTX_GUEST_FSBASE,
    CTX_IDENTITY_LIVE_GATE, CTX_IDENTITY_PID, CTX_IDENTITY_TID, CTX_INDIRECT_ACTUAL_TARGET,
    CTX_INDIRECT_CACHE_SITE, CTX_KICK_RESTORE_RCX, CTX_LAST_COPIED_X87_DATA_VALID,
    CTX_LAST_COPIED_X87_GUEST_DATA_VA, CTX_LAST_COPIED_X87_GUEST_VA, CTX_SCRATCH, CTX_SCRATCH2,
    SNAP_GUEST_R15, X86IdentitySyscall,
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

/// `mov [r15+disp32], rax` — REX.WB (0x49) + 89 /r + ModRM(mod=10, reg=000=rax,
/// rm=111=r15) + disp32.
fn mov_ctx_from_rax(disp: i32) -> [u8; 7] {
    let d = disp.to_le_bytes();
    [0x49, 0x89, 0x87, d[0], d[1], d[2], d[3]]
}

/// `mov rax, [r15+disp32]` — REX.WB (0x49) + 8B /r + ModRM(mod=10, reg=000=rax,
/// rm=111=r15) + disp32.
fn mov_rax_from_ctx(disp: i32) -> [u8; 7] {
    let d = disp.to_le_bytes();
    [0x49, 0x8B, 0x87, d[0], d[1], d[2], d[3]]
}

fn mov_ctx_from_rcx(disp: i32) -> [u8; 7] {
    let d = disp.to_le_bytes();
    [0x49, 0x89, 0x8F, d[0], d[1], d[2], d[3]]
}

fn mov_rcx_from_ctx(disp: i32) -> [u8; 7] {
    let d = disp.to_le_bytes();
    [0x49, 0x8B, 0x8F, d[0], d[1], d[2], d[3]]
}

/// `mov dword ptr [r15+disp32], imm32`; preserves every guest register/flag.
/// Returns the byte offset of the immediate so the runtime can publish a site
/// id before the block becomes executable.
fn emit_mov_ctx_imm32(disp: i32, immediate: u32, out: &mut Vec<u8>) -> usize {
    let d = disp.to_le_bytes();
    out.extend_from_slice(&[0x41, 0xC7, 0x87, d[0], d[1], d[2], d[3]]);
    let immediate_off = out.len();
    out.extend_from_slice(&immediate.to_le_bytes());
    immediate_off
}

/// Publish a full guest VA without borrowing a guest GPR: two dword immediate
/// stores preserve RFLAGS and are independently safe under an asynchronous
/// kick. The gateway reads the value only after the following jump.
fn emit_self_set_resume_immediates(resume_va: u64, out: &mut Vec<u8>) {
    emit_mov_ctx_imm32(CTX_EXIT_RESUME, resume_va as u32, out);
    emit_mov_ctx_imm32(CTX_EXIT_RESUME + 4, (resume_va >> 32) as u32, out);
}

/// Record a completed copied x87 stack instruction without borrowing a guest
/// GPR or changing RFLAGS. The FreeBSD gateway uses this only when host XSAVE
/// fails to materialize the corresponding JIT FIP.
fn emit_copied_x87_guest_va(guest_va: u64, out: &mut Vec<u8>) {
    emit_mov_ctx_imm32(CTX_LAST_COPIED_X87_GUEST_VA, guest_va as u32, out);
    emit_mov_ctx_imm32(
        CTX_LAST_COPIED_X87_GUEST_VA + 4,
        (guest_va >> 32) as u32,
        out,
    );
}

/// Publish the data-address witness after its full 64-bit value. The valid
/// flag is the commit record: an asynchronous exit can never mistake a partly
/// written address for a guest FDP, and guest address zero remains representable.
fn emit_copied_x87_data_address(
    address: Register,
    va: u64,
    out: &mut Vec<u8>,
) -> Result<(), EmitError> {
    let destination =
        MemoryOperand::with_base_displ(Register::R15, i64::from(CTX_LAST_COPIED_X87_GUEST_DATA_VA));
    let store = Instruction::with2(Code::Mov_rm64_r64, destination, address)
        .map_err(|_| EmitError::Reencode { va })?;
    encode_into(&store, va, out)?;
    emit_mov_ctx_imm32(CTX_LAST_COPIED_X87_DATA_VALID, 1, out);
    Ok(())
}

/// Emit `jrcxz rel8`. Unlike cmp/test + jcc, this does not alter guest RFLAGS.
fn emit_jrcxz(out: &mut Vec<u8>) -> usize {
    out.push(0xE3);
    let rel8_off = out.len();
    out.push(0);
    rel8_off
}

fn patch_local_rel8(out: &mut [u8], rel8_off: usize, target_off: usize) {
    let displacement = target_off as i64 - (rel8_off + 1) as i64;
    debug_assert!(i8::try_from(displacement).is_ok());
    out[rel8_off] = displacement as i8 as u8;
}

fn emit_jmp_rel32(out: &mut Vec<u8>) -> usize {
    out.push(0xE9);
    let rel32_off = out.len();
    out.extend_from_slice(&0_i32.to_le_bytes());
    rel32_off
}

fn patch_local_rel32(out: &mut [u8], rel32_off: usize, target_off: usize) {
    let displacement = target_off as i64 - (rel32_off + 4) as i64;
    out[rel32_off..rel32_off + 4].copy_from_slice(&(displacement as i32).to_le_bytes());
}

/// Emit the SELF-SET of `exit_resume` to `resume_va`, preserving `rax` through
/// the context scratch slot (the exit stub saves every guest GPR, so this must
/// not clobber one). All `mov`s — guest rflags are untouched:
/// ```text
///   mov [r15+CTX_SCRATCH], rax      ; save rax
///   movabs rax, resume_va           ; the resume guest VA
///   mov [r15+CTX_EXIT_RESUME], rax  ; publish it
///   mov rax, [r15+CTX_SCRATCH]      ; restore rax
/// ```
/// Chaining requires this: a block reached by a direct-branch jump from
/// another block was never entered with the driver's per-block `exit_resume`
/// pre-set, so each exit must carry its own resume VA.
fn emit_self_set_resume(resume_va: u64, out: &mut Vec<u8>) {
    out.extend_from_slice(&mov_ctx_from_rax(CTX_SCRATCH));
    out.push(0x48);
    out.push(0xB8); // movabs rax, imm64
    out.extend_from_slice(&resume_va.to_le_bytes());
    out.extend_from_slice(&mov_ctx_from_rax(CTX_EXIT_RESUME));
    out.extend_from_slice(&mov_rax_from_ctx(CTX_SCRATCH));
}

/// Emit the translated bytes for `block`. `source` is the guest bytes for
/// `[block.start, block.end)`. Returns the JIT-ready byte sequence: the
/// caller copies it through the JIT region's RW alias and sets the context's
/// `entry` to the corresponding exec VA. The bytes are placement-independent
/// (no field depends on where in the cache they land).
pub fn emit_block(source: &[u8], block: &X86Block) -> Result<Vec<u8>, EmitError> {
    match block.exit {
        X86Exit::Syscall { va, .. } => {
            let (mut out, _) = emit_copy_body(source, block, va)?;
            out.extend_from_slice(&jmp_indirect_r15(CTX_EXIT_SYSCALL_ADDR));
            Ok(out)
        }
        X86Exit::ControlFlow { va, .. } => {
            // Copy the straight-line body up to (not including) the branch,
            // then exit to Rust, which resolves the target from the captured
            // guest state (see `cflow::resolve`). The branch itself is not
            // executed on the host — its semantics are applied in Rust.
            let (mut out, _) = emit_copy_body(source, block, va)?;
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
            let (mut out, _) = emit_copy_body(source, block, va)?;
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
            let (mut out, _) = emit_copy_body(source, block, target)?;
            out.extend_from_slice(&jmp_indirect_r15(CTX_EXIT_INDIRECT_ADDR));
            Ok(out)
        }
    }
}

/// One chainable outgoing edge of a translated block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainEdge {
    /// Guest VA of the successor block this edge branches to.
    pub target_va: u64,
    /// Byte offset within the emitted block of the original branch's 4-byte
    /// `rel32`. It initially targets the cold stub. Publication patches this
    /// last so the edge becomes hot only after its guard target is ready.
    pub entry_rel32_off: usize,
    /// Byte offset of the edge's executable stop-word guard.
    pub guard_off: usize,
    /// Byte offset of the guard's final `jmp rel32` target field. Publication
    /// patches this to the translated successor before redirecting the entry
    /// branch to [`Self::guard_off`].
    pub guard_target_rel32_off: usize,
}

/// One emitted return site whose monomorphic cache id is assigned by the
/// runtime before publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndirectCacheSite {
    /// Byte offset of the four-byte, initially-zero one-based site id.
    pub site_id_imm_off: usize,
    /// Architectural stack advance performed by a cache hit (`8 + imm16`).
    pub stack_adjust: u64,
}

/// A translated block plus its chainable edges (empty ⇒ the terminator exits
/// to Rust as `emit_block` does: syscall/sensitive/continue/indirect/call/ret).
#[derive(Clone, Debug)]
pub struct LinkedBlock {
    pub bytes: Vec<u8>,
    pub edges: Vec<ChainEdge>,
    /// Optional return-cache site. Other indirect forms remain cold.
    pub indirect_cache: Option<IndirectCacheSite>,
    /// Reverse map for synchronous host faults in emitted guest instructions.
    pub fault_map: Vec<FaultMapEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScratchRestore {
    pub snapshot_gpr: usize,
    pub scratch_index: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultMapEntry {
    pub emitted_start: usize,
    pub emitted_end: usize,
    pub guest_va: u64,
    /// The exact emitted instruction is a copied x87 instruction whose host
    /// FIP must be reverse-mapped at the next full gateway exit. MMX and SIMD
    /// instructions are deliberately false even though they share xstate.
    pub is_copied_x87: bool,
    pub restores: Vec<ScratchRestore>,
}

/// The bytes of one chain-miss COLD stub (52 bytes). Reached when a patchable
/// slot still points here (target not yet translated). It records the slot's
/// `rel32` address (so the run loop can patch it), publishes the resolved
/// target VA as the resume, and exits to Rust via the indirect stub. `slot_off`
/// is the block-relative offset of the slot's `rel32`; `cold_off` is where this
/// stub begins in the block; both are needed to compute the RIP-relative `lea`.
fn emit_cold_stub(slot_rel32_off: usize, target_va: u64, cold_off: usize, out: &mut Vec<u8>) {
    let start = out.len();
    debug_assert_eq!(start, cold_off);
    // mov [r15+CTX_SCRATCH], rax  — save rax.
    out.extend_from_slice(&mov_ctx_from_rax(CTX_SCRATCH));
    // lea rax, [rip+disp32]  (48 8d 05 <disp32>) — rax = &slot.rel32.
    // disp is relative to the END of the lea (cold_off + 7 + 7 == +14).
    let lea_end = cold_off + 14;
    let disp = slot_rel32_off as i64 - lea_end as i64;
    out.extend_from_slice(&[0x48, 0x8d, 0x05]);
    out.extend_from_slice(&(disp as i32).to_le_bytes());
    // mov [r15+CTX_CHAIN_PATCH], rax — record the patch site.
    out.extend_from_slice(&mov_ctx_from_rax(CTX_CHAIN_PATCH));
    // movabs rax, target_va — the resolved successor guest VA.
    out.push(0x48);
    out.push(0xB8);
    out.extend_from_slice(&target_va.to_le_bytes());
    // mov [r15+CTX_EXIT_RESUME], rax — publish the resume.
    out.extend_from_slice(&mov_ctx_from_rax(CTX_EXIT_RESUME));
    // mov rax, [r15+CTX_SCRATCH] — restore rax.
    out.extend_from_slice(&mov_rax_from_ctx(CTX_SCRATCH));
    // jmp *CTX_EXIT_INDIRECT_ADDR(r15) — exit to Rust.
    out.extend_from_slice(&jmp_indirect_r15(CTX_EXIT_INDIRECT_ADDR));
    debug_assert_eq!(out.len() - start, COLD_STUB_LEN);
}

/// Byte length of one [`emit_cold_stub`].
const COLD_STUB_LEN: usize = 52;

/// Emit one hot-edge executable stop guard. The original edge remains pointed
/// at its cold stub until the runtime first patches `guard_target_rel32_off` to
/// the translated successor and only then patches the original branch to
/// `guard_off`.
///
/// RCX is the sole temporary. Every instruction before the successor is a
/// `mov`, `jrcxz`, or `jmp`, so guest RFLAGS are bit-for-bit unchanged. The
/// active spill flag gives the existing asynchronous-kick shim enough state to
/// recover guest RCX at any point after the stop-word pointer replaces it.
fn emit_chain_guard(target_va: u64, cold_off: usize, out: &mut Vec<u8>) -> (usize, usize) {
    let guard_off = out.len();
    out.extend_from_slice(&mov_ctx_from_rcx(CTX_SCRATCH2));
    emit_mov_ctx_imm32(CTX_KICK_RESTORE_RCX, 1, out);
    out.extend_from_slice(&mov_rcx_from_ctx(CTX_EXECUTABLE_STOP_WORD));
    let null_to_successor = emit_jrcxz(out);
    out.extend_from_slice(&[0x8B, 0x09]); // mov ecx, dword ptr [rcx]
    let zero_to_successor = emit_jrcxz(out);

    // Nonzero: the successor has not executed. Restore the complete guest RCX,
    // publish that successor as the exact resume boundary, and leave through
    // the gateway's kicked stub without borrowing another guest register.
    out.extend_from_slice(&mov_rcx_from_ctx(CTX_SCRATCH2));
    emit_mov_ctx_imm32(CTX_KICK_RESTORE_RCX, 0, out);
    emit_self_set_resume_immediates(target_va, out);
    out.extend_from_slice(&jmp_indirect_r15(CTX_EXIT_KICKED_ADDR));

    let successor_path = out.len();
    out.extend_from_slice(&mov_rcx_from_ctx(CTX_SCRATCH2));
    emit_mov_ctx_imm32(CTX_KICK_RESTORE_RCX, 0, out);
    let guard_target_rel32_off = emit_jmp_rel32(out);

    patch_local_rel8(out, null_to_successor, successor_path);
    patch_local_rel8(out, zero_to_successor, successor_path);
    // Defensive initial destination: even if an entry is redirected too early,
    // the existing cold behavior remains intact. Ordered publication replaces
    // this target before making the guard reachable.
    patch_local_rel32(out, guard_target_rel32_off, cold_off);
    debug_assert_eq!(out.len() - guard_off, CHAIN_GUARD_LEN);
    (guard_off, guard_target_rel32_off)
}

/// Byte length of one [`emit_chain_guard`].
const CHAIN_GUARD_LEN: usize = 101;

fn statically_known_identity_syscall(
    source: &[u8],
    block: &X86Block,
    syscall_va: u64,
) -> Option<X86IdentitySyscall> {
    let last = block.instructions.last()?;
    if last.va.checked_add(u64::from(last.len))? != syscall_va {
        return None;
    }
    let start = usize::try_from(last.va.checked_sub(block.start)?).ok()?;
    let end = start.checked_add(usize::from(last.len))?;
    let mut decoder = Decoder::with_ip(64, source.get(start..end)?, last.va, DecoderOptions::NONE);
    let inst = decoder.decode();
    let raw = match (inst.code(), inst.op0_register()) {
        (Code::Mov_r32_imm32, Register::EAX) => inst.immediate32(),
        (Code::Mov_r64_imm64, Register::RAX) => u32::try_from(inst.immediate64()).ok()?,
        (Code::Mov_rm64_imm32, Register::RAX) => u32::try_from(inst.immediate32to64()).ok()?,
        _ => return None,
    };
    X86IdentitySyscall::from_static_x86_ordinal(raw)
}

/// Emit a statically identified getpid/gettid as a live-gated context load plus
/// one patchable successor edge. `jrcxz` tests the pointer and atomic value
/// without modifying RFLAGS; RAX/RCX are restored exactly on the fallback.
fn emit_identity_syscall_or_fallback(
    identity: X86IdentitySyscall,
    resume: u64,
    out: &mut Vec<u8>,
) -> ChainEdge {
    out.extend_from_slice(&mov_ctx_from_rax(CTX_SCRATCH));
    out.extend_from_slice(&mov_ctx_from_rcx(CTX_SCRATCH2));
    out.extend_from_slice(&mov_rcx_from_ctx(CTX_IDENTITY_LIVE_GATE));
    let null_to_fallback = emit_jrcxz(out);
    out.extend_from_slice(&[0x8B, 0x09]); // mov ecx, dword ptr [rcx]
    let disabled_to_fallback = emit_jrcxz(out);

    let result_offset = match identity {
        X86IdentitySyscall::GetPid => CTX_IDENTITY_PID,
        X86IdentitySyscall::GetTid => CTX_IDENTITY_TID,
    };
    out.extend_from_slice(&mov_rax_from_ctx(result_offset));
    out.extend_from_slice(&mov_rcx_from_ctx(CTX_SCRATCH2));
    let identity_to_slot = emit_jmp_rel32(out);

    let fallback = out.len();
    out.extend_from_slice(&mov_rax_from_ctx(CTX_SCRATCH));
    out.extend_from_slice(&mov_rcx_from_ctx(CTX_SCRATCH2));
    emit_self_set_resume(resume, out);
    out.extend_from_slice(&jmp_indirect_r15(CTX_EXIT_SYSCALL_ADDR));

    let slot_off = out.len();
    let cold_off = slot_off + 5;
    out.push(0xE9);
    out.extend_from_slice(&0_i32.to_le_bytes());
    emit_cold_stub(slot_off + 1, resume, cold_off, out);
    let (guard_off, guard_target_rel32_off) = emit_chain_guard(resume, cold_off, out);

    patch_local_rel8(out, null_to_fallback, fallback);
    patch_local_rel8(out, disabled_to_fallback, fallback);
    patch_local_rel32(out, identity_to_slot, slot_off);

    ChainEdge {
        target_va: resume,
        entry_rel32_off: slot_off + 1,
        guard_off,
        guard_target_rel32_off,
    }
}

/// The second opcode byte of the `0F 8x` near `jcc rel32` for a condition.
fn jcc_rel32_opcode(cc: ConditionCode) -> Option<u8> {
    Some(match cc {
        ConditionCode::o => 0x80,
        ConditionCode::no => 0x81,
        ConditionCode::b => 0x82,
        ConditionCode::ae => 0x83,
        ConditionCode::e => 0x84,
        ConditionCode::ne => 0x85,
        ConditionCode::be => 0x86,
        ConditionCode::a => 0x87,
        ConditionCode::s => 0x88,
        ConditionCode::ns => 0x89,
        ConditionCode::p => 0x8A,
        ConditionCode::np => 0x8B,
        ConditionCode::l => 0x8C,
        ConditionCode::ge => 0x8D,
        ConditionCode::le => 0x8E,
        ConditionCode::g => 0x8F,
        ConditionCode::None => return None,
    })
}

/// Emit a return-target capture that preserves guest RFLAGS and every GPR at
/// the gateway boundary. RCX is transiently spilled while reading `[rsp]`;
/// synchronous faults reverse-map the spill, and the FreeBSD kick shim uses
/// `CTX_KICK_RESTORE_RCX` to repair an asynchronous interruption.
fn emit_return_cache_site(
    guest_va: u64,
    stack_adjust: u64,
    out: &mut Vec<u8>,
    fault_map: &mut Vec<FaultMapEntry>,
) -> IndirectCacheSite {
    out.extend_from_slice(&mov_ctx_from_rcx(CTX_SCRATCH2));
    emit_mov_ctx_imm32(CTX_KICK_RESTORE_RCX, 1, out);

    let load_start = out.len();
    out.extend_from_slice(&[0x48, 0x8B, 0x0C, 0x24]); // mov rcx, [rsp]
    let load_end = out.len();
    fault_map.push(FaultMapEntry {
        emitted_start: load_start,
        emitted_end: load_end,
        guest_va,
        is_copied_x87: false,
        restores: vec![ScratchRestore {
            snapshot_gpr: crate::gateway::reg::RCX,
            scratch_index: 1,
        }],
    });

    out.extend_from_slice(&mov_ctx_from_rcx(CTX_INDIRECT_ACTUAL_TARGET));
    out.extend_from_slice(&mov_rcx_from_ctx(CTX_SCRATCH2));
    emit_mov_ctx_imm32(CTX_KICK_RESTORE_RCX, 0, out);
    emit_self_set_resume_immediates(guest_va, out);
    let site_id_imm_off = emit_mov_ctx_imm32(CTX_INDIRECT_CACHE_SITE, 0, out);
    out.extend_from_slice(&jmp_indirect_r15(CTX_EXIT_INDIRECT_ADDR));
    IndirectCacheSite {
        site_id_imm_off,
        stack_adjust,
    }
}

/// How a block's terminating branch chains.
enum BranchChain {
    /// `jmp rel` — one successor.
    Jmp { target: u64 },
    /// `jcc rel` — taken vs fall-through successors.
    Jcc {
        opcode: u8,
        taken: u64,
        fallthrough: u64,
    },
    /// `ret`/`ret imm16` — capture the live stack target for a gateway-owned
    /// monomorphic cache; misses remain resolved in Rust.
    Return { stack_adjust: u64 },
    /// `call`/other indirect — not chained; resolved in Rust from the snapshot.
    Resolve,
}

/// Classify a block's terminating branch for chaining.
fn classify_branch(bytes: &[u8], va: u64) -> BranchChain {
    let mut decoder = Decoder::with_ip(64, bytes, va, DecoderOptions::NONE);
    let inst = decoder.decode();
    if inst.is_invalid() {
        return BranchChain::Resolve;
    }
    match inst.flow_control() {
        FlowControl::UnconditionalBranch if inst.op0_kind() == OpKind::NearBranch64 => {
            BranchChain::Jmp {
                target: inst.near_branch64(),
            }
        }
        FlowControl::ConditionalBranch if inst.op0_kind() == OpKind::NearBranch64 => {
            match jcc_rel32_opcode(inst.condition_code()) {
                Some(opcode) => BranchChain::Jcc {
                    opcode,
                    taken: inst.near_branch64(),
                    fallthrough: va + inst.len() as u64,
                },
                None => BranchChain::Resolve,
            }
        }
        FlowControl::Return if inst.code() == Code::Retnq => {
            BranchChain::Return { stack_adjust: 8 }
        }
        FlowControl::Return if inst.code() == Code::Retnq_imm16 => BranchChain::Return {
            stack_adjust: 8 + u64::from(inst.immediate16()),
        },
        _ => BranchChain::Resolve,
    }
}

/// Emit a block with direct-branch CHAINING. Identical to [`emit_block`] except
/// that a block ending in a direct `jmp`/`jcc` gets patchable jump slots (one
/// per successor) that initially target cold stubs and are later patched by the
/// runtime to enter a per-edge stop-word guard. A zero word continues through
/// the guard's separately published successor jump without a gateway round
/// trip; a nonzero word exits at that successor boundary. Every exit SELF-SETS its
/// resume VA (a chained-into block was not entered with the driver's per-block
/// `exit_resume`). `call`/`ret`/indirect branches, syscalls, sensitive
/// instructions, and continues keep the resolve-in-Rust exit.
pub fn emit_block_linked(source: &[u8], block: &X86Block) -> Result<LinkedBlock, EmitError> {
    let no_edges = |bytes, fault_map| LinkedBlock {
        bytes,
        edges: Vec::new(),
        indirect_cache: None,
        fault_map,
    };
    match block.exit {
        X86Exit::Syscall { va, resume, int80 } => {
            let (mut out, fault_map) = emit_copy_body(source, block, va)?;
            if let Some(identity) = (!int80)
                .then(|| statically_known_identity_syscall(source, block, va))
                .flatten()
            {
                let edge = emit_identity_syscall_or_fallback(identity, resume, &mut out);
                Ok(LinkedBlock {
                    bytes: out,
                    edges: vec![edge],
                    indirect_cache: None,
                    fault_map,
                })
            } else {
                emit_self_set_resume(resume, &mut out);
                out.extend_from_slice(&jmp_indirect_r15(CTX_EXIT_SYSCALL_ADDR));
                Ok(no_edges(out, fault_map))
            }
        }
        X86Exit::Sensitive { va, .. } => {
            // The run loop re-decodes the sensitive instruction at the resume
            // VA to recover its kind, so resume = the instruction's own VA.
            let (mut out, fault_map) = emit_copy_body(source, block, va)?;
            emit_self_set_resume(va, &mut out);
            out.extend_from_slice(&jmp_indirect_r15(CTX_EXIT_SENSITIVE_ADDR));
            Ok(no_edges(out, fault_map))
        }
        X86Exit::Continue { target, .. } => {
            // A structural boundary falls through to the next block — emit it
            // as a chainable unconditional jump so page-spanning straight-line
            // code links block-to-block instead of round-tripping.
            let (mut out, fault_map) = emit_copy_body(source, block, target)?;
            let slot_off = out.len();
            let cold_off = slot_off + 5;
            let rel = cold_off as i64 - (slot_off + 5) as i64;
            out.push(0xE9);
            out.extend_from_slice(&(rel as i32).to_le_bytes());
            emit_cold_stub(slot_off + 1, target, cold_off, &mut out);
            let (guard_off, guard_target_rel32_off) = emit_chain_guard(target, cold_off, &mut out);
            Ok(LinkedBlock {
                bytes: out,
                edges: vec![ChainEdge {
                    target_va: target,
                    entry_rel32_off: slot_off + 1,
                    guard_off,
                    guard_target_rel32_off,
                }],
                indirect_cache: None,
                fault_map,
            })
        }
        X86Exit::Unsupported { .. } => Err(EmitError::Unsupported("unsupported-instruction")),
        X86Exit::ControlFlow { va, len } => {
            let off = (va - block.start) as usize;
            let branch = source
                .get(off..off + len as usize)
                .ok_or(EmitError::ShortSource {
                    need: off + len as usize,
                    got: source.len(),
                })?;
            match classify_branch(branch, va) {
                BranchChain::Return { stack_adjust } => {
                    let (mut out, mut fault_map) = emit_copy_body(source, block, va)?;
                    let indirect_cache =
                        emit_return_cache_site(va, stack_adjust, &mut out, &mut fault_map);
                    Ok(LinkedBlock {
                        bytes: out,
                        edges: Vec::new(),
                        indirect_cache: Some(indirect_cache),
                        fault_map,
                    })
                }
                BranchChain::Resolve => {
                    // call/ret/indirect: exit to Rust; the run loop re-decodes
                    // the branch at the resume VA and resolves it.
                    let (mut out, fault_map) = emit_copy_body(source, block, va)?;
                    emit_self_set_resume(va, &mut out);
                    out.extend_from_slice(&jmp_indirect_r15(CTX_EXIT_INDIRECT_ADDR));
                    Ok(no_edges(out, fault_map))
                }
                BranchChain::Jmp { target } => {
                    let (mut out, fault_map) = emit_copy_body(source, block, va)?;
                    // jmpSlot: E9 <rel32 -> coldJ>  (patchable).
                    let slot_off = out.len();
                    let cold_off = slot_off + 5;
                    let rel = cold_off as i64 - (slot_off + 5) as i64;
                    out.push(0xE9);
                    out.extend_from_slice(&(rel as i32).to_le_bytes());
                    emit_cold_stub(slot_off + 1, target, cold_off, &mut out);
                    let (guard_off, guard_target_rel32_off) =
                        emit_chain_guard(target, cold_off, &mut out);
                    Ok(LinkedBlock {
                        bytes: out,
                        edges: vec![ChainEdge {
                            target_va: target,
                            entry_rel32_off: slot_off + 1,
                            guard_off,
                            guard_target_rel32_off,
                        }],
                        indirect_cache: None,
                        fault_map,
                    })
                }
                BranchChain::Jcc {
                    opcode,
                    taken,
                    fallthrough,
                } => {
                    let (mut out, fault_map) = emit_copy_body(source, block, va)?;
                    // jcc rel32 -> takenSlot (0F 8x <rel32>), 6 bytes.
                    let jcc_off = out.len();
                    let fall_slot_off = jcc_off + 6;
                    let taken_slot_off = fall_slot_off + 5;
                    let cold_f_off = taken_slot_off + 5;
                    let cold_t_off = cold_f_off + COLD_STUB_LEN;
                    // jcc -> takenSlot
                    out.push(0x0F);
                    out.push(opcode);
                    let jcc_rel = taken_slot_off as i64 - (jcc_off + 6) as i64;
                    out.extend_from_slice(&(jcc_rel as i32).to_le_bytes());
                    // fallSlot: E9 -> coldF
                    let fall_rel = cold_f_off as i64 - (fall_slot_off + 5) as i64;
                    out.push(0xE9);
                    out.extend_from_slice(&(fall_rel as i32).to_le_bytes());
                    // takenSlot: E9 -> coldT
                    let taken_rel = cold_t_off as i64 - (taken_slot_off + 5) as i64;
                    out.push(0xE9);
                    out.extend_from_slice(&(taken_rel as i32).to_le_bytes());
                    // Cold stubs retain the initial behavior; unreachable guards
                    // follow them and are published target-first by the runtime.
                    emit_cold_stub(fall_slot_off + 1, fallthrough, cold_f_off, &mut out);
                    emit_cold_stub(taken_slot_off + 1, taken, cold_t_off, &mut out);
                    let (fall_guard_off, fall_guard_target_rel32_off) =
                        emit_chain_guard(fallthrough, cold_f_off, &mut out);
                    let (taken_guard_off, taken_guard_target_rel32_off) =
                        emit_chain_guard(taken, cold_t_off, &mut out);
                    Ok(LinkedBlock {
                        bytes: out,
                        edges: vec![
                            ChainEdge {
                                target_va: taken,
                                entry_rel32_off: taken_slot_off + 1,
                                guard_off: taken_guard_off,
                                guard_target_rel32_off: taken_guard_target_rel32_off,
                            },
                            ChainEdge {
                                target_va: fallthrough,
                                entry_rel32_off: fall_slot_off + 1,
                                guard_off: fall_guard_off,
                                guard_target_rel32_off: fall_guard_target_rel32_off,
                            },
                        ],
                        indirect_cache: None,
                        fault_map,
                    })
                }
            }
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
) -> Result<(Vec<u8>, Vec<FaultMapEntry>), EmitError> {
    let copy_len = (terminator_va - block.start) as usize;
    if source.len() < copy_len {
        return Err(EmitError::ShortSource {
            need: copy_len,
            got: source.len(),
        });
    }
    let mut out = Vec::with_capacity(copy_len + 7);
    let mut fault_map = Vec::with_capacity(block.instructions.len());
    for planned in &block.instructions {
        let off = (planned.va - block.start) as usize;
        let bytes = &source[off..off + planned.len as usize];
        if let Some(entry) = emit_one(bytes, planned.va, &mut out)? {
            fault_map.push(entry);
        }
    }
    Ok((out, fault_map))
}

/// How one instruction touches virtualized guest `%r15`.
struct R15Use {
    written: bool,
}

/// Emit one Copy-class instruction: verbatim unless it has a RIP-relative
/// memory operand (rewrite against the absolute guest VA) or touches
/// virtualized guest r15 (rename it to a scratch backed by the snapshot).
fn emit_one(bytes: &[u8], va: u64, out: &mut Vec<u8>) -> Result<Option<FaultMapEntry>, EmitError> {
    let mut decoder = Decoder::with_ip(64, bytes, va, DecoderOptions::NONE);
    let inst: Instruction = decoder.decode();
    if inst.is_invalid() {
        return Err(EmitError::Undecodable { va });
    }
    let is_copied_x87 = inst.cpuid_features().iter().any(|feature| {
        matches!(
            feature,
            CpuidFeature::FPU
                | CpuidFeature::FPU287
                | CpuidFeature::FPU287XL_ONLY
                | CpuidFeature::FPU387
                | CpuidFeature::FPU387SL_ONLY
        )
    });
    // FIP names every completed non-control x87 instruction. Iced's
    // used-register view omits the implicit ST-stack write for some memory
    // loads (notably FLD m80), so it cannot be the authority here. The small
    // architectural control family below is the complete set that leaves FIP
    // unchanged; state-transfer forms never reach Copy emission.
    let records_x87_fip = is_copied_x87
        && !matches!(
            inst.mnemonic(),
            Mnemonic::Fldcw
                | Mnemonic::Fnstcw
                | Mnemonic::Fstcw
                | Mnemonic::Fnstsw
                | Mnemonic::Fstsw
                | Mnemonic::Fnclex
                | Mnemonic::Fclex
                | Mnemonic::Fninit
                | Mnemonic::Finit
                | Mnemonic::Fnop
                | Mnemonic::Wait
        );
    let records_x87_data_address = records_x87_fip && has_memory_operand(&inst);
    let ip_rel = inst.is_ip_rel_memory_operand();
    let r15_use = r15_usage(&inst);
    if !ip_rel && r15_use.is_none() && !records_x87_data_address {
        let emitted_start = out.len();
        out.extend_from_slice(bytes);
        let emitted_end = out.len();
        if records_x87_fip {
            emit_copied_x87_guest_va(va, out);
        }
        return Ok(Some(FaultMapEntry {
            emitted_start,
            emitted_end,
            guest_va: va,
            is_copied_x87,
            restores: Vec::new(),
        }));
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
            encode_into(&mov, va, out)?;
            return Ok(None);
        }
        if dst.size() == 4 {
            // 32-bit lea truncates the address; mov r32, imm32 matches that
            // (and zero-extends to 64 bits, exactly like lea r32 does).
            let mov = Instruction::with2(Code::Mov_r32_imm32, dst, target as u32)
                .map_err(|_| EmitError::Reencode { va })?;
            encode_into(&mov, va, out)?;
            return Ok(None);
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
    // A copied x87 memory instruction needs an exact FDP even when XSAVEOPT
    // omits it. Reuse the already-materialized RIP target or the r15 rename
    // where possible; only then borrow another spilled register.
    let data_address = if records_x87_data_address {
        if let Some(base) = base {
            Some(base)
        } else if let Some(rename) = rename {
            Some(rename)
        } else {
            let s = scratches.take().ok_or(EmitError::NoScratch { va })?;
            let slot = spill_slots[spilled.len()];
            spilled.push((s, slot));
            Some(s)
        }
    } else {
        None
    };
    // LEA ignores segment bases. FS is live guest TLS during translated
    // execution, so add its virtual base explicitly after calculating the
    // architecturally sized offset. GS never reaches copy emission.
    let fs_address = if records_x87_data_address && inst.segment_prefix() == Register::FS {
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

    let emitted_start = out.len();
    encode_into(&rewritten, va, out)?;
    let emitted_end = out.len();
    if let Some(data_address) = data_address {
        emit_x87_memory_data_address(&inst, bytes, va, rename, data_address, fs_address, out)?;
        emit_copied_x87_data_address(data_address, va, out)?;
    }
    if records_x87_fip {
        emit_copied_x87_guest_va(va, out);
    }

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
    let restores = spilled
        .iter()
        .enumerate()
        .filter_map(|(scratch_index, (register, _))| {
            snapshot_gpr_index(*register).map(|snapshot_gpr| ScratchRestore {
                snapshot_gpr,
                scratch_index,
            })
        })
        .collect();
    Ok(Some(FaultMapEntry {
        emitted_start,
        emitted_end,
        guest_va: va,
        is_copied_x87,
        restores,
    }))
}

/// Whether the decoded instruction has an explicit ModRM/SIB memory operand.
/// All copied x87 data forms use this representation; register-only forms
/// retain the entry FDP and therefore publish no data-address sideband.
fn has_memory_operand(inst: &Instruction) -> bool {
    (0..inst.op_count()).any(|operand| inst.op_kind(operand) == OpKind::Memory)
}

/// The legacy prefixes before an x87 opcode. For no-base/no-index addressing,
/// iced's operand fields do not retain whether the source used 32-bit address
/// size; preserve that one bit explicitly when re-encoding the witness LEA.
fn has_address_size_override(bytes: &[u8]) -> bool {
    let mut address_size = false;
    for &byte in bytes {
        match byte {
            0x67 => address_size = true,
            0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 | 0x66 => {}
            0x40..=0x4F => {}
            _ => break,
        }
    }
    address_size
}

fn x87_memory_operand(inst: &Instruction, rename: Option<Register>) -> MemoryOperand {
    let remap = |register: Register| {
        if register.full_register() == Register::R15 {
            // The copied instruction uses the renamed physical scratch. The
            // post-instruction LEA must use that same value, not the pinned
            // context pointer.
            sized_gpr(rename.unwrap_or(Register::R15), register.size())
        } else {
            register
        }
    };
    MemoryOperand::new(
        remap(inst.memory_base()),
        remap(inst.memory_index()),
        inst.memory_index_scale(),
        inst.memory_displacement64() as i64,
        inst.memory_displ_size(),
        false,
        Register::None,
    )
}

/// Calculate and publish the exact linear address used by a completed copied
/// x87 memory instruction. The source operand's address-size semantics live in
/// the LEA; the guest FS base is added separately because LEA deliberately
/// ignores segmentation. GS forms are rejected by the planner.
fn emit_x87_memory_data_address(
    inst: &Instruction,
    bytes: &[u8],
    va: u64,
    rename: Option<Register>,
    data_address: Register,
    fs_address: Option<Register>,
    out: &mut Vec<u8>,
) -> Result<(), EmitError> {
    let memory = x87_memory_operand(inst, rename);
    // RIP-relative operands were rewritten through `data_address` before the
    // copied instruction and retain their compile-time guest target. Other
    // forms need a post-instruction LEA over the original effective-address
    // expression, including 32-bit address-size zero extension.
    if !inst.is_ip_rel_memory_operand() {
        if memory.base == Register::None
            && memory.index == Register::None
            && has_address_size_override(bytes)
        {
            // `lea r64,[disp32]` normally uses long-mode's sign-extended
            // absolute displacement. The source's 67 prefix makes it the
            // zero-extended 32-bit absolute form instead.
            out.push(0x67);
        }
        let lea = Instruction::with2(Code::Lea_r64_m, data_address, memory)
            .map_err(|_| EmitError::Reencode { va })?;
        encode_into(&lea, va, out)?;
    }
    if let Some(fs_address) = fs_address {
        let fsbase = MemoryOperand::with_base_displ(Register::R15, i64::from(CTX_GUEST_FSBASE));
        let load = Instruction::with2(Code::Mov_r64_rm64, fs_address, fsbase)
            .map_err(|_| EmitError::Reencode { va })?;
        encode_into(&load, va, out)?;
        let add = MemoryOperand::with_base_index_scale(data_address, fs_address, 1);
        let lea = Instruction::with2(Code::Lea_r64_m, data_address, add)
            .map_err(|_| EmitError::Reencode { va })?;
        encode_into(&lea, va, out)?;
    }
    Ok(())
}

fn snapshot_gpr_index(register: Register) -> Option<usize> {
    use crate::gateway::reg;
    Some(match register.full_register() {
        Register::RAX => reg::RAX,
        Register::RCX => reg::RCX,
        Register::RDX => reg::RDX,
        Register::RBX => reg::RBX,
        Register::RSP => reg::RSP,
        Register::RBP => reg::RBP,
        Register::RSI => reg::RSI,
        Register::RDI => reg::RDI,
        Register::R8 => reg::R8,
        Register::R9 => reg::R9,
        Register::R10 => reg::R10,
        Register::R11 => reg::R11,
        Register::R12 => reg::R12,
        Register::R13 => reg::R13,
        Register::R14 => reg::R14,
        Register::R15 => reg::R15,
        _ => return None,
    })
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

    fn plan_and_emit_linked(img: &[u8]) -> LinkedBlock {
        let reader = |va: u64| {
            let off = (va - BASE) as usize;
            img.get(off..).map(|s| s.to_vec()).unwrap_or_default()
        };
        let block = plan_block(BASE, 256, 4096, reader).expect("plan");
        emit_block_linked(img, &block).expect("emit-linked")
    }

    /// Follow a `jmp rel32`/`jcc rel32`/`E9` at byte offset `at` in `bytes`
    /// (placed at exec base 0) and return the absolute target offset.
    fn follow_rel32(bytes: &[u8], at: usize, rel32_at: usize) -> usize {
        let rel = i32::from_le_bytes(bytes[rel32_at..rel32_at + 4].try_into().unwrap());
        let next = rel32_at + 4;
        let _ = at;
        (next as i64 + rel as i64) as usize
    }

    fn assert_guarded_publication(
        bytes: &[u8],
        edge: ChainEdge,
        expected_cold: usize,
        successor: usize,
    ) {
        assert_eq!(
            follow_rel32(bytes, edge.entry_rel32_off - 1, edge.entry_rel32_off),
            expected_cold,
            "the unpublished entry must retain cold behavior"
        );
        assert_eq!(
            follow_rel32(
                bytes,
                edge.guard_target_rel32_off - 1,
                edge.guard_target_rel32_off,
            ),
            expected_cold,
            "the unpublished guard target is defensively cold"
        );

        let mut published = bytes.to_vec();
        patch_local_rel32(&mut published, edge.guard_target_rel32_off, successor);
        assert_eq!(
            follow_rel32(&published, edge.entry_rel32_off - 1, edge.entry_rel32_off,),
            expected_cold,
            "publishing the guard target alone must not make the edge hot"
        );
        patch_local_rel32(&mut published, edge.entry_rel32_off, edge.guard_off);
        assert_eq!(
            follow_rel32(&published, edge.entry_rel32_off - 1, edge.entry_rel32_off,),
            edge.guard_off,
            "the published entry must target the guard, never the successor"
        );
        assert_eq!(
            follow_rel32(
                &published,
                edge.guard_target_rel32_off - 1,
                edge.guard_target_rel32_off,
            ),
            successor,
            "the guard owns the separately published successor target"
        );
        assert_eq!(
            published[edge.guard_off], 0x49,
            "guard starts by spilling rcx"
        );
        assert_eq!(
            published[edge.guard_target_rel32_off - 1],
            0xE9,
            "guard target metadata names its final jmp rel32"
        );
    }

    #[test]
    fn linked_unconditional_jmp_slot_targets_cold_stub_then_edge_patchable() {
        // nop (90); jmp +0 (eb 00) — one copy byte then an unconditional jmp.
        static IMG: &[u8] = &[0x90, 0xeb, 0x00];
        let lb = plan_and_emit_linked(IMG);
        assert_eq!(lb.bytes[0], 0x90, "the nop copies");
        // jmp slot at offset 1: E9 <rel32>.
        assert_eq!(lb.bytes[1], 0xE9, "patchable jmp slot opcode");
        // The one edge's rel32 is at offset 2, and initially targets the cold
        // stub which begins right after the 5-byte slot (offset 6).
        assert_eq!(lb.edges.len(), 1);
        assert_eq!(lb.edges[0].entry_rel32_off, 2);
        assert_eq!(lb.edges[0].target_va, BASE + 3, "jmp +0 target = VA after");
        let cold = follow_rel32(&lb.bytes, 1, 2);
        assert_eq!(cold, 6, "slot initially jumps to the cold stub at +6");
        // Cold stub: mov [r15+scratch], rax (49 89 87 ..).
        assert_eq!(&lb.bytes[cold..cold + 3], &[0x49, 0x89, 0x87]);
        // Its lea rax,[rip+disp] must point at the slot's rel32 (offset 2).
        assert_eq!(&lb.bytes[cold + 7..cold + 10], &[0x48, 0x8d, 0x05]);
        let lea_disp = i32::from_le_bytes(lb.bytes[cold + 10..cold + 14].try_into().unwrap());
        assert_eq!(
            (cold as i64 + 14 + lea_disp as i64) as usize,
            2,
            "cold stub's lea resolves to the slot rel32 address"
        );
        assert_guarded_publication(&lb.bytes, lb.edges[0], cold, lb.bytes.len() + 0x80);
    }

    #[test]
    fn linked_conditional_jcc_has_two_slots_and_cold_stubs() {
        // 74 02  je +2  (taken = VA+4, fallthrough = VA+2).
        static IMG: &[u8] = &[0x74, 0x02];
        let lb = plan_and_emit_linked(IMG);
        // jcc rel32 at offset 0: 0F 84 (je) <rel32> -> takenSlot.
        assert_eq!(&lb.bytes[0..2], &[0x0F, 0x84], "je rel32");
        let taken_slot = follow_rel32(&lb.bytes, 0, 2);
        assert_eq!(taken_slot, 11, "jcc targets takenSlot at +11 (6+5)");
        // fallSlot at +6, takenSlot at +11 (both E9).
        assert_eq!(lb.bytes[6], 0xE9, "fall slot");
        assert_eq!(lb.bytes[11], 0xE9, "taken slot");
        // Two edges: taken (VA+4) at takenSlot+1=12, fallthrough (VA+2) at
        // fallSlot+1=7.
        assert_eq!(lb.edges.len(), 2);
        assert_eq!(lb.edges[0].target_va, BASE + 4);
        assert_eq!(lb.edges[0].entry_rel32_off, 12);
        assert_eq!(lb.edges[1].target_va, BASE + 2);
        assert_eq!(lb.edges[1].entry_rel32_off, 7);
        // Slots initially target their cold stubs.
        let cold_f = follow_rel32(&lb.bytes, 6, 7);
        let cold_t = follow_rel32(&lb.bytes, 11, 12);
        assert_eq!(cold_f, 16, "fall slot -> coldF at +16");
        assert_eq!(cold_t, 16 + COLD_STUB_LEN, "taken slot -> coldT");
        // Each cold stub materializes its target via movabs (48 b8 ..) at +21.
        let f_imm = u64::from_le_bytes(lb.bytes[cold_f + 23..cold_f + 31].try_into().unwrap());
        assert_eq!(f_imm, BASE + 2, "coldF resume = fallthrough");
        let t_imm = u64::from_le_bytes(lb.bytes[cold_t + 23..cold_t + 31].try_into().unwrap());
        assert_eq!(t_imm, BASE + 4, "coldT resume = taken");

        let successor = lb.bytes.len() + 0x80;
        assert_guarded_publication(&lb.bytes, lb.edges[0], cold_t, successor);
        assert_guarded_publication(&lb.bytes, lb.edges[1], cold_f, successor + 0x40);
    }

    #[test]
    fn only_static_identity_syscalls_gain_a_chain_edge() {
        // ff e0  jmp rax — indirect, not chainable.
        static IND: &[u8] = &[0xff, 0xe0];
        assert!(plan_and_emit_linked(IND).edges.is_empty());
        // mov eax,60; syscall — ordinary exit_group remains the compact
        // dispatcher path and does not force FPU preservation/chaining.
        static SYS: &[u8] = &[0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05];
        let lb = plan_and_emit_linked(SYS);
        assert!(lb.edges.is_empty());
        // The fallback self-sets its resume (movabs of VA+7) before the
        // syscall exit stub.
        let needle = {
            let mut v = vec![0x48, 0xb8];
            v.extend_from_slice(&(BASE + 7).to_le_bytes());
            v
        };
        assert!(
            lb.bytes.windows(needle.len()).any(|w| w == needle),
            "syscall exit self-sets resume = VA after syscall"
        );

        // mov eax,39; syscall — statically known getpid gains exactly one
        // patchable edge to the post-syscall VA.
        static GETPID: &[u8] = &[0xb8, 0x27, 0x00, 0x00, 0x00, 0x0f, 0x05];
        let getpid = plan_and_emit_linked(GETPID);
        assert_eq!(getpid.edges.len(), 1);
        assert_eq!(getpid.edges[0].target_va, BASE + 7);
        let identity_edge = getpid.edges[0];
        let identity_cold = follow_rel32(
            &getpid.bytes,
            identity_edge.entry_rel32_off - 1,
            identity_edge.entry_rel32_off,
        );
        assert_guarded_publication(
            &getpid.bytes,
            identity_edge,
            identity_cold,
            getpid.bytes.len() + 0x80,
        );

        // int 0x80 uses the i386 syscall table: ordinal 39 is not getpid.
        static INT80_39: &[u8] = &[0xb8, 0x27, 0x00, 0x00, 0x00, 0xcd, 0x80];
        assert!(plan_and_emit_linked(INT80_39).edges.is_empty());
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
    fn all_xsave_forms_are_never_physically_emitted() {
        for image in [
            &[0x0f, 0xae, 0x64, 0x24, 0x40][..],
            &[0x48, 0x0f, 0xae, 0x64, 0x24, 0x40][..],
            &[0x0f, 0xae, 0x74, 0x24, 0x40][..],
            &[0x48, 0x0f, 0xae, 0x74, 0x24, 0x40][..],
            &[0x0f, 0xc7, 0x64, 0x24, 0x40][..],
            &[0x48, 0x0f, 0xc7, 0x64, 0x24, 0x40][..],
        ] {
            let out = plan_and_emit(image);
            assert_eq!(out.len(), 7, "only the sensitive-exit jump is emitted");
            assert_eq!(out, jmp_indirect_r15(CTX_EXIT_SENSITIVE_ADDR));
            assert!(
                !out.windows(image.len()).any(|window| window == image),
                "guest XSAVE bytes must never reach executable JIT memory"
            );
        }
    }

    #[test]
    fn exact_xrstor_forms_are_never_physically_emitted() {
        for image in [
            &[0x0f, 0xae, 0x6c, 0x24, 0x40][..],
            &[0x48, 0x0f, 0xae, 0x6c, 0x24, 0x40][..],
        ] {
            let out = plan_and_emit(image);
            assert_eq!(out.len(), 7, "only the sensitive-exit jump is emitted");
            assert_eq!(out, jmp_indirect_r15(CTX_EXIT_SENSITIVE_ADDR));
            assert!(
                !out.windows(image.len()).any(|window| window == image),
                "guest XRSTOR bytes must never reach executable JIT memory"
            );
        }
    }

    #[test]
    fn linked_return_emits_a_cold_monomorphic_cache_site() {
        let linked = plan_and_emit_linked(&[0xC3]); // ret
        let site = linked
            .indirect_cache
            .expect("a return should publish one indirect-cache site");
        assert_eq!(site.stack_adjust, 8);
        assert_eq!(
            &linked.bytes[site.site_id_imm_off..site.site_id_imm_off + 4],
            &[0; 4],
            "the runtime assigns a one-based site id before publication"
        );
        assert!(
            linked.fault_map.iter().any(|entry| entry.guest_va == BASE
                && entry.restores.contains(&ScratchRestore {
                    snapshot_gpr: crate::gateway::reg::RCX,
                    scratch_index: 1,
                })),
            "a return-stack fault must restore the temporary rcx spill"
        );
    }

    #[test]
    fn linked_return_immediate_records_the_exact_stack_advance() {
        let linked = plan_and_emit_linked(&[0xC2, 0x34, 0x12]); // ret $0x1234
        assert_eq!(
            linked.indirect_cache.map(|site| site.stack_adjust),
            Some(8 + 0x1234)
        );
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
    fn linked_fault_map_tracks_exact_verbatim_instruction() {
        // mov [rax],rbx; syscall
        let linked = plan_and_emit_linked(&[0x48, 0x89, 0x18, 0x0f, 0x05]);
        assert_eq!(linked.fault_map.len(), 1);
        assert_eq!(
            linked.fault_map[0],
            FaultMapEntry {
                emitted_start: 0,
                emitted_end: 3,
                guest_va: BASE,
                is_copied_x87: false,
                restores: Vec::new(),
            }
        );
    }

    #[test]
    fn linked_fault_map_marks_only_copied_x87_instructions_for_fip_recovery() {
        let x87 = plan_and_emit_linked(&[0xdb, 0x28, 0x0f, 0x05]); // fld tbyte ptr [rax]
        assert_eq!(x87.fault_map.len(), 1);
        assert!(x87.fault_map[0].is_copied_x87);
        let rip_x87 = plan_and_emit_linked(&[0xdb, 0x2d, 0, 0, 0, 0, 0x0f, 0x05]);
        assert!(rip_x87.fault_map[0].is_copied_x87);
        let mut expected_fip_witness = Vec::new();
        emit_copied_x87_guest_va(BASE, &mut expected_fip_witness);
        assert!(
            x87.bytes
                .windows(expected_fip_witness.len())
                .any(|bytes| bytes == expected_fip_witness),
            "completed copied x87 instructions must publish their exact guest VA"
        );
        assert!(
            rip_x87
                .bytes
                .windows(expected_fip_witness.len())
                .any(|bytes| bytes == expected_fip_witness),
            "rewritten RIP-relative x87 instructions must publish their exact guest VA"
        );
        let data_slot = (CTX_LAST_COPIED_X87_GUEST_DATA_VA as u32).to_le_bytes();
        assert!(
            x87.bytes
                .windows(7)
                .any(|bytes| bytes[..3] == [0x49, 0x89, 0x8f] && bytes[3..] == data_slot),
            "base/index copied x87 form must spill-compute and publish FDP"
        );
        assert!(
            rip_x87
                .bytes
                .windows(7)
                .any(|bytes| bytes[..3] == [0x49, 0x89, 0x87] && bytes[3..] == data_slot),
            "RIP-relative copied x87 form must publish its compile-time FDP"
        );
        let valid_slot = (CTX_LAST_COPIED_X87_DATA_VALID as u32).to_le_bytes();
        assert!(
            rip_x87.bytes.windows(11).any(|bytes| {
                bytes[..3] == [0x41, 0xc7, 0x87]
                    && bytes[3..7] == valid_slot
                    && bytes[7..] == 1_u32.to_le_bytes()
            }),
            "FDP validity must commit after the full address, including zero"
        );

        let mmx = plan_and_emit_linked(&[0x0f, 0x77, 0x0f, 0x05]); // emms
        assert_eq!(mmx.fault_map.len(), 1);
        assert!(!mmx.fault_map[0].is_copied_x87);
    }

    #[test]
    fn linked_fault_map_restores_rip_relative_scratch() {
        // mov edx,[rip+0x20]; syscall. The memory operation is emitted only
        // after rax is spilled and materializes the absolute guest address.
        let linked = plan_and_emit_linked(&[0x8b, 0x15, 0x20, 0, 0, 0, 0x0f, 0x05]);
        assert_eq!(linked.fault_map.len(), 1);
        assert_eq!(linked.fault_map[0].emitted_start, 17);
        assert_eq!(linked.fault_map[0].emitted_end, 19);
        assert_eq!(linked.fault_map[0].guest_va, BASE);
        assert_eq!(
            linked.fault_map[0].restores,
            vec![ScratchRestore {
                snapshot_gpr: crate::gateway::reg::RAX,
                scratch_index: 0,
            }]
        );
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

        let linked = emit_block_linked(IMG, &block).expect("emit linked continue");
        assert_eq!(linked.edges.len(), 1);
        assert_eq!(linked.edges[0].target_va, BASE + 2);
        let edge = linked.edges[0];
        let cold = follow_rel32(
            &linked.bytes,
            edge.entry_rel32_off - 1,
            edge.entry_rel32_off,
        );
        assert_guarded_publication(&linked.bytes, edge, cold, linked.bytes.len() + 0x80);
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
