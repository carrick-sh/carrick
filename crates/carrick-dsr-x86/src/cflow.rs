//! Control-flow resolution: given a block's terminating branch and the guest
//! register/flag snapshot captured at the indirect exit, compute the next
//! guest VA (and apply the branch's stack effect for `call`/`ret`).
//!
//! Keeping this in Rust — rather than emitting flag-evaluating code — means
//! every branch takes a gateway round-trip (correct, unchained); direct-branch
//! chaining that patches blocks together is the later fast path. The exit stub
//! captures `rflags`, so conditional branches evaluate against real guest
//! flags here.
//!
//! Stack effect for `call`/`ret` writes/reads the guest stack directly: in the
//! native model a guest VA IS a host VA (guest memory is mapped into the host
//! address space), so `snapshot.gpr[RSP]` is a live host pointer. A guest with
//! an unmapped stack faults through the (M2-runtime) signal shim, not here.

use iced_x86::{
    Code, ConditionCode, Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register,
};

use crate::gateway::{X86UcontextSnapshot, reg};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CflowError {
    #[error("control-flow resolve: could not decode branch at 0x{va:x}")]
    Undecodable { va: u64 },
    #[error("control-flow resolve: branch form at 0x{va:x} is not lowered yet")]
    Unsupported { va: u64 },
}

/// Predecoded control-flow instruction. Hot indirect sites (especially `ret`)
/// reuse this plan instead of rebuilding iced-x86's decoder tables on every
/// gateway round-trip.
#[derive(Clone, Debug)]
pub struct ControlFlowPlan {
    instruction: Instruction,
    va: u64,
    fallthrough: u64,
}

impl ControlFlowPlan {
    pub fn decode(bytes: &[u8], va: u64) -> Result<Self, CflowError> {
        let mut decoder = Decoder::with_ip(64, bytes, va, DecoderOptions::NONE);
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return Err(CflowError::Undecodable { va });
        }
        Ok(Self {
            fallthrough: va + instruction.len() as u64,
            instruction,
            va,
        })
    }

    pub fn resolve(&self, snapshot: &mut X86UcontextSnapshot) -> Result<u64, CflowError> {
        let inst = &self.instruction;
        let va = self.va;
        let fallthrough = self.fallthrough;
        match inst.flow_control() {
            FlowControl::UnconditionalBranch => rel_target(inst, va),
            FlowControl::ConditionalBranch => {
                let taken = match counter_branch_taken(inst, snapshot) {
                    Some(taken) => taken,
                    None => condition_holds(inst.condition_code(), snapshot.rflags),
                };
                if taken {
                    rel_target(inst, va)
                } else {
                    Ok(fallthrough)
                }
            }
            FlowControl::Call => {
                let target = rel_target(inst, va)?;
                push64(snapshot, fallthrough);
                Ok(target)
            }
            FlowControl::IndirectBranch => indirect_target(inst, va, snapshot),
            FlowControl::IndirectCall => {
                // Read the target BEFORE the push (an rsp-based memory operand
                // must see the pre-call rsp, exactly like hardware).
                let target = indirect_target(inst, va, snapshot)?;
                push64(snapshot, fallthrough);
                Ok(target)
            }
            FlowControl::Return => {
                let target = pop64(snapshot);
                // `ret imm16` additionally releases the callee-popped argument
                // bytes after the return address.
                if inst.code() == Code::Retnq_imm16 {
                    snapshot.gpr[reg::RSP] =
                        snapshot.gpr[reg::RSP].wrapping_add(u64::from(inst.immediate16()));
                }
                Ok(target)
            }
            _ => Err(CflowError::Unsupported { va }),
        }
    }
}

/// Resolve the branch that terminates a block. `bytes` starts at the branch
/// instruction, `va` is its guest VA. Returns the next guest VA to translate.
/// For `call`/`ret`, mutates `snapshot.gpr[RSP]` and the guest stack.
pub fn resolve(
    bytes: &[u8],
    va: u64,
    snapshot: &mut X86UcontextSnapshot,
) -> Result<u64, CflowError> {
    ControlFlowPlan::decode(bytes, va)?.resolve(snapshot)
}

/// Absolute target of a near rel8/rel32 branch.
fn rel_target(inst: &Instruction, va: u64) -> Result<u64, CflowError> {
    match inst.op0_kind() {
        OpKind::NearBranch64 => Ok(inst.near_branch64()),
        _ => Err(CflowError::Unsupported { va }),
    }
}

/// Target of an indirect `jmp/call r/m64`: the register value, or a 64-bit
/// load from the resolved effective address (guest VA == host VA natively).
/// Far forms and segment-prefixed operands (the base would need the swapped
/// fs/gs base, which is not live here on the host side) stay unsupported.
fn indirect_target(
    inst: &Instruction,
    va: u64,
    snapshot: &X86UcontextSnapshot,
) -> Result<u64, CflowError> {
    match inst.op0_kind() {
        OpKind::Register => gpr_value(inst.op0_register(), snapshot, va),
        OpKind::Memory => {
            if inst.segment_prefix() == Register::FS || inst.segment_prefix() == Register::GS {
                return Err(CflowError::Unsupported { va });
            }
            let mut addr = inst.memory_displacement64();
            let base = inst.memory_base();
            if base != Register::None && base != Register::RIP {
                // RIP-relative displacement64 is already absolute (the
                // decoder ran with the branch VA as IP).
                addr = addr.wrapping_add(gpr_value(base, snapshot, va)?);
            }
            let index = inst.memory_index();
            if index != Register::None {
                let scaled = gpr_value(index, snapshot, va)?
                    .wrapping_mul(u64::from(inst.memory_index_scale()));
                addr = addr.wrapping_add(scaled);
            }
            // SAFETY: addr is a guest VA == host VA in the native mapping
            // model; a bad guest pointer faults through the signal shim.
            Ok(unsafe { (addr as *const u64).read_unaligned() })
        }
        _ => Err(CflowError::Unsupported { va }),
    }
}

/// The 64-bit value of a full-width GPR from the snapshot (indirect branch
/// operands are always 64-bit in long mode). The snapshot's gpr array is in
/// x86 encoding order, which is exactly iced's RAX..R15 enum order.
fn gpr_value(
    register: Register,
    snapshot: &X86UcontextSnapshot,
    va: u64,
) -> Result<u64, CflowError> {
    if !matches!(register as u32, r if (Register::RAX as u32..=Register::R15 as u32).contains(&r)) {
        return Err(CflowError::Unsupported { va });
    }
    let index = (register as u32 - Register::RAX as u32) as usize;
    Ok(snapshot.gpr[index])
}

fn push64(snapshot: &mut X86UcontextSnapshot, value: u64) {
    let rsp = snapshot.gpr[reg::RSP].wrapping_sub(8);
    snapshot.gpr[reg::RSP] = rsp;
    // SAFETY: rsp is a guest VA == host VA in the native mapping model.
    unsafe { (rsp as *mut u64).write_unaligned(value) };
}

fn pop64(snapshot: &mut X86UcontextSnapshot) -> u64 {
    let rsp = snapshot.gpr[reg::RSP];
    // SAFETY: as above; a bad guest rsp faults through the signal shim.
    let value = unsafe { (rsp as *const u64).read_unaligned() };
    snapshot.gpr[reg::RSP] = rsp.wrapping_add(8);
    value
}

// rflags bit positions.
const CF: u64 = 1 << 0;
const PF: u64 = 1 << 2;
const ZF: u64 = 1 << 6;
const SF: u64 = 1 << 7;
const OF: u64 = 1 << 11;

#[derive(Clone, Copy)]
enum CounterWidth {
    Cx,
    Ecx,
    Rcx,
}

#[derive(Clone, Copy)]
enum CounterBranch {
    Zero(CounterWidth),
    Loop(CounterWidth),
    LoopEqual(CounterWidth),
    LoopNotEqual(CounterWidth),
}

fn counter_branch_kind(code: Code) -> Option<CounterBranch> {
    use CounterBranch::{Loop, LoopEqual, LoopNotEqual, Zero};
    use CounterWidth::{Cx, Ecx, Rcx};
    Some(match code {
        Code::Jcxz_rel8_16 | Code::Jcxz_rel8_32 => Zero(Cx),
        Code::Jecxz_rel8_16 | Code::Jecxz_rel8_32 | Code::Jecxz_rel8_64 => Zero(Ecx),
        Code::Jrcxz_rel8_16 | Code::Jrcxz_rel8_64 => Zero(Rcx),
        Code::Loop_rel8_16_CX | Code::Loop_rel8_32_CX => Loop(Cx),
        Code::Loop_rel8_16_ECX | Code::Loop_rel8_32_ECX | Code::Loop_rel8_64_ECX => Loop(Ecx),
        Code::Loop_rel8_16_RCX | Code::Loop_rel8_64_RCX => Loop(Rcx),
        Code::Loope_rel8_16_CX | Code::Loope_rel8_32_CX => LoopEqual(Cx),
        Code::Loope_rel8_16_ECX | Code::Loope_rel8_32_ECX | Code::Loope_rel8_64_ECX => {
            LoopEqual(Ecx)
        }
        Code::Loope_rel8_16_RCX | Code::Loope_rel8_64_RCX => LoopEqual(Rcx),
        Code::Loopne_rel8_16_CX | Code::Loopne_rel8_32_CX => LoopNotEqual(Cx),
        Code::Loopne_rel8_16_ECX | Code::Loopne_rel8_32_ECX | Code::Loopne_rel8_64_ECX => {
            LoopNotEqual(Ecx)
        }
        Code::Loopne_rel8_16_RCX | Code::Loopne_rel8_64_RCX => LoopNotEqual(Rcx),
        _ => return None,
    })
}

fn counter_value(snapshot: &X86UcontextSnapshot, width: CounterWidth) -> u64 {
    match width {
        CounterWidth::Cx => snapshot.gpr[reg::RCX] & u64::from(u16::MAX),
        CounterWidth::Ecx => snapshot.gpr[reg::RCX] & u64::from(u32::MAX),
        CounterWidth::Rcx => snapshot.gpr[reg::RCX],
    }
}

fn decrement_counter(snapshot: &mut X86UcontextSnapshot, width: CounterWidth) -> u64 {
    let old = snapshot.gpr[reg::RCX];
    match width {
        CounterWidth::Cx => {
            let low = (old as u16).wrapping_sub(1);
            snapshot.gpr[reg::RCX] = (old & !u64::from(u16::MAX)) | u64::from(low);
            u64::from(low)
        }
        CounterWidth::Ecx => {
            let low = (old as u32).wrapping_sub(1);
            snapshot.gpr[reg::RCX] = u64::from(low);
            u64::from(low)
        }
        CounterWidth::Rcx => {
            let value = old.wrapping_sub(1);
            snapshot.gpr[reg::RCX] = value;
            value
        }
    }
}

fn counter_branch_taken(inst: &Instruction, snapshot: &mut X86UcontextSnapshot) -> Option<bool> {
    let kind = counter_branch_kind(inst.code())?;
    Some(match kind {
        CounterBranch::Zero(width) => counter_value(snapshot, width) == 0,
        CounterBranch::Loop(width) => decrement_counter(snapshot, width) != 0,
        CounterBranch::LoopEqual(width) => {
            decrement_counter(snapshot, width) != 0 && snapshot.rflags & ZF != 0
        }
        CounterBranch::LoopNotEqual(width) => {
            decrement_counter(snapshot, width) != 0 && snapshot.rflags & ZF == 0
        }
    })
}

fn condition_holds(code: ConditionCode, flags: u64) -> bool {
    let cf = flags & CF != 0;
    let pf = flags & PF != 0;
    let zf = flags & ZF != 0;
    let sf = flags & SF != 0;
    let of = flags & OF != 0;
    match code {
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
        // `None` is not a conditional branch; treated as always-taken is
        // wrong, so report unsupported by returning false is also wrong —
        // callers only reach here for ConditionalBranch flow, which always
        // carries a real code. Default false is unreachable in practice.
        ConditionCode::None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VA: u64 = 0x40_0000;

    fn snap() -> X86UcontextSnapshot {
        X86UcontextSnapshot::new()
    }

    #[test]
    fn unconditional_jmp_targets_the_rel() {
        // eb 05  jmp +5 (from end of instruction): target = VA + 2 + 5
        let mut s = snap();
        assert_eq!(resolve(&[0xeb, 0x05], VA, &mut s).unwrap(), VA + 7);
    }

    #[test]
    fn conditional_branch_evaluates_guest_flags() {
        // 74 05  je +5 : taken iff ZF
        let taken_va = VA + 7;
        let fall_va = VA + 2;
        let mut s = snap();
        s.rflags |= ZF;
        assert_eq!(resolve(&[0x74, 0x05], VA, &mut s).unwrap(), taken_va);
        s.rflags &= !ZF;
        assert_eq!(resolve(&[0x74, 0x05], VA, &mut s).unwrap(), fall_va);
    }

    #[test]
    fn counter_branches_use_and_update_rcx_without_changing_flags() {
        let mut s = snap();
        s.rflags = 0x202 | ZF;
        let flags = s.rflags;

        // e3 05  jrcxz +5: tests RCX directly and does not decrement it. GNU
        // GMP's __gmpn_add_n uses this exact shape for limb counts below four;
        // treating ConditionCode::None as false wrapped RCX and ran off-heap.
        s.gpr[reg::RCX] = 0;
        assert_eq!(resolve(&[0xe3, 0x05], VA, &mut s).unwrap(), VA + 7);
        assert_eq!(s.gpr[reg::RCX], 0);
        s.gpr[reg::RCX] = 1;
        assert_eq!(resolve(&[0xe3, 0x05], VA, &mut s).unwrap(), VA + 2);
        assert_eq!(s.gpr[reg::RCX], 1);

        // e2 fe  loop -2: decrements RCX and branches while nonzero.
        s.gpr[reg::RCX] = 2;
        assert_eq!(resolve(&[0xe2, 0xfe], VA, &mut s).unwrap(), VA);
        assert_eq!(s.gpr[reg::RCX], 1);
        s.gpr[reg::RCX] = 1;
        assert_eq!(resolve(&[0xe2, 0xfe], VA, &mut s).unwrap(), VA + 2);
        assert_eq!(s.gpr[reg::RCX], 0);

        // e1 fe  loope -2: also requires ZF, but preserves all flags.
        s.gpr[reg::RCX] = 2;
        assert_eq!(resolve(&[0xe1, 0xfe], VA, &mut s).unwrap(), VA);
        assert_eq!(s.gpr[reg::RCX], 1);
        assert_eq!(s.rflags, flags);
    }

    #[test]
    fn signed_and_unsigned_conditions_differ() {
        // 7c 02  jl +2 : taken iff SF != OF
        let mut s = snap();
        s.rflags |= SF; // SF=1, OF=0 -> SF!=OF -> taken
        assert_eq!(resolve(&[0x7c, 0x02], VA, &mut s).unwrap(), VA + 4);
        s.rflags |= OF; // SF=1, OF=1 -> equal -> fall through
        assert_eq!(resolve(&[0x7c, 0x02], VA, &mut s).unwrap(), VA + 2);
    }

    #[test]
    fn call_pushes_return_address_and_ret_pops_it() {
        // Give the guest a real stack in this process's address space.
        let stack = vec![0u8; 4096];
        let top = stack.as_ptr() as u64 + 4096;
        let mut s = snap();
        s.gpr[reg::RSP] = top;
        // e8 00 00 00 00  call +0 : target = VA+5, pushes return addr VA+5
        let target = resolve(&[0xe8, 0, 0, 0, 0], VA, &mut s).unwrap();
        assert_eq!(target, VA + 5);
        assert_eq!(s.gpr[reg::RSP], top - 8, "call decremented rsp");
        // c3  ret : pops the pushed return address
        let ret_to = resolve(&[0xc3], target, &mut s).unwrap();
        assert_eq!(ret_to, VA + 5, "ret returns to the pushed address");
        assert_eq!(s.gpr[reg::RSP], top, "ret restored rsp");
    }

    #[test]
    fn indirect_register_branch_reads_the_snapshot() {
        // ff e0  jmp rax
        let mut s = snap();
        s.gpr[reg::RAX] = 0x77_0000;
        assert_eq!(resolve(&[0xff, 0xe0], VA, &mut s).unwrap(), 0x77_0000);
        // ff e7  jmp rdi
        s.gpr[reg::RDI] = 0x88_0000;
        assert_eq!(resolve(&[0xff, 0xe7], VA, &mut s).unwrap(), 0x88_0000);
        // 41 ff e7  jmp r15 — the VIRTUALIZED register resolves from the
        // snapshot like any other (the live r15 is the context pointer, but
        // cflow never touches live registers).
        s.gpr[reg::R15] = 0x99_0000;
        assert_eq!(resolve(&[0x41, 0xff, 0xe7], VA, &mut s).unwrap(), 0x99_0000);
    }

    #[test]
    fn indirect_memory_branch_loads_the_target() {
        // A function-pointer table in this process's memory (guest VA == host
        // VA in the native model).
        let table: Vec<u64> = vec![0x11_0000, 0x22_0000, 0x33_0000];
        let mut s = snap();
        s.gpr[reg::RAX] = table.as_ptr() as u64;
        s.gpr[reg::RCX] = 2;
        // ff 20         jmp [rax]
        assert_eq!(resolve(&[0xff, 0x20], VA, &mut s).unwrap(), 0x11_0000);
        // ff 24 c8      jmp [rax+rcx*8] — scaled index (switch-table shape)
        assert_eq!(resolve(&[0xff, 0x24, 0xc8], VA, &mut s).unwrap(), 0x33_0000);
        // ff 60 08      jmp [rax+8] — displacement (PLT/vtable shape)
        assert_eq!(resolve(&[0xff, 0x60, 0x08], VA, &mut s).unwrap(), 0x22_0000);
    }

    #[test]
    fn indirect_call_pushes_the_return_address_after_reading_the_target() {
        let stack = vec![0u8; 4096];
        let top = stack.as_ptr() as u64 + 4096;
        let mut s = snap();
        s.gpr[reg::RSP] = top;
        s.gpr[reg::RDX] = 0x55_0000;
        // ff d2  call rdx
        let target = resolve(&[0xff, 0xd2], VA, &mut s).unwrap();
        assert_eq!(target, 0x55_0000);
        assert_eq!(s.gpr[reg::RSP], top - 8);
        // The pushed return address is the fallthrough (VA + 2).
        let pushed = unsafe { ((top - 8) as *const u64).read_unaligned() };
        assert_eq!(pushed, VA + 2);
    }

    #[test]
    fn ret_imm16_releases_callee_popped_bytes() {
        let stack = vec![0u8; 4096];
        let top = stack.as_ptr() as u64 + 4096;
        let mut s = snap();
        // A return address at [top-24] with 16 bytes of stack args above it.
        s.gpr[reg::RSP] = top - 24;
        unsafe { ((top - 24) as *mut u64).write_unaligned(0x66_0000) };
        // c2 10 00  ret 0x10
        assert_eq!(resolve(&[0xc2, 0x10, 0x00], VA, &mut s).unwrap(), 0x66_0000);
        assert_eq!(s.gpr[reg::RSP], top, "rsp released ra + 16 arg bytes");
    }

    #[test]
    fn segment_prefixed_indirect_branches_stay_unsupported() {
        // 64 ff 20  jmp fs:[rax] — the host-side resolver has no live guest
        // fs base to honor; fail closed.
        let mut s = snap();
        s.gpr[reg::RAX] = 0x1000;
        assert_eq!(
            resolve(&[0x64, 0xff, 0x20], VA, &mut s),
            Err(CflowError::Unsupported { va: VA })
        );
    }
}
