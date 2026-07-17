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

use iced_x86::{ConditionCode, Decoder, DecoderOptions, FlowControl, Instruction};

use crate::gateway::{X86UcontextSnapshot, reg};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CflowError {
    #[error("control-flow resolve: could not decode branch at 0x{va:x}")]
    Undecodable { va: u64 },
    #[error("control-flow resolve: branch form at 0x{va:x} is not lowered yet")]
    Unsupported { va: u64 },
}

/// Resolve the branch that terminates a block. `bytes` starts at the branch
/// instruction, `va` is its guest VA. Returns the next guest VA to translate.
/// For `call`/`ret`, mutates `snapshot.gpr[RSP]` and the guest stack.
pub fn resolve(
    bytes: &[u8],
    va: u64,
    snapshot: &mut X86UcontextSnapshot,
) -> Result<u64, CflowError> {
    let mut decoder = Decoder::with_ip(64, bytes, va, DecoderOptions::NONE);
    let inst: Instruction = decoder.decode();
    if inst.is_invalid() {
        return Err(CflowError::Undecodable { va });
    }
    let len = inst.len() as u64;
    let fallthrough = va + len;

    match inst.flow_control() {
        FlowControl::UnconditionalBranch => rel_target(&inst, va),
        FlowControl::ConditionalBranch => {
            if condition_holds(inst.condition_code(), snapshot.rflags) {
                rel_target(&inst, va)
            } else {
                Ok(fallthrough)
            }
        }
        FlowControl::Call => {
            let target = rel_target(&inst, va)?;
            push64(snapshot, fallthrough);
            Ok(target)
        }
        FlowControl::Return => Ok(pop64(snapshot)),
        _ => Err(CflowError::Unsupported { va }),
    }
}

/// Absolute target of a near rel8/rel32 branch. Indirect (register/memory)
/// branches are not lowered yet.
fn rel_target(inst: &Instruction, va: u64) -> Result<u64, CflowError> {
    match inst.op0_kind() {
        iced_x86::OpKind::NearBranch64 => Ok(inst.near_branch64()),
        _ => Err(CflowError::Unsupported { va }),
    }
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
    fn indirect_branch_is_unsupported_for_now() {
        // ff e0  jmp rax
        let mut s = snap();
        assert_eq!(
            resolve(&[0xff, 0xe0], VA, &mut s),
            Err(CflowError::Unsupported { va: VA })
        );
    }
}
