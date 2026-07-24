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
//! Production stack and memory-indirect accesses flow through one neutral
//! [`ControlFlowMemory`] callback. This lets an identity-mapped runtime hold its
//! executable epoch and mapping guards for the complete access rather than
//! creating unchecked host pointers. [`ControlFlowPlan::resolve`] retains the
//! direct identity-memory behavior only as a native test convenience.

use iced_x86::{
    Code, ConditionCode, Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register,
};

use carrick_dsr::identity_memory::{
    ExecutableMutationAuthority, IdentityCheckedReadError, IdentityCheckedWriteError,
    IdentityGuestMemory, identity_checked_read_exact, identity_checked_write_exact,
};
use carrick_guest_mem::GuestVa;

use crate::gateway::{X86UcontextSnapshot, reg};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CflowMemoryAccess {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CflowMemoryFaultKind {
    Unmapped,
    AccessDenied,
    BusAddress,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CflowError {
    #[error("control-flow resolve: could not decode branch at 0x{va:x}")]
    Undecodable { va: u64 },
    #[error("control-flow resolve: branch form at 0x{va:x} is not lowered yet")]
    Unsupported { va: u64 },
    #[error("control-flow resolve: guest memory read {kind:?} at 0x{address:x}")]
    MemoryRead {
        address: u64,
        kind: CflowMemoryFaultKind,
    },
    #[error("control-flow resolve: guest memory write {kind:?} at 0x{address:x}")]
    MemoryWrite {
        address: u64,
        kind: CflowMemoryFaultKind,
    },
    #[error("control-flow resolve: {access:?} memory backend failed at 0x{address:x}: {detail}")]
    MemoryBackend {
        access: CflowMemoryAccess,
        address: u64,
        detail: String,
    },
}

/// Neutral memory seam for resolving call, return, and memory-indirect exits.
///
/// A single mutable object owns both operations so production runtimes do not
/// need two closures that simultaneously borrow their guest-memory backend.
pub trait ControlFlowMemory {
    fn read_u64(&mut self, address: u64) -> Result<u64, CflowError>;
    fn write_u64(&mut self, address: u64, value: u64) -> Result<(), CflowError>;
}

struct IdentityTestMemory;

impl ControlFlowMemory for IdentityTestMemory {
    fn read_u64(&mut self, address: u64) -> Result<u64, CflowError> {
        // SAFETY: this adapter is used only by the native test convenience
        // wrapper, whose callers provide live identity-mapped addresses.
        Ok(unsafe { (address as *const u64).read_unaligned() })
    }

    fn write_u64(&mut self, address: u64, value: u64) -> Result<(), CflowError> {
        // SAFETY: same native-test-only identity-memory contract as `read_u64`.
        unsafe { (address as *mut u64).write_unaligned(value) };
        Ok(())
    }
}

fn cflow_guest_memory_fault(
    access: CflowMemoryAccess,
    fault: carrick_guest_mem::protections::GuestMemoryFault,
) -> CflowError {
    let address = fault.address.raw();
    let kind = match fault.kind {
        carrick_guest_mem::protections::GuestMemoryFaultKind::Unmapped => {
            CflowMemoryFaultKind::Unmapped
        }
        carrick_guest_mem::protections::GuestMemoryFaultKind::AccessDenied => {
            CflowMemoryFaultKind::AccessDenied
        }
    };
    match access {
        CflowMemoryAccess::Read => CflowError::MemoryRead { address, kind },
        CflowMemoryAccess::Write => CflowError::MemoryWrite { address, kind },
    }
}

fn cflow_memory_backend_error(
    access: CflowMemoryAccess,
    address: u64,
    error: impl std::fmt::Display,
) -> CflowError {
    let _ = access;
    CflowError::MemoryBackend {
        access,
        address,
        detail: error.to_string(),
    }
}

#[cfg(test)]
fn cflow_raw_memory_fault(
    access: CflowMemoryAccess,
    address: u64,
    length: usize,
) -> Option<CflowError> {
    carrick_dsr::identity_memory::identity_raw_fault_address(address, length).map(|address| {
        match access {
            CflowMemoryAccess::Read => CflowError::MemoryRead {
                address,
                kind: CflowMemoryFaultKind::Unmapped,
            },
            CflowMemoryAccess::Write => CflowError::MemoryWrite {
                address,
                kind: CflowMemoryFaultKind::Unmapped,
            },
        }
    })
}

/// The only orphan-forced piece of the identity-memory closure: `IdentityGuestMemory<A>`
/// is foreign to this crate and `ControlFlowMemory` is foreign to `carrick-dsr`
/// (which does not depend on `carrick-dsr-x86`), so this impl can only live
/// here — see `carrick-dsr::identity_memory`'s module doc.
impl<A: ExecutableMutationAuthority> ControlFlowMemory for IdentityGuestMemory<A> {
    fn read_u64(&mut self, address: u64) -> Result<u64, CflowError> {
        const LENGTH: usize = std::mem::size_of::<u64>();
        let mut bytes = [0u8; LENGTH];
        identity_checked_read_exact(GuestVa(address), &mut bytes).map_err(|error| match error {
            IdentityCheckedReadError::Fault(fault) => {
                cflow_guest_memory_fault(CflowMemoryAccess::Read, fault)
            }
            IdentityCheckedReadError::BusAddress { address } => CflowError::MemoryRead {
                address: address.raw(),
                kind: CflowMemoryFaultKind::BusAddress,
            },
            IdentityCheckedReadError::Backend { address, detail } => {
                cflow_memory_backend_error(CflowMemoryAccess::Read, address.raw(), detail)
            }
        })?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn write_u64(&mut self, address: u64, value: u64) -> Result<(), CflowError> {
        identity_checked_write_exact(self, GuestVa(address), &value.to_le_bytes()).map_err(
            |error| match error {
                IdentityCheckedWriteError::Fault(fault) => {
                    cflow_guest_memory_fault(CflowMemoryAccess::Write, fault)
                }
                IdentityCheckedWriteError::BusAddress { address } => CflowError::MemoryWrite {
                    address: address.raw(),
                    kind: CflowMemoryFaultKind::BusAddress,
                },
                IdentityCheckedWriteError::Backend { address, detail } => {
                    cflow_memory_backend_error(CflowMemoryAccess::Write, address.raw(), detail)
                }
            },
        )
    }
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

    /// Native-test convenience wrapper over direct identity-mapped memory.
    /// Production runtimes must use [`Self::resolve_with_memory`].
    pub fn resolve(&self, snapshot: &mut X86UcontextSnapshot) -> Result<u64, CflowError> {
        self.resolve_with_memory(snapshot, &mut IdentityTestMemory)
    }

    pub fn resolve_with_memory<M: ControlFlowMemory + ?Sized>(
        &self,
        snapshot: &mut X86UcontextSnapshot,
        memory: &mut M,
    ) -> Result<u64, CflowError> {
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
                push64(snapshot, fallthrough, memory)?;
                Ok(target)
            }
            FlowControl::IndirectBranch => indirect_target(inst, va, snapshot, memory),
            FlowControl::IndirectCall => {
                // Read the target BEFORE the push (an rsp-based memory operand
                // must see the pre-call rsp, exactly like hardware).
                let target = indirect_target(inst, va, snapshot, memory)?;
                push64(snapshot, fallthrough, memory)?;
                Ok(target)
            }
            FlowControl::Return => {
                let rsp = snapshot.gpr[reg::RSP];
                let target = memory.read_u64(rsp)?;
                let stack_adjust = 8 + if inst.code() == Code::Retnq_imm16 {
                    u64::from(inst.immediate16())
                } else {
                    0
                };
                // Architectural stack state changes only after the read
                // succeeds. A failed access leaves the snapshot retryable.
                snapshot.gpr[reg::RSP] = rsp.wrapping_add(stack_adjust);
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
fn indirect_target<M: ControlFlowMemory + ?Sized>(
    inst: &Instruction,
    va: u64,
    snapshot: &X86UcontextSnapshot,
    memory: &mut M,
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
            memory.read_u64(addr)
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

fn push64<M: ControlFlowMemory + ?Sized>(
    snapshot: &mut X86UcontextSnapshot,
    value: u64,
    memory: &mut M,
) -> Result<(), CflowError> {
    let rsp = snapshot.gpr[reg::RSP].wrapping_sub(8);
    memory.write_u64(rsp, value)?;
    // Architectural stack state changes only after the write succeeds.
    snapshot.gpr[reg::RSP] = rsp;
    Ok(())
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
    use carrick_guest_mem::protections::{GuestMemoryFault, GuestMemoryFaultKind};
    #[cfg(target_os = "freebsd")]
    use std::os::fd::AsRawFd;

    const VA: u64 = 0x40_0000;

    /// Test-only, no-op `ExecutableMutationAuthority`: these tests exercise
    /// `IdentityGuestMemory::uncoordinated()`, whose `executable_epoch` is
    /// always `None`, so this trait's own method is never actually invoked —
    /// it exists only because `IdentityGuestMemory<A>` needs a concrete `A`
    /// to monomorphize against. Its only consumer
    /// (`cflow_write_contains_truncated_shared_mapping_bus_faults`) is
    /// FreeBSD-gated (see that test's own doc comment).
    #[cfg(target_os = "freebsd")]
    struct TestMutationAuthority;

    #[cfg(target_os = "freebsd")]
    impl ExecutableMutationAuthority for TestMutationAuthority {
        type Lease = ();
        type Error = std::convert::Infallible;

        fn begin_mutation(self: &std::sync::Arc<Self>) -> Result<Self::Lease, Self::Error> {
            unreachable!("uncoordinated() never binds an executable_epoch")
        }
    }

    fn snap() -> X86UcontextSnapshot {
        X86UcontextSnapshot::new()
    }

    #[derive(Default)]
    struct RecordingMemory {
        read_value: u64,
        reads: Vec<u64>,
        writes: Vec<(u64, u64)>,
        fail_read: bool,
        fail_write: bool,
    }

    impl ControlFlowMemory for RecordingMemory {
        fn read_u64(&mut self, address: u64) -> Result<u64, CflowError> {
            self.reads.push(address);
            if self.fail_read {
                Err(CflowError::MemoryRead {
                    address,
                    kind: CflowMemoryFaultKind::Unmapped,
                })
            } else {
                Ok(self.read_value)
            }
        }

        fn write_u64(&mut self, address: u64, value: u64) -> Result<(), CflowError> {
            self.writes.push((address, value));
            if self.fail_write {
                Err(CflowError::MemoryWrite {
                    address,
                    kind: CflowMemoryFaultKind::Unmapped,
                })
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn callback_services_indirect_call_read_then_stack_write_once() {
        let plan = ControlFlowPlan::decode(&[0xff, 0x14, 0x24], VA).expect("decode call [rsp]");
        let mut s = snap();
        s.gpr[reg::RSP] = 0x8000;
        let mut memory = RecordingMemory {
            read_value: 0x55_0000,
            ..RecordingMemory::default()
        };

        let target = plan
            .resolve_with_memory(&mut s, &mut memory)
            .expect("resolve indirect call");

        assert_eq!(target, 0x55_0000);
        assert_eq!(memory.reads, vec![0x8000], "target read exactly once");
        assert_eq!(memory.writes, vec![(0x7ff8, VA + 3)]);
        assert_eq!(s.gpr[reg::RSP], 0x7ff8);
    }

    #[test]
    fn failed_indirect_call_reads_target_once_without_pushing() {
        let plan = ControlFlowPlan::decode(&[0xff, 0x14, 0x24], VA).expect("decode call [rsp]");
        let mut snapshot = snap();
        snapshot.gpr[reg::RSP] = 0x8000;
        let mut memory = RecordingMemory {
            fail_read: true,
            ..RecordingMemory::default()
        };

        assert_eq!(
            plan.resolve_with_memory(&mut snapshot, &mut memory),
            Err(CflowError::MemoryRead {
                address: 0x8000,
                kind: CflowMemoryFaultKind::Unmapped,
            })
        );
        assert_eq!(memory.reads, vec![0x8000], "target read exactly once");
        assert!(memory.writes.is_empty(), "failed target read cannot push");
        assert_eq!(snapshot.gpr[reg::RSP], 0x8000);
    }

    #[test]
    fn callback_memory_failure_leaves_stack_state_unchanged() {
        let call = ControlFlowPlan::decode(&[0xe8, 0, 0, 0, 0], VA).expect("decode call");
        let mut call_snapshot = snap();
        call_snapshot.gpr[reg::RSP] = 0x9000;
        let mut write_fails = RecordingMemory {
            fail_write: true,
            ..RecordingMemory::default()
        };
        assert_eq!(
            call.resolve_with_memory(&mut call_snapshot, &mut write_fails),
            Err(CflowError::MemoryWrite {
                address: 0x8ff8,
                kind: CflowMemoryFaultKind::Unmapped,
            })
        );
        assert_eq!(call_snapshot.gpr[reg::RSP], 0x9000);

        let ret = ControlFlowPlan::decode(&[0xc3], VA).expect("decode ret");
        let mut ret_snapshot = snap();
        ret_snapshot.gpr[reg::RSP] = 0xa000;
        let mut read_fails = RecordingMemory {
            fail_read: true,
            ..RecordingMemory::default()
        };
        assert_eq!(
            ret.resolve_with_memory(&mut ret_snapshot, &mut read_fails),
            Err(CflowError::MemoryRead {
                address: 0xa000,
                kind: CflowMemoryFaultKind::Unmapped,
            })
        );
        assert_eq!(read_fails.reads, vec![0xa000], "return read exactly once");
        assert_eq!(ret_snapshot.gpr[reg::RSP], 0xa000);
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

    #[test]
    fn cflow_only_exposes_guest_access_failures_as_retryable_faults() {
        let address = 0x1234_5000;
        assert_eq!(
            cflow_guest_memory_fault(
                CflowMemoryAccess::Read,
                GuestMemoryFault {
                    address: carrick_guest_mem::GuestVa(address),
                    kind: GuestMemoryFaultKind::AccessDenied,
                },
            ),
            CflowError::MemoryRead {
                address,
                kind: CflowMemoryFaultKind::AccessDenied,
            }
        );
        assert_eq!(
            cflow_raw_memory_fault(CflowMemoryAccess::Read, (1 << 47) - 4, 8),
            Some(CflowError::MemoryRead {
                address: 1 << 47,
                kind: CflowMemoryFaultKind::Unmapped,
            }),
            "cross-boundary faults name the first inaccessible byte"
        );
        assert_eq!(
            cflow_memory_backend_error(
                CflowMemoryAccess::Write,
                address,
                carrick_guest_mem::MemoryError::HostMap("injected coordinator failure".into()),
            ),
            CflowError::MemoryBackend {
                access: CflowMemoryAccess::Write,
                address,
                detail: "host mapping operation failed: injected coordinator failure".into(),
            }
        );
    }

    // FreeBSD-only: this pins a real host-kernel behavior difference, not a
    // portability bug in `identity_kernel_copyout_exact`'s pipe-based
    // containment trick. The write/read/pipe syscalls it uses exist
    // identically on Darwin, but writing into a nonblocking pipe from a
    // truncated `MAP_SHARED` file mapping only raises `EFAULT` on FreeBSD;
    // this `IdentityGuestMemory` model is only ever instantiated by the
    // FreeBSD/x86_64 native lane in production (Darwin's native lane uses a
    // completely different `NativeDispatchMemory`/aarch64-translator type),
    // so this is exactly the "moved code compiles everywhere, this one
    // assertion is host-specific" case the parent plan anticipated.
    #[test]
    #[cfg(target_os = "freebsd")]
    fn cflow_write_contains_truncated_shared_mapping_bus_faults() {
        use carrick_dsr::identity_memory::{
            IDENTITY_HOST_MAPPING_LOCK, IDENTITY_PROTECTIONS, identity_kernel_copy_pipe_census,
            identity_kernel_copyout_operation_census, reset_identity_kernel_copy_pipe_census,
            reset_identity_kernel_copyout_operation_census,
        };

        const LEN: usize = 8192;
        const FILE_END: u64 = 4096;
        let file = tempfile::tempfile().expect("temporary file backing");
        file.set_len(LEN as u64).expect("size file backing");
        // SAFETY: this test owns the file and complete shared mapping.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                LEN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let address = mapping as u64;
        {
            let _mapping_guard = IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_mapping_protection_and_sharing(
                address,
                LEN,
                false,
                false,
                carrick_guest_mem::MappingSharing::Shared,
            );
        }
        file.set_len(FILE_END)
            .expect("truncate writable shared mapping");

        let value = 0x8877_6655_4433_2211u64;
        let mut memory = IdentityGuestMemory::<TestMutationAuthority>::uncoordinated();
        {
            let _mapping_guard = IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_no_access(address + FILE_END, 4096, true);
        }
        assert_eq!(
            memory.write_u64(address + FILE_END, value),
            Err(CflowError::MemoryWrite {
                address: address + FILE_END,
                kind: CflowMemoryFaultKind::AccessDenied,
            }),
            "registry ACCERR must take precedence over truncated backing"
        );
        {
            let _mapping_guard = IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_no_access(address + FILE_END, 4096, false);
            IDENTITY_PROTECTIONS.set_unmapped(address + FILE_END, 4096, true);
        }
        assert_eq!(
            memory.write_u64(address + FILE_END, value),
            Err(CflowError::MemoryWrite {
                address: address + FILE_END,
                kind: CflowMemoryFaultKind::Unmapped,
            }),
            "registry MAPERR must take precedence over truncated backing"
        );
        {
            let _mapping_guard = IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_mapping_protection_and_sharing(
                address + FILE_END,
                4096,
                false,
                false,
                carrick_guest_mem::MappingSharing::Shared,
            );
        }
        reset_identity_kernel_copy_pipe_census();
        reset_identity_kernel_copyout_operation_census();
        assert_eq!(
            memory.write_u64(address + FILE_END, value),
            Err(CflowError::MemoryWrite {
                address: address + FILE_END,
                kind: CflowMemoryFaultKind::BusAddress,
            }),
            "kernel copyout must contain host SIGBUS and keep the cflow write retryable"
        );
        assert!(identity_kernel_copy_pipe_census() > 0);
        assert!(
            identity_kernel_copyout_operation_census() > 0,
            "truncatable shared writes must retain kernel-contained copyout"
        );

        file.set_len(LEN as u64).expect("repair file backing");
        reset_identity_kernel_copy_pipe_census();
        reset_identity_kernel_copyout_operation_census();
        memory
            .write_u64(address + FILE_END, value)
            .expect("repaired shared stack slot accepts the retried push");
        assert!(identity_kernel_copy_pipe_census() > 0);
        assert!(identity_kernel_copyout_operation_census() > 0);
        let mut found = [0u8; 8];
        // SAFETY: `found` is writable and the repaired file range is live.
        assert_eq!(
            unsafe {
                libc::pread(
                    file.as_raw_fd(),
                    found.as_mut_ptr().cast(),
                    found.len(),
                    FILE_END as libc::off_t,
                )
            },
            found.len() as isize
        );
        assert_eq!(found, value.to_le_bytes());

        {
            let _mapping_guard = IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_unmapped(address, LEN, true);
            // SAFETY: this test owns the complete mapping.
            assert_eq!(unsafe { libc::munmap(mapping, LEN) }, 0);
        }
    }
}
