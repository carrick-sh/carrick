//! Shared checked effective-address machinery for XSAVE-family emulation.
//!
//! Iced supplies the decoded long-mode memory operand. This module resolves it
//! only against the captured guest register file and explicit virtual segment
//! bases; it never converts the resulting guest address to a host pointer.

use carrick_guest_mem::GuestVa;
use iced_x86::{CodeSize, Instruction, InstructionInfoFactory, OpKind, Register};

use crate::gateway::{X86UcontextSnapshot, reg};

/// A guest GS base must be supplied deliberately. Most Linux/x86_64 tasks use
/// an architectural zero GS base; callers that virtualize GS can name a value
/// without conflating it with FS.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum X86GuestGsBase {
    #[default]
    Zero,
    Value(u64),
}

impl X86GuestGsBase {
    const fn raw(self) -> u64 {
        match self {
            Self::Zero => 0,
            Self::Value(value) => value,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum X86XstateAddressError {
    UnsupportedInstruction,
    UnsupportedAddressSize,
    UnsupportedSegment,
    UnsupportedAddressForm,
    GeneralProtectionNoncanonical,
    StackSegmentNoncanonical,
    MisalignedAddress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct X86XstateResolvedAddress {
    pub address: GuestVa,
    pub instruction_len: u8,
    pub effective_segment_is_ss: bool,
}

pub(crate) fn resolve_xstate_memory_operand(
    instruction: &Instruction,
    snapshot: &X86UcontextSnapshot,
    guest_fsbase: u64,
    guest_gsbase: X86GuestGsBase,
) -> Result<X86XstateResolvedAddress, X86XstateAddressError> {
    resolve_sensitive_memory_operand(instruction, snapshot, guest_fsbase, guest_gsbase, 64)
}

/// Resolve one sensitive long-mode memory operand through captured guest state.
/// `required_alignment` is architectural: XSAVE uses 64, FXSAVE uses 16, and
/// legacy x87 environment/state transfers use 1. It must be a power of two so
/// the check cannot silently impose a different alignment contract.
pub(crate) fn resolve_sensitive_memory_operand(
    instruction: &Instruction,
    snapshot: &X86UcontextSnapshot,
    guest_fsbase: u64,
    guest_gsbase: X86GuestGsBase,
    required_alignment: u64,
) -> Result<X86XstateResolvedAddress, X86XstateAddressError> {
    if required_alignment == 0 || !required_alignment.is_power_of_two() {
        return Err(X86XstateAddressError::UnsupportedAddressForm);
    }
    if instruction.is_invalid() || instruction.op0_kind() != OpKind::Memory {
        return Err(X86XstateAddressError::UnsupportedInstruction);
    }

    let mut info_factory = InstructionInfoFactory::new();
    let info = info_factory.info(instruction);
    let memories = info.used_memory();
    let Some(memory) = memories.first().filter(|_| memories.len() == 1) else {
        return Err(X86XstateAddressError::UnsupportedAddressForm);
    };
    let address_size = memory.address_size();
    if !matches!(address_size, CodeSize::Code32 | CodeSize::Code64) {
        return Err(X86XstateAddressError::UnsupportedAddressSize);
    }

    let (segment_base, effective_segment_is_ss) = match memory.segment() {
        Register::None | Register::CS | Register::DS | Register::ES => (0, false),
        Register::SS => (0, true),
        Register::FS => (guest_fsbase, false),
        Register::GS => (guest_gsbase.raw(), false),
        _ => return Err(X86XstateAddressError::UnsupportedSegment),
    };

    // For RIP-relative operands iced has already converted the decoded
    // displacement to the absolute target using the decoder IP and reports no
    // base in UsedMemory. Other forms retain base/index/scale/displacement.
    let base = register_value(memory.base(), snapshot)?;
    let index = register_value(memory.index(), snapshot)?;
    let offset = memory
        .displacement()
        .wrapping_add(base)
        .wrapping_add(index.wrapping_mul(u64::from(memory.scale())));
    let offset = if address_size == CodeSize::Code32 {
        u64::from(offset as u32)
    } else {
        offset
    };
    let address = offset.wrapping_add(segment_base);
    if !is_canonical(address) {
        return Err(if effective_segment_is_ss {
            X86XstateAddressError::StackSegmentNoncanonical
        } else {
            X86XstateAddressError::GeneralProtectionNoncanonical
        });
    }
    if address & (required_alignment - 1) != 0 {
        return Err(X86XstateAddressError::MisalignedAddress);
    }

    Ok(X86XstateResolvedAddress {
        address: GuestVa(address),
        instruction_len: instruction.len() as u8,
        effective_segment_is_ss,
    })
}

fn register_value(
    register: Register,
    snapshot: &X86UcontextSnapshot,
) -> Result<u64, X86XstateAddressError> {
    let value = match register.full_register() {
        Register::None => 0,
        Register::RAX => snapshot.gpr[reg::RAX],
        Register::RCX => snapshot.gpr[reg::RCX],
        Register::RDX => snapshot.gpr[reg::RDX],
        Register::RBX => snapshot.gpr[reg::RBX],
        Register::RSP => snapshot.gpr[reg::RSP],
        Register::RBP => snapshot.gpr[reg::RBP],
        Register::RSI => snapshot.gpr[reg::RSI],
        Register::RDI => snapshot.gpr[reg::RDI],
        Register::R8 => snapshot.gpr[reg::R8],
        Register::R9 => snapshot.gpr[reg::R9],
        Register::R10 => snapshot.gpr[reg::R10],
        Register::R11 => snapshot.gpr[reg::R11],
        Register::R12 => snapshot.gpr[reg::R12],
        Register::R13 => snapshot.gpr[reg::R13],
        Register::R14 => snapshot.gpr[reg::R14],
        Register::R15 => snapshot.gpr[reg::R15],
        _ => return Err(X86XstateAddressError::UnsupportedAddressForm),
    };
    Ok(value)
}

pub(crate) const fn is_canonical(address: u64) -> bool {
    let upper = address >> 48;
    if address & (1 << 47) == 0 {
        upper == 0
    } else {
        upper == u16::MAX as u64
    }
}
