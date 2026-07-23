//! Pure checked emulation of FXSAVE/FXSAVE64/FXRSTOR/FXRSTOR64.
//!
//! These instructions transfer only the legacy x87/SSE 512-byte image. Guest
//! bytes are never executed and guest addresses never become host pointers.
//! Reserved destination bytes are omitted from save writes, restore imports
//! only architecturally defined fields, and the authoritative snapshot commits
//! a restore only after the complete image and MXCSR have been validated.

use std::convert::Infallible;

use carrick_guest_mem::GuestVa;
use iced_x86::{Code, Decoder, DecoderOptions};

use crate::decode::X86FxStateKind;
use crate::gateway::X86UcontextSnapshot;
use crate::xstate_address::{
    X86GuestGsBase, X86XstateAddressError, is_canonical, resolve_sensitive_memory_operand,
};
use crate::xstate_restore::X86XstateMemoryReader;
use crate::xstate_save::X86XstateMemoryWriter;

const FX_IMAGE_LEN: usize = 512;
const X87_FEATURE: u64 = 1 << 0;
const SSE_FEATURE: u64 = 1 << 1;
const XSTATE_BV_OFFSET: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum X86FxStateGpReason {
    #[error("the instruction is not a supported FXSAVE-family user-state form")]
    UnsupportedInstruction,
    #[error("the memory operand does not use a supported long-mode address size")]
    UnsupportedAddressSize,
    #[error("the memory operand uses an unsupported segment override")]
    UnsupportedSegment,
    #[error("the memory operand uses an unsupported register form")]
    UnsupportedAddressForm,
    #[error("the effective address is noncanonical")]
    NoncanonicalAddress,
    #[error("the effective address is not 16-byte aligned")]
    MisalignedAddress,
    #[error("the 512-byte operand range is not canonical and non-wrapping")]
    InvalidOperandRange,
    #[error("MXCSR contains a bit outside the runtime MXCSR_MASK")]
    InvalidMxcsr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum X86FxStateSsReason {
    #[error("the stack-segment effective address is noncanonical")]
    NoncanonicalAddress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum X86FxStateInternalReason {
    #[error("classified {expected:?} but decoded {decoded:?}")]
    InstructionKindMismatch {
        expected: X86FxStateKind,
        decoded: X86FxStateKind,
    },
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum X86FxStateError<ReadError = Infallible, WriteError = Infallible> {
    #[error("x86 FXSAVE-family general protection: {0}")]
    GeneralProtection(X86FxStateGpReason),
    #[error("x86 FXSAVE-family stack-segment fault: {0}")]
    StackSegment(X86FxStateSsReason),
    #[error("x86 FXSAVE-family checked guest-memory read failed")]
    Read(ReadError),
    #[error("x86 FXSAVE-family checked guest-memory write failed")]
    Write(WriteError),
    #[error("x86 FXSAVE-family internal failure: {0}")]
    Internal(X86FxStateInternalReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86FxStatePlan {
    kind: X86FxStateKind,
    address: GuestVa,
    instruction_len: u8,
    effective_segment_is_ss: bool,
}

impl X86FxStatePlan {
    pub fn decode_for_kind(
        expected: X86FxStateKind,
        bytes: &[u8],
        snapshot: &X86UcontextSnapshot,
        guest_fsbase: u64,
        guest_gsbase: X86GuestGsBase,
    ) -> Result<Self, X86FxStateError> {
        let mut decoder = Decoder::with_ip(64, bytes, snapshot.rip, DecoderOptions::NONE);
        let instruction = decoder.decode();
        let decoded = match instruction.code() {
            Code::Fxsave_m512byte => X86FxStateKind::Fxsave,
            Code::Fxsave64_m512byte => X86FxStateKind::Fxsave64,
            Code::Fxrstor_m512byte => X86FxStateKind::Fxrstor,
            Code::Fxrstor64_m512byte => X86FxStateKind::Fxrstor64,
            _ => {
                return Err(X86FxStateError::GeneralProtection(
                    X86FxStateGpReason::UnsupportedInstruction,
                ));
            }
        };
        if decoded != expected {
            return Err(X86FxStateError::Internal(
                X86FxStateInternalReason::InstructionKindMismatch { expected, decoded },
            ));
        }
        let resolved = resolve_sensitive_memory_operand(
            &instruction,
            snapshot,
            guest_fsbase,
            guest_gsbase,
            16,
        )
        .map_err(fx_address_error)?;
        validate_operand_range::<Infallible, Infallible>(
            resolved.address,
            resolved.effective_segment_is_ss,
        )?;
        Ok(Self {
            kind: decoded,
            address: resolved.address,
            instruction_len: resolved.instruction_len,
            effective_segment_is_ss: resolved.effective_segment_is_ss,
        })
    }

    pub const fn kind(self) -> X86FxStateKind {
        self.kind
    }

    pub const fn address(self) -> GuestVa {
        self.address
    }

    pub const fn instruction_len(self) -> u8 {
        self.instruction_len
    }

    pub const fn effective_segment_is_ss(self) -> bool {
        self.effective_segment_is_ss
    }
}

fn fx_address_error(error: X86XstateAddressError) -> X86FxStateError {
    match error {
        X86XstateAddressError::UnsupportedInstruction => {
            X86FxStateError::GeneralProtection(X86FxStateGpReason::UnsupportedInstruction)
        }
        X86XstateAddressError::UnsupportedAddressSize => {
            X86FxStateError::GeneralProtection(X86FxStateGpReason::UnsupportedAddressSize)
        }
        X86XstateAddressError::UnsupportedSegment => {
            X86FxStateError::GeneralProtection(X86FxStateGpReason::UnsupportedSegment)
        }
        X86XstateAddressError::UnsupportedAddressForm => {
            X86FxStateError::GeneralProtection(X86FxStateGpReason::UnsupportedAddressForm)
        }
        X86XstateAddressError::GeneralProtectionNoncanonical => {
            X86FxStateError::GeneralProtection(X86FxStateGpReason::NoncanonicalAddress)
        }
        X86XstateAddressError::StackSegmentNoncanonical => {
            X86FxStateError::StackSegment(X86FxStateSsReason::NoncanonicalAddress)
        }
        X86XstateAddressError::MisalignedAddress => {
            X86FxStateError::GeneralProtection(X86FxStateGpReason::MisalignedAddress)
        }
    }
}

fn range_fault<ReadError, WriteError>(
    effective_segment_is_ss: bool,
) -> X86FxStateError<ReadError, WriteError> {
    if effective_segment_is_ss {
        X86FxStateError::StackSegment(X86FxStateSsReason::NoncanonicalAddress)
    } else {
        X86FxStateError::GeneralProtection(X86FxStateGpReason::InvalidOperandRange)
    }
}

fn validate_operand_range<ReadError, WriteError>(
    address: GuestVa,
    effective_segment_is_ss: bool,
) -> Result<(), X86FxStateError<ReadError, WriteError>> {
    let end = address
        .raw()
        .checked_add(FX_IMAGE_LEN as u64)
        .ok_or_else(|| range_fault(effective_segment_is_ss))?;
    if !is_canonical(address.raw()) || !is_canonical(end - 1) {
        return Err(range_fault(effective_segment_is_ss));
    }
    Ok(())
}

fn destination_at<ReadError, WriteError>(
    plan: X86FxStatePlan,
    offset: usize,
) -> Result<GuestVa, X86FxStateError<ReadError, WriteError>> {
    let offset = u64::try_from(offset)
        .map_err(|_| X86FxStateError::GeneralProtection(X86FxStateGpReason::InvalidOperandRange))?;
    plan.address
        .raw()
        .checked_add(offset)
        .map(GuestVa)
        .ok_or_else(|| range_fault(plan.effective_segment_is_ss))
}

struct PreparedWrite {
    address: GuestVa,
    bytes: Vec<u8>,
}

fn prepare_write<ReadError, WriteError>(
    writes: &mut Vec<PreparedWrite>,
    plan: X86FxStatePlan,
    offset: usize,
    bytes: &[u8],
) -> Result<(), X86FxStateError<ReadError, WriteError>> {
    writes.push(PreparedWrite {
        address: destination_at(plan, offset)?,
        bytes: bytes.to_vec(),
    });
    Ok(())
}

fn raw_xstate_bv(snapshot: &X86UcontextSnapshot) -> u64 {
    u64::from_le_bytes(
        snapshot.xsave[XSTATE_BV_OFFSET..XSTATE_BV_OFFSET + 8]
            .try_into()
            .unwrap_or([0; 8]),
    )
}

impl X86UcontextSnapshot {
    /// Save x87/SSE state in exact FXSAVE layout. Every destination range is
    /// validated before the first write; later writer faults retain earlier
    /// writes. Reserved bytes (including each 80-bit register's six-byte pad
    /// and the final 96-byte tail) are never written.
    pub fn emulate_fxsave_with_writer<W: X86XstateMemoryWriter + ?Sized>(
        &self,
        plan: X86FxStatePlan,
        mxcsr_mask: u32,
        writer: &mut W,
    ) -> Result<(), X86FxStateError<Infallible, W::Error>> {
        if !plan.kind.is_save() {
            return Err(X86FxStateError::GeneralProtection(
                X86FxStateGpReason::UnsupportedInstruction,
            ));
        }
        validate_operand_range(plan.address, plan.effective_segment_is_ss)?;

        let initial = Self::new();
        let source_x87 = if self.xstate_bv() & X87_FEATURE != 0 {
            self
        } else {
            &initial
        };
        let source_sse = if self.xstate_bv() & SSE_FEATURE != 0 {
            self
        } else {
            &initial
        };

        let mut writes = Vec::with_capacity(14);
        prepare_write(&mut writes, plan, 0, &source_x87.xsave[0..5])?;
        prepare_write(&mut writes, plan, 6, &source_x87.xsave[6..8])?;
        if plan.kind.is_64() {
            prepare_write(&mut writes, plan, 8, &source_x87.xsave[8..24])?;
        } else {
            prepare_write(&mut writes, plan, 8, &source_x87.xsave[8..12])?;
            prepare_write(&mut writes, plan, 12, &source_x87.x87_fcs().to_le_bytes())?;
            prepare_write(&mut writes, plan, 16, &source_x87.xsave[16..20])?;
            prepare_write(&mut writes, plan, 20, &source_x87.x87_fds().to_le_bytes())?;
        }
        let mut mxcsr = [0u8; 8];
        mxcsr[0..4].copy_from_slice(&source_sse.xsave[24..28]);
        mxcsr[4..8].copy_from_slice(&mxcsr_mask.to_le_bytes());
        prepare_write(&mut writes, plan, 24, &mxcsr)?;
        for physical_slot in 0..8usize {
            let offset = 32 + physical_slot * 16;
            prepare_write(
                &mut writes,
                plan,
                offset,
                &source_x87.xsave[offset..offset + 10],
            )?;
        }
        prepare_write(&mut writes, plan, 160, &source_sse.xsave[160..416])?;

        for write in writes {
            writer
                .write_exact(write.address, &write.bytes)
                .map_err(X86FxStateError::Write)?;
        }
        Ok(())
    }

    /// Atomically restore x87/SSE from an exact 512-byte image. Invalid MXCSR
    /// returns #GP before any snapshot field changes. A successful restore
    /// materializes x87 and SSE while preserving every AVX+/PKRU component.
    pub fn emulate_fxrstor_with_reader<R: X86XstateMemoryReader + ?Sized>(
        &mut self,
        plan: X86FxStatePlan,
        mxcsr_mask: u32,
        reader: &mut R,
    ) -> Result<(), X86FxStateError<R::Error, Infallible>> {
        if plan.kind.is_save() {
            return Err(X86FxStateError::GeneralProtection(
                X86FxStateGpReason::UnsupportedInstruction,
            ));
        }
        validate_operand_range(plan.address, plan.effective_segment_is_ss)?;
        // Read only architectural fields. Reserved bytes, the six-byte pads
        // after each 80-bit register, and the final 96-byte tail are neither
        // imported nor made spuriously faultable. All bytes stay private until
        // the final assignment, so even a late read fault is atomic.
        let mut controls = [0u8; 5];
        let mut opcode = [0u8; 2];
        let mut pointers = [0u8; 16];
        let mut mxcsr = [0u8; 4];
        let mut registers = [[0u8; 10]; 8];
        let mut xmm = [0u8; 256];
        read_field(reader, plan, 0, &mut controls)?;
        read_field(reader, plan, 6, &mut opcode)?;
        if plan.kind.is_64() {
            read_field(reader, plan, 8, &mut pointers)?;
        } else {
            read_field(reader, plan, 8, &mut pointers[0..4])?;
            read_field(reader, plan, 12, &mut pointers[4..6])?;
            read_field(reader, plan, 16, &mut pointers[8..12])?;
            read_field(reader, plan, 20, &mut pointers[12..14])?;
        }
        read_field(reader, plan, 24, &mut mxcsr)?;
        let mxcsr_value = u32::from_le_bytes(mxcsr);
        if mxcsr_value & !mxcsr_mask != 0 {
            return Err(X86FxStateError::GeneralProtection(
                X86FxStateGpReason::InvalidMxcsr,
            ));
        }
        for (slot, value) in registers.iter_mut().enumerate() {
            read_field(reader, plan, 32 + slot * 16, value)?;
        }
        read_field(reader, plan, 160, &mut xmm)?;

        let mut temporary = self.clone();
        temporary.xsave[0..2].copy_from_slice(
            &(u16::from_le_bytes([controls[0], controls[1]]) & 0x1f7f).to_le_bytes(),
        );
        temporary.xsave[2..4].copy_from_slice(
            &(u16::from_le_bytes([controls[2], controls[3]]) & 0x7fff).to_le_bytes(),
        );
        temporary.xsave[4] = controls[4];
        temporary.xsave[6..8].copy_from_slice(&(u16::from_le_bytes(opcode) & 0x07ff).to_le_bytes());
        if plan.kind.is_64() {
            temporary.xsave[8..24].copy_from_slice(&pointers);
        } else {
            temporary.xsave[8..12].copy_from_slice(&pointers[0..4]);
            temporary.xsave[12..16].fill(0);
            temporary.xsave[16..20].copy_from_slice(&pointers[8..12]);
            temporary.xsave[20..24].fill(0);
            temporary.restore_x87_selectors(
                u16::from_le_bytes([pointers[4], pointers[5]]),
                u16::from_le_bytes([pointers[12], pointers[13]]),
            );
        }
        temporary.xsave[24..28].copy_from_slice(&mxcsr);
        for (slot, value) in registers.iter().enumerate() {
            let offset = 32 + slot * 16;
            temporary.xsave[offset..offset + 10].copy_from_slice(value);
        }
        temporary.xsave[160..416].copy_from_slice(&xmm);
        temporary.xsave[XSTATE_BV_OFFSET..XSTATE_BV_OFFSET + 8]
            .copy_from_slice(&(raw_xstate_bv(self) | X87_FEATURE | SSE_FEATURE).to_le_bytes());
        *self = temporary;
        Ok(())
    }
}

fn read_field<R: X86XstateMemoryReader + ?Sized>(
    reader: &mut R,
    plan: X86FxStatePlan,
    offset: usize,
    destination: &mut [u8],
) -> Result<(), X86FxStateError<R::Error, Infallible>> {
    let address = destination_at(plan, offset)?;
    reader
        .read_exact(address, destination)
        .map_err(X86FxStateError::Read)
}
