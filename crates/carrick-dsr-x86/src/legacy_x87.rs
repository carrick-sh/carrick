//! Pure checked emulation of legacy x87 environment and full-state transfers.
//!
//! Long mode still admits the operand-size-selected 14/28-byte environment
//! formats and the corresponding 94/108-byte full images. Carrick codecs these
//! layouts directly from the authoritative FXSAVE-compatible snapshot. Guest
//! opcodes and guest addresses are never executed or treated as host pointers.

use std::convert::Infallible;

use carrick_guest_mem::GuestVa;
use iced_x86::{Code, Decoder, DecoderOptions};

use crate::decode::X86LegacyX87Kind;
use crate::gateway::X86UcontextSnapshot;
use crate::xstate_address::{
    X86GuestGsBase, X86XstateAddressError, is_canonical, resolve_sensitive_memory_operand,
};
use crate::xstate_restore::X86XstateMemoryReader;
use crate::xstate_save::X86XstateMemoryWriter;

const X87_FEATURE: u64 = 1;
const XSTATE_BV_OFFSET: usize = 512;
const X87_REGISTER_COUNT: usize = 8;
const X87_REGISTER_LEN: usize = 10;
const FCW_VALID_BITS: u16 = 0x1f7f;
const FSW_VALID_BITS: u16 = 0x7fff;
const FOP_VALID_BITS: u16 = 0x07ff;
const EXCEPTION_MASK_BITS: u16 = 0x003f;
const FSW_EXCEPTION_SUMMARY: u16 = 1 << 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum X86LegacyX87GpReason {
    #[error("the instruction is not a supported legacy x87 state-transfer form")]
    UnsupportedInstruction,
    #[error("the memory operand does not use a supported long-mode address size")]
    UnsupportedAddressSize,
    #[error("the memory operand uses an unsupported segment override")]
    UnsupportedSegment,
    #[error("the memory operand uses an unsupported register form")]
    UnsupportedAddressForm,
    #[error("the effective address is noncanonical")]
    NoncanonicalAddress,
    #[error("the operand range is not canonical and non-wrapping")]
    InvalidOperandRange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum X86LegacyX87SsReason {
    #[error("the stack-segment effective address is noncanonical")]
    NoncanonicalAddress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum X86LegacyX87InternalReason {
    #[error("classified {expected:?} but decoded {decoded:?}")]
    InstructionKindMismatch {
        expected: X86LegacyX87Kind,
        decoded: X86LegacyX87Kind,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86X87ExceptionKind {
    Invalid,
    Denormal,
    DivideByZero,
    Overflow,
    Underflow,
    Precision,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum X86LegacyX87Error<ReadError = Infallible, WriteError = Infallible> {
    #[error("x86 legacy x87 general protection: {0}")]
    GeneralProtection(X86LegacyX87GpReason),
    #[error("x86 legacy x87 stack-segment fault: {0}")]
    StackSegment(X86LegacyX87SsReason),
    #[error("x86 legacy x87 instruction observed a pending unmasked exception: {0:?}")]
    PendingException(X86X87ExceptionKind),
    #[error("x86 legacy x87 checked guest-memory read failed")]
    Read(ReadError),
    #[error("x86 legacy x87 checked guest-memory write failed")]
    Write(WriteError),
    #[error("x86 legacy x87 internal failure: {0}")]
    Internal(X86LegacyX87InternalReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86LegacyX87Plan {
    kind: X86LegacyX87Kind,
    address: GuestVa,
    instruction_len: u8,
    effective_segment_is_ss: bool,
}

impl X86LegacyX87Plan {
    pub fn decode_for_kind(
        expected: X86LegacyX87Kind,
        bytes: &[u8],
        snapshot: &X86UcontextSnapshot,
        guest_fsbase: u64,
        guest_gsbase: X86GuestGsBase,
    ) -> Result<Self, X86LegacyX87Error> {
        let mut decoder = Decoder::with_ip(64, bytes, snapshot.rip, DecoderOptions::NONE);
        let instruction = decoder.decode();
        let decoded = decoded_kind(instruction.code()).ok_or(
            X86LegacyX87Error::GeneralProtection(X86LegacyX87GpReason::UnsupportedInstruction),
        )?;
        if decoded != expected {
            return Err(X86LegacyX87Error::Internal(
                X86LegacyX87InternalReason::InstructionKindMismatch { expected, decoded },
            ));
        }
        let resolved =
            resolve_sensitive_memory_operand(&instruction, snapshot, guest_fsbase, guest_gsbase, 1)
                .map_err(address_error)?;
        let plan = Self {
            kind: decoded,
            address: resolved.address,
            instruction_len: resolved.instruction_len,
            effective_segment_is_ss: resolved.effective_segment_is_ss,
        };
        checked_address::<Infallible, Infallible>(plan, 0, plan.total_len())?;
        Ok(plan)
    }

    pub const fn kind(self) -> X86LegacyX87Kind {
        self.kind
    }

    pub const fn address(self) -> GuestVa {
        self.address
    }

    pub const fn instruction_len(self) -> u8 {
        self.instruction_len
    }

    pub const fn total_len(self) -> usize {
        self.kind.environment_len()
            + if self.kind.includes_registers() {
                X87_REGISTER_COUNT * X87_REGISTER_LEN
            } else {
                0
            }
    }
}

fn decoded_kind(code: Code) -> Option<X86LegacyX87Kind> {
    Some(match code {
        Code::Fldenv_m14byte => X86LegacyX87Kind::Fldenv14,
        Code::Fldenv_m28byte => X86LegacyX87Kind::Fldenv28,
        Code::Fnstenv_m14byte => X86LegacyX87Kind::Fnstenv14,
        Code::Fstenv_m14byte => X86LegacyX87Kind::Fstenv14,
        Code::Fnstenv_m28byte => X86LegacyX87Kind::Fnstenv28,
        Code::Fstenv_m28byte => X86LegacyX87Kind::Fstenv28,
        Code::Frstor_m94byte => X86LegacyX87Kind::Frstor94,
        Code::Frstor_m108byte => X86LegacyX87Kind::Frstor108,
        Code::Fnsave_m94byte => X86LegacyX87Kind::Fnsave94,
        Code::Fsave_m94byte => X86LegacyX87Kind::Fsave94,
        Code::Fnsave_m108byte => X86LegacyX87Kind::Fnsave108,
        Code::Fsave_m108byte => X86LegacyX87Kind::Fsave108,
        _ => return None,
    })
}

fn address_error(error: X86XstateAddressError) -> X86LegacyX87Error {
    match error {
        X86XstateAddressError::UnsupportedInstruction => {
            X86LegacyX87Error::GeneralProtection(X86LegacyX87GpReason::UnsupportedInstruction)
        }
        X86XstateAddressError::UnsupportedAddressSize => {
            X86LegacyX87Error::GeneralProtection(X86LegacyX87GpReason::UnsupportedAddressSize)
        }
        X86XstateAddressError::UnsupportedSegment => {
            X86LegacyX87Error::GeneralProtection(X86LegacyX87GpReason::UnsupportedSegment)
        }
        X86XstateAddressError::UnsupportedAddressForm => {
            X86LegacyX87Error::GeneralProtection(X86LegacyX87GpReason::UnsupportedAddressForm)
        }
        X86XstateAddressError::GeneralProtectionNoncanonical => {
            X86LegacyX87Error::GeneralProtection(X86LegacyX87GpReason::NoncanonicalAddress)
        }
        X86XstateAddressError::StackSegmentNoncanonical => {
            X86LegacyX87Error::StackSegment(X86LegacyX87SsReason::NoncanonicalAddress)
        }
        // Alignment one makes this unreachable, but keep the fail-closed map.
        X86XstateAddressError::MisalignedAddress => {
            X86LegacyX87Error::GeneralProtection(X86LegacyX87GpReason::UnsupportedAddressForm)
        }
    }
}

fn range_error<ReadError, WriteError>(
    plan: X86LegacyX87Plan,
) -> X86LegacyX87Error<ReadError, WriteError> {
    if plan.effective_segment_is_ss {
        X86LegacyX87Error::StackSegment(X86LegacyX87SsReason::NoncanonicalAddress)
    } else {
        X86LegacyX87Error::GeneralProtection(X86LegacyX87GpReason::InvalidOperandRange)
    }
}

fn checked_address<ReadError, WriteError>(
    plan: X86LegacyX87Plan,
    offset: usize,
    len: usize,
) -> Result<GuestVa, X86LegacyX87Error<ReadError, WriteError>> {
    let offset = u64::try_from(offset).map_err(|_| range_error(plan))?;
    let len = u64::try_from(len).map_err(|_| range_error(plan))?;
    let start = plan
        .address
        .raw()
        .checked_add(offset)
        .ok_or_else(|| range_error(plan))?;
    let end = start.checked_add(len).ok_or_else(|| range_error(plan))?;
    if !is_canonical(start) || (len != 0 && !is_canonical(end - 1)) {
        return Err(range_error(plan));
    }
    Ok(GuestVa(start))
}

fn read_exact<R: X86XstateMemoryReader + ?Sized>(
    reader: &mut R,
    plan: X86LegacyX87Plan,
    offset: usize,
    destination: &mut [u8],
) -> Result<(), X86LegacyX87Error<R::Error, Infallible>> {
    let address = checked_address(plan, offset, destination.len())?;
    reader
        .read_exact(address, destination)
        .map_err(X86LegacyX87Error::Read)
}

fn write_exact<W: X86XstateMemoryWriter + ?Sized>(
    writer: &mut W,
    plan: X86LegacyX87Plan,
    offset: usize,
    source: &[u8],
) -> Result<(), X86LegacyX87Error<Infallible, W::Error>> {
    let address = checked_address(plan, offset, source.len())?;
    writer
        .write_exact(address, source)
        .map_err(X86LegacyX87Error::Write)
}

fn raw_xstate_bv(snapshot: &X86UcontextSnapshot) -> u64 {
    u64::from_le_bytes(
        snapshot.xsave[XSTATE_BV_OFFSET..XSTATE_BV_OFFSET + 8]
            .try_into()
            .unwrap_or([0; 8]),
    )
}

fn x87_source<'a>(
    snapshot: &'a X86UcontextSnapshot,
    initial: &'a X86UcontextSnapshot,
) -> &'a X86UcontextSnapshot {
    if snapshot.xstate_bv() & X87_FEATURE != 0 {
        snapshot
    } else {
        initial
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn x87_full_tag(snapshot: &X86UcontextSnapshot) -> u16 {
    let abridged = snapshot.xsave[4];
    let status = u16_at(&snapshot.xsave, 2);
    let top = usize::from((status >> 11) & 7);
    let mut full = 0u16;
    for logical in 0..X87_REGISTER_COUNT {
        let physical = (top + logical) & 7;
        let tag = if abridged & (1 << physical) == 0 {
            3
        } else {
            classify_x87_value(&snapshot.xsave[32 + logical * 16..32 + logical * 16 + 10])
        };
        full |= tag << (physical * 2);
    }
    full
}

fn classify_x87_value(value: &[u8]) -> u16 {
    let significand = u64::from_le_bytes(value[0..8].try_into().unwrap_or([0; 8]));
    let sign_exponent = u16::from_le_bytes(value[8..10].try_into().unwrap_or([0; 2]));
    let exponent = sign_exponent & 0x7fff;
    if exponent == 0 && significand == 0 {
        1 // zero
    } else if exponent == 0 || exponent == 0x7fff || significand & (1 << 63) == 0 {
        2 // denormal, infinity, NaN, or unsupported encoding
    } else {
        0 // finite normal
    }
}

fn abridged_tag(full: u16) -> u8 {
    let mut abridged = 0u8;
    for physical in 0..X87_REGISTER_COUNT {
        if (full >> (physical * 2)) & 3 != 3 {
            abridged |= 1 << physical;
        }
    }
    abridged
}

fn encode_environment(snapshot: &X86UcontextSnapshot, len: usize) -> Vec<u8> {
    let control = u16_at(&snapshot.xsave, 0) & FCW_VALID_BITS;
    let status = u16_at(&snapshot.xsave, 2) & FSW_VALID_BITS;
    let tag = x87_full_tag(snapshot);
    let fop = u16_at(&snapshot.xsave, 6) & FOP_VALID_BITS;
    let fip = u64::from_le_bytes(snapshot.xsave[8..16].try_into().unwrap_or([0; 8]));
    let fdp = u64::from_le_bytes(snapshot.xsave[16..24].try_into().unwrap_or([0; 8]));
    if len == 14 {
        let mut environment = vec![0u8; 14];
        environment[0..2].copy_from_slice(&control.to_le_bytes());
        environment[2..4].copy_from_slice(&status.to_le_bytes());
        environment[4..6].copy_from_slice(&tag.to_le_bytes());
        environment[6..8].copy_from_slice(&(fip as u16).to_le_bytes());
        environment[8..10].copy_from_slice(&snapshot.x87_fcs().to_le_bytes());
        environment[10..12].copy_from_slice(&(fdp as u16).to_le_bytes());
        environment[12..14].copy_from_slice(&snapshot.x87_fds().to_le_bytes());
        environment
    } else {
        let mut environment = vec![0xffu8; 28];
        environment[0..2].copy_from_slice(&control.to_le_bytes());
        environment[4..6].copy_from_slice(&status.to_le_bytes());
        environment[8..10].copy_from_slice(&tag.to_le_bytes());
        environment[12..16].copy_from_slice(&(fip as u32).to_le_bytes());
        environment[16..18].copy_from_slice(&snapshot.x87_fcs().to_le_bytes());
        environment[18..20].copy_from_slice(&fop.to_le_bytes());
        environment[20..24].copy_from_slice(&(fdp as u32).to_le_bytes());
        environment[24..26].copy_from_slice(&snapshot.x87_fds().to_le_bytes());
        environment
    }
}

fn rotate_logical_register_slots(snapshot: &mut X86UcontextSnapshot, new_status: u16) {
    let old_status = u16_at(&snapshot.xsave, 2);
    let old_top = usize::from((old_status >> 11) & 7);
    let new_top = usize::from((new_status >> 11) & 7);
    if old_top == new_top {
        return;
    }

    // FXSAVE numbers its 16-byte payload slots as logical ST(0)..ST(7), while
    // TOP selects which physical register is currently ST(0). FLDENV changes
    // TOP without changing any physical register, so reindex the logical slots
    // before publishing the new status word. For new logical slot L, the same
    // physical register lived at old logical slot (new_top + L - old_top) mod 8.
    let old_slots: [u8; X87_REGISTER_COUNT * 16] = snapshot.xsave[32..160]
        .try_into()
        .unwrap_or([0; X87_REGISTER_COUNT * 16]);
    for new_logical in 0..X87_REGISTER_COUNT {
        let old_logical =
            (new_top + new_logical + X87_REGISTER_COUNT - old_top) & (X87_REGISTER_COUNT - 1);
        let source = old_logical * 16;
        let destination = 32 + new_logical * 16;
        snapshot.xsave[destination..destination + 16]
            .copy_from_slice(&old_slots[source..source + 16]);
    }
}

fn decode_environment(
    snapshot: &mut X86UcontextSnapshot,
    environment: &[u8],
    preserve_physical_registers: bool,
) {
    let control = u16_at(environment, 0) & FCW_VALID_BITS;
    let previous_fop = u16_at(&snapshot.xsave, 6) & FOP_VALID_BITS;
    let (status, full_tag, fip, fcs, fop, fdp, fds) = if environment.len() == 14 {
        (
            u16_at(environment, 2) & FSW_VALID_BITS,
            u16_at(environment, 4),
            u64::from(u16_at(environment, 6)),
            u16_at(environment, 8),
            previous_fop,
            u64::from(u16_at(environment, 10)),
            u16_at(environment, 12),
        )
    } else {
        (
            u16_at(environment, 4) & FSW_VALID_BITS,
            u16_at(environment, 8),
            u64::from(u32_at(environment, 12)),
            u16_at(environment, 16),
            u16_at(environment, 18) & FOP_VALID_BITS,
            u64::from(u32_at(environment, 20)),
            u16_at(environment, 24),
        )
    };
    if preserve_physical_registers {
        rotate_logical_register_slots(snapshot, status);
    }
    snapshot.xsave[0..2].copy_from_slice(&control.to_le_bytes());
    snapshot.xsave[2..4].copy_from_slice(&status.to_le_bytes());
    snapshot.xsave[4] = abridged_tag(full_tag);
    snapshot.xsave[6..8].copy_from_slice(&fop.to_le_bytes());
    snapshot.xsave[8..16].copy_from_slice(&fip.to_le_bytes());
    snapshot.xsave[16..24].copy_from_slice(&fdp.to_le_bytes());
    snapshot.restore_x87_selectors(fcs, fds);
    let xstate_bv = raw_xstate_bv(snapshot) | X87_FEATURE;
    snapshot.xsave[XSTATE_BV_OFFSET..XSTATE_BV_OFFSET + 8]
        .copy_from_slice(&xstate_bv.to_le_bytes());
}

fn initialize_x87(snapshot: &mut X86UcontextSnapshot) {
    let initial = X86UcontextSnapshot::new();
    snapshot.xsave[0..5].copy_from_slice(&initial.xsave[0..5]);
    snapshot.xsave[6..24].copy_from_slice(&initial.xsave[6..24]);
    // FSAVE/FNSAVE empties the x87 stack and resets its environment, but the
    // physical 80-bit register payloads are not cleared. Keep all eight slots
    // byte-for-byte so a subsequent FXSAVE observes the retained payload.
    snapshot.restore_x87_selectors(initial.x87_fcs(), initial.x87_fds());
    let xstate_bv = raw_xstate_bv(snapshot) | X87_FEATURE;
    snapshot.xsave[XSTATE_BV_OFFSET..XSTATE_BV_OFFSET + 8]
        .copy_from_slice(&xstate_bv.to_le_bytes());
}

impl X86UcontextSnapshot {
    /// Whether a WAIT-taking x87 instruction must first deliver the virtual
    /// pending x87 exception. No host FWAIT is executed.
    pub fn x87_pending_exception(&self) -> Option<X86X87ExceptionKind> {
        if self.xstate_bv() & X87_FEATURE == 0 {
            return None;
        }
        let status = u16_at(&self.xsave, 2);
        if status & FSW_EXCEPTION_SUMMARY == 0 {
            return None;
        }
        let control = u16_at(&self.xsave, 0);
        let unmasked = (status & EXCEPTION_MASK_BITS) & !(control & EXCEPTION_MASK_BITS);
        if unmasked == 0 {
            return None;
        }
        Some(if unmasked & (1 << 0) != 0 {
            X86X87ExceptionKind::Invalid
        } else if unmasked & (1 << 1) != 0 {
            X86X87ExceptionKind::Denormal
        } else if unmasked & (1 << 2) != 0 {
            X86X87ExceptionKind::DivideByZero
        } else if unmasked & (1 << 3) != 0 {
            X86X87ExceptionKind::Overflow
        } else if unmasked & (1 << 4) != 0 {
            X86X87ExceptionKind::Underflow
        } else if unmasked & (1 << 5) != 0 {
            X86X87ExceptionKind::Precision
        } else {
            X86X87ExceptionKind::Invalid
        })
    }

    pub fn x87_exception_pending(&self) -> bool {
        self.x87_pending_exception().is_some()
    }

    /// Execute an environment/full-state save through ordered exact writes.
    /// A late memory fault retains earlier writes. FNSTENV masks exceptions and
    /// FNSAVE initializes x87 only after every write succeeds.
    pub fn emulate_legacy_x87_save<W: X86XstateMemoryWriter + ?Sized>(
        &mut self,
        plan: X86LegacyX87Plan,
        writer: &mut W,
    ) -> Result<(), X86LegacyX87Error<Infallible, W::Error>> {
        if !plan.kind.is_save() {
            return Err(X86LegacyX87Error::GeneralProtection(
                X86LegacyX87GpReason::UnsupportedInstruction,
            ));
        }
        checked_address(plan, 0, plan.total_len())?;
        if plan.kind.waits()
            && let Some(exception) = self.x87_pending_exception()
        {
            return Err(X86LegacyX87Error::PendingException(exception));
        }
        let initial = Self::new();
        let source = x87_source(self, &initial);
        let environment = encode_environment(source, plan.kind.environment_len());
        write_exact(writer, plan, 0, &environment)?;
        if plan.kind.includes_registers() {
            for logical in 0..X87_REGISTER_COUNT {
                let source_offset = 32 + logical * 16;
                write_exact(
                    writer,
                    plan,
                    plan.kind.environment_len() + logical * X87_REGISTER_LEN,
                    &source.xsave[source_offset..source_offset + X87_REGISTER_LEN],
                )?;
            }
            initialize_x87(self);
        } else {
            let control = u16_at(&self.xsave, 0) | EXCEPTION_MASK_BITS;
            self.xsave[0..2].copy_from_slice(&control.to_le_bytes());
        }
        Ok(())
    }

    /// Atomically restore one legacy environment or full x87 image. Every
    /// source byte is read before the authoritative snapshot changes.
    pub fn emulate_legacy_x87_restore<R: X86XstateMemoryReader + ?Sized>(
        &mut self,
        plan: X86LegacyX87Plan,
        reader: &mut R,
    ) -> Result<(), X86LegacyX87Error<R::Error, Infallible>> {
        if plan.kind.is_save() {
            return Err(X86LegacyX87Error::GeneralProtection(
                X86LegacyX87GpReason::UnsupportedInstruction,
            ));
        }
        checked_address(plan, 0, plan.total_len())?;
        if plan.kind.waits()
            && let Some(exception) = self.x87_pending_exception()
        {
            return Err(X86LegacyX87Error::PendingException(exception));
        }
        let mut environment = vec![0u8; plan.kind.environment_len()];
        read_exact(reader, plan, 0, &mut environment)?;
        let mut registers = [[0u8; X87_REGISTER_LEN]; X87_REGISTER_COUNT];
        if plan.kind.includes_registers() {
            for (logical, value) in registers.iter_mut().enumerate() {
                read_exact(
                    reader,
                    plan,
                    plan.kind.environment_len() + logical * X87_REGISTER_LEN,
                    value,
                )?;
            }
        }
        let mut temporary = self.clone();
        // FLDENV imports only environment state: a changed TOP must reindex the
        // logical FXSAVE slots to retain physical-register identity. FRSTOR's
        // following 8x10-byte payload is already ordered as ST(0)..ST(7) for
        // the imported TOP, so it must remain in exact wire order.
        decode_environment(
            &mut temporary,
            &environment,
            !plan.kind.includes_registers(),
        );
        if plan.kind.includes_registers() {
            for (logical, value) in registers.iter().enumerate() {
                let destination = 32 + logical * 16;
                temporary.xsave[destination..destination + X87_REGISTER_LEN].copy_from_slice(value);
            }
        }
        *self = temporary;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::reg;

    const BASE: u64 = 0x20_000;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum MemoryError {
        Bounds,
        Injected,
    }

    struct Memory {
        bytes: Vec<u8>,
        reads: Vec<(u64, usize)>,
        writes: Vec<(u64, usize)>,
        fail_read: Option<usize>,
        fail_write: Option<usize>,
    }

    impl Memory {
        fn new(fill: u8) -> Self {
            Self {
                bytes: vec![fill; 4096],
                reads: Vec::new(),
                writes: Vec::new(),
                fail_read: None,
                fail_write: None,
            }
        }
    }

    impl X86XstateMemoryReader for Memory {
        type Error = MemoryError;

        fn read_exact(
            &mut self,
            address: GuestVa,
            destination: &mut [u8],
        ) -> Result<(), Self::Error> {
            let call = self.reads.len();
            self.reads.push((address.raw(), destination.len()));
            if self.fail_read == Some(call) {
                return Err(MemoryError::Injected);
            }
            let offset =
                usize::try_from(address.raw().checked_sub(BASE).ok_or(MemoryError::Bounds)?)
                    .map_err(|_| MemoryError::Bounds)?;
            destination.copy_from_slice(
                self.bytes
                    .get(offset..offset + destination.len())
                    .ok_or(MemoryError::Bounds)?,
            );
            Ok(())
        }
    }

    impl X86XstateMemoryWriter for Memory {
        type Error = MemoryError;

        fn write_exact(&mut self, address: GuestVa, source: &[u8]) -> Result<(), Self::Error> {
            let call = self.writes.len();
            self.writes.push((address.raw(), source.len()));
            if self.fail_write == Some(call) {
                return Err(MemoryError::Injected);
            }
            let offset =
                usize::try_from(address.raw().checked_sub(BASE).ok_or(MemoryError::Bounds)?)
                    .map_err(|_| MemoryError::Bounds)?;
            self.bytes
                .get_mut(offset..offset + source.len())
                .ok_or(MemoryError::Bounds)?
                .copy_from_slice(source);
            Ok(())
        }
    }

    fn plan(
        kind: X86LegacyX87Kind,
        bytes: &[u8],
        snapshot: &mut X86UcontextSnapshot,
    ) -> X86LegacyX87Plan {
        snapshot.rip = 0x40_0000;
        snapshot.gpr[reg::RAX] = BASE;
        X86LegacyX87Plan::decode_for_kind(kind, bytes, snapshot, 0, X86GuestGsBase::Zero)
            .expect("decode legacy x87 plan")
    }

    #[test]
    fn exact_forms_decode_to_14_28_94_and_108_byte_plans() {
        for (kind, bytes, total) in [
            (X86LegacyX87Kind::Fldenv28, &[0xd9, 0x20][..], 28),
            (X86LegacyX87Kind::Fldenv14, &[0x66, 0xd9, 0x20][..], 14),
            (X86LegacyX87Kind::Fnstenv28, &[0xd9, 0x30][..], 28),
            (X86LegacyX87Kind::Fnstenv14, &[0x66, 0xd9, 0x30][..], 14),
            (X86LegacyX87Kind::Frstor108, &[0xdd, 0x20][..], 108),
            (X86LegacyX87Kind::Frstor94, &[0x66, 0xdd, 0x20][..], 94),
            (X86LegacyX87Kind::Fnsave108, &[0xdd, 0x30][..], 108),
            (X86LegacyX87Kind::Fnsave94, &[0x66, 0xdd, 0x30][..], 94),
        ] {
            let mut snapshot = X86UcontextSnapshot::new();
            let decoded = plan(kind, bytes, &mut snapshot);
            assert_eq!(decoded.total_len(), total);
            assert_eq!(decoded.instruction_len() as usize, bytes.len());
        }
    }

    #[test]
    fn environment_layouts_use_virtual_selectors_full_tags_and_exact_reserved_words() {
        let mut snapshot = X86UcontextSnapshot::new();
        snapshot.restore_x87_selectors(0x1357, 0x2468);
        snapshot.xsave[2..4].copy_from_slice(&0x3000u16.to_le_bytes()); // TOP=6
        snapshot.xsave[4] = 0xc0; // physical six and seven nonempty
        snapshot.xsave[32..42].fill(0); // logical ST0 = zero
        snapshot.xsave[48..56].copy_from_slice(&0x8000_0000_0000_0000u64.to_le_bytes());
        snapshot.xsave[56..58].copy_from_slice(&0x3fffu16.to_le_bytes()); // logical ST1 = 1
        snapshot.xsave[6..8].copy_from_slice(&0x06eeu16.to_le_bytes());
        snapshot.xsave[8..16].copy_from_slice(&0x1122_3344_89ab_cdefu64.to_le_bytes());
        snapshot.xsave[16..24].copy_from_slice(&0x8877_6655_7654_3210u64.to_le_bytes());

        let plan28 = plan(X86LegacyX87Kind::Fnstenv28, &[0xd9, 0x30], &mut snapshot);
        let mut memory = Memory::new(0xa5);
        snapshot
            .emulate_legacy_x87_save(plan28, &mut memory)
            .expect("save env28");
        assert_eq!(u16_at(&memory.bytes, 0), 0x037f);
        assert_eq!(u16_at(&memory.bytes, 4), 0x3000);
        assert_eq!(u16_at(&memory.bytes, 8), 0x1fff);
        assert_eq!(&memory.bytes[2..4], &[0xff; 2]);
        assert_eq!(&memory.bytes[6..8], &[0xff; 2]);
        assert_eq!(&memory.bytes[10..12], &[0xff; 2]);
        assert_eq!(u32_at(&memory.bytes, 12), 0x89ab_cdef);
        assert_eq!(u16_at(&memory.bytes, 16), 0x1357);
        assert_eq!(u16_at(&memory.bytes, 18), 0x06ee);
        assert_eq!(u32_at(&memory.bytes, 20), 0x7654_3210);
        assert_eq!(u16_at(&memory.bytes, 24), 0x2468);
        assert_eq!(&memory.bytes[26..28], &[0xff; 2]);

        let plan14 = plan(
            X86LegacyX87Kind::Fnstenv14,
            &[0x66, 0xd9, 0x30],
            &mut snapshot,
        );
        memory.bytes.fill(0xa5);
        snapshot
            .emulate_legacy_x87_save(plan14, &mut memory)
            .expect("save env14");
        assert_eq!(u16_at(&memory.bytes, 0), 0x037f);
        assert_eq!(u16_at(&memory.bytes, 2), 0x3000);
        assert_eq!(u16_at(&memory.bytes, 4), 0x1fff);
        assert_eq!(u16_at(&memory.bytes, 6), 0xcdef);
        assert_eq!(u16_at(&memory.bytes, 8), 0x1357);
        assert_eq!(u16_at(&memory.bytes, 10), 0x3210);
        assert_eq!(u16_at(&memory.bytes, 12), 0x2468);
    }

    #[test]
    fn restores_are_atomic_convert_full_tags_and_zero_extend_pointers() {
        let mut snapshot = X86UcontextSnapshot::new();
        let plan = plan(X86LegacyX87Kind::Frstor108, &[0xdd, 0x20], &mut snapshot);
        let mut memory = Memory::new(0);
        memory.bytes[0..2].copy_from_slice(&0xffffu16.to_le_bytes());
        memory.bytes[4..6].copy_from_slice(&0xf800u16.to_le_bytes());
        memory.bytes[8..10].copy_from_slice(&0x1fffu16.to_le_bytes());
        memory.bytes[12..16].copy_from_slice(&0x89ab_cdefu32.to_le_bytes());
        memory.bytes[16..18].copy_from_slice(&0x1357u16.to_le_bytes());
        memory.bytes[18..20].copy_from_slice(&0xeeeeu16.to_le_bytes());
        memory.bytes[20..24].copy_from_slice(&0x7654_3210u32.to_le_bytes());
        memory.bytes[24..26].copy_from_slice(&0x2468u16.to_le_bytes());
        for logical in 0..8usize {
            memory.bytes[28 + logical * 10..38 + logical * 10].fill(logical as u8 + 1);
        }
        let before = snapshot.clone();
        memory.fail_read = Some(4);
        assert_eq!(
            snapshot.emulate_legacy_x87_restore(plan, &mut memory),
            Err(X86LegacyX87Error::Read(MemoryError::Injected))
        );
        assert_eq!(snapshot.xsave, before.xsave);
        assert_eq!(snapshot.x87_fcs(), before.x87_fcs());
        memory.fail_read = None;
        snapshot
            .emulate_legacy_x87_restore(plan, &mut memory)
            .expect("restore full image");
        assert_eq!(u16_at(&snapshot.xsave, 0), 0x1f7f);
        assert_eq!(u16_at(&snapshot.xsave, 2), 0x7800);
        assert_eq!(snapshot.xsave[4], 0xc0);
        assert_eq!(u16_at(&snapshot.xsave, 6), 0x06ee);
        assert_eq!(
            u64::from_le_bytes(snapshot.xsave[8..16].try_into().unwrap_or([0; 8])),
            0x89ab_cdef
        );
        assert_eq!(snapshot.x87_fcs(), 0x1357);
        assert_eq!(snapshot.x87_fds(), 0x2468);
        for logical in 0..8usize {
            assert_eq!(
                &snapshot.xsave[32 + logical * 16..42 + logical * 16],
                &[logical as u8 + 1; 10]
            );
        }
    }

    #[test]
    fn fldenv_top_change_rotates_logical_slots_to_preserve_physical_registers() {
        let mut snapshot = X86UcontextSnapshot::new();
        snapshot.xsave[2..4].copy_from_slice(&0x0800u16.to_le_bytes()); // old TOP=1
        for logical in 0..X87_REGISTER_COUNT {
            snapshot.xsave[32 + logical * 16..48 + logical * 16].fill(logical as u8 + 0x10);
        }
        let plan = plan(X86LegacyX87Kind::Fldenv28, &[0xd9, 0x20], &mut snapshot);
        let mut memory = Memory::new(0);
        memory.bytes[0..2].copy_from_slice(&0x037fu16.to_le_bytes());
        memory.bytes[4..6].copy_from_slice(&0x3000u16.to_le_bytes()); // new TOP=6
        memory.bytes[8..10].copy_from_slice(&0xffffu16.to_le_bytes());

        snapshot
            .emulate_legacy_x87_restore(plan, &mut memory)
            .expect("restore environment with changed TOP");

        for new_logical in 0..X87_REGISTER_COUNT {
            let old_logical = (6 + new_logical + X87_REGISTER_COUNT - 1) & (X87_REGISTER_COUNT - 1);
            assert_eq!(
                &snapshot.xsave[32 + new_logical * 16..48 + new_logical * 16],
                &[old_logical as u8 + 0x10; 16],
                "logical ST({new_logical}) must retain physical register identity"
            );
        }
    }

    #[test]
    fn fourteen_byte_restore_preserves_fop_missing_from_the_wire_format() {
        for kind in [X86LegacyX87Kind::Fldenv14, X86LegacyX87Kind::Frstor94] {
            let mut snapshot = X86UcontextSnapshot::new();
            snapshot.xsave[6..8].copy_from_slice(&0x0321u16.to_le_bytes());
            let plan = plan(
                kind,
                &[
                    0x66,
                    if kind.includes_registers() {
                        0xdd
                    } else {
                        0xd9
                    },
                    0x20,
                ],
                &mut snapshot,
            );
            let mut memory = Memory::new(0);
            memory.bytes[0..2].copy_from_slice(&0x037fu16.to_le_bytes());
            memory.bytes[2..4].copy_from_slice(&0u16.to_le_bytes());
            memory.bytes[4..6].copy_from_slice(&0xffffu16.to_le_bytes());

            snapshot
                .emulate_legacy_x87_restore(plan, &mut memory)
                .expect("restore 14-byte environment form");
            assert_eq!(
                u16_at(&snapshot.xsave, 6),
                0x0321,
                "{kind:?} must retain the prior FOP"
            );
        }
    }

    #[test]
    fn save_side_effects_commit_only_after_complete_ordered_writes() {
        let mut snapshot = X86UcontextSnapshot::new();
        snapshot.xsave[0..2].copy_from_slice(&0x0340u16.to_le_bytes());
        snapshot.xsave[32..42].fill(0x5a);
        let plan = plan(X86LegacyX87Kind::Fnsave108, &[0xdd, 0x30], &mut snapshot);
        let before = snapshot.clone();
        let mut memory = Memory::new(0xa5);
        memory.fail_write = Some(4);
        assert_eq!(
            snapshot.emulate_legacy_x87_save(plan, &mut memory),
            Err(X86LegacyX87Error::Write(MemoryError::Injected))
        );
        assert_eq!(snapshot.xsave, before.xsave, "failed save must not FNINIT");
        assert_eq!(
            memory.writes,
            vec![
                (BASE, 28),
                (BASE + 28, 10),
                (BASE + 38, 10),
                (BASE + 48, 10),
                (BASE + 58, 10)
            ]
        );
        memory.fail_write = None;
        memory.writes.clear();
        snapshot
            .emulate_legacy_x87_save(plan, &mut memory)
            .expect("retry save");
        assert_eq!(u16_at(&snapshot.xsave, 0), 0x037f);
        assert_eq!(snapshot.xsave[4], 0);
        assert_eq!(
            &snapshot.xsave[32..42],
            &[0x5a; 10],
            "FNSAVE's implicit FINIT must retain physical payload bytes"
        );
    }

    #[test]
    fn fnstenv_masks_only_after_the_complete_environment_write() {
        let mut snapshot = X86UcontextSnapshot::new();
        snapshot.xsave[0..2].copy_from_slice(&0x0340u16.to_le_bytes());
        let plan = plan(X86LegacyX87Kind::Fnstenv28, &[0xd9, 0x30], &mut snapshot);
        let mut memory = Memory::new(0xa5);
        memory.fail_write = Some(0);
        assert_eq!(
            snapshot.emulate_legacy_x87_save(plan, &mut memory),
            Err(X86LegacyX87Error::Write(MemoryError::Injected))
        );
        assert_eq!(u16_at(&snapshot.xsave, 0), 0x0340);
        memory.fail_write = None;
        snapshot
            .emulate_legacy_x87_save(plan, &mut memory)
            .expect("retry FNSTENV");
        assert_eq!(u16_at(&snapshot.xsave, 0), 0x037f);
    }

    #[test]
    fn wait_state_is_virtual_and_no_wait_forms_complete() {
        let mut snapshot = X86UcontextSnapshot::new();
        snapshot.xsave[XSTATE_BV_OFFSET..XSTATE_BV_OFFSET + 8].fill(0);
        snapshot.xsave[0..2].copy_from_slice(&0x0340u16.to_le_bytes());
        snapshot.xsave[2..4].copy_from_slice(&0x0081u16.to_le_bytes());
        assert_eq!(
            snapshot.x87_pending_exception(),
            None,
            "stale legacy bytes are not live when XSTATE_BV omits x87"
        );
        snapshot.xsave[XSTATE_BV_OFFSET..XSTATE_BV_OFFSET + 8]
            .copy_from_slice(&X87_FEATURE.to_le_bytes());
        snapshot.xsave[2..4].copy_from_slice(&FSW_EXCEPTION_SUMMARY.to_le_bytes());
        assert_eq!(
            snapshot.x87_pending_exception(),
            None,
            "ES without an unmasked exception flag is not a fault"
        );
        snapshot.xsave[0..2].copy_from_slice(&0x037fu16.to_le_bytes());
        snapshot.xsave[2..4].copy_from_slice(&0x0081u16.to_le_bytes());
        assert_eq!(
            snapshot.x87_pending_exception(),
            None,
            "ES with only masked exception flags is not a fault"
        );
        snapshot.xsave[0..2].copy_from_slice(&0x0340u16.to_le_bytes());
        snapshot.xsave[2..4].copy_from_slice(&0x0081u16.to_le_bytes());
        assert_eq!(
            snapshot.x87_pending_exception(),
            Some(X86X87ExceptionKind::Invalid)
        );
        snapshot.xsave[0..2].copy_from_slice(&0x037bu16.to_le_bytes());
        snapshot.xsave[2..4].copy_from_slice(&0x0084u16.to_le_bytes());
        assert_eq!(
            snapshot.x87_pending_exception(),
            Some(X86X87ExceptionKind::DivideByZero)
        );
        // Iced deliberately splits the architectural FSTENV spelling into a
        // standalone WAIT plus FNSTENV. The former exits as X87Wait; the latter
        // reaches this no-wait codec only after WAIT succeeds.
        let mut memory = Memory::new(0xa5);
        let no_wait = plan(X86LegacyX87Kind::Fnstenv28, &[0xd9, 0x30], &mut snapshot);
        snapshot
            .emulate_legacy_x87_save(no_wait, &mut memory)
            .expect("FNSTENV ignores pending exception");
        assert_eq!(
            u16_at(&snapshot.xsave, 0) & EXCEPTION_MASK_BITS,
            EXCEPTION_MASK_BITS
        );
        assert_eq!(
            snapshot.x87_pending_exception(),
            None,
            "FNSTENV masking must let a subsequent WAIT proceed"
        );
    }
}
