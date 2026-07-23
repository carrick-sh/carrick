//! Pure, checked emulation of user-mode `XRSTOR`/`XRSTOR64`.
//!
//! The module never executes the guest instruction and never turns a guest
//! address into a host pointer. Iced supplies the decoded memory operand; a
//! caller-owned checked reader supplies only the architectural source ranges
//! that the request can actually restore.

use std::convert::Infallible;

use carrick_guest_mem::GuestVa;
use iced_x86::{Code, Decoder, DecoderOptions};

use crate::decode::X86XstateRestoreKind;
use crate::gateway::{
    X86SnapshotXstateCapabilities, X86SnapshotXstateComponent, X86SnapshotXstateLayout,
    X86UcontextSnapshot, XSAVE_AREA_LEN, reg,
};
pub use crate::xstate_address::X86GuestGsBase;
use crate::xstate_address::{X86XstateAddressError, is_canonical, resolve_xstate_memory_operand};

const XSAVE_HEADER_OFFSET: usize = 512;
const XSAVE_HEADER_LEN: usize = 64;
const XSAVE_EXTENDED_OFFSET: usize = XSAVE_HEADER_OFFSET + XSAVE_HEADER_LEN;
const XCOMP_COMPACTED: u64 = 1 << 63;
const X87_FEATURE: u64 = 1 << 0;
const SSE_FEATURE: u64 = 1 << 1;

/// Why checked XRSTOR emulation would deliver `#GP(0)` to the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum X86XstateRestoreGpReason {
    #[error("the instruction is not a supported user XRSTOR memory form")]
    UnsupportedInstruction,
    #[error("the memory operand does not use a supported long-mode address size")]
    UnsupportedAddressSize,
    #[error("the memory operand uses an unsupported segment override")]
    UnsupportedSegment,
    #[error("the memory operand uses an unsupported register form")]
    UnsupportedAddressForm,
    #[error("the effective address is noncanonical")]
    NoncanonicalAddress,
    #[error("the effective address is not 64-byte aligned")]
    MisalignedAddress,
    #[error("the XSAVE source range is not a canonical non-wrapping range")]
    InvalidSourceRange,
    #[error("XSTATE_BV or XCOMP_BV names an unsafe component")]
    UnsafeComponent,
    #[error("the compacted XSAVE component map is inconsistent")]
    InvalidCompactedLayout,
    #[error("reserved XSAVE header bytes are nonzero")]
    NonzeroReservedHeader,
    #[error("MXCSR contains a bit outside MXCSR_MASK")]
    InvalidMxcsr,
}

/// Why checked XRSTOR emulation would deliver `#SS(0)` to the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum X86XstateRestoreSsReason {
    #[error("the stack-segment effective address is noncanonical")]
    NoncanonicalAddress,
}

/// Checked XRSTOR failure. Guest-memory faults retain the caller's exact error
/// type instead of being collapsed into a host pointer or errno.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum X86XstateRestoreError<E = Infallible> {
    #[error("x86 XRSTOR general protection: {0}")]
    GeneralProtection(X86XstateRestoreGpReason),
    #[error("x86 XRSTOR stack-segment fault: {0}")]
    StackSegment(X86XstateRestoreSsReason),
    #[error("x86 XRSTOR checked guest-memory read failed")]
    Read(E),
    #[error("x86 XRSTOR internal failure: {0}")]
    Internal(X86XstateRestoreInternalReason),
}

/// Non-architectural failures in Carrick's XRSTOR setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum X86XstateRestoreInternalReason {
    #[error("invalid xstate layout")]
    InvalidLayout,
}

/// Exact guest-memory reader used by XRSTOR emulation.
///
/// Each call names one architectural byte range. Implementations must either
/// fill all of `destination` or return their own error; partial success is not
/// observable by the snapshot because emulation commits atomically.
pub trait X86XstateMemoryReader {
    type Error;

    fn read_exact(&mut self, address: GuestVa, destination: &mut [u8]) -> Result<(), Self::Error>;
}

/// A decoded XRSTOR instruction and its exact guest effective address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86XstateRestorePlan {
    kind: X86XstateRestoreKind,
    address: GuestVa,
    instruction_len: u8,
    effective_segment_is_ss: bool,
}

impl X86XstateRestorePlan {
    /// Decode the original guest instruction at `snapshot.rip` and resolve its
    /// long-mode effective address from the captured register file.
    pub fn decode(
        bytes: &[u8],
        snapshot: &X86UcontextSnapshot,
        guest_fsbase: u64,
        guest_gsbase: X86GuestGsBase,
    ) -> Result<Self, X86XstateRestoreError> {
        let mut decoder = Decoder::with_ip(64, bytes, snapshot.rip, DecoderOptions::NONE);
        let instruction = decoder.decode();
        let kind = match instruction.code() {
            Code::Xrstor_mem => X86XstateRestoreKind::Xrstor,
            Code::Xrstor64_mem => X86XstateRestoreKind::Xrstor64,
            _ => {
                return Err(X86XstateRestoreError::GeneralProtection(
                    X86XstateRestoreGpReason::UnsupportedInstruction,
                ));
            }
        };
        let resolved =
            resolve_xstate_memory_operand(&instruction, snapshot, guest_fsbase, guest_gsbase)
                .map_err(xstate_address_error)?;

        Ok(Self {
            kind,
            address: resolved.address,
            instruction_len: resolved.instruction_len,
            effective_segment_is_ss: resolved.effective_segment_is_ss,
        })
    }

    pub const fn kind(self) -> X86XstateRestoreKind {
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

fn xstate_address_error(error: X86XstateAddressError) -> X86XstateRestoreError {
    match error {
        X86XstateAddressError::UnsupportedInstruction => X86XstateRestoreError::GeneralProtection(
            X86XstateRestoreGpReason::UnsupportedInstruction,
        ),
        X86XstateAddressError::UnsupportedAddressSize => X86XstateRestoreError::GeneralProtection(
            X86XstateRestoreGpReason::UnsupportedAddressSize,
        ),
        X86XstateAddressError::UnsupportedSegment => {
            X86XstateRestoreError::GeneralProtection(X86XstateRestoreGpReason::UnsupportedSegment)
        }
        X86XstateAddressError::UnsupportedAddressForm => X86XstateRestoreError::GeneralProtection(
            X86XstateRestoreGpReason::UnsupportedAddressForm,
        ),
        X86XstateAddressError::GeneralProtectionNoncanonical => {
            X86XstateRestoreError::GeneralProtection(X86XstateRestoreGpReason::NoncanonicalAddress)
        }
        X86XstateAddressError::StackSegmentNoncanonical => {
            X86XstateRestoreError::StackSegment(X86XstateRestoreSsReason::NoncanonicalAddress)
        }
        X86XstateAddressError::MisalignedAddress => {
            X86XstateRestoreError::GeneralProtection(X86XstateRestoreGpReason::MisalignedAddress)
        }
    }
}

fn noncanonical_address<E>(plan: X86XstateRestorePlan) -> X86XstateRestoreError<E> {
    if plan.effective_segment_is_ss {
        X86XstateRestoreError::StackSegment(X86XstateRestoreSsReason::NoncanonicalAddress)
    } else {
        X86XstateRestoreError::GeneralProtection(X86XstateRestoreGpReason::NoncanonicalAddress)
    }
}

fn checked_source_address<E>(
    plan: X86XstateRestorePlan,
    offset: usize,
    len: usize,
) -> Result<GuestVa, X86XstateRestoreError<E>> {
    let offset = u64::try_from(offset).map_err(|_| {
        X86XstateRestoreError::GeneralProtection(X86XstateRestoreGpReason::InvalidSourceRange)
    })?;
    let len = u64::try_from(len).map_err(|_| {
        X86XstateRestoreError::GeneralProtection(X86XstateRestoreGpReason::InvalidSourceRange)
    })?;
    let start =
        plan.address
            .raw()
            .checked_add(offset)
            .ok_or(X86XstateRestoreError::GeneralProtection(
                X86XstateRestoreGpReason::InvalidSourceRange,
            ))?;
    let end = start
        .checked_add(len)
        .ok_or(X86XstateRestoreError::GeneralProtection(
            X86XstateRestoreGpReason::InvalidSourceRange,
        ))?;
    if !is_canonical(start) || (len != 0 && !is_canonical(end - 1)) {
        return Err(noncanonical_address(plan));
    }
    Ok(GuestVa(start))
}

fn read_source<R: X86XstateMemoryReader + ?Sized>(
    reader: &mut R,
    plan: X86XstateRestorePlan,
    offset: usize,
    destination: &mut [u8],
) -> Result<(), X86XstateRestoreError<R::Error>> {
    let address = checked_source_address(plan, offset, destination.len())?;
    reader
        .read_exact(address, destination)
        .map_err(X86XstateRestoreError::Read)
}

fn le_u32(bytes: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*bytes)
}

fn le_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

fn invalid_layout<E>() -> X86XstateRestoreError<E> {
    X86XstateRestoreError::Internal(X86XstateRestoreInternalReason::InvalidLayout)
}

fn component_bounds<E>(
    component: usize,
    metadata: X86SnapshotXstateComponent,
) -> Result<(usize, usize), X86XstateRestoreError<E>> {
    let start = usize::try_from(metadata.offset).map_err(|_| invalid_layout())?;
    let size = usize::try_from(metadata.size).map_err(|_| invalid_layout())?;
    let end = start.checked_add(size).ok_or_else(invalid_layout)?;
    if component < 2 || size == 0 || start < XSAVE_EXTENDED_OFFSET || end > XSAVE_AREA_LEN {
        return Err(invalid_layout());
    }
    Ok((start, end))
}

fn align64<E>(value: usize) -> Result<usize, X86XstateRestoreError<E>> {
    value
        .checked_add(63)
        .map(|value| value & !63)
        .ok_or_else(invalid_layout)
}

fn compacted_offsets<E>(
    layout: &X86SnapshotXstateLayout,
    compacted_features: u64,
) -> Result<[usize; 64], X86XstateRestoreError<E>> {
    let capabilities = layout.capabilities();
    let mut offsets = [0usize; 64];
    let mut cursor = XSAVE_EXTENDED_OFFSET;
    for (component, offset) in offsets.iter_mut().enumerate().skip(2) {
        if compacted_features & (1u64 << component) == 0 {
            continue;
        }
        let metadata = capabilities.components[component];
        let (_, standard_end) = component_bounds(component, metadata)?;
        let size = usize::try_from(metadata.size).map_err(|_| invalid_layout())?;
        if layout.compacted_align64_features() & (1u64 << component) != 0 {
            cursor = align64(cursor)?;
        }
        *offset = cursor;
        cursor = cursor.checked_add(size).ok_or_else(invalid_layout)?;
        if cursor > XSAVE_AREA_LEN || standard_end > XSAVE_AREA_LEN {
            return Err(invalid_layout());
        }
    }
    let compacted_size = usize::try_from(
        layout
            .compacted_size_for(compacted_features)
            .map_err(|_| invalid_layout())?,
    )
    .map_err(|_| invalid_layout())?;
    if cursor != compacted_size {
        return Err(invalid_layout());
    }
    Ok(offsets)
}

fn validate_layout<E>(
    layout: &X86SnapshotXstateLayout,
) -> Result<X86SnapshotXstateCapabilities, X86XstateRestoreError<E>> {
    layout.validate().map_err(|_| invalid_layout())?;
    Ok(layout.capabilities())
}

impl X86UcontextSnapshot {
    /// Atomically emulate the xstate effect of one decoded XRSTOR instruction.
    ///
    /// EDX:EAX is masked to Carrick's safely virtualized XCR0. The source
    /// header is always read and validated first. Payload reads are limited to
    /// requested-and-present architectural ranges, with compacted components
    /// translated into this snapshot's standard XSAVE layout. RIP/GPRs/RFLAGS
    /// and virtual PKRU are not changed; the sensitive-instruction service
    /// advances RIP after this operation succeeds.
    pub fn emulate_xrstor_with_reader<R: X86XstateMemoryReader + ?Sized>(
        &mut self,
        plan: X86XstateRestorePlan,
        layout: &X86SnapshotXstateLayout,
        reader: &mut R,
    ) -> Result<(), X86XstateRestoreError<R::Error>> {
        let capabilities = validate_layout::<R::Error>(layout)?;
        let safe_supported = capabilities.supported_features;
        let request =
            u64::from(self.gpr[reg::RAX] as u32) | (u64::from(self.gpr[reg::RDX] as u32) << 32);
        let effective = request & safe_supported;

        let mut header = [0u8; XSAVE_HEADER_LEN];
        read_source(reader, plan, XSAVE_HEADER_OFFSET, &mut header)?;
        let source_bv = le_u64(&header[0..8]);
        let xcomp_bv = le_u64(&header[8..16]);
        if header[16..].iter().any(|byte| *byte != 0) {
            return Err(X86XstateRestoreError::GeneralProtection(
                X86XstateRestoreGpReason::NonzeroReservedHeader,
            ));
        }
        if source_bv & !safe_supported != 0 {
            return Err(X86XstateRestoreError::GeneralProtection(
                X86XstateRestoreGpReason::UnsafeComponent,
            ));
        }

        let compacted = xcomp_bv & XCOMP_COMPACTED != 0;
        let compacted_features = xcomp_bv & !XCOMP_COMPACTED;
        if compacted_features & !safe_supported != 0 {
            return Err(X86XstateRestoreError::GeneralProtection(
                X86XstateRestoreGpReason::UnsafeComponent,
            ));
        }
        if compacted {
            if source_bv & !compacted_features != 0 {
                return Err(X86XstateRestoreError::GeneralProtection(
                    X86XstateRestoreGpReason::InvalidCompactedLayout,
                ));
            }
        } else if xcomp_bv != 0 {
            return Err(X86XstateRestoreError::GeneralProtection(
                X86XstateRestoreGpReason::InvalidCompactedLayout,
            ));
        }

        let compacted_component_offsets = if compacted {
            compacted_offsets(layout, compacted_features)?
        } else {
            [0usize; 64]
        };
        // Validate every requested extended destination before the first
        // payload read. Source-memory failures may still arrive late, but all
        // state remains private until the final assignment below.
        for component in 2..64usize {
            if effective & (1u64 << component) != 0 {
                component_bounds::<R::Error>(component, capabilities.components[component])?;
            }
        }

        let initial = Self::new();
        let mut temporary = self.clone();

        if effective & X87_FEATURE != 0 {
            if source_bv & X87_FEATURE != 0 {
                restore_x87(reader, plan, &mut temporary)?;
            } else {
                initialize_x87(&mut temporary, &initial);
            }
        }
        if effective & SSE_FEATURE != 0 {
            if source_bv & SSE_FEATURE != 0 {
                restore_sse(reader, plan, capabilities.mxcsr_mask, &mut temporary)?;
            } else {
                initialize_sse(&mut temporary, &initial);
            }
        }

        for (component, &compacted_source_start) in
            compacted_component_offsets.iter().enumerate().skip(2)
        {
            let bit = 1u64 << component;
            if effective & bit == 0 {
                continue;
            }
            let metadata = capabilities.components[component];
            let (destination_start, destination_end) =
                component_bounds::<R::Error>(component, metadata)?;
            if source_bv & bit == 0 {
                temporary.xsave[destination_start..destination_end]
                    .copy_from_slice(&initial.xsave[destination_start..destination_end]);
                continue;
            }
            let source_start = if compacted {
                compacted_source_start
            } else {
                destination_start
            };
            let mut component_bytes = vec![0u8; destination_end - destination_start];
            read_source(reader, plan, source_start, &mut component_bytes)?;
            temporary.xsave[destination_start..destination_end].copy_from_slice(&component_bytes);
        }

        let old_bv = self.xstate_bv();
        let result_bv = (old_bv & !effective) | (source_bv & effective);
        temporary.xsave[XSAVE_HEADER_OFFSET..XSAVE_HEADER_OFFSET + 8]
            .copy_from_slice(&result_bv.to_le_bytes());
        // The authoritative snapshot always remains standard format; source
        // compacted metadata and all reserved header bytes are never imported.
        temporary.xsave[XSAVE_HEADER_OFFSET + 8..XSAVE_EXTENDED_OFFSET].fill(0);
        *self = temporary;
        Ok(())
    }
}

fn restore_x87<R: X86XstateMemoryReader + ?Sized>(
    reader: &mut R,
    plan: X86XstateRestorePlan,
    temporary: &mut X86UcontextSnapshot,
) -> Result<(), X86XstateRestoreError<R::Error>> {
    // Byte 5 is reserved. Non-REX XRSTOR imports the 16-bit FCS/FDS fields
    // but ignores each following reserved 16-bit half. XRSTOR64 instead uses
    // both complete 64-bit pointer slots and leaves virtual selectors alone.
    let mut controls = [0u8; 5];
    let mut opcode = [0u8; 2];
    let mut registers = [0u8; 128];
    read_source(reader, plan, 0, &mut controls)?;
    read_source(reader, plan, 6, &mut opcode)?;

    temporary.xsave[0..5].copy_from_slice(&controls);
    temporary.xsave[6..8].copy_from_slice(&opcode);
    match plan.kind {
        X86XstateRestoreKind::Xrstor64 => {
            let mut pointers = [0u8; 16];
            read_source(reader, plan, 8, &mut pointers)?;
            temporary.xsave[8..24].copy_from_slice(&pointers);
        }
        X86XstateRestoreKind::Xrstor => {
            let mut fip = [0u8; 4];
            let mut fcs = [0u8; 2];
            let mut fdp = [0u8; 4];
            let mut fds = [0u8; 2];
            read_source(reader, plan, 8, &mut fip)?;
            read_source(reader, plan, 12, &mut fcs)?;
            read_source(reader, plan, 16, &mut fdp)?;
            read_source(reader, plan, 20, &mut fds)?;
            temporary.xsave[8..12].copy_from_slice(&fip);
            temporary.xsave[12..16].fill(0);
            temporary.xsave[16..20].copy_from_slice(&fdp);
            temporary.xsave[20..24].fill(0);
            temporary.restore_x87_selectors(u16::from_le_bytes(fcs), u16::from_le_bytes(fds));
        }
    }
    read_source(reader, plan, 32, &mut registers)?;
    temporary.xsave[32..160].copy_from_slice(&registers);
    Ok(())
}

fn initialize_x87(snapshot: &mut X86UcontextSnapshot, initial: &X86UcontextSnapshot) {
    snapshot.xsave[0..5].copy_from_slice(&initial.xsave[0..5]);
    snapshot.xsave[6..24].copy_from_slice(&initial.xsave[6..24]);
    snapshot.xsave[32..160].copy_from_slice(&initial.xsave[32..160]);
    snapshot.restore_x87_selectors(initial.x87_fcs(), initial.x87_fds());
}

fn restore_sse<R: X86XstateMemoryReader + ?Sized>(
    reader: &mut R,
    plan: X86XstateRestorePlan,
    mxcsr_mask: u32,
    temporary: &mut X86UcontextSnapshot,
) -> Result<(), X86XstateRestoreError<R::Error>> {
    let mut mxcsr = [0u8; 4];
    read_source(reader, plan, 24, &mut mxcsr)?;
    if le_u32(&mxcsr) & !mxcsr_mask != 0 {
        return Err(X86XstateRestoreError::GeneralProtection(
            X86XstateRestoreGpReason::InvalidMxcsr,
        ));
    }
    let mut xmm = [0u8; 256];
    read_source(reader, plan, 160, &mut xmm)?;
    temporary.xsave[24..28].copy_from_slice(&mxcsr);
    temporary.xsave[160..416].copy_from_slice(&xmm);
    Ok(())
}

fn initialize_sse(snapshot: &mut X86UcontextSnapshot, initial: &X86UcontextSnapshot) {
    snapshot.xsave[24..28].copy_from_slice(&initial.xsave[24..28]);
    snapshot.xsave[160..416].copy_from_slice(&initial.xsave[160..416]);
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE_BASE: u64 = 0x10_000;
    const RIP: u64 = 0x40_0000;
    const SAFE_FEATURES: u64 =
        X87_FEATURE | SSE_FEATURE | (1 << 2) | (1 << 5) | (1 << 6) | (1 << 7);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TestReadError {
        Bounds,
        Injected,
    }

    struct ImageReader {
        base: u64,
        bytes: Vec<u8>,
        reads: Vec<(GuestVa, usize)>,
        fail_at: Option<usize>,
    }

    impl ImageReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                base: IMAGE_BASE,
                bytes,
                reads: Vec::new(),
                fail_at: None,
            }
        }
    }

    impl X86XstateMemoryReader for ImageReader {
        type Error = TestReadError;

        fn read_exact(
            &mut self,
            address: GuestVa,
            destination: &mut [u8],
        ) -> Result<(), Self::Error> {
            let read_number = self.reads.len();
            self.reads.push((address, destination.len()));
            if self.fail_at == Some(read_number) {
                return Err(TestReadError::Injected);
            }
            let offset = address
                .raw()
                .checked_sub(self.base)
                .and_then(|offset| usize::try_from(offset).ok())
                .ok_or(TestReadError::Bounds)?;
            let source = self
                .bytes
                .get(offset..offset + destination.len())
                .ok_or(TestReadError::Bounds)?;
            destination.copy_from_slice(source);
            Ok(())
        }
    }

    fn capabilities() -> X86SnapshotXstateLayout {
        let mut components = [X86SnapshotXstateComponent::default(); 64];
        components[2] = X86SnapshotXstateComponent {
            offset: 576,
            size: 256,
        };
        components[5] = X86SnapshotXstateComponent {
            offset: 832,
            size: 64,
        };
        components[6] = X86SnapshotXstateComponent {
            offset: 896,
            size: 512,
        };
        components[7] = X86SnapshotXstateComponent {
            offset: 1408,
            size: 1024,
        };
        X86SnapshotXstateLayout::new(
            X86SnapshotXstateCapabilities {
                supported_features: SAFE_FEATURES,
                standard_size: 2432,
                mxcsr_mask: 0x0000_ffbf,
                components,
            },
            (1 << 5) | (1 << 6) | (1 << 7),
        )
        .expect("valid test xstate layout")
    }

    fn sparse_compacted_layout() -> X86SnapshotXstateLayout {
        let mut components = [X86SnapshotXstateComponent::default(); 64];
        components[2] = X86SnapshotXstateComponent {
            offset: 1024,
            size: 32,
        };
        components[5] = X86SnapshotXstateComponent {
            offset: 2048,
            size: 16,
        };
        components[6] = X86SnapshotXstateComponent {
            offset: 2304,
            size: 24,
        };
        components[7] = X86SnapshotXstateComponent {
            offset: 3072,
            size: 32,
        };
        X86SnapshotXstateLayout::new(
            X86SnapshotXstateCapabilities {
                supported_features: SAFE_FEATURES,
                standard_size: 3104,
                mxcsr_mask: 0x0000_ffbf,
                components,
            },
            (1 << 5) | (1 << 7),
        )
        .expect("valid sparse xstate layout")
    }

    fn image_with_header(xstate_bv: u64, xcomp_bv: u64) -> Vec<u8> {
        let mut image = vec![0u8; 4096];
        image[512..520].copy_from_slice(&xstate_bv.to_le_bytes());
        image[520..528].copy_from_slice(&xcomp_bv.to_le_bytes());
        image
    }

    fn snapshot_at_image(request: u64) -> X86UcontextSnapshot {
        let mut snapshot = X86UcontextSnapshot::new();
        snapshot.rip = RIP;
        snapshot.gpr[reg::RSP] = IMAGE_BASE;
        snapshot.gpr[reg::RAX] = request & u64::from(u32::MAX);
        snapshot.gpr[reg::RDX] = request >> 32;
        snapshot
    }

    fn xrstor64_plan(snapshot: &X86UcontextSnapshot) -> X86XstateRestorePlan {
        X86XstateRestorePlan::decode(
            &[0x48, 0x0f, 0xae, 0x2c, 0x24],
            snapshot,
            0,
            X86GuestGsBase::Zero,
        )
        .expect("decode xrstor64 [rsp]")
    }

    fn set_bv(snapshot: &mut X86UcontextSnapshot, value: u64) {
        snapshot.xsave[512..520].copy_from_slice(&value.to_le_bytes());
    }

    fn fill_extended_standard(image: &mut [u8], capabilities: &X86SnapshotXstateCapabilities) {
        for component in [2usize, 5, 6, 7] {
            let metadata = capabilities.components[component];
            let start = metadata.offset as usize;
            let end = start + metadata.size as usize;
            image[start..end].fill((component as u8).wrapping_mul(0x11));
        }
    }

    fn assert_snapshot_eq(actual: &X86UcontextSnapshot, expected: &X86UcontextSnapshot) {
        assert_eq!(actual.gpr, expected.gpr);
        assert_eq!(actual.rip, expected.rip);
        assert_eq!(actual.rflags, expected.rflags);
        assert_eq!(actual.pkru(), expected.pkru());
        assert_eq!(actual.x87_fcs(), expected.x87_fcs());
        assert_eq!(actual.x87_fds(), expected.x87_fds());
        assert_eq!(actual.xsave, expected.xsave);
    }

    #[test]
    fn effective_address_uses_exact_rsp_rex_index_rip_and_fs_state() {
        let mut snapshot = X86UcontextSnapshot::new();
        snapshot.rip = RIP;
        snapshot.gpr[reg::RSP] = 0x1000;
        let rsp = X86XstateRestorePlan::decode(
            &[0x0f, 0xae, 0x6c, 0x24, 0x40],
            &snapshot,
            0,
            X86GuestGsBase::Zero,
        )
        .expect("xrstor [rsp+0x40]");
        assert_eq!(rsp.address(), GuestVa(0x1040));
        assert_eq!(rsp.kind(), X86XstateRestoreKind::Xrstor);
        assert_eq!(rsp.instruction_len(), 5);
        assert!(rsp.effective_segment_is_ss());

        snapshot.gpr[reg::R8] = 0x1000;
        snapshot.gpr[reg::R9] = 0x10;
        let rex = X86XstateRestorePlan::decode(
            &[0x4b, 0x0f, 0xae, 0x6c, 0x88, 0x40],
            &snapshot,
            0,
            X86GuestGsBase::Zero,
        )
        .expect("xrstor64 [r8+r9*4+0x40]");
        assert_eq!(rex.address(), GuestVa(0x1080));
        assert_eq!(rex.kind(), X86XstateRestoreKind::Xrstor64);
        assert!(!rex.effective_segment_is_ss());

        let rip = X86XstateRestorePlan::decode(
            &[0x48, 0x0f, 0xae, 0x2d, 0x38, 0x00, 0x00, 0x00],
            &snapshot,
            0,
            X86GuestGsBase::Zero,
        )
        .expect("xrstor64 [rip+0x38]");
        assert_eq!(rip.address(), GuestVa(RIP + 8 + 0x38));

        snapshot.gpr[reg::RBP] = 0x1080;
        let negative = X86XstateRestorePlan::decode(
            &[0x48, 0x0f, 0xae, 0x6d, 0xc0],
            &snapshot,
            0,
            X86GuestGsBase::Zero,
        )
        .expect("xrstor64 [rbp-0x40]");
        assert_eq!(negative.address(), GuestVa(0x1040));
        assert!(negative.effective_segment_is_ss());

        snapshot.gpr[reg::RAX] = u64::MAX - 63;
        let wrapped = X86XstateRestorePlan::decode(
            &[0x48, 0x0f, 0xae, 0x68, 0x40],
            &snapshot,
            0,
            X86GuestGsBase::Zero,
        )
        .expect("xrstor64 [rax+0x40] wraps architecturally");
        assert_eq!(wrapped.address(), GuestVa(0));

        snapshot.gpr[reg::RAX] = 0x40;
        let fs = X86XstateRestorePlan::decode(
            &[0x64, 0x48, 0x0f, 0xae, 0x28],
            &snapshot,
            0x3000,
            X86GuestGsBase::Zero,
        )
        .expect("xrstor64 fs:[rax]");
        assert_eq!(fs.address(), GuestVa(0x3040));
        assert!(!fs.effective_segment_is_ss());

        let gs = X86XstateRestorePlan::decode(
            &[0x65, 0x48, 0x0f, 0xae, 0x28],
            &snapshot,
            0,
            X86GuestGsBase::Value(0x4000),
        )
        .expect("xrstor64 gs:[rax]");
        assert_eq!(gs.address(), GuestVa(0x4040));
    }

    #[test]
    fn addr32_wraps_before_zero_extension_and_segment_base_addition() {
        let mut snapshot = X86UcontextSnapshot::new();
        snapshot.rip = RIP;
        snapshot.gpr[reg::R8] = 0xffff_ffff_0000_1000;
        snapshot.gpr[reg::R9] = 0xaaaa_aaaa_0000_0010;
        let indexed = X86XstateRestorePlan::decode(
            &[0x67, 0x4b, 0x0f, 0xae, 0x6c, 0x88, 0x40],
            &snapshot,
            0,
            X86GuestGsBase::Zero,
        )
        .expect("addr32 xrstor64 [r8d+r9d*4+0x40]");
        assert_eq!(indexed.address(), GuestVa(0x1080));

        snapshot.gpr[reg::RAX] = 0xffff_ffff_ffff_ffc0;
        let wrapped = X86XstateRestorePlan::decode(
            &[0x67, 0x48, 0x0f, 0xae, 0x68, 0x40],
            &snapshot,
            0,
            X86GuestGsBase::Zero,
        )
        .expect("addr32 addition wraps modulo 2^32");
        assert_eq!(wrapped.address(), GuestVa(0));

        let fs = X86XstateRestorePlan::decode(
            &[0x64, 0x67, 0x48, 0x0f, 0xae, 0x68, 0x40],
            &snapshot,
            0x3000,
            X86GuestGsBase::Zero,
        )
        .expect("FS base is added after addr32 zero extension");
        assert_eq!(fs.address(), GuestVa(0x3000));
    }

    #[test]
    fn effective_segments_accept_zero_base_overrides_and_record_ss() {
        let mut snapshot = X86UcontextSnapshot::new();
        snapshot.rip = RIP;
        snapshot.gpr[reg::RAX] = 0x1000;
        snapshot.gpr[reg::RSP] = 0x2000;

        for prefix in [0x2e, 0x3e, 0x26] {
            let plan = X86XstateRestorePlan::decode(
                &[prefix, 0x48, 0x0f, 0xae, 0x28],
                &snapshot,
                0,
                X86GuestGsBase::Zero,
            )
            .expect("zero-base segment override");
            assert_eq!(plan.address(), GuestVa(0x1000));
            assert!(!plan.effective_segment_is_ss());
        }

        let explicit_ss = X86XstateRestorePlan::decode(
            &[0x36, 0x48, 0x0f, 0xae, 0x28],
            &snapshot,
            0,
            X86GuestGsBase::Zero,
        )
        .expect("SS override");
        assert_eq!(explicit_ss.address(), GuestVa(0x1000));
        assert!(explicit_ss.effective_segment_is_ss());

        let default_ss = X86XstateRestorePlan::decode(
            &[0x48, 0x0f, 0xae, 0x2c, 0x24],
            &snapshot,
            0,
            X86GuestGsBase::Zero,
        )
        .expect("default RSP segment");
        assert_eq!(default_ss.address(), GuestVa(0x2000));
        assert!(default_ss.effective_segment_is_ss());
    }

    #[test]
    fn effective_address_faults_on_noncanonical_misaligned_and_unsupported_forms() {
        let mut snapshot = X86UcontextSnapshot::new();
        snapshot.rip = RIP;
        snapshot.gpr[reg::RAX] = 0x0000_8000_0000_0000;
        assert_eq!(
            X86XstateRestorePlan::decode(
                &[0x48, 0x0f, 0xae, 0x28],
                &snapshot,
                0,
                X86GuestGsBase::Zero
            ),
            Err(X86XstateRestoreError::GeneralProtection(
                X86XstateRestoreGpReason::NoncanonicalAddress
            ))
        );

        snapshot.gpr[reg::RAX] = 0x1008;
        assert_eq!(
            X86XstateRestorePlan::decode(
                &[0x48, 0x0f, 0xae, 0x28],
                &snapshot,
                0,
                X86GuestGsBase::Zero
            ),
            Err(X86XstateRestoreError::GeneralProtection(
                X86XstateRestoreGpReason::MisalignedAddress
            ))
        );

        snapshot.gpr[reg::RSP] = 0x0000_8000_0000_0000;
        assert_eq!(
            X86XstateRestorePlan::decode(
                &[0x48, 0x0f, 0xae, 0x2c, 0x24],
                &snapshot,
                0,
                X86GuestGsBase::Zero
            ),
            Err(X86XstateRestoreError::StackSegment(
                X86XstateRestoreSsReason::NoncanonicalAddress
            ))
        );

        snapshot.gpr[reg::RSP] = 0x1008;
        assert_eq!(
            X86XstateRestorePlan::decode(
                &[0x48, 0x0f, 0xae, 0x2c, 0x24],
                &snapshot,
                0,
                X86GuestGsBase::Zero
            ),
            Err(X86XstateRestoreError::GeneralProtection(
                X86XstateRestoreGpReason::MisalignedAddress
            )),
            "misaligned SS operands still raise #GP(0)"
        );
        assert_eq!(
            X86XstateRestorePlan::decode(&[0x0f, 0xc7, 0x18], &snapshot, 0, X86GuestGsBase::Zero),
            Err(X86XstateRestoreError::GeneralProtection(
                X86XstateRestoreGpReason::UnsupportedInstruction
            )),
            "supervisor XRSTORS never enters the pure user-state emulator"
        );
    }

    #[test]
    fn standard_image_restores_x87_sse_ymm_opmask_and_zmm_without_reserved_bytes() {
        let capabilities = capabilities();
        let mut image = image_with_header(SAFE_FEATURES, 0);
        image[0..5].copy_from_slice(&[0x7f, 0x03, 0x20, 0x00, 0xff]);
        image[5] = 0xee;
        for (index, byte) in image[6..24].iter_mut().enumerate() {
            *byte = 0x20 + index as u8;
        }
        image[24..28].copy_from_slice(&0x0000_1fa0u32.to_le_bytes());
        image[28..32].fill(0xee);
        image[32..160].fill(0x33);
        image[160..416].fill(0x44);
        image[416..512].fill(0xee);
        fill_extended_standard(&mut image, &capabilities);

        let mut snapshot = snapshot_at_image(SAFE_FEATURES);
        snapshot.xsave[5] = 0x5a;
        snapshot.xsave[28..32].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        snapshot.xsave[416..512].fill(0xa5);
        snapshot.apply_guest_pkru_write(0x1122_3344);
        let plan = xrstor64_plan(&snapshot);
        let mut reader = ImageReader::new(image.clone());
        snapshot
            .emulate_xrstor_with_reader(plan, &capabilities, &mut reader)
            .expect("restore standard image");

        assert_eq!(&snapshot.xsave[0..5], &image[0..5]);
        assert_eq!(snapshot.xsave[5], 0x5a, "reserved byte 5 is preserved");
        assert_eq!(&snapshot.xsave[6..28], &image[6..28]);
        assert_eq!(
            &snapshot.xsave[28..32],
            &0x1234_5678u32.to_le_bytes(),
            "MXCSR_MASK is never imported"
        );
        assert_eq!(&snapshot.xsave[32..416], &image[32..416]);
        assert!(snapshot.xsave[416..512].iter().all(|byte| *byte == 0xa5));
        for component in [2usize, 5, 6, 7] {
            let metadata = capabilities.components[component];
            let start = metadata.offset as usize;
            let end = start + metadata.size as usize;
            assert_eq!(&snapshot.xsave[start..end], &image[start..end]);
        }
        assert_eq!(snapshot.xstate_bv(), SAFE_FEATURES);
        assert_eq!(snapshot.pkru().raw(), 0x1122_3344);
    }

    #[test]
    fn requested_present_copies_absent_initializes_and_unrequested_preserves() {
        let capabilities = capabilities();
        let source_bv = X87_FEATURE | (1 << 2) | (1 << 5);
        let mut image = image_with_header(source_bv, 0);
        image[0..5].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55]);
        image[6..24].fill(0x66);
        image[32..160].fill(0x77);
        fill_extended_standard(&mut image, &capabilities);

        let effective = X87_FEATURE | SSE_FEATURE | (1 << 2) | (1 << 6);
        let mut snapshot = snapshot_at_image(effective);
        set_bv(&mut snapshot, SSE_FEATURE | (1 << 5) | (1 << 6));
        snapshot.xsave[24..28].fill(0xff);
        snapshot.xsave[160..416].fill(0xff);
        snapshot.xsave[832..896].fill(0xab);
        let preserved_opmask = snapshot.xsave[832..896].to_vec();
        let plan = xrstor64_plan(&snapshot);
        let mut reader = ImageReader::new(image.clone());
        snapshot
            .emulate_xrstor_with_reader(plan, &capabilities, &mut reader)
            .expect("mixed restore");

        assert_eq!(&snapshot.xsave[0..5], &image[0..5]);
        assert_eq!(
            &snapshot.xsave[24..28],
            &X86UcontextSnapshot::new().xsave[24..28],
            "requested-absent SSE gets architectural initial state"
        );
        assert!(snapshot.xsave[160..416].iter().all(|byte| *byte == 0));
        assert_eq!(&snapshot.xsave[576..832], &image[576..832]);
        assert_eq!(&snapshot.xsave[832..896], preserved_opmask);
        assert!(
            snapshot.xsave[896..1408].iter().all(|byte| *byte == 0),
            "requested-absent extended state gets architectural initial state"
        );
        assert_eq!(
            snapshot.xstate_bv(),
            (SSE_FEATURE | (1 << 5) | (1 << 6)) & !effective | source_bv & effective
        );
        assert!(
            !reader
                .reads
                .iter()
                .any(|(address, _)| address.raw() == IMAGE_BASE + 832),
            "unrequested source opmask must not be read"
        );
        assert!(
            !reader
                .reads
                .iter()
                .any(|(address, _)| address.raw() == IMAGE_BASE + 896),
            "requested-absent ZMM high state has no source payload to read"
        );
    }

    #[test]
    fn advertised_compacted_extent_round_trips_with_cpuid_alignment() {
        let layout = sparse_compacted_layout();
        let source_bv = (1 << 2) | (1 << 5);
        let xcomp = XCOMP_COMPACTED | layout.supported_features;
        let compacted_size = layout
            .compacted_size_for(layout.supported_features)
            .expect("validated compacted geometry") as usize;
        assert_eq!(layout.standard_size, 3104);
        assert_eq!(compacted_size, 736);
        assert_eq!(
            layout
                .compacted_size_for(source_bv)
                .expect("supported compacted subset"),
            656
        );

        // Model the exact byte extent an XSAVEC user allocates from CPUID D.1
        // EBX. A restore that reads one byte past the advertised geometry will
        // fail through ImageReader's bounds check instead of passing on padding.
        let mut image = image_with_header(source_bv, xcomp);
        image.truncate(compacted_size);
        image[576..608].fill(0x22);
        // Component 5 follows component 2 but CPUID ECX[1] rounds 608 to 640.
        image[640..656].fill(0x55);

        let mut snapshot = snapshot_at_image(source_bv);
        let plan = xrstor64_plan(&snapshot);
        let mut reader = ImageReader::new(image);
        snapshot
            .emulate_xrstor_with_reader(plan, &layout, &mut reader)
            .expect("restore exact advertised compacted image");
        assert!(snapshot.xsave[1024..1056].iter().all(|byte| *byte == 0x22));
        assert!(snapshot.xsave[2048..2064].iter().all(|byte| *byte == 0x55));
        assert_eq!(snapshot.xstate_bv(), source_bv | 0x3);
        assert!(snapshot.xsave[520..576].iter().all(|byte| *byte == 0));
        assert_eq!(
            reader.reads,
            vec![
                (GuestVa(IMAGE_BASE + 512), 64),
                (GuestVa(IMAGE_BASE + 576), 32),
                (GuestVa(IMAGE_BASE + 640), 16),
            ]
        );
    }

    #[test]
    fn compacted_avx_only_feature_map_is_valid() {
        let layout = sparse_compacted_layout();
        let avx = 1 << 2;
        let mut image = image_with_header(avx, XCOMP_COMPACTED | avx);
        image[576..608].fill(0xa2);

        let mut snapshot = snapshot_at_image(avx);
        let plan = xrstor64_plan(&snapshot);
        let mut reader = ImageReader::new(image);
        snapshot
            .emulate_xrstor_with_reader(plan, &layout, &mut reader)
            .expect("restore compacted AVX-only image");

        assert!(snapshot.xsave[1024..1056].iter().all(|byte| *byte == 0xa2));
        assert_eq!(snapshot.xstate_bv(), X87_FEATURE | SSE_FEATURE | avx);
        assert_eq!(
            reader.reads,
            vec![
                (GuestVa(IMAGE_BASE + 512), 64),
                (GuestVa(IMAGE_BASE + 576), 32),
            ]
        );
    }

    #[test]
    fn compacted_offset_counts_xcomp_component_omitted_from_xstate() {
        let layout = sparse_compacted_layout();
        let avx = 1 << 2;
        let opmask = 1 << 5;
        let mut image = image_with_header(opmask, XCOMP_COMPACTED | avx | opmask);
        image[576..608].fill(0xa2);
        image[640..656].fill(0xb5);

        let mut snapshot = snapshot_at_image(opmask);
        let plan = xrstor64_plan(&snapshot);
        let mut reader = ImageReader::new(image);
        snapshot
            .emulate_xrstor_with_reader(plan, &layout, &mut reader)
            .expect("restore later compacted component");

        assert!(snapshot.xsave[2048..2064].iter().all(|byte| *byte == 0xb5));
        assert_eq!(
            reader.reads,
            vec![
                (GuestVa(IMAGE_BASE + 512), 64),
                (GuestVa(IMAGE_BASE + 640), 16),
            ],
            "component 2 occupies compacted bytes even when XSTATE_BV omits it"
        );
    }

    #[test]
    fn malformed_header_mxcsr_and_unsafe_components_are_atomic() {
        let capabilities = capabilities();
        let mutators: [fn(&mut Vec<u8>); 5] = [
            |image| image[512..520].copy_from_slice(&(1u64 << 9).to_le_bytes()),
            |image| {
                image[520..528]
                    .copy_from_slice(&(XCOMP_COMPACTED | SAFE_FEATURES | (1 << 9)).to_le_bytes())
            },
            |image| image[520..528].copy_from_slice(&SAFE_FEATURES.to_le_bytes()),
            |image| {
                image[512..520].copy_from_slice(&(1u64 << 7).to_le_bytes());
                image[520..528].copy_from_slice(&(XCOMP_COMPACTED | 0x3).to_le_bytes());
            },
            |image| image[528] = 1,
        ];
        for mutate in mutators {
            let mut image = image_with_header(0x3, 0);
            mutate(&mut image);
            let mut snapshot = snapshot_at_image(SAFE_FEATURES);
            let before = snapshot.clone();
            let plan = xrstor64_plan(&snapshot);
            let mut reader = ImageReader::new(image);
            assert!(matches!(
                snapshot.emulate_xrstor_with_reader(plan, &capabilities, &mut reader),
                Err(X86XstateRestoreError::GeneralProtection(_))
            ));
            assert_snapshot_eq(&snapshot, &before);
        }

        let mut image = image_with_header(SSE_FEATURE, 0);
        image[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut snapshot = snapshot_at_image(SSE_FEATURE);
        let before = snapshot.clone();
        let plan = xrstor64_plan(&snapshot);
        let mut reader = ImageReader::new(image);
        assert_eq!(
            snapshot.emulate_xrstor_with_reader(plan, &capabilities, &mut reader),
            Err(X86XstateRestoreError::GeneralProtection(
                X86XstateRestoreGpReason::InvalidMxcsr
            ))
        );
        assert_snapshot_eq(&snapshot, &before);
    }

    #[test]
    fn full_width_mxcsr_mask_accepts_and_preserves_supported_upper_bit() {
        let base = capabilities();
        let mut full_width = base.capabilities();
        full_width.mxcsr_mask |= 1 << 17;
        let layout = X86SnapshotXstateLayout::new(full_width, base.compacted_align64_features())
            .expect("upper MXCSR mask bits are valid capability data");
        let mxcsr: u32 = (1 << 17) | 0x1f80;
        let mut image = image_with_header(SSE_FEATURE, 0);
        image[24..28].copy_from_slice(&mxcsr.to_le_bytes());
        image[160..416].fill(0x5c);

        let mut snapshot = snapshot_at_image(SSE_FEATURE);
        let plan = xrstor64_plan(&snapshot);
        let mut reader = ImageReader::new(image);
        snapshot
            .emulate_xrstor_with_reader(plan, &layout, &mut reader)
            .expect("supported upper MXCSR bit");
        assert_eq!(&snapshot.xsave[24..28], &mxcsr.to_le_bytes());
        assert_eq!(&snapshot.xsave[160..416], &[0x5c; 256]);
    }

    #[test]
    fn invalid_capability_geometry_faults_before_any_source_read() {
        let valid = capabilities();
        let base = valid.capabilities();
        let alignments = valid.compacted_align64_features();
        let mut overlap = base;
        overlap.components[5].offset = 800;
        let invalid = [
            X86SnapshotXstateLayout::new_unchecked(
                X86SnapshotXstateCapabilities {
                    standard_size: 575,
                    ..base
                },
                alignments,
            ),
            X86SnapshotXstateLayout::new_unchecked(
                X86SnapshotXstateCapabilities {
                    standard_size: base.standard_size + 1,
                    ..base
                },
                alignments,
            ),
            X86SnapshotXstateLayout::new_unchecked(overlap, alignments),
            X86SnapshotXstateLayout::new_unchecked(base, alignments | (1 << 9)),
            X86SnapshotXstateLayout::new_unchecked(
                X86SnapshotXstateCapabilities {
                    supported_features: SAFE_FEATURES | (1 << 9),
                    ..base
                },
                alignments,
            ),
            X86SnapshotXstateLayout::new_unchecked(
                X86SnapshotXstateCapabilities {
                    supported_features: SAFE_FEATURES & !(1 << 7),
                    ..base
                },
                alignments & !(1 << 7),
            ),
            X86SnapshotXstateLayout::new_unchecked(
                X86SnapshotXstateCapabilities {
                    supported_features: SAFE_FEATURES & !(1 << 2),
                    ..base
                },
                alignments,
            ),
        ];

        for layout in &invalid {
            assert!(matches!(
                X86SnapshotXstateLayout::new(
                    layout.capabilities(),
                    layout.compacted_align64_features(),
                ),
                Err(crate::gateway::X86SnapshotXstateError::InvalidLayout(_))
            ));
        }

        for layout in invalid {
            let mut snapshot = snapshot_at_image(SAFE_FEATURES);
            let before = snapshot.clone();
            let plan = xrstor64_plan(&snapshot);
            let mut reader = ImageReader::new(image_with_header(0x3, 0));
            assert_eq!(
                snapshot.emulate_xrstor_with_reader(plan, &layout, &mut reader),
                Err(X86XstateRestoreError::Internal(
                    X86XstateRestoreInternalReason::InvalidLayout
                ))
            );
            assert_snapshot_eq(&snapshot, &before);
            assert!(reader.reads.is_empty());
        }
    }

    #[test]
    fn noncanonical_ss_source_range_and_reader_fault_remain_typed_and_atomic() {
        let capabilities = capabilities();
        let mut crossing = snapshot_at_image(SAFE_FEATURES);
        crossing.gpr[reg::RSP] = 0x0000_7fff_ffff_ffc0;
        let before = crossing.clone();
        let plan = xrstor64_plan(&crossing);
        let mut reader = ImageReader::new(image_with_header(0x3, 0));
        assert_eq!(
            crossing.emulate_xrstor_with_reader(plan, &capabilities, &mut reader),
            Err(X86XstateRestoreError::StackSegment(
                X86XstateRestoreSsReason::NoncanonicalAddress
            ))
        );
        assert_snapshot_eq(&crossing, &before);
        assert!(reader.reads.is_empty());

        let mut snapshot = snapshot_at_image(SAFE_FEATURES);
        let before = snapshot.clone();
        let plan = xrstor64_plan(&snapshot);
        let mut reader = ImageReader::new(image_with_header(0x3, 0));
        reader.fail_at = Some(0);
        assert_eq!(
            snapshot.emulate_xrstor_with_reader(plan, &capabilities, &mut reader),
            Err(X86XstateRestoreError::Read(TestReadError::Injected))
        );
        assert_snapshot_eq(&snapshot, &before);
        assert_eq!(reader.reads, vec![(GuestVa(IMAGE_BASE + 512), 64)]);
    }

    #[test]
    fn request_bit9_is_ignored_and_virtual_pkru_is_unchanged() {
        let capabilities = capabilities();
        let image = image_with_header(0x3, 0);
        let mut snapshot = snapshot_at_image(1 << 9);
        snapshot.apply_guest_pkru_write(0xa5a5_5a5a);
        snapshot.xsave[576..832].fill(0xcc);
        let before_xsave = snapshot.xsave;
        let plan = xrstor64_plan(&snapshot);
        let mut reader = ImageReader::new(image);
        snapshot
            .emulate_xrstor_with_reader(plan, &capabilities, &mut reader)
            .expect("unsupported request bits are ignored");
        assert_eq!(snapshot.pkru().raw(), 0xa5a5_5a5a);
        assert_eq!(snapshot.xsave, before_xsave);
        assert_eq!(reader.reads, vec![(GuestVa(IMAGE_BASE + 512), 64)]);
    }

    #[test]
    fn plain_xrstor_imports_selectors_zero_extends_pointers_and_ignores_reserved_halves() {
        let capabilities = capabilities();
        let mut image = image_with_header(X87_FEATURE, 0);
        image[0..5].copy_from_slice(&[0x7f, 0x03, 0, 0, 0]);
        image[6..8].copy_from_slice(&[0x34, 0x12]);
        image[8..12].copy_from_slice(&0x89ab_cdefu32.to_le_bytes());
        image[12..16].copy_from_slice(&[0xa1, 0xb2, 0xc3, 0xd4]);
        image[16..20].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        image[20..24].copy_from_slice(&[0x5a, 0x6b, 0x7c, 0x8d]);
        image[32..160].fill(0x5a);

        let mut snapshot = snapshot_at_image(X87_FEATURE);
        let plan = X86XstateRestorePlan::decode(
            &[0x0f, 0xae, 0x2c, 0x24],
            &snapshot,
            0,
            X86GuestGsBase::Zero,
        )
        .expect("decode plain xrstor");
        let mut reader = ImageReader::new(image);
        snapshot
            .emulate_xrstor_with_reader(plan, &capabilities, &mut reader)
            .expect("plain XRSTOR follows native pointer semantics");
        assert_eq!(&snapshot.xsave[8..16], &0x89ab_cdefu64.to_le_bytes());
        assert_eq!(&snapshot.xsave[16..24], &0x1234_5678u64.to_le_bytes());
        assert_eq!(snapshot.x87_fcs(), 0xb2a1);
        assert_eq!(snapshot.x87_fds(), 0x6b5a);
        assert_eq!(
            reader.reads,
            vec![
                (GuestVa(IMAGE_BASE + 512), 64),
                (GuestVa(IMAGE_BASE), 5),
                (GuestVa(IMAGE_BASE + 6), 2),
                (GuestVa(IMAGE_BASE + 8), 4),
                (GuestVa(IMAGE_BASE + 12), 2),
                (GuestVa(IMAGE_BASE + 16), 4),
                (GuestVa(IMAGE_BASE + 20), 2),
                (GuestVa(IMAGE_BASE + 32), 128),
            ],
            "plain XRSTOR must import selectors without reading reserved halves"
        );
    }

    #[test]
    fn non_rex_requested_absent_initializes_and_unrequested_preserves_selectors() {
        let capabilities = capabilities();
        let mut absent = snapshot_at_image(X87_FEATURE);
        absent.restore_x87_selectors(0x1357, 0x2468);
        let plan = X86XstateRestorePlan::decode(
            &[0x0f, 0xae, 0x2c, 0x24],
            &absent,
            0,
            X86GuestGsBase::Zero,
        )
        .expect("decode plain xrstor");
        let mut reader = ImageReader::new(image_with_header(0, 0));
        absent
            .emulate_xrstor_with_reader(plan, &capabilities, &mut reader)
            .expect("requested-absent x87 initialization");
        assert_eq!(absent.x87_fcs(), carrick_abi::LINUX_X8664_USER_CS);
        assert_eq!(absent.x87_fds(), carrick_abi::LINUX_X8664_USER_DS);
        assert_eq!(reader.reads, vec![(GuestVa(IMAGE_BASE + 512), 64)]);

        let mut unrequested = snapshot_at_image(0);
        unrequested.restore_x87_selectors(0x3579, 0x468a);
        let plan = X86XstateRestorePlan::decode(
            &[0x0f, 0xae, 0x2c, 0x24],
            &unrequested,
            0,
            X86GuestGsBase::Zero,
        )
        .expect("decode plain xrstor");
        let mut reader = ImageReader::new(image_with_header(X87_FEATURE, 0));
        unrequested
            .emulate_xrstor_with_reader(plan, &capabilities, &mut reader)
            .expect("unrequested x87 preservation");
        assert_eq!(unrequested.x87_fcs(), 0x3579);
        assert_eq!(unrequested.x87_fds(), 0x468a);
        assert_eq!(reader.reads, vec![(GuestVa(IMAGE_BASE + 512), 64)]);
    }

    #[test]
    fn xrstor64_keeps_full_64bit_legacy_pointers() {
        let capabilities = capabilities();
        let mut image = image_with_header(X87_FEATURE, 0);
        let fip = 0x1122_3344_5566_7788u64;
        let fdp = 0x99aa_bbcc_ddee_ff00u64;
        image[8..16].copy_from_slice(&fip.to_le_bytes());
        image[16..24].copy_from_slice(&fdp.to_le_bytes());

        let mut snapshot = snapshot_at_image(X87_FEATURE);
        snapshot.restore_x87_selectors(0x1357, 0x2468);
        let plan = xrstor64_plan(&snapshot);
        let mut reader = ImageReader::new(image);
        snapshot
            .emulate_xrstor_with_reader(plan, &capabilities, &mut reader)
            .expect("XRSTOR64 follows native pointer semantics");
        assert_eq!(&snapshot.xsave[8..16], &fip.to_le_bytes());
        assert_eq!(&snapshot.xsave[16..24], &fdp.to_le_bytes());
        assert_eq!(snapshot.x87_fcs(), 0x1357);
        assert_eq!(snapshot.x87_fds(), 0x2468);
        assert!(reader.reads.contains(&(GuestVa(IMAGE_BASE + 8), 16)));
    }

    #[test]
    fn late_memory_error_is_atomic() {
        let capabilities = capabilities();
        let mut image = image_with_header(SAFE_FEATURES, 0);
        image[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        fill_extended_standard(&mut image, &capabilities);
        let mut snapshot = snapshot_at_image(SAFE_FEATURES);
        snapshot.xsave.fill(0xa5);
        set_bv(&mut snapshot, SAFE_FEATURES);
        snapshot.apply_guest_pkru_write(7);
        let before = snapshot.clone();
        let plan = xrstor64_plan(&snapshot);
        let mut reader = ImageReader::new(image);
        reader.fail_at = Some(8);
        assert_eq!(
            snapshot.emulate_xrstor_with_reader(plan, &capabilities, &mut reader),
            Err(X86XstateRestoreError::Read(TestReadError::Injected))
        );
        assert_snapshot_eq(&snapshot, &before);
        assert_eq!(
            reader.reads.len(),
            9,
            "failure was injected after earlier payload reads"
        );
    }

    #[test]
    fn exact_read_census_is_one_read_per_required_range_per_service_attempt() {
        let capabilities = capabilities();
        let mut image = image_with_header(SAFE_FEATURES, 0);
        image[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        fill_extended_standard(&mut image, &capabilities);
        let mut snapshot = snapshot_at_image(SAFE_FEATURES);
        let plan = xrstor64_plan(&snapshot);
        let mut reader = ImageReader::new(image);
        snapshot
            .emulate_xrstor_with_reader(plan, &capabilities, &mut reader)
            .expect("restore all safe components");
        assert_eq!(
            reader.reads,
            vec![
                (GuestVa(IMAGE_BASE + 512), 64),
                (GuestVa(IMAGE_BASE), 5),
                (GuestVa(IMAGE_BASE + 6), 2),
                (GuestVa(IMAGE_BASE + 8), 16),
                (GuestVa(IMAGE_BASE + 32), 128),
                (GuestVa(IMAGE_BASE + 24), 4),
                (GuestVa(IMAGE_BASE + 160), 256),
                (GuestVa(IMAGE_BASE + 576), 256),
                (GuestVa(IMAGE_BASE + 832), 64),
                (GuestVa(IMAGE_BASE + 896), 512),
                (GuestVa(IMAGE_BASE + 1408), 1024),
            ],
            "one pure service attempt reads every required architectural source range exactly once"
        );
        let total: usize = reader.reads.iter().map(|(_, len)| *len).sum();
        assert_eq!(total, 2331);
        assert!(total < XSAVE_AREA_LEN);
    }
}
