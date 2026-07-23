//! Pure, checked emulation of user-mode XSAVE/XSAVEOPT/XSAVEC forms.
//!
//! No guest save instruction is ever executed by the host. The authoritative
//! standard-format snapshot supplies architectural bytes, and a caller-owned
//! checked reader/writer pair receives only the exact destination ranges named
//! by the virtual instruction. Non-REX x87 pointer forms write Carrick's exact
//! virtual FCS/FDS state while leaving each reserved 16-bit half untouched.

use std::convert::Infallible;
use std::ops::Range;

use carrick_guest_mem::GuestVa;
use iced_x86::{Code, Decoder, DecoderOptions};

use crate::decode::X86XstateSaveKind;
use crate::gateway::{
    X86SnapshotXstateComponent, X86SnapshotXstateLayout, X86UcontextSnapshot, XSAVE_AREA_LEN, reg,
};
use crate::xstate_address::{
    X86GuestGsBase, X86XstateAddressError, is_canonical, resolve_xstate_memory_operand,
};
use crate::xstate_restore::X86XstateMemoryReader;

const XSAVE_HEADER_OFFSET: usize = 512;
const XSAVE_STANDARD_HEADER_WRITTEN_LEN: usize = 8;
const XSAVEC_HEADER_WRITTEN_LEN: usize = 16;
const XSAVE_EXTENDED_OFFSET: usize = 576;
const XCOMP_COMPACTED: u64 = 1 << 63;
const X87_FEATURE: u64 = 1 << 0;
const SSE_FEATURE: u64 = 1 << 1;

/// Why checked XSAVE emulation would deliver `#GP(0)` to the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum X86XstateSaveGpReason {
    #[error("the instruction is not a supported user XSAVE memory form")]
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
    #[error("the XSAVE destination range is not canonical and non-wrapping")]
    InvalidDestinationRange,
}

/// Why checked XSAVE emulation would deliver `#SS(0)` to the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum X86XstateSaveSsReason {
    #[error("the stack-segment effective address is noncanonical")]
    NoncanonicalAddress,
}

/// Checked XSAVE failure. Earlier exact writes are intentionally not rolled
/// back if a later checked guest-memory write faults, matching restartable
/// hardware's permitted partial-memory behavior.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum X86XstateSaveError<ReadError = Infallible, WriteError = Infallible> {
    #[error("x86 XSAVE general protection: {0}")]
    GeneralProtection(X86XstateSaveGpReason),
    #[error("x86 XSAVE stack-segment fault: {0}")]
    StackSegment(X86XstateSaveSsReason),
    #[error("x86 XSAVE checked guest-memory read failed")]
    Read(ReadError),
    #[error("x86 XSAVE checked guest-memory write failed")]
    Write(WriteError),
    #[error("x86 XSAVE internal failure: {0}")]
    Internal(X86XstateSaveInternalReason),
}

/// Non-architectural failures in Carrick's XSAVE setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum X86XstateSaveInternalReason {
    #[error("invalid xstate layout")]
    InvalidLayout,
    #[error("the authoritative snapshot names an unsupported xstate component")]
    UnsupportedSnapshotFeatures,
    #[error("classified {expected:?} but decoded {decoded:?}")]
    InstructionKindMismatch {
        expected: X86XstateSaveKind,
        decoded: X86XstateSaveKind,
    },
}

/// Exact guest-memory writer used by XSAVE emulation.
pub trait X86XstateMemoryWriter {
    type Error;

    fn write_exact(&mut self, address: GuestVa, source: &[u8]) -> Result<(), Self::Error>;
}

/// A decoded XSAVE-family instruction and its exact guest effective address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86XstateSavePlan {
    kind: X86XstateSaveKind,
    address: GuestVa,
    instruction_len: u8,
    effective_segment_is_ss: bool,
}

impl X86XstateSavePlan {
    /// Decode the original instruction at `snapshot.rip` and resolve its
    /// long-mode effective address through the shared XSAVE-family machinery.
    pub fn decode(
        bytes: &[u8],
        snapshot: &X86UcontextSnapshot,
        guest_fsbase: u64,
        guest_gsbase: X86GuestGsBase,
    ) -> Result<Self, X86XstateSaveError> {
        let mut decoder = Decoder::with_ip(64, bytes, snapshot.rip, DecoderOptions::NONE);
        let instruction = decoder.decode();
        let kind = match instruction.code() {
            Code::Xsave_mem => X86XstateSaveKind::Xsave,
            Code::Xsave64_mem => X86XstateSaveKind::Xsave64,
            Code::Xsaveopt_mem => X86XstateSaveKind::Xsaveopt,
            Code::Xsaveopt64_mem => X86XstateSaveKind::Xsaveopt64,
            Code::Xsavec_mem => X86XstateSaveKind::Xsavec,
            Code::Xsavec64_mem => X86XstateSaveKind::Xsavec64,
            _ => {
                return Err(X86XstateSaveError::GeneralProtection(
                    X86XstateSaveGpReason::UnsupportedInstruction,
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

    /// Decode while asserting the kind already established by sensitive
    /// classification. A disagreement is an internal fail-closed error, not a
    /// guest `#GP`: both decoders inspected the same immutable instruction.
    pub fn decode_for_kind(
        expected: X86XstateSaveKind,
        bytes: &[u8],
        snapshot: &X86UcontextSnapshot,
        guest_fsbase: u64,
        guest_gsbase: X86GuestGsBase,
    ) -> Result<Self, X86XstateSaveError> {
        let plan = Self::decode(bytes, snapshot, guest_fsbase, guest_gsbase)?;
        if plan.kind != expected {
            return Err(X86XstateSaveError::Internal(
                X86XstateSaveInternalReason::InstructionKindMismatch {
                    expected,
                    decoded: plan.kind,
                },
            ));
        }
        Ok(plan)
    }

    pub const fn kind(self) -> X86XstateSaveKind {
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

fn xstate_address_error(error: X86XstateAddressError) -> X86XstateSaveError {
    match error {
        X86XstateAddressError::UnsupportedInstruction => {
            X86XstateSaveError::GeneralProtection(X86XstateSaveGpReason::UnsupportedInstruction)
        }
        X86XstateAddressError::UnsupportedAddressSize => {
            X86XstateSaveError::GeneralProtection(X86XstateSaveGpReason::UnsupportedAddressSize)
        }
        X86XstateAddressError::UnsupportedSegment => {
            X86XstateSaveError::GeneralProtection(X86XstateSaveGpReason::UnsupportedSegment)
        }
        X86XstateAddressError::UnsupportedAddressForm => {
            X86XstateSaveError::GeneralProtection(X86XstateSaveGpReason::UnsupportedAddressForm)
        }
        X86XstateAddressError::GeneralProtectionNoncanonical => {
            X86XstateSaveError::GeneralProtection(X86XstateSaveGpReason::NoncanonicalAddress)
        }
        X86XstateAddressError::StackSegmentNoncanonical => {
            X86XstateSaveError::StackSegment(X86XstateSaveSsReason::NoncanonicalAddress)
        }
        X86XstateAddressError::MisalignedAddress => {
            X86XstateSaveError::GeneralProtection(X86XstateSaveGpReason::MisalignedAddress)
        }
    }
}

fn invalid_layout<ReadError, WriteError>() -> X86XstateSaveError<ReadError, WriteError> {
    X86XstateSaveError::Internal(X86XstateSaveInternalReason::InvalidLayout)
}

fn component_bounds<ReadError, WriteError>(
    component: usize,
    metadata: X86SnapshotXstateComponent,
) -> Result<Range<usize>, X86XstateSaveError<ReadError, WriteError>> {
    let start = usize::try_from(metadata.offset).map_err(|_| invalid_layout())?;
    let size = usize::try_from(metadata.size).map_err(|_| invalid_layout())?;
    let end = start.checked_add(size).ok_or_else(invalid_layout)?;
    if component < 2 || size == 0 || start < XSAVE_EXTENDED_OFFSET || end > XSAVE_AREA_LEN {
        return Err(invalid_layout());
    }
    Ok(start..end)
}

fn align64<ReadError, WriteError>(
    value: usize,
) -> Result<usize, X86XstateSaveError<ReadError, WriteError>> {
    value
        .checked_add(63)
        .map(|value| value & !63)
        .ok_or_else(invalid_layout)
}

fn compacted_offsets<ReadError, WriteError>(
    layout: &X86SnapshotXstateLayout,
    features: u64,
) -> Result<[usize; 64], X86XstateSaveError<ReadError, WriteError>> {
    let capabilities = layout.capabilities();
    let mut offsets = [0usize; 64];
    let mut cursor = XSAVE_EXTENDED_OFFSET;
    for (component, offset) in offsets.iter_mut().enumerate().skip(2) {
        let bit = 1u64 << component;
        if features & bit == 0 {
            continue;
        }
        let source = component_bounds(component, capabilities.components[component])?;
        if layout.compacted_align64_features() & bit != 0 {
            cursor = align64(cursor)?;
        }
        *offset = cursor;
        cursor = cursor
            .checked_add(source.len())
            .ok_or_else(invalid_layout)?;
        if cursor > XSAVE_AREA_LEN {
            return Err(invalid_layout());
        }
    }
    let advertised = usize::try_from(
        layout
            .compacted_size_for(features)
            .map_err(|_| invalid_layout())?,
    )
    .map_err(|_| invalid_layout())?;
    if advertised != cursor {
        return Err(invalid_layout());
    }
    Ok(offsets)
}

fn noncanonical_address<ReadError, WriteError>(
    plan: X86XstateSavePlan,
) -> X86XstateSaveError<ReadError, WriteError> {
    if plan.effective_segment_is_ss {
        X86XstateSaveError::StackSegment(X86XstateSaveSsReason::NoncanonicalAddress)
    } else {
        X86XstateSaveError::GeneralProtection(X86XstateSaveGpReason::NoncanonicalAddress)
    }
}

fn checked_destination_address<ReadError, WriteError>(
    plan: X86XstateSavePlan,
    offset: usize,
    len: usize,
) -> Result<GuestVa, X86XstateSaveError<ReadError, WriteError>> {
    let offset = u64::try_from(offset).map_err(|_| {
        X86XstateSaveError::GeneralProtection(X86XstateSaveGpReason::InvalidDestinationRange)
    })?;
    let len = u64::try_from(len).map_err(|_| {
        X86XstateSaveError::GeneralProtection(X86XstateSaveGpReason::InvalidDestinationRange)
    })?;
    let start =
        plan.address
            .raw()
            .checked_add(offset)
            .ok_or(X86XstateSaveError::GeneralProtection(
                X86XstateSaveGpReason::InvalidDestinationRange,
            ))?;
    let end = start
        .checked_add(len)
        .ok_or(X86XstateSaveError::GeneralProtection(
            X86XstateSaveGpReason::InvalidDestinationRange,
        ))?;
    if !is_canonical(start) || (len != 0 && !is_canonical(end - 1)) {
        return Err(noncanonical_address(plan));
    }
    Ok(GuestVa(start))
}

struct PreparedWrite {
    address: GuestVa,
    bytes: Vec<u8>,
}

fn prepare_bytes_write<ReadError, WriteError>(
    writes: &mut Vec<PreparedWrite>,
    plan: X86XstateSavePlan,
    destination_offset: usize,
    bytes: &[u8],
) -> Result<(), X86XstateSaveError<ReadError, WriteError>> {
    let address = checked_destination_address(plan, destination_offset, bytes.len())?;
    writes.push(PreparedWrite {
        address,
        bytes: bytes.to_vec(),
    });
    Ok(())
}

fn prepare_x87_writes<ReadError, WriteError>(
    writes: &mut Vec<PreparedWrite>,
    source: &X86UcontextSnapshot,
    plan: X86XstateSavePlan,
) -> Result<(), X86XstateSaveError<ReadError, WriteError>> {
    prepare_bytes_write(writes, plan, 0, &source.xsave[0..5])?;
    prepare_bytes_write(writes, plan, 6, &source.xsave[6..8])?;
    if plan.kind.is_64() {
        prepare_bytes_write(writes, plan, 8, &source.xsave[8..24])?;
    } else {
        prepare_bytes_write(writes, plan, 8, &source.xsave[8..12])?;
        prepare_bytes_write(writes, plan, 12, &source.x87_fcs().to_le_bytes())?;
        prepare_bytes_write(writes, plan, 16, &source.xsave[16..20])?;
        prepare_bytes_write(writes, plan, 20, &source.x87_fds().to_le_bytes())?;
    }
    prepare_bytes_write(writes, plan, 32, &source.xsave[32..160])?;
    Ok(())
}

fn prepare_mxcsr_write<ReadError, WriteError>(
    writes: &mut Vec<PreparedWrite>,
    source: &X86UcontextSnapshot,
    plan: X86XstateSavePlan,
    mxcsr_mask: u32,
) -> Result<(), X86XstateSaveError<ReadError, WriteError>> {
    let mut bytes = [0u8; 8];
    bytes[0..4].copy_from_slice(&source.xsave[24..28]);
    bytes[4..8].copy_from_slice(&mxcsr_mask.to_le_bytes());
    prepare_bytes_write(writes, plan, 24, &bytes)
}

impl X86UcontextSnapshot {
    /// Emulate one decoded user XSAVE-family instruction through exact checked
    /// memory accesses. Standard XSAVE/XSAVEOPT first read the destination's
    /// existing `XSTATE_BV` and update only that eight-byte field; XSAVEC writes
    /// its complete 16-byte compacted header without reading the destination.
    /// Every layout and destination range is validated before the first write.
    pub fn emulate_xsave_with_memory<
        R: X86XstateMemoryReader + ?Sized,
        W: X86XstateMemoryWriter + ?Sized,
    >(
        &self,
        plan: X86XstateSavePlan,
        layout: &X86SnapshotXstateLayout,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<(), X86XstateSaveError<R::Error, W::Error>> {
        layout.validate().map_err(|_| invalid_layout())?;
        let capabilities = layout.capabilities();
        let supported = capabilities.supported_features;
        let snapshot_bv = self.xstate_bv();
        if snapshot_bv & !supported != 0 {
            return Err(X86XstateSaveError::Internal(
                X86XstateSaveInternalReason::UnsupportedSnapshotFeatures,
            ));
        }
        let request =
            u64::from(self.gpr[reg::RAX] as u32) | (u64::from(self.gpr[reg::RDX] as u32) << 32);
        let effective = request & supported;
        if effective == 0 && !plan.kind.is_compacted() {
            return Ok(());
        }

        let compacted = plan.kind.is_compacted();
        let plain = matches!(
            plan.kind,
            X86XstateSaveKind::Xsave | X86XstateSaveKind::Xsave64
        );
        let present = snapshot_bv & effective;
        let initial = Self::new();
        let compacted_component_offsets = if compacted {
            compacted_offsets::<R::Error, W::Error>(layout, effective)?
        } else {
            [0usize; 64]
        };

        // Build and range-check the complete operation before exposing the
        // first byte to guest memory. Read/write faults after that validation
        // retain the hardware-compatible retry/partial-write behavior.
        let mut writes = Vec::new();
        let write_x87 = if plain {
            effective & X87_FEATURE != 0
        } else {
            present & X87_FEATURE != 0
        };
        if write_x87 {
            let source = if snapshot_bv & X87_FEATURE != 0 {
                self
            } else {
                &initial
            };
            prepare_x87_writes(&mut writes, source, plan)?;
        }

        if compacted {
            let mxcsr_noninitial = self.xsave[24..28] != initial.xsave[24..28];
            let save_sse = effective & SSE_FEATURE != 0
                && (snapshot_bv & SSE_FEATURE != 0 || mxcsr_noninitial);
            let output_bv = present | if save_sse { SSE_FEATURE } else { 0 };
            if save_sse {
                prepare_mxcsr_write(&mut writes, self, plan, capabilities.mxcsr_mask)?;
                let xmm_source = if snapshot_bv & SSE_FEATURE != 0 {
                    self
                } else {
                    &initial
                };
                prepare_bytes_write(&mut writes, plan, 160, &xmm_source.xsave[160..416])?;
            }
            let mut header = [0u8; XSAVEC_HEADER_WRITTEN_LEN];
            header[0..8].copy_from_slice(&output_bv.to_le_bytes());
            header[8..16].copy_from_slice(&(XCOMP_COMPACTED | effective).to_le_bytes());
            prepare_bytes_write(&mut writes, plan, XSAVE_HEADER_OFFSET, &header)?;
        } else {
            if effective & (SSE_FEATURE | (1 << 2)) != 0 {
                let mxcsr_source = if snapshot_bv & SSE_FEATURE != 0 {
                    self
                } else {
                    &initial
                };
                prepare_mxcsr_write(&mut writes, mxcsr_source, plan, capabilities.mxcsr_mask)?;
            }
            let write_xmm = if plain {
                effective & SSE_FEATURE != 0
            } else {
                present & SSE_FEATURE != 0
            };
            if write_xmm {
                let source = if snapshot_bv & SSE_FEATURE != 0 {
                    self
                } else {
                    &initial
                };
                prepare_bytes_write(&mut writes, plan, 160, &source.xsave[160..416])?;
            }
        }

        for (component, &compacted_destination) in
            compacted_component_offsets.iter().enumerate().skip(2)
        {
            let bit = 1u64 << component;
            let write_component = if plain {
                effective & bit != 0
            } else {
                present & bit != 0
            };
            if !write_component {
                continue;
            }
            let source_range = component_bounds::<R::Error, W::Error>(
                component,
                capabilities.components[component],
            )?;
            let destination = if compacted {
                compacted_destination
            } else {
                source_range.start
            };
            let source = if snapshot_bv & bit != 0 {
                self
            } else {
                &initial
            };
            prepare_bytes_write(&mut writes, plan, destination, &source.xsave[source_range])?;
        }

        if !compacted {
            let header_address = checked_destination_address::<R::Error, W::Error>(
                plan,
                XSAVE_HEADER_OFFSET,
                XSAVE_STANDARD_HEADER_WRITTEN_LEN,
            )?;
            let mut old_bv_bytes = [0u8; XSAVE_STANDARD_HEADER_WRITTEN_LEN];
            reader
                .read_exact(header_address, &mut old_bv_bytes)
                .map_err(X86XstateSaveError::Read)?;
            let old_bv = u64::from_le_bytes(old_bv_bytes);
            let output_bv = (old_bv & !effective) | (snapshot_bv & effective);
            prepare_bytes_write(
                &mut writes,
                plan,
                XSAVE_HEADER_OFFSET,
                &output_bv.to_le_bytes(),
            )?;
        }

        for write in writes {
            writer
                .write_exact(write.address, &write.bytes)
                .map_err(X86XstateSaveError::Write)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::X86SnapshotXstateCapabilities;

    const IMAGE_BASE: u64 = 0x20_000;
    const RIP: u64 = 0x40_0000;
    const SAFE_FEATURES: u64 =
        X87_FEATURE | SSE_FEATURE | (1 << 2) | (1 << 5) | (1 << 6) | (1 << 7);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TestMemoryError {
        Bounds,
        Injected,
    }

    struct ImageReader {
        base: u64,
        bytes: Vec<u8>,
        reads: Vec<(GuestVa, usize)>,
        fail: bool,
    }

    impl ImageReader {
        fn from_writer(writer: &ImageWriter) -> Self {
            Self {
                base: writer.base,
                bytes: writer.bytes.clone(),
                reads: Vec::new(),
                fail: false,
            }
        }
    }

    impl X86XstateMemoryReader for ImageReader {
        type Error = TestMemoryError;

        fn read_exact(
            &mut self,
            address: GuestVa,
            destination: &mut [u8],
        ) -> Result<(), Self::Error> {
            self.reads.push((address, destination.len()));
            if self.fail {
                return Err(TestMemoryError::Injected);
            }
            let offset = address
                .raw()
                .checked_sub(self.base)
                .and_then(|value| usize::try_from(value).ok())
                .ok_or(TestMemoryError::Bounds)?;
            let source = self
                .bytes
                .get(offset..offset + destination.len())
                .ok_or(TestMemoryError::Bounds)?;
            destination.copy_from_slice(source);
            Ok(())
        }
    }

    struct ImageWriter {
        base: u64,
        bytes: Vec<u8>,
        writes: Vec<(GuestVa, usize)>,
        fail_at: Option<usize>,
    }

    impl ImageWriter {
        fn new(fill: u8) -> Self {
            Self {
                base: IMAGE_BASE,
                bytes: vec![fill; 4096],
                writes: Vec::new(),
                fail_at: None,
            }
        }
    }

    impl X86XstateMemoryWriter for ImageWriter {
        type Error = TestMemoryError;

        fn write_exact(&mut self, address: GuestVa, source: &[u8]) -> Result<(), Self::Error> {
            let number = self.writes.len();
            self.writes.push((address, source.len()));
            if self.fail_at == Some(number) {
                return Err(TestMemoryError::Injected);
            }
            let offset = address
                .raw()
                .checked_sub(self.base)
                .and_then(|value| usize::try_from(value).ok())
                .ok_or(TestMemoryError::Bounds)?;
            let destination = self
                .bytes
                .get_mut(offset..offset + source.len())
                .ok_or(TestMemoryError::Bounds)?;
            destination.copy_from_slice(source);
            Ok(())
        }
    }

    fn emulate(
        snapshot: &X86UcontextSnapshot,
        plan: X86XstateSavePlan,
        layout: &X86SnapshotXstateLayout,
        writer: &mut ImageWriter,
    ) -> Result<(), X86XstateSaveError<TestMemoryError, TestMemoryError>> {
        let mut reader = ImageReader::from_writer(writer);
        snapshot.emulate_xsave_with_memory(plan, layout, &mut reader, writer)
    }

    fn layout() -> X86SnapshotXstateLayout {
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
        .expect("valid layout")
    }

    fn sparse_layout() -> X86SnapshotXstateLayout {
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
        .expect("valid sparse layout")
    }

    fn snapshot(request: u64, present: u64) -> X86UcontextSnapshot {
        let mut snapshot = X86UcontextSnapshot::new();
        snapshot.rip = RIP;
        snapshot.gpr[reg::RSP] = IMAGE_BASE;
        snapshot.gpr[reg::RAX] = request & u64::from(u32::MAX);
        snapshot.gpr[reg::RDX] = request >> 32;
        snapshot.xsave[512..520].copy_from_slice(&present.to_le_bytes());
        for (index, byte) in snapshot.xsave.iter_mut().enumerate() {
            if !(512..520).contains(&index) {
                *byte = (index as u8).wrapping_mul(17).wrapping_add(3);
            }
        }
        snapshot
    }

    fn decode(bytes: &[u8], snapshot: &X86UcontextSnapshot) -> X86XstateSavePlan {
        X86XstateSavePlan::decode(bytes, snapshot, 0, X86GuestGsBase::Zero)
            .expect("decode save plan")
    }

    #[test]
    fn all_user_save_forms_decode_and_xsaves_is_rejected() {
        let snapshot = snapshot(0, 0);
        for (bytes, kind, is_64, is_compacted) in [
            (
                &[0x0f, 0xae, 0x64, 0x24, 0x40][..],
                X86XstateSaveKind::Xsave,
                false,
                false,
            ),
            (
                &[0x48, 0x0f, 0xae, 0x64, 0x24, 0x40][..],
                X86XstateSaveKind::Xsave64,
                true,
                false,
            ),
            (
                &[0x0f, 0xae, 0x74, 0x24, 0x40][..],
                X86XstateSaveKind::Xsaveopt,
                false,
                false,
            ),
            (
                &[0x48, 0x0f, 0xae, 0x74, 0x24, 0x40][..],
                X86XstateSaveKind::Xsaveopt64,
                true,
                false,
            ),
            (
                &[0x0f, 0xc7, 0x64, 0x24, 0x40][..],
                X86XstateSaveKind::Xsavec,
                false,
                true,
            ),
            (
                &[0x48, 0x0f, 0xc7, 0x64, 0x24, 0x40][..],
                X86XstateSaveKind::Xsavec64,
                true,
                true,
            ),
        ] {
            let plan = decode(bytes, &snapshot);
            assert_eq!(plan.kind(), kind);
            assert_eq!(kind.is_64(), is_64);
            assert_eq!(kind.is_compacted(), is_compacted);
            assert_eq!(plan.address(), GuestVa(IMAGE_BASE + 0x40));
            assert!(plan.effective_segment_is_ss());
        }
        assert_eq!(
            X86XstateSavePlan::decode_for_kind(
                X86XstateSaveKind::Xsave64,
                &[0x0f, 0xae, 0x64, 0x24, 0x40],
                &snapshot,
                0,
                X86GuestGsBase::Zero,
            ),
            Err(X86XstateSaveError::Internal(
                X86XstateSaveInternalReason::InstructionKindMismatch {
                    expected: X86XstateSaveKind::Xsave64,
                    decoded: X86XstateSaveKind::Xsave,
                }
            ))
        );

        for bytes in [
            &[0x0f, 0xc7, 0x6c, 0x24, 0x40][..],
            &[0x48, 0x0f, 0xc7, 0x6c, 0x24, 0x40][..],
        ] {
            assert_eq!(
                X86XstateSavePlan::decode(bytes, &snapshot, 0, X86GuestGsBase::Zero),
                Err(X86XstateSaveError::GeneralProtection(
                    X86XstateSaveGpReason::UnsupportedInstruction
                ))
            );
        }
    }

    #[test]
    fn exact_standard_ranges_preserve_every_reserved_sentinel() {
        let layout = layout();
        let snapshot = snapshot(SAFE_FEATURES, SAFE_FEATURES);
        let before = snapshot.clone();
        let plan = decode(&[0x48, 0x0f, 0xae, 0x24, 0x24], &snapshot);
        let mut writer = ImageWriter::new(0xa5);
        emulate(&snapshot, plan, &layout, &mut writer).expect("save standard image");

        let expected = [
            (0, 5),
            (6, 2),
            (8, 16),
            (32, 128),
            (24, 8),
            (160, 256),
            (576, 256),
            (832, 64),
            (896, 512),
            (1408, 1024),
            (512, 8),
        ];
        assert_eq!(
            writer.writes,
            expected
                .iter()
                .map(|(offset, len)| (GuestVa(IMAGE_BASE + *offset), *len))
                .collect::<Vec<_>>()
        );
        let mut written = vec![false; writer.bytes.len()];
        for (offset, len) in expected {
            let offset = usize::try_from(offset).expect("test offset fits usize");
            written[offset..offset + len].fill(true);
        }
        for (index, byte) in writer.bytes.iter().enumerate() {
            if !written[index] {
                assert_eq!(*byte, 0xa5, "reserved byte {index} changed");
            }
        }
        assert_eq!(snapshot.gpr, before.gpr);
        assert_eq!(snapshot.rflags, before.rflags);
        assert_eq!(snapshot.rip, before.rip);
        assert_eq!(snapshot.pkru(), before.pkru());
        assert_eq!(snapshot.xsave, before.xsave);
    }

    #[test]
    fn plain_save_writes_initial_requested_payload_and_preserves_unrequested_bv() {
        let layout = layout();
        let requested = X87_FEATURE | SSE_FEATURE | (1 << 2);
        let snapshot = snapshot(requested, X87_FEATURE | (1 << 5));
        let plan = decode(&[0x0f, 0xae, 0x24, 0x24], &snapshot);
        let mut writer = ImageWriter::new(0xcc);
        let old_bv = (1 << 9) | (1 << 5) | SSE_FEATURE;
        writer.bytes[512..520].copy_from_slice(&old_bv.to_le_bytes());
        let old_xcomp = 0x55aa_0123_4567_89abu64;
        writer.bytes[520..528].copy_from_slice(&old_xcomp.to_le_bytes());
        emulate(&snapshot, plan, &layout, &mut writer).expect("mixed standard save");

        assert_eq!(
            u64::from_le_bytes(writer.bytes[512..520].try_into().unwrap()),
            X87_FEATURE | (1 << 5) | (1 << 9)
        );
        assert_eq!(
            u64::from_le_bytes(writer.bytes[520..528].try_into().unwrap()),
            old_xcomp,
            "standard XSAVE must not overwrite XCOMP_BV"
        );
        assert!(writer.bytes[0..5].iter().any(|byte| *byte != 0xcc));
        let initial = X86UcontextSnapshot::new();
        assert_eq!(&writer.bytes[24..28], &initial.xsave[24..28]);
        assert_eq!(&writer.bytes[28..32], &layout.mxcsr_mask.to_le_bytes());
        assert_eq!(&writer.bytes[160..416], &initial.xsave[160..416]);
        assert_eq!(&writer.bytes[576..832], &initial.xsave[576..832]);
        assert!(writer.bytes[832..896].iter().all(|byte| *byte == 0xcc));
    }

    #[test]
    fn compacted_offsets_follow_sparse_feature_map_and_alignment() {
        let layout = sparse_layout();
        let requested = X87_FEATURE | SSE_FEATURE | (1 << 2) | (1 << 5);
        let snapshot = snapshot(requested, (1 << 2) | (1 << 5));
        let plan = decode(&[0x48, 0x0f, 0xc7, 0x24, 0x24], &snapshot);
        let mut writer = ImageWriter::new(0xee);
        emulate(&snapshot, plan, &layout, &mut writer).expect("compacted save");

        assert_eq!(
            u64::from_le_bytes(writer.bytes[512..520].try_into().unwrap()),
            SSE_FEATURE | (1 << 2) | (1 << 5)
        );
        assert_eq!(
            u64::from_le_bytes(writer.bytes[520..528].try_into().unwrap()),
            XCOMP_COMPACTED | requested
        );
        assert_eq!(&writer.bytes[576..608], &snapshot.xsave[1024..1056]);
        assert_eq!(&writer.bytes[640..656], &snapshot.xsave[2048..2064]);
        assert!(writer.bytes[608..640].iter().all(|byte| *byte == 0xee));
    }

    #[test]
    fn compacted_destination_counts_requested_components_absent_from_xstate_bv() {
        let layout = sparse_layout();
        let request = (1 << 2) | (1 << 5);
        let snapshot = snapshot(request, 1 << 5);
        let plan = decode(&[0x0f, 0xc7, 0x24, 0x24], &snapshot);
        let mut writer = ImageWriter::new(0xd3);
        emulate(&snapshot, plan, &layout, &mut writer)
            .expect("compacted save with an absent requested component");

        assert_eq!(
            u64::from_le_bytes(writer.bytes[512..520].try_into().unwrap()),
            1 << 5
        );
        assert_eq!(
            u64::from_le_bytes(writer.bytes[520..528].try_into().unwrap()),
            XCOMP_COMPACTED | request
        );
        assert!(writer.bytes[576..608].iter().all(|byte| *byte == 0xd3));
        assert_eq!(&writer.bytes[640..656], &snapshot.xsave[2048..2064]);
    }

    #[test]
    fn hostile_pkru_request_is_ignored_but_xsavec_feature_map_is_retained() {
        let layout = layout();
        let hostile = 1u64 << 9;
        let snapshot = snapshot(hostile | (1 << 2), 1 << 2);
        let before = snapshot.clone();
        let plan = decode(&[0x0f, 0xc7, 0x24, 0x24], &snapshot);
        let mut writer = ImageWriter::new(0x7d);
        emulate(&snapshot, plan, &layout, &mut writer).expect("mask unsafe request");
        assert_eq!(
            u64::from_le_bytes(writer.bytes[512..520].try_into().unwrap()),
            1 << 2
        );
        assert_eq!(
            u64::from_le_bytes(writer.bytes[520..528].try_into().unwrap()),
            XCOMP_COMPACTED | (1 << 2)
        );
        assert_eq!(snapshot.gpr, before.gpr);
        assert_eq!(snapshot.rflags, before.rflags);
        assert_eq!(snapshot.rip, before.rip);
        assert_eq!(snapshot.pkru(), before.pkru());
        assert_eq!(snapshot.xsave, before.xsave);
    }

    #[test]
    fn xsaveopt_omits_init_payload_but_updates_mxcsr_and_standard_bv() {
        let layout = layout();
        let requested = SSE_FEATURE | (1 << 2);
        let mut snapshot = snapshot(requested, 0);
        snapshot.xsave[160..416].fill(0x82);
        snapshot.xsave[576..832].fill(0x83);
        let plan = decode(&[0x48, 0x0f, 0xae, 0x34, 0x24], &snapshot);
        let mut writer = ImageWriter::new(0xd1);
        writer.bytes[512..520].copy_from_slice(&(requested | (1 << 9)).to_le_bytes());
        emulate(&snapshot, plan, &layout, &mut writer).expect("init-state XSAVEOPT");

        assert_eq!(
            u64::from_le_bytes(writer.bytes[512..520].try_into().unwrap()),
            1 << 9
        );
        assert_eq!(
            &writer.bytes[24..28],
            &X86UcontextSnapshot::new().xsave[24..28]
        );
        assert_eq!(&writer.bytes[28..32], &layout.mxcsr_mask.to_le_bytes());
        assert!(writer.bytes[160..416].iter().all(|byte| *byte == 0xd1));
        assert!(writer.bytes[576..832].iter().all(|byte| *byte == 0xd1));
    }

    #[test]
    fn standard_header_read_is_mandatory_faultable_and_zero_request_is_noop() {
        let layout = layout();
        let state = snapshot(SSE_FEATURE, SSE_FEATURE);
        let plan = decode(&[0x48, 0x0f, 0xae, 0x34, 0x24], &state);
        let mut writer = ImageWriter::new(0x4a);
        writer.bytes[512..520].copy_from_slice(&(1u64 << 9).to_le_bytes());
        let mut reader = ImageReader::from_writer(&writer);
        state
            .emulate_xsave_with_memory(plan, &layout, &mut reader, &mut writer)
            .expect("standard save");
        assert_eq!(reader.reads, vec![(GuestVa(IMAGE_BASE + 512), 8)]);
        assert!(writer.writes.contains(&(GuestVa(IMAGE_BASE + 512), 8)));
        assert!(!writer.writes.contains(&(GuestVa(IMAGE_BASE + 512), 16)));

        let mut fault_writer = ImageWriter::new(0x6b);
        let mut fault_reader = ImageReader::from_writer(&fault_writer);
        fault_reader.fail = true;
        assert_eq!(
            state.emulate_xsave_with_memory(plan, &layout, &mut fault_reader, &mut fault_writer,),
            Err(X86XstateSaveError::Read(TestMemoryError::Injected))
        );
        assert_eq!(fault_reader.reads, vec![(GuestVa(IMAGE_BASE + 512), 8)]);
        assert!(fault_writer.writes.is_empty());

        let zero = snapshot(0, SAFE_FEATURES);
        let zero_plan = decode(&[0x48, 0x0f, 0xae, 0x24, 0x24], &zero);
        let mut zero_writer = ImageWriter::new(0x7c);
        let before = zero_writer.bytes.clone();
        let mut zero_reader = ImageReader::from_writer(&zero_writer);
        zero_reader.fail = true;
        zero.emulate_xsave_with_memory(zero_plan, &layout, &mut zero_reader, &mut zero_writer)
            .expect("zero effective request does not access memory");
        assert!(zero_reader.reads.is_empty());
        assert!(zero_writer.writes.is_empty());
        assert_eq!(zero_writer.bytes, before);
    }

    #[test]
    fn standard_avx_only_saves_mxcsr_and_mask_without_xmm() {
        let layout = layout();
        let avx = 1 << 2;
        let mut snapshot = snapshot(avx, SSE_FEATURE | avx);
        snapshot.xsave[24..28].copy_from_slice(&0x0000_1fc0u32.to_le_bytes());
        snapshot.xsave[160..416].fill(0x91);
        snapshot.xsave[576..832].fill(0x27);
        let plan = decode(&[0x48, 0x0f, 0xae, 0x34, 0x24], &snapshot);
        let mut writer = ImageWriter::new(0xda);
        emulate(&snapshot, plan, &layout, &mut writer).expect("AVX-only XSAVEOPT");

        assert_eq!(&writer.bytes[24..28], &0x0000_1fc0u32.to_le_bytes());
        assert_eq!(&writer.bytes[28..32], &layout.mxcsr_mask.to_le_bytes());
        assert!(writer.bytes[160..416].iter().all(|byte| *byte == 0xda));
        assert_eq!(&writer.bytes[576..832], &[0x27; 256]);
    }

    #[test]
    fn xsavec_sse_mxcsr_exception_and_avx_only_match_host_semantics() {
        let layout = layout();
        let mut sse = snapshot(SSE_FEATURE, 0);
        sse.xsave[24..28].copy_from_slice(&0x0000_1fc0u32.to_le_bytes());
        sse.xsave[160..416].fill(0x93);
        let sse_plan = decode(&[0x48, 0x0f, 0xc7, 0x24, 0x24], &sse);
        let mut sse_writer = ImageWriter::new(0xe1);
        emulate(&sse, sse_plan, &layout, &mut sse_writer).expect("XSAVEC SSE exception");
        assert_eq!(
            u64::from_le_bytes(sse_writer.bytes[512..520].try_into().unwrap()),
            SSE_FEATURE
        );
        assert_eq!(&sse_writer.bytes[24..28], &0x0000_1fc0u32.to_le_bytes());
        assert_eq!(&sse_writer.bytes[28..32], &layout.mxcsr_mask.to_le_bytes());
        assert_eq!(
            &sse_writer.bytes[160..416],
            &X86UcontextSnapshot::new().xsave[160..416],
            "absent SSE supplies architectural initial XMM bytes"
        );

        let avx = 1 << 2;
        let mut avx_only = snapshot(avx, avx);
        avx_only.xsave[24..28].copy_from_slice(&0x0000_1fc0u32.to_le_bytes());
        avx_only.xsave[576..832].fill(0x34);
        let avx_plan = decode(&[0x48, 0x0f, 0xc7, 0x24, 0x24], &avx_only);
        let mut avx_writer = ImageWriter::new(0xe2);
        emulate(&avx_only, avx_plan, &layout, &mut avx_writer).expect("AVX-only XSAVEC");
        assert_eq!(
            u64::from_le_bytes(avx_writer.bytes[512..520].try_into().unwrap()),
            avx
        );
        assert_eq!(
            u64::from_le_bytes(avx_writer.bytes[520..528].try_into().unwrap()),
            XCOMP_COMPACTED | avx
        );
        assert!(avx_writer.bytes[24..32].iter().all(|byte| *byte == 0xe2));
        assert!(avx_writer.bytes[160..416].iter().all(|byte| *byte == 0xe2));
        assert_eq!(&avx_writer.bytes[576..832], &[0x34; 256]);
    }

    #[test]
    fn non_rex_x87_writes_virtual_selectors_and_rex_writes_only_full_pointers() {
        let layout = layout();
        let mut snapshot = snapshot(X87_FEATURE, X87_FEATURE);
        snapshot.xsave[8..12].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        snapshot.xsave[16..20].copy_from_slice(&0x5566_7788u32.to_le_bytes());
        snapshot.restore_x87_selectors(0x1357, 0x2468);
        let plan = decode(&[0x0f, 0xae, 0x24, 0x24], &snapshot);
        let mut writer = ImageWriter::new(0xa6);
        emulate(&snapshot, plan, &layout, &mut writer).expect("non-REX selector XSAVE");
        assert_eq!(&writer.bytes[8..12], &0x1122_3344u32.to_le_bytes());
        assert_eq!(&writer.bytes[12..14], &0x1357u16.to_le_bytes());
        assert_eq!(&writer.bytes[14..16], &[0xa6, 0xa6]);
        assert_eq!(&writer.bytes[16..20], &0x5566_7788u32.to_le_bytes());
        assert_eq!(&writer.bytes[20..22], &0x2468u16.to_le_bytes());
        assert_eq!(&writer.bytes[22..24], &[0xa6, 0xa6]);

        let rex_plan = decode(&[0x48, 0x0f, 0xae, 0x24, 0x24], &snapshot);
        let mut rex_writer = ImageWriter::new(0xc8);
        emulate(&snapshot, rex_plan, &layout, &mut rex_writer)
            .expect("REX.W carries exact full pointers without selector fields");
        assert_eq!(&rex_writer.bytes[8..24], &snapshot.xsave[8..24]);
    }

    #[test]
    fn late_writer_fault_keeps_partial_memory_and_never_mutates_snapshot() {
        let layout = layout();
        let snapshot = snapshot(SAFE_FEATURES, SAFE_FEATURES);
        let before = snapshot.clone();
        let plan = decode(&[0x48, 0x0f, 0xae, 0x24, 0x24], &snapshot);
        let mut writer = ImageWriter::new(0x44);
        writer.fail_at = Some(7);
        assert_eq!(
            emulate(&snapshot, plan, &layout, &mut writer),
            Err(X86XstateSaveError::Write(TestMemoryError::Injected))
        );
        assert_ne!(&writer.bytes[0..5], &[0x44; 5]);
        assert_eq!(&writer.bytes[832..896], &[0x44; 64]);
        assert_eq!(snapshot.gpr, before.gpr);
        assert_eq!(snapshot.rflags, before.rflags);
        assert_eq!(snapshot.rip, before.rip);
        assert_eq!(snapshot.pkru(), before.pkru());
        assert_eq!(snapshot.xsave, before.xsave);
    }

    #[test]
    fn later_noncanonical_destination_is_rejected_before_first_write() {
        let layout = layout();
        let snapshot = snapshot(SAFE_FEATURES, SAFE_FEATURES);
        let plan = X86XstateSavePlan {
            kind: X86XstateSaveKind::Xsave64,
            address: GuestVa(0x0000_7fff_ffff_fc00),
            instruction_len: 5,
            effective_segment_is_ss: false,
        };
        let mut writer = ImageWriter::new(0);
        assert_eq!(
            emulate(&snapshot, plan, &layout, &mut writer),
            Err(X86XstateSaveError::GeneralProtection(
                X86XstateSaveGpReason::NoncanonicalAddress
            ))
        );
        assert!(writer.writes.is_empty());
    }

    #[test]
    fn invalid_layout_or_snapshot_is_rejected_before_first_write() {
        let good = layout();
        let mut snapshot = snapshot(SAFE_FEATURES, SAFE_FEATURES | (1 << 9));
        let plan = decode(&[0x48, 0x0f, 0xae, 0x24, 0x24], &snapshot);
        let mut writer = ImageWriter::new(0);
        assert_eq!(
            emulate(&snapshot, plan, &good, &mut writer),
            Err(X86XstateSaveError::Internal(
                X86XstateSaveInternalReason::UnsupportedSnapshotFeatures
            ))
        );
        assert!(writer.writes.is_empty());

        snapshot.xsave[512..520].copy_from_slice(&SAFE_FEATURES.to_le_bytes());
        let capabilities = good.capabilities();
        let invalid = X86SnapshotXstateLayout::new_unchecked(capabilities, 1 << 9);
        assert_eq!(
            emulate(&snapshot, plan, &invalid, &mut writer),
            Err(X86XstateSaveError::Internal(
                X86XstateSaveInternalReason::InvalidLayout
            ))
        );
        assert!(writer.writes.is_empty());
    }
}
