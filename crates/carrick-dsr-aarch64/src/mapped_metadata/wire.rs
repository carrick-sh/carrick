//! V3's fixed-width, little-endian byte contract and allocation-free layout check.

use zerocopy::byteorder::{I64, LittleEndian, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::artifact_spike::{PortableBiasedMemoryRecovery, PortableRecoveryAction};
use crate::emit::{
    BiasedBase, BiasedBaseCoordinate, BiasedExclusiveRecovery, BiasedExclusiveResume,
    CounterReadRecovery, CounterScratchDestination, DirectBindingCaptureProgress,
    DirectBindingRecoveryPhase, RecoveryAction,
};
use crate::types::{BiasedExclusiveScratch, DsrError, DsrScratchGpr};

pub const MAPPED_METADATA_SCHEMA_V3: u32 = 3;
pub const MAPPED_METADATA_MAGIC_V3: [u8; 8] = *b"CRKMDV3\0";
pub const MAPPED_METADATA_ENDIAN_MARKER_V3: u32 = 0x0102_0304;
const SECTION_ALIGNMENT_V3: u64 = 8;
const SECTION_DIRECTORY_ENTRIES_V3: usize = 12;
pub(crate) const WIRE_EXECUTABLE_HOST_FILE_V3: u32 = 1;
pub(crate) const WIRE_EXECUTABLE_DIGEST_V3: u32 = 2;

/// The stable kind of a V3 table. Zero is reserved for an unused fixed
/// directory slot, never a section payload.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum SectionKind {
    Block = 1,
    PcMap = 2,
    RecoverySpan = 3,
    RecoveryAction = 4,
    GuestRange = 5,
    Binding = 6,
    BindingRelocation = 7,
    EdgeGroup = 8,
    EdgeMember = 9,
    GuestPcIndex = 10,
    BlockGuestIndex = 11,
    BindingTargetIndex = 12,
}

impl SectionKind {
    pub const fn raw(self) -> u32 {
        self as u32
    }

    pub const fn record_stride(self) -> u32 {
        match self {
            Self::Block => WIRE_BLOCK_V3_SIZE as u32,
            Self::PcMap => PC_MAP_RECORD_V3_SIZE as u32,
            Self::RecoverySpan => RECOVERY_SPAN_RECORD_V3_SIZE as u32,
            Self::RecoveryAction => RECOVERY_ACTION_RECORD_V3_SIZE as u32,
            Self::GuestRange => GUEST_RANGE_RECORD_V3_SIZE as u32,
            Self::Binding => BINDING_RECORD_V3_SIZE as u32,
            Self::BindingRelocation => BINDING_RELOCATION_RECORD_V3_SIZE as u32,
            Self::EdgeGroup => EDGE_GROUP_RECORD_V3_SIZE as u32,
            Self::EdgeMember => EDGE_MEMBER_RECORD_V3_SIZE as u32,
            Self::GuestPcIndex => GUEST_PC_INDEX_RECORD_V3_SIZE as u32,
            Self::BlockGuestIndex => BLOCK_GUEST_INDEX_RECORD_V3_SIZE as u32,
            Self::BindingTargetIndex => BINDING_TARGET_INDEX_RECORD_V3_SIZE as u32,
        }
    }

    const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::Block),
            2 => Some(Self::PcMap),
            3 => Some(Self::RecoverySpan),
            4 => Some(Self::RecoveryAction),
            5 => Some(Self::GuestRange),
            6 => Some(Self::Binding),
            7 => Some(Self::BindingRelocation),
            8 => Some(Self::EdgeGroup),
            9 => Some(Self::EdgeMember),
            10 => Some(Self::GuestPcIndex),
            11 => Some(Self::BlockGuestIndex),
            12 => Some(Self::BindingTargetIndex),
            _ => None,
        }
    }
}

/// Structural failures that make a mapped V3 file ineligible for use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MappedMetadataError {
    OwnedManifest,
    Arithmetic,
    MissingSection {
        kind: SectionKind,
    },
    Key,
    Block,
    PcMap,
    RecoverySpan,
    RecoveryAction,
    GuestRange,
    Binding,
    BindingRelocation,
    EdgeGroup,
    EdgeBackReference,
    HeaderTruncated {
        actual: usize,
    },
    Magic,
    Schema {
        found: u32,
    },
    EndianMarker {
        found: u32,
    },
    HeaderSize {
        found: u32,
    },
    HeaderReserved,
    ExecutableKind {
        raw: u32,
    },
    ExecutableUnusedStorage {
        executable_kind: u32,
    },
    TotalLength {
        declared: u64,
        actual: u64,
    },
    SectionKind {
        raw: u32,
    },
    SectionReserved {
        kind: SectionKind,
    },
    SectionStride {
        kind: SectionKind,
        expected: u32,
        actual: u32,
    },
    SectionLength {
        kind: SectionKind,
        expected: u64,
        actual: u64,
    },
    SectionRangeOverflow {
        kind: SectionKind,
    },
    SectionBounds {
        kind: SectionKind,
        end: u64,
        total: u64,
    },
    SectionAlignment {
        kind: SectionKind,
        offset: u64,
    },
    DuplicateSection {
        kind: SectionKind,
    },
    SectionOverlap {
        left: SectionKind,
        right: SectionKind,
    },
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct WireSectionV3 {
    pub kind: U32<LittleEndian>,
    pub stride: U32<LittleEndian>,
    pub offset: U64<LittleEndian>,
    pub byte_len: U64<LittleEndian>,
    pub count: U64<LittleEndian>,
    pub reserved: U64<LittleEndian>,
}

/// The stable `HostFile` executable identity payload. Signed host-file times
/// remain signed little-endian integers on disk.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct WireHostFileExecutableV3 {
    pub device: U64<LittleEndian>,
    pub inode: U64<LittleEndian>,
    pub size: U64<LittleEndian>,
    pub mtime_seconds: I64<LittleEndian>,
    pub mtime_nanoseconds: I64<LittleEndian>,
}

/// The stable digest executable identity payload. Its trailing bytes remain
/// zero so both executable alternatives have a fixed 40-byte footprint.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct WireDigestExecutableV3 {
    pub digest: [u8; 32],
    pub reserved: [u8; 8],
}

/// Fixed representation of the identity that selects a translation unit.
/// The non-selected executable payload is all zero, selected by the stable
/// `WIRE_EXECUTABLE_*_V3` discriminant.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct WireTranslationUnitKeyV3 {
    pub executable_kind: U32<LittleEndian>,
    pub page_profile: U32<LittleEndian>,
    pub address_mode: U32<LittleEndian>,
    pub translator_abi: U32<LittleEndian>,
    pub segment_file_offset: U64<LittleEndian>,
    pub segment_file_len: U64<LittleEndian>,
    pub guest_va_start: U64<LittleEndian>,
    pub guest_va_len: U64<LittleEndian>,
    pub host_bias: U64<LittleEndian>,
    pub host_file: WireHostFileExecutableV3,
    pub digest: WireDigestExecutableV3,
    pub source_fingerprint: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct WireHeaderV3 {
    pub magic: [u8; 8],
    pub schema: U32<LittleEndian>,
    pub endian_marker: U32<LittleEndian>,
    pub header_size: U32<LittleEndian>,
    pub reserved: U32<LittleEndian>,
    pub total_len: U64<LittleEndian>,
    pub key: WireTranslationUnitKeyV3,
    pub code_sha256: [u8; 32],
    pub code_len: U64<LittleEndian>,
    pub binding_data_len: U64<LittleEndian>,
    pub binding_layout: U32<LittleEndian>,
    pub cell_size: U32<LittleEndian>,
    pub binding_reserved: U64<LittleEndian>,
    pub sections: [WireSectionV3; SECTION_DIRECTORY_ENTRIES_V3],
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct WireBlockV3 {
    pub guest_start: U64<LittleEndian>,
    pub generation_binding: U64<LittleEndian>,
    pub entry_offset: U32<LittleEndian>,
    pub code_len: U32<LittleEndian>,
    pub flags: U32<LittleEndian>,
    pub reserved: U32<LittleEndian>,
    pub pc_map_start: U64<LittleEndian>,
    pub pc_map_count: U64<LittleEndian>,
    pub recovery_start: U64<LittleEndian>,
    pub recovery_count: U64<LittleEndian>,
    pub guest_range_start: U64<LittleEndian>,
    pub guest_range_count: U64<LittleEndian>,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct WirePcMapV3 {
    pub guest: U64<LittleEndian>,
    pub cache_offset: U32<LittleEndian>,
    pub guest_order_ordinal: U32<LittleEndian>,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct WireRecoverySpanV3 {
    pub cache_offset: U32<LittleEndian>,
    pub entry_count: U32<LittleEndian>,
    pub action_index: U64<LittleEndian>,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct WireRecoveryActionV3 {
    pub tag: U32<LittleEndian>,
    pub reserved: U32<LittleEndian>,
    pub payload: [U64<LittleEndian>; 5],
}

impl WireRecoveryActionV3 {
    pub(crate) fn from_portable(action: PortableRecoveryAction) -> Result<Self, DsrError> {
        let (tag, payload) = match action {
            PortableRecoveryAction::Noop => (0, [0; 5]),
            PortableRecoveryAction::RestoreGuestX17 => (1, [0; 5]),
            PortableRecoveryAction::RestoreGenerationGuardRegisters => (2, [0; 5]),
            PortableRecoveryAction::RestoreGenerationGuard => (3, [0; 5]),
            PortableRecoveryAction::RestoreIndirectRegisters => (4, [0; 5]),
            PortableRecoveryAction::RestoreIndirectResolver => (5, [0; 5]),
            PortableRecoveryAction::RestoreScratch { register } => (6, words(&[register])),
            PortableRecoveryAction::RestoreScratchInvalidBiasedLiteral { register } => {
                (7, words(&[register]))
            }
            PortableRecoveryAction::RestoreScratchCompleted { register } => (8, words(&[register])),
            PortableRecoveryAction::CommitVirtualizedAndRestoreScratch {
                register,
                virtual_register,
            } => (9, words(&[register, virtual_register])),
            PortableRecoveryAction::RestoreScratchAndContext {
                register,
                context_register,
            } => (10, words(&[register, context_register])),
            PortableRecoveryAction::RestoreScratchAndContextCompleted {
                register,
                context_register,
            } => (11, words(&[register, context_register])),
            PortableRecoveryAction::CommitVirtualizedAndRestoreScratchAndContext {
                register,
                context_register,
                virtual_register,
            } => (12, words(&[register, context_register, virtual_register])),
            PortableRecoveryAction::RestoreDualVirtualReadOnly {
                x18_scratch,
                x28_scratch,
                context_scratch,
            } => (13, words(&[x18_scratch, x28_scratch, context_scratch])),
            PortableRecoveryAction::RestoreDualVirtualReadOnlyCompleted {
                x18_scratch,
                x28_scratch,
                context_scratch,
            } => (14, words(&[x18_scratch, x28_scratch, context_scratch])),
            PortableRecoveryAction::CommitDualVirtualAndRestore {
                x18_scratch,
                x28_scratch,
                context_scratch,
                virtual_register,
                virtual_scratch,
            } => (
                15,
                words(&[
                    x18_scratch,
                    x28_scratch,
                    context_scratch,
                    virtual_register,
                    virtual_scratch,
                ]),
            ),
            PortableRecoveryAction::CommitDualVirtualPairAndRestore {
                x18_scratch,
                x28_scratch,
                context_scratch,
                first_register,
                second_register,
            } => (
                16,
                words(&[
                    x18_scratch,
                    x28_scratch,
                    context_scratch,
                    first_register,
                    second_register,
                ]),
            ),
            PortableRecoveryAction::CommitReservedResident { virtual_register } => {
                (21, words(&[virtual_register]))
            }
            PortableRecoveryAction::RestoreIndirectLean => (22, [0; 5]),
            PortableRecoveryAction::RestoreIndirectLeanCall => (23, [0; 5]),
            PortableRecoveryAction::RecoverCounterRead(recovery) => {
                let destination = match recovery.committed_scratch_destination {
                    None => 0,
                    Some(CounterScratchDestination::X15) => 1,
                    Some(CounterScratchDestination::X16) => 2,
                    Some(CounterScratchDestination::X17) => 3,
                };
                (
                    17,
                    [
                        destination,
                        u64::from(recovery.instruction_complete),
                        0,
                        0,
                        0,
                    ],
                )
            }
            PortableRecoveryAction::RecoverBiasedMemory(recovery) => {
                (18, encode_biased_memory(recovery)?)
            }
            PortableRecoveryAction::RecoverBiasedExclusive(recovery) => {
                let resume = match recovery.resume {
                    BiasedExclusiveResume::Load => 0,
                    BiasedExclusiveResume::Exact => 1,
                    BiasedExclusiveResume::Retry => 2,
                };
                (
                    19,
                    [
                        u64::from(recovery.scratch.address.index()),
                        u64::from(recovery.scratch.bias.index()),
                        resume,
                        0,
                        0,
                    ],
                )
            }
            PortableRecoveryAction::RestoreDirectBinding {
                phase,
                capture_progress,
                committed_link,
            } => {
                let phase = match phase {
                    DirectBindingRecoveryPhase::ScratchCapture => 0,
                    DirectBindingRecoveryPhase::CellAddress => 1,
                    DirectBindingRecoveryPhase::TargetAcquire => 2,
                    DirectBindingRecoveryPhase::AuthorityValidate => 3,
                    DirectBindingRecoveryPhase::AuthorityInstall => 4,
                    DirectBindingRecoveryPhase::ArchitecturalRestore => 5,
                    DirectBindingRecoveryPhase::FinalBranch => 6,
                    DirectBindingRecoveryPhase::MissExit => 7,
                };
                let capture = match capture_progress {
                    DirectBindingCaptureProgress::None => 0,
                    DirectBindingCaptureProgress::X15 => 1,
                    DirectBindingCaptureProgress::X15X16 => 2,
                    DirectBindingCaptureProgress::X15X16X30 => 3,
                    DirectBindingCaptureProgress::Complete => 4,
                };
                let (present, value) = committed_link.map_or((0, 0), |value| (1, value));
                (20, [phase, capture, present, value, 0])
            }
        };
        let wire = Self {
            tag: U32::new(tag),
            reserved: U32::new(0),
            payload: payload.map(U64::new),
        };
        wire.into_portable()
            .map_err(|_| DsrError::CachePolicy("invalid portable recovery action".to_string()))?;
        Ok(wire)
    }

    pub(crate) fn validate(self, host_bias: Option<u64>) -> Result<(), MappedMetadataError> {
        let portable = self.into_portable()?;
        if matches!(
            portable,
            PortableRecoveryAction::RecoverBiasedMemory(_)
                | PortableRecoveryAction::RecoverBiasedExclusive(_)
        ) && host_bias.is_none()
        {
            return Err(MappedMetadataError::RecoveryAction);
        }
        portable
            .rebind_with_host_bias(host_bias)
            .map(|_| ())
            .map_err(|_| MappedMetadataError::RecoveryAction)
    }

    pub(crate) fn into_recovery_action(
        self,
        host_bias: Option<u64>,
    ) -> Result<RecoveryAction, DsrError> {
        let portable = self
            .into_portable()
            .map_err(|_| DsrError::CachePolicy("invalid mapped V3 recovery action".to_string()))?;
        portable.rebind_with_host_bias(host_bias)
    }

    fn into_portable(self) -> Result<PortableRecoveryAction, MappedMetadataError> {
        if self.reserved.get() != 0 {
            return Err(MappedMetadataError::RecoveryAction);
        }
        let p = self.payload.map(|word| word.get());
        let action = match self.tag.get() {
            0 if unused(&p, 0) => PortableRecoveryAction::Noop,
            1 if unused(&p, 0) => PortableRecoveryAction::RestoreGuestX17,
            2 if unused(&p, 0) => PortableRecoveryAction::RestoreGenerationGuardRegisters,
            3 if unused(&p, 0) => PortableRecoveryAction::RestoreGenerationGuard,
            4 if unused(&p, 0) => PortableRecoveryAction::RestoreIndirectRegisters,
            5 if unused(&p, 0) => PortableRecoveryAction::RestoreIndirectResolver,
            6 if unused(&p, 1) => PortableRecoveryAction::RestoreScratch {
                register: gpr_word(p[0])?,
            },
            7 if unused(&p, 1) => PortableRecoveryAction::RestoreScratchInvalidBiasedLiteral {
                register: gpr_word(p[0])?,
            },
            8 if unused(&p, 1) => PortableRecoveryAction::RestoreScratchCompleted {
                register: gpr_word(p[0])?,
            },
            9 if unused(&p, 2) => PortableRecoveryAction::CommitVirtualizedAndRestoreScratch {
                register: gpr_word(p[0])?,
                virtual_register: gpr_word(p[1])?,
            },
            10 if unused(&p, 2) => PortableRecoveryAction::RestoreScratchAndContext {
                register: gpr_word(p[0])?,
                context_register: gpr_word(p[1])?,
            },
            11 if unused(&p, 2) => PortableRecoveryAction::RestoreScratchAndContextCompleted {
                register: gpr_word(p[0])?,
                context_register: gpr_word(p[1])?,
            },
            12 if unused(&p, 3) => {
                PortableRecoveryAction::CommitVirtualizedAndRestoreScratchAndContext {
                    register: gpr_word(p[0])?,
                    context_register: gpr_word(p[1])?,
                    virtual_register: gpr_word(p[2])?,
                }
            }
            13 if unused(&p, 3) => PortableRecoveryAction::RestoreDualVirtualReadOnly {
                x18_scratch: gpr_word(p[0])?,
                x28_scratch: gpr_word(p[1])?,
                context_scratch: gpr_word(p[2])?,
            },
            14 if unused(&p, 3) => PortableRecoveryAction::RestoreDualVirtualReadOnlyCompleted {
                x18_scratch: gpr_word(p[0])?,
                x28_scratch: gpr_word(p[1])?,
                context_scratch: gpr_word(p[2])?,
            },
            15 => PortableRecoveryAction::CommitDualVirtualAndRestore {
                x18_scratch: gpr_word(p[0])?,
                x28_scratch: gpr_word(p[1])?,
                context_scratch: gpr_word(p[2])?,
                virtual_register: gpr_word(p[3])?,
                virtual_scratch: gpr_word(p[4])?,
            },
            16 => PortableRecoveryAction::CommitDualVirtualPairAndRestore {
                x18_scratch: gpr_word(p[0])?,
                x28_scratch: gpr_word(p[1])?,
                context_scratch: gpr_word(p[2])?,
                first_register: gpr_word(p[3])?,
                second_register: gpr_word(p[4])?,
            },
            17 if unused(&p, 2) => {
                PortableRecoveryAction::RecoverCounterRead(CounterReadRecovery {
                    committed_scratch_destination: match p[0] {
                        0 => None,
                        1 => Some(CounterScratchDestination::X15),
                        2 => Some(CounterScratchDestination::X16),
                        3 => Some(CounterScratchDestination::X17),
                        _ => return Err(MappedMetadataError::RecoveryAction),
                    },
                    instruction_complete: bool_word(p[1])?,
                })
            }
            18 => PortableRecoveryAction::RecoverBiasedMemory(decode_biased_memory(p)?),
            19 if unused(&p, 3) => {
                PortableRecoveryAction::RecoverBiasedExclusive(BiasedExclusiveRecovery {
                    scratch: BiasedExclusiveScratch {
                        address: scratch_gpr(p[0])?,
                        bias: scratch_gpr(p[1])?,
                    },
                    resume: match p[2] {
                        0 => BiasedExclusiveResume::Load,
                        1 => BiasedExclusiveResume::Exact,
                        2 => BiasedExclusiveResume::Retry,
                        _ => return Err(MappedMetadataError::RecoveryAction),
                    },
                })
            }
            20 if p[4] == 0 => PortableRecoveryAction::RestoreDirectBinding {
                phase: match p[0] {
                    0 => DirectBindingRecoveryPhase::ScratchCapture,
                    1 => DirectBindingRecoveryPhase::CellAddress,
                    2 => DirectBindingRecoveryPhase::TargetAcquire,
                    3 => DirectBindingRecoveryPhase::AuthorityValidate,
                    4 => DirectBindingRecoveryPhase::AuthorityInstall,
                    5 => DirectBindingRecoveryPhase::ArchitecturalRestore,
                    6 => DirectBindingRecoveryPhase::FinalBranch,
                    7 => DirectBindingRecoveryPhase::MissExit,
                    _ => return Err(MappedMetadataError::RecoveryAction),
                },
                capture_progress: match p[1] {
                    0 => DirectBindingCaptureProgress::None,
                    1 => DirectBindingCaptureProgress::X15,
                    2 => DirectBindingCaptureProgress::X15X16,
                    3 => DirectBindingCaptureProgress::X15X16X30,
                    4 => DirectBindingCaptureProgress::Complete,
                    _ => return Err(MappedMetadataError::RecoveryAction),
                },
                committed_link: match p[2] {
                    0 if p[3] == 0 => None,
                    1 => Some(p[3]),
                    _ => return Err(MappedMetadataError::RecoveryAction),
                },
            },
            21 if unused(&p, 1) => PortableRecoveryAction::CommitReservedResident {
                virtual_register: gpr_word(p[0])?,
            },
            22 if unused(&p, 0) => PortableRecoveryAction::RestoreIndirectLean,
            23 if unused(&p, 0) => PortableRecoveryAction::RestoreIndirectLeanCall,
            _ => return Err(MappedMetadataError::RecoveryAction),
        };
        Ok(action)
    }
}

fn words(values: &[u32]) -> [u64; 5] {
    let mut words = [0; 5];
    for (target, value) in words.iter_mut().zip(values) {
        *target = u64::from(*value);
    }
    words
}

fn unused(payload: &[u64; 5], used: usize) -> bool {
    payload[used..].iter().all(|word| *word == 0)
}

fn u32_word(value: u64) -> Result<u32, MappedMetadataError> {
    u32::try_from(value).map_err(|_| MappedMetadataError::RecoveryAction)
}

fn gpr_word(value: u64) -> Result<u32, MappedMetadataError> {
    let value = u32_word(value)?;
    DsrScratchGpr::new(value)
        .map(DsrScratchGpr::index)
        .ok_or(MappedMetadataError::RecoveryAction)
}

fn bool_word(value: u64) -> Result<bool, MappedMetadataError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(MappedMetadataError::RecoveryAction),
    }
}

fn scratch_gpr(value: u64) -> Result<DsrScratchGpr, MappedMetadataError> {
    let value = u32_word(value)?;
    DsrScratchGpr::new(value).ok_or(MappedMetadataError::RecoveryAction)
}

fn packed_register(value: Option<u32>) -> Result<u64, DsrError> {
    match value {
        None => Ok(0),
        Some(value) if value <= 30 => Ok(u64::from(value + 1)),
        Some(value) => Err(DsrError::CachePolicy(format!(
            "invalid portable recovery register x{value}"
        ))),
    }
}

fn encode_biased_memory(recovery: PortableBiasedMemoryRecovery) -> Result<[u64; 5], DsrError> {
    for register in recovery
        .scratch_registers
        .into_iter()
        .chain([recovery.base_scratch])
    {
        if register > 30 {
            return Err(DsrError::CachePolicy(format!(
                "invalid portable recovery register x{register}"
            )));
        }
    }
    if recovery.scratch_count > 4 {
        return Err(DsrError::CachePolicy(
            "invalid portable recovery scratch count".to_string(),
        ));
    }
    let base = match recovery.base {
        BiasedBase::None => 0,
        BiasedBase::StackPointer => 1,
        BiasedBase::VirtualX18 => 2,
        BiasedBase::VirtualX28 => 3,
        BiasedBase::VirtualReserved => 4,
        BiasedBase::Register(register) if register <= 30 => u64::from(register) + 5,
        BiasedBase::Register(register) => {
            return Err(DsrError::CachePolicy(format!(
                "invalid portable recovery base x{register}"
            )));
        }
    };
    let flags = u64::from(recovery.scratch_count)
        | ((match recovery.base_coordinate {
            BiasedBaseCoordinate::Host => 0,
            BiasedBaseCoordinate::Guest => 1,
        }) << 3)
        | (u64::from(recovery.commit_base) << 4)
        | (u64::from(recovery.instruction_complete) << 5)
        | (packed_register(recovery.virtual_x18_scratch)? << 6)
        | (packed_register(recovery.virtual_x28_scratch)? << 12)
        | (packed_register(recovery.virtual_reserved_scratch)? << 18);
    Ok([
        u64::from(recovery.scratch_registers[0]) | (u64::from(recovery.scratch_registers[1]) << 32),
        u64::from(recovery.scratch_registers[2]) | (u64::from(recovery.scratch_registers[3]) << 32),
        u64::from(recovery.base_scratch) | (base << 32),
        flags,
        0,
    ])
}

fn decode_biased_memory(p: [u64; 5]) -> Result<PortableBiasedMemoryRecovery, MappedMetadataError> {
    if p[4] != 0 || p[3] >> 24 != 0 {
        return Err(MappedMetadataError::RecoveryAction);
    }
    let register = |value: u64| -> Result<u32, MappedMetadataError> {
        let value = u32_word(value)?;
        (value <= 30)
            .then_some(value)
            .ok_or(MappedMetadataError::RecoveryAction)
    };
    let option = |value: u64| -> Result<Option<u32>, MappedMetadataError> {
        match value {
            0 => Ok(None),
            1..=31 => Ok(Some(
                u32::try_from(value - 1).map_err(|_| MappedMetadataError::RecoveryAction)?,
            )),
            _ => Err(MappedMetadataError::RecoveryAction),
        }
    };
    let base_raw = p[2] >> 32;
    let base = match base_raw {
        0 => BiasedBase::None,
        1 => BiasedBase::StackPointer,
        2 => BiasedBase::VirtualX18,
        3 => BiasedBase::VirtualX28,
        4 => BiasedBase::VirtualReserved,
        5..=35 => BiasedBase::Register(
            u32::try_from(base_raw - 5).map_err(|_| MappedMetadataError::RecoveryAction)?,
        ),
        _ => return Err(MappedMetadataError::RecoveryAction),
    };
    let scratch_count = u8::try_from(p[3] & 7).map_err(|_| MappedMetadataError::RecoveryAction)?;
    if scratch_count > 4 {
        return Err(MappedMetadataError::RecoveryAction);
    }
    Ok(PortableBiasedMemoryRecovery {
        scratch_registers: [
            register(p[0] & 0xffff_ffff)?,
            register(p[0] >> 32)?,
            register(p[1] & 0xffff_ffff)?,
            register(p[1] >> 32)?,
        ],
        scratch_count,
        base_scratch: register(p[2] & 0xffff_ffff)?,
        base,
        base_coordinate: if (p[3] >> 3) & 1 == 0 {
            BiasedBaseCoordinate::Host
        } else {
            BiasedBaseCoordinate::Guest
        },
        commit_base: (p[3] >> 4) & 1 != 0,
        instruction_complete: (p[3] >> 5) & 1 != 0,
        virtual_x18_scratch: option((p[3] >> 6) & 0x3f)?,
        virtual_x28_scratch: option((p[3] >> 12) & 0x3f)?,
        virtual_reserved_scratch: option((p[3] >> 18) & 0x3f)?,
    })
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct WireGuestRangeV3 {
    pub start: U64<LittleEndian>,
    pub end: U64<LittleEndian>,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct WireBindingV3 {
    pub source: U64<LittleEndian>,
    pub target: U64<LittleEndian>,
    pub ordinal: U32<LittleEndian>,
    pub kind: U32<LittleEndian>,
    pub stub_start: U32<LittleEndian>,
    pub stub_end: U32<LittleEndian>,
    pub edge_member_index: U64<LittleEndian>,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct WireBindingRelocationV3 {
    pub ordinal: U32<LittleEndian>,
    pub adrp_offset: U32<LittleEndian>,
    pub add_offset: U32<LittleEndian>,
    pub miss_adrp_offset: U32<LittleEndian>,
    pub miss_add_offset: U32<LittleEndian>,
    pub data_offset: U32<LittleEndian>,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct WireEdgeGroupV3 {
    pub source: U64<LittleEndian>,
    pub target: U64<LittleEndian>,
    pub member_start: U64<LittleEndian>,
    pub member_count: U64<LittleEndian>,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct WireEdgeMemberV3 {
    pub binding_ordinal: U32<LittleEndian>,
    pub reserved: U32<LittleEndian>,
}

/// One block-local PC ordinal, sorted by `(guest, pc_ordinal)` in the
/// publisher. The guest VA remains canonical in `WirePcMapV3`, avoiding an
/// extra eight bytes per multi-million-entry PC table.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct WireGuestPcIndexV3 {
    pub pc_map_ordinal: U32<LittleEndian>,
    pub reserved: U32<LittleEndian>,
}

/// One block ordinal, sorted by the referenced block's guest start.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct WireBlockGuestIndexV3 {
    pub block_index: U32<LittleEndian>,
    pub reserved: U32<LittleEndian>,
}

/// One binding ordinal, sorted by `(target, binding_ordinal)`.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct WireBindingTargetIndexV3 {
    pub binding_ordinal: U32<LittleEndian>,
    pub reserved: U32<LittleEndian>,
}

pub const WIRE_SECTION_SIZE_V3: usize = std::mem::size_of::<WireSectionV3>();
pub const HEADER_SIZE_V3: usize = std::mem::size_of::<WireHeaderV3>();
const WIRE_BLOCK_V3_SIZE: usize = std::mem::size_of::<WireBlockV3>();
pub const PC_MAP_RECORD_V3_SIZE: usize = std::mem::size_of::<WirePcMapV3>();
pub const RECOVERY_SPAN_RECORD_V3_SIZE: usize = std::mem::size_of::<WireRecoverySpanV3>();
pub const RECOVERY_ACTION_RECORD_V3_SIZE: usize = std::mem::size_of::<WireRecoveryActionV3>();
pub const GUEST_RANGE_RECORD_V3_SIZE: usize = std::mem::size_of::<WireGuestRangeV3>();
pub const BINDING_RECORD_V3_SIZE: usize = std::mem::size_of::<WireBindingV3>();
pub const BINDING_RELOCATION_RECORD_V3_SIZE: usize = std::mem::size_of::<WireBindingRelocationV3>();
pub const EDGE_GROUP_RECORD_V3_SIZE: usize = std::mem::size_of::<WireEdgeGroupV3>();
pub const EDGE_MEMBER_RECORD_V3_SIZE: usize = std::mem::size_of::<WireEdgeMemberV3>();
pub const GUEST_PC_INDEX_RECORD_V3_SIZE: usize = std::mem::size_of::<WireGuestPcIndexV3>();
pub const BLOCK_GUEST_INDEX_RECORD_V3_SIZE: usize = std::mem::size_of::<WireBlockGuestIndexV3>();
pub const BINDING_TARGET_INDEX_RECORD_V3_SIZE: usize =
    std::mem::size_of::<WireBindingTargetIndexV3>();

const _: () = assert!(WIRE_SECTION_SIZE_V3 == 40);
const _: () = assert!(std::mem::size_of::<WireHostFileExecutableV3>() == 40);
const _: () = assert!(std::mem::size_of::<WireDigestExecutableV3>() == 40);
const _: () = assert!(std::mem::size_of::<WireTranslationUnitKeyV3>() == 168);
const _: () = assert!(WIRE_BLOCK_V3_SIZE == 80);
const _: () = assert!(PC_MAP_RECORD_V3_SIZE == 16);
const _: () = assert!(RECOVERY_SPAN_RECORD_V3_SIZE == 16);
const _: () = assert!(RECOVERY_ACTION_RECORD_V3_SIZE == 48);
const _: () = assert!(GUEST_RANGE_RECORD_V3_SIZE == 16);
const _: () = assert!(BINDING_RECORD_V3_SIZE == 40);
const _: () = assert!(BINDING_RELOCATION_RECORD_V3_SIZE == 24);
const _: () = assert!(EDGE_GROUP_RECORD_V3_SIZE == 32);
const _: () = assert!(EDGE_MEMBER_RECORD_V3_SIZE == 8);
const _: () = assert!(GUEST_PC_INDEX_RECORD_V3_SIZE == 8);
const _: () = assert!(BLOCK_GUEST_INDEX_RECORD_V3_SIZE == 8);
const _: () = assert!(BINDING_TARGET_INDEX_RECORD_V3_SIZE == 8);
const _: () = assert!(HEADER_SIZE_V3 == 744);

/// A validated offset into the metadata byte slice.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct MappedMetadataOffset(u64);

impl MappedMetadataOffset {
    const fn from_wire(raw: u64) -> Self {
        Self(raw)
    }

    pub(crate) const fn get(self) -> u64 {
        self.0
    }

    fn checked_end(self, len: MappedMetadataLength) -> Option<u64> {
        self.0.checked_add(len.0)
    }
}

/// A validated byte length in the metadata byte slice.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct MappedMetadataLength(u64);

impl MappedMetadataLength {
    const fn from_wire(raw: u64) -> Self {
        Self(raw)
    }

    pub(crate) const fn get(self) -> u64 {
        self.0
    }
}

/// A validated fixed-record count in a metadata section.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct MappedMetadataRecordCount(u64);

impl MappedMetadataRecordCount {
    const fn from_wire(raw: u64) -> Self {
        Self(raw)
    }

    pub(crate) const fn get(self) -> u64 {
        self.0
    }

    fn checked_byte_len(self, stride: u32) -> Option<MappedMetadataLength> {
        self.0
            .checked_mul(u64::from(stride))
            .map(MappedMetadataLength)
    }
}

/// A checked, copy-only directory view. It deliberately retains no slices so
/// callers can pair it with any byte-backed mapping lifetime in the next layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedLayout {
    sections: [Option<ValidatedSection>; SECTION_DIRECTORY_ENTRIES_V3],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedSection {
    kind: SectionKind,
    offset: MappedMetadataOffset,
    byte_len: MappedMetadataLength,
    count: MappedMetadataRecordCount,
}

impl ValidatedSection {
    #[allow(
        dead_code,
        reason = "Task 3 consumes the section kind through mapped runtime views"
    )]
    pub(crate) const fn kind(self) -> SectionKind {
        self.kind
    }

    pub(crate) const fn offset(self) -> MappedMetadataOffset {
        self.offset
    }

    #[allow(
        dead_code,
        reason = "retained as checked geometry for Task 3 mapping evidence"
    )]
    pub(crate) const fn byte_len(self) -> MappedMetadataLength {
        self.byte_len
    }

    pub(crate) const fn count(self) -> MappedMetadataRecordCount {
        self.count
    }
}

impl ValidatedLayout {
    /// Returns the already-validated semantic geometry for one table kind.
    pub(crate) const fn section(&self, kind: SectionKind) -> Option<ValidatedSection> {
        self.sections[kind.raw() as usize - 1]
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, MappedMetadataError> {
        if bytes.len() < HEADER_SIZE_V3 {
            return Err(MappedMetadataError::HeaderTruncated {
                actual: bytes.len(),
            });
        }
        let header = WireHeaderV3::ref_from_bytes(&bytes[..HEADER_SIZE_V3]).map_err(|_| {
            MappedMetadataError::HeaderTruncated {
                actual: bytes.len(),
            }
        })?;
        if header.magic != MAPPED_METADATA_MAGIC_V3 {
            return Err(MappedMetadataError::Magic);
        }
        if header.schema.get() != MAPPED_METADATA_SCHEMA_V3 {
            return Err(MappedMetadataError::Schema {
                found: header.schema.get(),
            });
        }
        if header.endian_marker.get() != MAPPED_METADATA_ENDIAN_MARKER_V3 {
            return Err(MappedMetadataError::EndianMarker {
                found: header.endian_marker.get(),
            });
        }
        if header.header_size.get() != HEADER_SIZE_V3 as u32 {
            return Err(MappedMetadataError::HeaderSize {
                found: header.header_size.get(),
            });
        }
        if header.reserved.get() != 0 || header.binding_reserved.get() != 0 {
            return Err(MappedMetadataError::HeaderReserved);
        }
        validate_executable_storage(&header.key)?;
        let actual = u64::try_from(bytes.len()).map_err(|_| MappedMetadataError::TotalLength {
            declared: header.total_len.get(),
            actual: u64::MAX,
        })?;
        if header.total_len.get() != actual {
            return Err(MappedMetadataError::TotalLength {
                declared: header.total_len.get(),
                actual,
            });
        }

        let mut sections = [None; SECTION_DIRECTORY_ENTRIES_V3];
        let mut intervals = [(
            SectionKind::Block,
            MappedMetadataOffset::from_wire(0),
            0_u64,
        ); SECTION_DIRECTORY_ENTRIES_V3];
        let mut interval_count = 0;
        for descriptor in &header.sections {
            let raw_kind = descriptor.kind.get();
            if raw_kind == 0 {
                if descriptor.stride.get() != 0
                    || descriptor.offset.get() != 0
                    || descriptor.byte_len.get() != 0
                    || descriptor.count.get() != 0
                    || descriptor.reserved.get() != 0
                {
                    return Err(MappedMetadataError::SectionKind { raw: 0 });
                }
                continue;
            }
            let Some(kind) = SectionKind::from_raw(raw_kind) else {
                return Err(MappedMetadataError::SectionKind { raw: raw_kind });
            };
            if descriptor.reserved.get() != 0 {
                return Err(MappedMetadataError::SectionReserved { kind });
            }
            let expected_stride = kind.record_stride();
            if descriptor.stride.get() != expected_stride {
                return Err(MappedMetadataError::SectionStride {
                    kind,
                    expected: expected_stride,
                    actual: descriptor.stride.get(),
                });
            }
            let offset = MappedMetadataOffset::from_wire(descriptor.offset.get());
            let byte_len = MappedMetadataLength::from_wire(descriptor.byte_len.get());
            let count = MappedMetadataRecordCount::from_wire(descriptor.count.get());
            let expected_len = count
                .checked_byte_len(expected_stride)
                .ok_or(MappedMetadataError::SectionRangeOverflow { kind })?;
            if byte_len != expected_len {
                return Err(MappedMetadataError::SectionLength {
                    kind,
                    expected: expected_len.get(),
                    actual: byte_len.get(),
                });
            }
            if !offset.get().is_multiple_of(SECTION_ALIGNMENT_V3) {
                return Err(MappedMetadataError::SectionAlignment {
                    kind,
                    offset: offset.get(),
                });
            }
            let end = offset
                .checked_end(byte_len)
                .ok_or(MappedMetadataError::SectionRangeOverflow { kind })?;
            if offset.get() < HEADER_SIZE_V3 as u64 {
                return Err(MappedMetadataError::SectionBounds {
                    kind,
                    end,
                    total: HEADER_SIZE_V3 as u64,
                });
            }
            if end > actual {
                return Err(MappedMetadataError::SectionBounds {
                    kind,
                    end,
                    total: actual,
                });
            }
            let kind_index = kind.raw() as usize - 1;
            if sections[kind_index].is_some() {
                return Err(MappedMetadataError::DuplicateSection { kind });
            }
            sections[kind_index] = Some(ValidatedSection {
                kind,
                offset,
                byte_len,
                count,
            });
            if byte_len.get() != 0 {
                intervals[interval_count] = (kind, offset, end);
                interval_count += 1;
            }
        }

        intervals[..interval_count]
            .sort_unstable_by_key(|(kind, start, _)| (start.get(), kind.raw()));
        for pair in intervals[..interval_count].windows(2) {
            let (left_kind, _left_start, left_end) = pair[0];
            let (right_kind, right_start, _right_end) = pair[1];
            if left_end > right_start.get() {
                return Err(MappedMetadataError::SectionOverlap {
                    left: left_kind,
                    right: right_kind,
                });
            }
        }
        Ok(Self { sections })
    }
}

fn validate_executable_storage(key: &WireTranslationUnitKeyV3) -> Result<(), MappedMetadataError> {
    let executable_kind = key.executable_kind.get();
    match executable_kind {
        WIRE_EXECUTABLE_HOST_FILE_V3 if key.digest.as_bytes().iter().all(|byte| *byte == 0) => {
            Ok(())
        }
        WIRE_EXECUTABLE_DIGEST_V3
            if key.host_file.as_bytes().iter().all(|byte| *byte == 0)
                && key.digest.reserved.iter().all(|byte| *byte == 0) =>
        {
            Ok(())
        }
        WIRE_EXECUTABLE_HOST_FILE_V3 | WIRE_EXECUTABLE_DIGEST_V3 => {
            Err(MappedMetadataError::ExecutableUnusedStorage { executable_kind })
        }
        raw => Err(MappedMetadataError::ExecutableKind { raw }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER_TOTAL_LEN_OFFSET: usize = 24;
    const KEY_OFFSET: usize = std::mem::offset_of!(WireHeaderV3, key);
    const KEY_EXECUTABLE_KIND_OFFSET: usize =
        KEY_OFFSET + std::mem::offset_of!(WireTranslationUnitKeyV3, executable_kind);
    const KEY_DIGEST_OFFSET: usize =
        KEY_OFFSET + std::mem::offset_of!(WireTranslationUnitKeyV3, digest);
    const HEADER_SECTION_OFFSET: usize = std::mem::offset_of!(WireHeaderV3, sections);
    const SECTION_KIND_OFFSET: usize = 0;
    const SECTION_STRIDE_OFFSET: usize = 4;
    const SECTION_OFFSET_OFFSET: usize = 8;
    const SECTION_BYTE_LEN_OFFSET: usize = 16;
    const SECTION_COUNT_OFFSET: usize = 24;
    const SECTION_RESERVED_OFFSET: usize = 32;

    #[derive(Clone, Copy)]
    struct SectionDescriptorValues {
        offset: u64,
        byte_len: u64,
        count: u64,
        stride: u32,
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn minimal_layout_fixture() -> Vec<u8> {
        let mut bytes = vec![0; HEADER_SIZE_V3];
        bytes[..8].copy_from_slice(&MAPPED_METADATA_MAGIC_V3);
        put_u32(&mut bytes, 8, MAPPED_METADATA_SCHEMA_V3);
        put_u32(&mut bytes, 12, MAPPED_METADATA_ENDIAN_MARKER_V3);
        put_u32(&mut bytes, 16, HEADER_SIZE_V3 as u32);
        put_u64(&mut bytes, HEADER_TOTAL_LEN_OFFSET, HEADER_SIZE_V3 as u64);
        put_u32(
            &mut bytes,
            KEY_EXECUTABLE_KIND_OFFSET,
            WIRE_EXECUTABLE_DIGEST_V3,
        );
        bytes[KEY_DIGEST_OFFSET] = 1;
        bytes
    }

    fn add_section(bytes: &mut Vec<u8>, kind: SectionKind, values: SectionDescriptorValues) {
        let descriptor_index = (0..SECTION_DIRECTORY_ENTRIES_V3)
            .find(|index| bytes[HEADER_SECTION_OFFSET + index * WIRE_SECTION_SIZE_V3] == 0)
            .expect("available descriptor");
        let descriptor = HEADER_SECTION_OFFSET + descriptor_index * WIRE_SECTION_SIZE_V3;
        let end = values
            .offset
            .checked_add(values.byte_len)
            .expect("test section end");
        if end > bytes.len() as u64 {
            bytes.resize(end as usize, 0);
        }
        put_u32(bytes, descriptor + SECTION_KIND_OFFSET, kind.raw());
        put_u32(bytes, descriptor + SECTION_STRIDE_OFFSET, values.stride);
        put_u64(bytes, descriptor + SECTION_OFFSET_OFFSET, values.offset);
        put_u64(bytes, descriptor + SECTION_BYTE_LEN_OFFSET, values.byte_len);
        put_u64(bytes, descriptor + SECTION_COUNT_OFFSET, values.count);
        put_u64(bytes, descriptor + SECTION_RESERVED_OFFSET, 0);
        let total_len = bytes.len() as u64;
        put_u64(bytes, HEADER_TOTAL_LEN_OFFSET, total_len);
    }

    fn section(
        kind: SectionKind,
        offset: u64,
        byte_len: u64,
        count: u64,
    ) -> SectionDescriptorValues {
        SectionDescriptorValues {
            offset,
            byte_len,
            count,
            stride: kind.record_stride(),
        }
    }

    #[test]
    fn v3_layout_rejects_each_structural_corruption_with_a_typed_error() {
        struct Case {
            name: &'static str,
            corrupt: fn(&mut Vec<u8>),
            expected: MappedMetadataError,
        }

        let cases = [
            Case {
                name: "total length",
                corrupt: |bytes| put_u64(bytes, HEADER_TOTAL_LEN_OFFSET, 1),
                expected: MappedMetadataError::TotalLength {
                    declared: 1,
                    actual: HEADER_SIZE_V3 as u64,
                },
            },
            Case {
                name: "section offset overflow",
                corrupt: |bytes| {
                    let descriptor = HEADER_SECTION_OFFSET;
                    put_u32(
                        bytes,
                        descriptor + SECTION_KIND_OFFSET,
                        SectionKind::PcMap.raw(),
                    );
                    put_u32(
                        bytes,
                        descriptor + SECTION_STRIDE_OFFSET,
                        SectionKind::PcMap.record_stride(),
                    );
                    put_u64(bytes, descriptor + SECTION_OFFSET_OFFSET, u64::MAX - 7);
                    put_u64(bytes, descriptor + SECTION_BYTE_LEN_OFFSET, 16);
                    put_u64(bytes, descriptor + SECTION_COUNT_OFFSET, 1);
                },
                expected: MappedMetadataError::SectionRangeOverflow {
                    kind: SectionKind::PcMap,
                },
            },
            Case {
                name: "overlap",
                corrupt: |bytes| {
                    add_section(
                        bytes,
                        SectionKind::PcMap,
                        section(SectionKind::PcMap, HEADER_SIZE_V3 as u64, 16, 1),
                    );
                    add_section(
                        bytes,
                        SectionKind::RecoverySpan,
                        section(SectionKind::RecoverySpan, HEADER_SIZE_V3 as u64 + 8, 16, 1),
                    );
                },
                expected: MappedMetadataError::SectionOverlap {
                    left: SectionKind::PcMap,
                    right: SectionKind::RecoverySpan,
                },
            },
            Case {
                name: "stride",
                corrupt: |bytes| {
                    add_section(
                        bytes,
                        SectionKind::PcMap,
                        SectionDescriptorValues {
                            offset: HEADER_SIZE_V3 as u64,
                            byte_len: 16,
                            count: 1,
                            stride: 8,
                        },
                    )
                },
                expected: MappedMetadataError::SectionStride {
                    kind: SectionKind::PcMap,
                    expected: SectionKind::PcMap.record_stride(),
                    actual: 8,
                },
            },
            Case {
                name: "alignment",
                corrupt: |bytes| {
                    add_section(
                        bytes,
                        SectionKind::PcMap,
                        section(SectionKind::PcMap, HEADER_SIZE_V3 as u64 + 1, 16, 1),
                    )
                },
                expected: MappedMetadataError::SectionAlignment {
                    kind: SectionKind::PcMap,
                    offset: HEADER_SIZE_V3 as u64 + 1,
                },
            },
            Case {
                name: "section covers header",
                corrupt: |bytes| {
                    add_section(
                        bytes,
                        SectionKind::PcMap,
                        section(SectionKind::PcMap, 0, 16, 1),
                    )
                },
                expected: MappedMetadataError::SectionBounds {
                    kind: SectionKind::PcMap,
                    end: 16,
                    total: HEADER_SIZE_V3 as u64,
                },
            },
            Case {
                name: "reserved bytes",
                corrupt: |bytes| {
                    add_section(
                        bytes,
                        SectionKind::PcMap,
                        section(SectionKind::PcMap, HEADER_SIZE_V3 as u64, 16, 1),
                    );
                    put_u64(bytes, HEADER_SECTION_OFFSET + SECTION_RESERVED_OFFSET, 1);
                },
                expected: MappedMetadataError::SectionReserved {
                    kind: SectionKind::PcMap,
                },
            },
            Case {
                name: "schema",
                corrupt: |bytes| put_u32(bytes, 8, MAPPED_METADATA_SCHEMA_V3 + 1),
                expected: MappedMetadataError::Schema {
                    found: MAPPED_METADATA_SCHEMA_V3 + 1,
                },
            },
            Case {
                name: "endian marker",
                corrupt: |bytes| put_u32(bytes, 12, 0),
                expected: MappedMetadataError::EndianMarker { found: 0 },
            },
            Case {
                name: "duplicate section kind",
                corrupt: |bytes| {
                    add_section(
                        bytes,
                        SectionKind::PcMap,
                        section(SectionKind::PcMap, HEADER_SIZE_V3 as u64, 16, 1),
                    );
                    add_section(
                        bytes,
                        SectionKind::PcMap,
                        section(SectionKind::PcMap, HEADER_SIZE_V3 as u64 + 16, 16, 1),
                    );
                },
                expected: MappedMetadataError::DuplicateSection {
                    kind: SectionKind::PcMap,
                },
            },
        ];

        for case in cases {
            let mut bytes = minimal_layout_fixture();
            (case.corrupt)(&mut bytes);
            assert_eq!(
                ValidatedLayout::parse(&bytes),
                Err(case.expected),
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn v3_layout_rejects_nonzero_unused_executable_variant_storage() {
        let mut bytes = minimal_layout_fixture();
        put_u32(&mut bytes, KEY_EXECUTABLE_KIND_OFFSET, 1);
        bytes[KEY_DIGEST_OFFSET] = 1;

        assert_eq!(
            ValidatedLayout::parse(&bytes),
            Err(MappedMetadataError::ExecutableUnusedStorage {
                executable_kind: WIRE_EXECUTABLE_HOST_FILE_V3,
            })
        );
    }

    #[test]
    fn v3_layout_allows_empty_sections_at_a_nonempty_section_start() {
        let mut bytes = minimal_layout_fixture();
        add_section(
            &mut bytes,
            SectionKind::RecoverySpan,
            section(
                SectionKind::RecoverySpan,
                HEADER_SIZE_V3 as u64,
                RECOVERY_SPAN_RECORD_V3_SIZE as u64,
                1,
            ),
        );
        add_section(
            &mut bytes,
            SectionKind::PcMap,
            section(SectionKind::PcMap, HEADER_SIZE_V3 as u64, 0, 0),
        );

        assert!(ValidatedLayout::parse(&bytes).is_ok());
    }

    #[test]
    fn v3_layout_exposes_checked_typed_section_geometry() {
        let mut bytes = minimal_layout_fixture();
        add_section(
            &mut bytes,
            SectionKind::PcMap,
            section(
                SectionKind::PcMap,
                HEADER_SIZE_V3 as u64,
                PC_MAP_RECORD_V3_SIZE as u64,
                1,
            ),
        );

        let layout = ValidatedLayout::parse(&bytes).expect("valid layout");
        let section = layout.section(SectionKind::PcMap).expect("PC-map section");
        assert_eq!(section.kind(), SectionKind::PcMap);
        assert_eq!(section.offset().get(), HEADER_SIZE_V3 as u64);
        assert_eq!(section.byte_len().get(), PC_MAP_RECORD_V3_SIZE as u64);
        assert_eq!(section.count().get(), 1);
    }

    #[test]
    fn every_portable_recovery_variant_round_trips_through_v3() {
        let x15 = DsrScratchGpr::new(15).expect("x15 scratch");
        let x16 = DsrScratchGpr::new(16).expect("x16 scratch");
        let actions = [
            PortableRecoveryAction::Noop,
            PortableRecoveryAction::RestoreGuestX17,
            PortableRecoveryAction::RestoreGenerationGuardRegisters,
            PortableRecoveryAction::RestoreGenerationGuard,
            PortableRecoveryAction::RestoreIndirectRegisters,
            PortableRecoveryAction::RestoreIndirectResolver,
            PortableRecoveryAction::RestoreIndirectLean,
            PortableRecoveryAction::RestoreIndirectLeanCall,
            PortableRecoveryAction::RestoreScratch { register: 15 },
            PortableRecoveryAction::RestoreScratchInvalidBiasedLiteral { register: 16 },
            PortableRecoveryAction::RestoreScratchCompleted { register: 17 },
            PortableRecoveryAction::CommitVirtualizedAndRestoreScratch {
                register: 15,
                virtual_register: 18,
            },
            PortableRecoveryAction::RestoreScratchAndContext {
                register: 16,
                context_register: 17,
            },
            PortableRecoveryAction::RestoreScratchAndContextCompleted {
                register: 17,
                context_register: 18,
            },
            PortableRecoveryAction::CommitVirtualizedAndRestoreScratchAndContext {
                register: 15,
                context_register: 16,
                virtual_register: 28,
            },
            PortableRecoveryAction::RestoreDualVirtualReadOnly {
                x18_scratch: 15,
                x28_scratch: 16,
                context_scratch: 17,
            },
            PortableRecoveryAction::RestoreDualVirtualReadOnlyCompleted {
                x18_scratch: 16,
                x28_scratch: 17,
                context_scratch: 18,
            },
            PortableRecoveryAction::CommitDualVirtualAndRestore {
                x18_scratch: 15,
                x28_scratch: 16,
                context_scratch: 17,
                virtual_register: 18,
                virtual_scratch: 28,
            },
            PortableRecoveryAction::CommitDualVirtualPairAndRestore {
                x18_scratch: 15,
                x28_scratch: 16,
                context_scratch: 17,
                first_register: 18,
                second_register: 28,
            },
            PortableRecoveryAction::RecoverCounterRead(CounterReadRecovery {
                committed_scratch_destination: Some(CounterScratchDestination::X16),
                instruction_complete: true,
            }),
            PortableRecoveryAction::RecoverBiasedMemory(PortableBiasedMemoryRecovery {
                scratch_registers: [15, 16, 17, 28],
                scratch_count: 4,
                base_scratch: 14,
                base: BiasedBase::Register(13),
                base_coordinate: BiasedBaseCoordinate::Guest,
                commit_base: true,
                virtual_x18_scratch: Some(12),
                virtual_x28_scratch: Some(11),
                virtual_reserved_scratch: Some(10),
                instruction_complete: true,
            }),
            PortableRecoveryAction::RecoverBiasedExclusive(BiasedExclusiveRecovery {
                scratch: BiasedExclusiveScratch {
                    address: x15,
                    bias: x16,
                },
                resume: BiasedExclusiveResume::Retry,
            }),
            PortableRecoveryAction::RestoreDirectBinding {
                phase: DirectBindingRecoveryPhase::AuthorityInstall,
                capture_progress: DirectBindingCaptureProgress::Complete,
                committed_link: Some(0x1234),
            },
        ];

        for action in actions {
            let wire = WireRecoveryActionV3::from_portable(action).expect("encode action");
            assert_eq!(wire.into_portable().expect("decode action"), action);
        }
    }

    #[test]
    fn v3_recovery_encoding_rejects_an_invalid_gpr() {
        assert!(
            WireRecoveryActionV3::from_portable(PortableRecoveryAction::RestoreScratch {
                register: 31,
            })
            .is_err()
        );
    }
}
