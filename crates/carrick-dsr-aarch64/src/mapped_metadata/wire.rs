#![allow(dead_code)] // Task 2 consumes the typed layout view and raw records.

//! V3's fixed-width, little-endian byte contract and allocation-free layout check.

use zerocopy::byteorder::{I64, LittleEndian, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub const MAPPED_METADATA_SCHEMA_V3: u32 = 3;
pub const MAPPED_METADATA_MAGIC_V3: [u8; 8] = *b"CRKMDV3\0";
pub const MAPPED_METADATA_ENDIAN_MARKER_V3: u32 = 0x0102_0304;
const SECTION_ALIGNMENT_V3: u64 = 8;
const SECTION_DIRECTORY_ENTRIES_V3: usize = 9;
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
            _ => None,
        }
    }
}

/// Structural failures that make a mapped V3 file ineligible for use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MappedMetadataError {
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
    pub dylib_sha256: [u8; 32],
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
    pub reserved: U32<LittleEndian>,
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
const _: () = assert!(HEADER_SIZE_V3 == 624);

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
    pub(crate) const fn kind(self) -> SectionKind {
        self.kind
    }

    pub(crate) const fn offset(self) -> MappedMetadataOffset {
        self.offset
    }

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
}
