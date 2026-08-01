//! Fixed, little-endian metadata records for mapped AArch64 translation units.
//!
//! This module deliberately owns only the byte-level V3 contract and its
//! structural validation. Mapping, publication, and translation-state use are
//! separate Darwin-native concerns.

mod builder;
mod view;
pub(crate) mod wire;

pub use builder::encode_translation_metadata_v3;
pub use view::{
    MappedBindingView, MappedBlockView, MappedEdgeGroupView, MappedPcMapView, MappedRecoveryView,
    MetadataBacking, ValidatedMappedTranslationMetadata, VecMetadataBacking,
};

pub use wire::{
    BINDING_RECORD_V3_SIZE, BINDING_RELOCATION_RECORD_V3_SIZE, EDGE_GROUP_RECORD_V3_SIZE,
    EDGE_MEMBER_RECORD_V3_SIZE, GUEST_RANGE_RECORD_V3_SIZE, HEADER_SIZE_V3,
    MAPPED_METADATA_ENDIAN_MARKER_V3, MAPPED_METADATA_MAGIC_V3, MAPPED_METADATA_SCHEMA_V3,
    MappedMetadataError, PC_MAP_RECORD_V3_SIZE, RECOVERY_ACTION_RECORD_V3_SIZE,
    RECOVERY_SPAN_RECORD_V3_SIZE, SectionKind, ValidatedLayout, WIRE_SECTION_SIZE_V3,
};
