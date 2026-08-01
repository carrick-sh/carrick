//! Container-lifetime authority for portable native AArch64 translations.

use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use carrick_dsr_aarch64::direct_binding::{DirectBindingCellRef, DirectBindingCellVa};
use carrick_dsr_aarch64::mapped_metadata::{
    MappedMetadataError, MetadataBacking, ValidatedMappedTranslationMetadata,
    encode_translation_metadata_v3,
};
pub use carrick_dsr_aarch64::shared_cache::PublishOutcome;
use carrick_dsr_aarch64::shared_cache::{
    LoadedTranslationMetadata, LoadedTranslationProtection, MAX_TRANSLATION_UNIT_CODE_BYTES,
    PendingTranslationUnit, SourceFingerprint, TRANSLATION_UNIT_BINDING_EXPORT,
    TRANSLATION_UNIT_SCHEMA_V2, TranslationMetadataLoadEvidence, TranslationMetadataMode,
    TranslationUnitKey, TranslationUnitManifest, UnitMissReason, pin_loaded_translation_protection,
    shared_source_fingerprint_reuse_enabled, translation_unit_base_export,
};
use sha2::{Digest, Sha256};

const AUTHORITY_MARKER: &str = ".carrick-authority";
const AUTHORITY_NONCE_LEN: usize = 16;
const MANIFEST_DECODE_LIMIT: usize = 256 * 1024 * 1024;
const MAX_MAPPED_METADATA_BYTES: u64 = MANIFEST_DECODE_LIMIT as u64;
const AOT_SEGMENT_PAGE_SIZE: u64 = 16 * 1024;

static CONTAINER_CACHE: Mutex<Option<ContainerCacheAuthority>> = Mutex::new(None);
static FIXED_WIDTH_MANIFEST_ENABLED: OnceLock<bool> = OnceLock::new();
static KEYED_DYLIB_IDENTITY_ENABLED: OnceLock<bool> = OnceLock::new();
static MAPPED_METADATA_ENABLED: OnceLock<bool> = OnceLock::new();

#[derive(Debug)]
pub struct UnitStoreError {
    operation: &'static str,
    reason: UnitMissReason,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl UnitStoreError {
    fn new(operation: &'static str, reason: UnitMissReason) -> Self {
        Self {
            operation,
            reason,
            source: None,
        }
    }

    fn with_source(
        operation: &'static str,
        reason: UnitMissReason,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            operation,
            reason,
            source: Some(Box::new(source)),
        }
    }

    pub const fn reason(&self) -> UnitMissReason {
        self.reason
    }
}

impl std::fmt::Display for UnitStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}: translation unit miss ({:?})",
            self.operation, self.reason
        )?;
        if let Some(source) = &self.source {
            write!(formatter, ": {source}")?;
        }
        Ok(())
    }
}

impl std::error::Error for UnitStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

#[derive(Debug)]
pub struct LoadedTranslationUnit {
    pub metadata: LoadedTranslationMetadata,
    pub base: std::ptr::NonNull<u8>,
    pub binding_base: Option<DirectBindingCellVa>,
    pub load_evidence: TranslationMetadataLoadEvidence,
    lease: Arc<LoadedTranslationLease>,
}

impl LoadedTranslationUnit {
    fn into_shared(self) -> carrick_dsr_aarch64::shared_cache::SharedLoadedTranslationUnit {
        let base = self.base.as_ptr() as usize;
        match self.metadata {
            LoadedTranslationMetadata::V2(manifest) => {
                let mut unit = carrick_dsr_aarch64::shared_cache::SharedLoadedTranslationUnit::new_with_binding_base(
                    manifest,
                    base,
                    self.binding_base,
                    self.lease,
                );
                unit.load_evidence = self.load_evidence;
                unit
            }
            LoadedTranslationMetadata::V3(metadata) => {
                carrick_dsr_aarch64::shared_cache::SharedLoadedTranslationUnit::new_mapped_with_binding_base(
                    metadata,
                    base,
                    self.binding_base,
                    self.load_evidence,
                    self.lease,
                )
            }
        }
    }
}

#[derive(Debug)]
struct ReadOnlyMetadataMapping {
    mapping: memmap2::Mmap,
    _file: File,
}

impl MetadataBacking for ReadOnlyMetadataMapping {
    fn bytes(&self) -> &[u8] {
        self.mapping.as_ref()
    }
}

#[allow(
    clippy::large_enum_variant,
    reason = "V2 retains the established decoded-manifest path and delays its sole Arc allocation until load succeeds"
)]
enum ValidatedUnitMetadata {
    V2(TranslationUnitManifest),
    V3(Arc<ValidatedMappedTranslationMetadata>),
}

impl ValidatedUnitMetadata {
    fn code_len(&self) -> u64 {
        match self {
            Self::V2(manifest) => manifest.code_len,
            Self::V3(metadata) => metadata.code_len(),
        }
    }

    fn binding_data_len(&self) -> u64 {
        match self {
            Self::V2(manifest) => manifest.binding_data_len,
            Self::V3(metadata) => metadata.binding_data_len(),
        }
    }

    fn binding_count(&self) -> usize {
        match self {
            Self::V2(manifest) => manifest.bindings.len(),
            Self::V3(metadata) => metadata.binding_count(),
        }
    }

    fn into_loaded(self) -> LoadedTranslationMetadata {
        match self {
            Self::V2(manifest) => LoadedTranslationMetadata::V2(Arc::new(manifest)),
            Self::V3(metadata) => LoadedTranslationMetadata::V3(metadata),
        }
    }
}

#[derive(Debug)]
struct LoadedTranslationLease {
    handle: std::ptr::NonNull<libc::c_void>,
}

// SAFETY: dyld owns the immutable code mapping for `handle`; writable data is
// reachable only through `DirectBindingCellRef` atomics. The manifest is
// immutable, and Drop is the sole `dlclose` after the final lease releases the
// loaded unit.
unsafe impl Send for LoadedTranslationUnit {}
// SAFETY: see `Send`; code is immutable and binding data is reachable only
// through `DirectBindingCellRef` atomics.
unsafe impl Sync for LoadedTranslationUnit {}

// SAFETY: dyld owns the handle's immutable mappings; the handle is only
// released when the final `Arc` drops.
unsafe impl Send for LoadedTranslationLease {}
// SAFETY: see `Send`; no mutation is exposed through this lifetime token.
unsafe impl Sync for LoadedTranslationLease {}

impl Drop for LoadedTranslationLease {
    fn drop(&mut self) {
        let _ = unsafe { libc::dlclose(self.handle.as_ptr()) };
    }
}

struct UnitFileLock(File);

impl Drop for UnitFileLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn fixed_width_manifest_enabled_from(value: Option<&std::ffi::OsStr>) -> bool {
    value != Some(std::ffi::OsStr::new("0"))
}

fn fixed_width_manifest_enabled() -> bool {
    *FIXED_WIDTH_MANIFEST_ENABLED.get_or_init(|| {
        let value = std::env::var_os("CARRICK_DSR_SHARED_MANIFEST_FIXED");
        fixed_width_manifest_enabled_from(value.as_deref())
    })
}

fn keyed_dylib_identity_enabled_from(value: Option<&std::ffi::OsStr>) -> bool {
    value != Some(std::ffi::OsStr::new("0"))
}

fn keyed_dylib_identity_enabled() -> bool {
    *KEYED_DYLIB_IDENTITY_ENABLED.get_or_init(|| {
        let value = std::env::var_os("CARRICK_DSR_SHARED_DYLIB_KEYED_IDENTITY");
        keyed_dylib_identity_enabled_from(value.as_deref())
    })
}

fn mapped_metadata_enabled_from(value: Option<&std::ffi::OsStr>) -> bool {
    value != Some(std::ffi::OsStr::new("0"))
}

fn mapped_metadata_enabled() -> bool {
    *MAPPED_METADATA_ENABLED.get_or_init(|| {
        let value = std::env::var_os("CARRICK_DSR_SHARED_MAPPED_METADATA");
        mapped_metadata_enabled_from(value.as_deref())
    })
}

fn encode_manifest_with_fixed_width(
    manifest: &TranslationUnitManifest,
    fixed_width: bool,
) -> Result<Vec<u8>, std::io::Error> {
    if fixed_width {
        bincode::serde::encode_to_vec(
            manifest,
            bincode::config::standard()
                .with_fixed_int_encoding()
                .with_limit::<MANIFEST_DECODE_LIMIT>(),
        )
    } else {
        bincode::serde::encode_to_vec(
            manifest,
            bincode::config::standard().with_limit::<MANIFEST_DECODE_LIMIT>(),
        )
    }
    .map_err(|error| invalid_data(format!("encode translation unit manifest: {error}")))
}

fn encode_manifest(manifest: &TranslationUnitManifest) -> Result<Vec<u8>, std::io::Error> {
    encode_manifest_with_fixed_width(manifest, fixed_width_manifest_enabled())
}

fn decode_manifest_with_fixed_width(
    bytes: &[u8],
    fixed_width: bool,
) -> Result<TranslationUnitManifest, std::io::Error> {
    let decoded = if fixed_width {
        bincode::serde::decode_from_slice(
            bytes,
            bincode::config::standard()
                .with_fixed_int_encoding()
                .with_limit::<MANIFEST_DECODE_LIMIT>(),
        )
    } else {
        bincode::serde::decode_from_slice(
            bytes,
            bincode::config::standard().with_limit::<MANIFEST_DECODE_LIMIT>(),
        )
    };
    let (manifest, consumed) = decoded
        .map_err(|error| invalid_data(format!("decode translation unit manifest: {error}")))?;
    if consumed != bytes.len() {
        return Err(invalid_data(format!(
            "translation unit manifest has {} trailing bytes",
            bytes.len().saturating_sub(consumed),
        )));
    }
    Ok(manifest)
}

fn decode_manifest(bytes: &[u8]) -> Result<TranslationUnitManifest, std::io::Error> {
    decode_manifest_with_fixed_width(bytes, fixed_width_manifest_enabled())
}

fn mapped_metadata_miss_reason(error: &MappedMetadataError) -> UnitMissReason {
    match error {
        MappedMetadataError::Key => UnitMissReason::ImageIdentity,
        MappedMetadataError::Magic
        | MappedMetadataError::Schema { .. }
        | MappedMetadataError::EndianMarker { .. }
        | MappedMetadataError::HeaderSize { .. }
        | MappedMetadataError::HeaderReserved
        | MappedMetadataError::ExecutableKind { .. }
        | MappedMetadataError::ExecutableUnusedStorage { .. }
        | MappedMetadataError::HeaderTruncated { .. }
        | MappedMetadataError::TotalLength { .. }
        | MappedMetadataError::SectionKind { .. }
        | MappedMetadataError::SectionReserved { .. }
        | MappedMetadataError::SectionStride { .. }
        | MappedMetadataError::MissingSection { .. } => UnitMissReason::Schema,
        MappedMetadataError::OwnedManifest
        | MappedMetadataError::Arithmetic
        | MappedMetadataError::Block
        | MappedMetadataError::PcMap
        | MappedMetadataError::RecoverySpan
        | MappedMetadataError::RecoveryAction
        | MappedMetadataError::GuestRange
        | MappedMetadataError::Binding
        | MappedMetadataError::BindingRelocation
        | MappedMetadataError::EdgeGroup
        | MappedMetadataError::EdgeBackReference
        | MappedMetadataError::SectionLength { .. }
        | MappedMetadataError::SectionRangeOverflow { .. }
        | MappedMetadataError::SectionBounds { .. }
        | MappedMetadataError::SectionAlignment { .. }
        | MappedMetadataError::DuplicateSection { .. }
        | MappedMetadataError::SectionOverlap { .. } => UnitMissReason::ManifestRange,
    }
}

fn mapped_metadata_error(operation: &'static str, error: MappedMetadataError) -> UnitStoreError {
    UnitStoreError::with_source(
        operation,
        mapped_metadata_miss_reason(&error),
        invalid_data(format!("{error:?}")),
    )
}

fn open_metadata_at(directory: &File, name: &CStr) -> Result<File, UnitStoreError> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        let reason = if error.raw_os_error() == Some(libc::ENOENT) {
            UnitMissReason::MissingPair
        } else {
            UnitMissReason::Schema
        };
        return Err(UnitStoreError::with_source(
            "open mapped metadata",
            reason,
            error,
        ));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(file.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(UnitStoreError::with_source(
            "stat mapped metadata",
            UnitMissReason::Schema,
            std::io::Error::last_os_error(),
        ));
    }
    let status = unsafe { status.assume_init() };
    if status.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(UnitStoreError::new(
            "validate mapped metadata file type",
            UnitMissReason::Schema,
        ));
    }
    let length = u64::try_from(status.st_size).map_err(|_| {
        UnitStoreError::new(
            "validate mapped metadata size",
            UnitMissReason::ManifestRange,
        )
    })?;
    if length == 0 || length > MAX_MAPPED_METADATA_BYTES {
        return Err(UnitStoreError::new(
            "validate mapped metadata size",
            UnitMissReason::ManifestRange,
        ));
    }
    Ok(file)
}

fn mapped_immutable_record_count(
    metadata: &ValidatedMappedTranslationMetadata,
) -> Result<u64, UnitStoreError> {
    let mut records = u64::try_from(metadata.binding_count()).map_err(|_| {
        UnitStoreError::new(
            "count mapped metadata records",
            UnitMissReason::ManifestRange,
        )
    })?;
    for index in 0..metadata.block_count() {
        let block = metadata.block(index).ok_or_else(|| {
            UnitStoreError::new(
                "count mapped metadata records",
                UnitMissReason::ManifestRange,
            )
        })?;
        let block_records = 1_u64
            .checked_add(u64::try_from(block.pc_map().len()).map_err(|_| {
                UnitStoreError::new(
                    "count mapped metadata records",
                    UnitMissReason::ManifestRange,
                )
            })?)
            .and_then(|count| {
                u64::try_from(block.recovery().span_count())
                    .ok()
                    .and_then(|spans| count.checked_add(spans))
            })
            .ok_or_else(|| {
                UnitStoreError::new(
                    "count mapped metadata records",
                    UnitMissReason::ManifestRange,
                )
            })?;
        records = records.checked_add(block_records).ok_or_else(|| {
            UnitStoreError::new(
                "count mapped metadata records",
                UnitMissReason::ManifestRange,
            )
        })?;
    }
    Ok(records)
}

fn owned_immutable_record_count(manifest: &TranslationUnitManifest) -> Result<u64, UnitStoreError> {
    let mut records = u64::try_from(manifest.bindings.len()).map_err(|_| {
        UnitStoreError::new(
            "count owned metadata records",
            UnitMissReason::ManifestRange,
        )
    })?;
    for block in &manifest.blocks {
        let counts = block.template.metadata_counts();
        let recovery_records = if counts.recovery_runs == 0 {
            counts.recovery_entries
        } else {
            counts.recovery_runs
        };
        let block_records = 1_usize
            .checked_add(counts.pc_map_entries)
            .and_then(|count| count.checked_add(recovery_records))
            .and_then(|count| u64::try_from(count).ok())
            .ok_or_else(|| {
                UnitStoreError::new(
                    "count owned metadata records",
                    UnitMissReason::ManifestRange,
                )
            })?;
        records = records.checked_add(block_records).ok_or_else(|| {
            UnitStoreError::new(
                "count owned metadata records",
                UnitMissReason::ManifestRange,
            )
        })?;
    }
    Ok(records)
}

fn map_and_validate_metadata(
    directory: &File,
    name: &CStr,
    expected_key: &TranslationUnitKey,
) -> Result<
    (
        Arc<ValidatedMappedTranslationMetadata>,
        TranslationMetadataLoadEvidence,
    ),
    UnitStoreError,
> {
    let file = open_metadata_at(directory, name)?;
    let length = usize::try_from(
        file.metadata()
            .map_err(|error| {
                UnitStoreError::with_source("stat mapped metadata", UnitMissReason::Schema, error)
            })?
            .len(),
    )
    .map_err(|_| {
        UnitStoreError::new(
            "validate mapped metadata size",
            UnitMissReason::ManifestRange,
        )
    })?;
    let mapping =
        unsafe { memmap2::MmapOptions::new().len(length).map(&file) }.map_err(|error| {
            UnitStoreError::with_source("map translation metadata", UnitMissReason::Schema, error)
        })?;
    let backing: Arc<dyn MetadataBacking> = Arc::new(ReadOnlyMetadataMapping {
        mapping,
        _file: file,
    });
    let validation_started = std::time::Instant::now();
    let metadata = ValidatedMappedTranslationMetadata::new(backing, expected_key)
        .map_err(|error| mapped_metadata_error("validate mapped metadata", error))?;
    let validation_ns = u64::try_from(validation_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let mapped_records = mapped_immutable_record_count(&metadata)?;
    let bytes_mapped = u64::try_from(length).map_err(|_| {
        UnitStoreError::new("measure mapped metadata", UnitMissReason::ManifestRange)
    })?;
    Ok((
        Arc::new(metadata),
        TranslationMetadataLoadEvidence {
            mode: TranslationMetadataMode::V3,
            bytes_read: 0,
            bytes_mapped,
            validation_ns,
            mapped_records,
            owned_records: 0,
        },
    ))
}

#[derive(Clone, Copy)]
struct MachOSectionRange {
    address: u64,
    size: u64,
    segment_address: u64,
    segment_size: u64,
    init_protection: i32,
    max_protection: i32,
}

struct MachOTranslationRanges {
    image_vmaddr: u64,
    text: MachOSectionRange,
    data: Option<MachOSectionRange>,
}

fn read_macho_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn read_macho_i32(bytes: &[u8], offset: usize) -> Option<i32> {
    read_macho_u32(bytes, offset).map(|value| value as i32)
}

fn read_macho_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}

fn macho_name_matches(raw: &[u8], expected: &[u8]) -> bool {
    raw.get(..expected.len()) == Some(expected)
        && raw
            .get(expected.len()..)
            .is_some_and(|tail| tail.iter().all(|byte| *byte == 0))
}

fn translation_ranges(dylib: &[u8]) -> Result<MachOTranslationRanges, UnitMissReason> {
    const MACH_HEADER_64_SIZE: usize = 32;
    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const LC_SEGMENT_64: u32 = 0x19;
    const SEGMENT_COMMAND_64_SIZE: usize = 72;
    const SECTION_64_SIZE: usize = 80;

    if read_macho_u32(dylib, 0) != Some(MH_MAGIC_64) {
        return Err(UnitMissReason::ManifestRange);
    }
    let command_count =
        usize::try_from(read_macho_u32(dylib, 16).ok_or(UnitMissReason::ManifestRange)?)
            .map_err(|_| UnitMissReason::ManifestRange)?;
    let command_bytes =
        usize::try_from(read_macho_u32(dylib, 20).ok_or(UnitMissReason::ManifestRange)?)
            .map_err(|_| UnitMissReason::ManifestRange)?;
    let commands_end = MACH_HEADER_64_SIZE
        .checked_add(command_bytes)
        .ok_or(UnitMissReason::ManifestRange)?;
    if commands_end > dylib.len() {
        return Err(UnitMissReason::ManifestRange);
    }

    let mut image_vmaddr = None;
    let mut text = None;
    let mut data = None;
    let mut command_offset = MACH_HEADER_64_SIZE;
    for _ in 0..command_count {
        let command = read_macho_u32(dylib, command_offset).ok_or(UnitMissReason::ManifestRange)?;
        let command_size = usize::try_from(
            read_macho_u32(dylib, command_offset + 4).ok_or(UnitMissReason::ManifestRange)?,
        )
        .map_err(|_| UnitMissReason::ManifestRange)?;
        let command_end = command_offset
            .checked_add(command_size)
            .ok_or(UnitMissReason::ManifestRange)?;
        if command_size < 8 || command_end > commands_end {
            return Err(UnitMissReason::ManifestRange);
        }
        if command == LC_SEGMENT_64 {
            if command_size < SEGMENT_COMMAND_64_SIZE {
                return Err(UnitMissReason::ManifestRange);
            }
            let segment_name = dylib
                .get(command_offset + 8..command_offset + 24)
                .ok_or(UnitMissReason::ManifestRange)?;
            let segment_vmaddr =
                read_macho_u64(dylib, command_offset + 24).ok_or(UnitMissReason::ManifestRange)?;
            let segment_vmsize =
                read_macho_u64(dylib, command_offset + 32).ok_or(UnitMissReason::ManifestRange)?;
            let segment_end = segment_vmaddr
                .checked_add(segment_vmsize)
                .ok_or(UnitMissReason::ManifestRange)?;
            let max_protection =
                read_macho_i32(dylib, command_offset + 56).ok_or(UnitMissReason::ManifestRange)?;
            let init_protection =
                read_macho_i32(dylib, command_offset + 60).ok_or(UnitMissReason::ManifestRange)?;
            let section_count = usize::try_from(
                read_macho_u32(dylib, command_offset + 64).ok_or(UnitMissReason::ManifestRange)?,
            )
            .map_err(|_| UnitMissReason::ManifestRange)?;
            let sections_size = section_count
                .checked_mul(SECTION_64_SIZE)
                .ok_or(UnitMissReason::ManifestRange)?;
            if SEGMENT_COMMAND_64_SIZE
                .checked_add(sections_size)
                .is_none_or(|size| size > command_size)
            {
                return Err(UnitMissReason::ManifestRange);
            }

            let wanted_section = if macho_name_matches(segment_name, b"__TEXT") {
                if image_vmaddr.replace(segment_vmaddr).is_some() {
                    return Err(UnitMissReason::ManifestRange);
                }
                Some((b"__text".as_slice(), &mut text))
            } else if macho_name_matches(segment_name, b"__DATA") {
                Some((b"__data".as_slice(), &mut data))
            } else {
                None
            };
            if let Some((section_name, output)) = wanted_section {
                for index in 0..section_count {
                    let section_offset = command_offset
                        .checked_add(SEGMENT_COMMAND_64_SIZE)
                        .and_then(|offset| {
                            index
                                .checked_mul(SECTION_64_SIZE)
                                .and_then(|index_offset| offset.checked_add(index_offset))
                        })
                        .ok_or(UnitMissReason::ManifestRange)?;
                    let name = dylib
                        .get(section_offset..section_offset + 16)
                        .ok_or(UnitMissReason::ManifestRange)?;
                    let owning_segment = dylib
                        .get(section_offset + 16..section_offset + 32)
                        .ok_or(UnitMissReason::ManifestRange)?;
                    if !macho_name_matches(name, section_name)
                        || !macho_name_matches(owning_segment, segment_name)
                    {
                        continue;
                    }
                    let address = read_macho_u64(dylib, section_offset + 32)
                        .ok_or(UnitMissReason::ManifestRange)?;
                    let size = read_macho_u64(dylib, section_offset + 40)
                        .ok_or(UnitMissReason::ManifestRange)?;
                    let end = address
                        .checked_add(size)
                        .ok_or(UnitMissReason::ManifestRange)?;
                    if address < segment_vmaddr || end > segment_end || output.is_some() {
                        return Err(UnitMissReason::ManifestRange);
                    }
                    *output = Some(MachOSectionRange {
                        address,
                        size,
                        segment_address: segment_vmaddr,
                        segment_size: segment_vmsize,
                        init_protection,
                        max_protection,
                    });
                }
            }
        }
        command_offset = command_end;
    }
    if command_offset != commands_end {
        return Err(UnitMissReason::ManifestRange);
    }

    let image_vmaddr = image_vmaddr.ok_or(UnitMissReason::ManifestRange)?;
    let text = text.ok_or(UnitMissReason::ManifestRange)?;
    if text.size == 0
        || !text.segment_address.is_multiple_of(AOT_SEGMENT_PAGE_SIZE)
        || !text.segment_size.is_multiple_of(AOT_SEGMENT_PAGE_SIZE)
        || text.init_protection & (libc::PROT_READ | libc::PROT_EXEC)
            != libc::PROT_READ | libc::PROT_EXEC
        || text.max_protection & libc::PROT_WRITE != 0
    {
        return Err(UnitMissReason::ManifestRange);
    }
    if let Some(data) = data
        && (data.size == 0
            || !data.segment_address.is_multiple_of(AOT_SEGMENT_PAGE_SIZE)
            || !data.segment_size.is_multiple_of(AOT_SEGMENT_PAGE_SIZE)
            || text
                .segment_address
                .checked_add(text.segment_size)
                .is_none_or(|text_end| text_end > data.segment_address)
            || data.init_protection & (libc::PROT_READ | libc::PROT_WRITE)
                != libc::PROT_READ | libc::PROT_WRITE
            || data.max_protection & libc::PROT_EXEC != 0)
    {
        return Err(UnitMissReason::ManifestRange);
    }
    Ok(MachOTranslationRanges {
        image_vmaddr,
        text,
        data,
    })
}

fn translation_ranges_from_file(path: &Path) -> Result<MachOTranslationRanges, UnitStoreError> {
    const MACH_HEADER_64_SIZE: usize = 32;
    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const MAX_LOAD_COMMAND_BYTES: usize = 1024 * 1024;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            UnitStoreError::with_source(
                "open translation unit headers",
                UnitMissReason::ManifestRange,
                error,
            )
        })?;
    let metadata = file.metadata().map_err(|error| {
        UnitStoreError::with_source(
            "stat translation unit headers",
            UnitMissReason::ManifestRange,
            error,
        )
    })?;
    if !metadata.is_file() {
        return Err(UnitStoreError::new(
            "validate translation unit file type",
            UnitMissReason::ManifestRange,
        ));
    }

    let mut header = [0_u8; MACH_HEADER_64_SIZE];
    file.read_exact_at(&mut header, 0).map_err(|error| {
        UnitStoreError::with_source(
            "read translation unit header",
            UnitMissReason::ManifestRange,
            error,
        )
    })?;
    if read_macho_u32(&header, 0) != Some(MH_MAGIC_64) {
        return Err(UnitStoreError::new(
            "validate translation unit header",
            UnitMissReason::ManifestRange,
        ));
    }
    let command_bytes = read_macho_u32(&header, 20)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value <= MAX_LOAD_COMMAND_BYTES)
        .ok_or_else(|| {
            UnitStoreError::new(
                "validate translation unit load commands",
                UnitMissReason::ManifestRange,
            )
        })?;
    let header_bytes = MACH_HEADER_64_SIZE
        .checked_add(command_bytes)
        .filter(|value| u64::try_from(*value).is_ok_and(|value| value <= metadata.len()))
        .ok_or_else(|| {
            UnitStoreError::new(
                "validate translation unit load command extent",
                UnitMissReason::ManifestRange,
            )
        })?;
    let mut bytes = vec![0_u8; header_bytes];
    bytes[..MACH_HEADER_64_SIZE].copy_from_slice(&header);
    if command_bytes != 0 {
        file.read_exact_at(
            &mut bytes[MACH_HEADER_64_SIZE..],
            MACH_HEADER_64_SIZE as u64,
        )
        .map_err(|error| {
            UnitStoreError::with_source(
                "read translation unit load commands",
                UnitMissReason::ManifestRange,
                error,
            )
        })?;
    }
    translation_ranges(&bytes)
        .map_err(|reason| UnitStoreError::new("validate translation unit sections", reason))
}

fn image_base_for_symbol(symbol: std::ptr::NonNull<u8>) -> Result<usize, UnitMissReason> {
    let mut info = std::mem::MaybeUninit::<libc::Dl_info>::zeroed();
    if unsafe { libc::dladdr(symbol.as_ptr().cast(), info.as_mut_ptr()) } == 0 {
        return Err(UnitMissReason::Dlopen);
    }
    let info = unsafe { info.assume_init() };
    std::ptr::NonNull::new(info.dli_fbase)
        .map(|base| base.as_ptr() as usize)
        .ok_or(UnitMissReason::Dlopen)
}

fn export_is_in_section(
    symbol: std::ptr::NonNull<u8>,
    length: usize,
    image_base: usize,
    image_vmaddr: u64,
    section: MachOSectionRange,
) -> bool {
    let Some(relative_start) = section.address.checked_sub(image_vmaddr) else {
        return false;
    };
    let Ok(relative_start) = usize::try_from(relative_start) else {
        return false;
    };
    let Ok(section_len) = usize::try_from(section.size) else {
        return false;
    };
    let Some(section_start) = image_base.checked_add(relative_start) else {
        return false;
    };
    let Some(section_end) = section_start.checked_add(section_len) else {
        return false;
    };
    let symbol_start = symbol.as_ptr() as usize;
    symbol_start >= section_start
        && symbol_start
            .checked_add(length)
            .is_some_and(|symbol_end| symbol_end <= section_end)
}

fn loaded_segment_range(
    image_base: usize,
    image_vmaddr: u64,
    section: MachOSectionRange,
) -> Option<(std::ptr::NonNull<u8>, usize)> {
    let relative_start = section.segment_address.checked_sub(image_vmaddr)?;
    let relative_start = usize::try_from(relative_start).ok()?;
    let length = usize::try_from(section.segment_size).ok()?;
    let start = image_base.checked_add(relative_start)?;
    start.checked_add(length)?;
    std::ptr::NonNull::new(start as *mut u8).map(|start| (start, length))
}

fn validate_loaded_binding_cells_atomically(
    metadata: &ValidatedUnitMetadata,
    binding_base: DirectBindingCellVa,
) -> Result<(), UnitMissReason> {
    let binding_len =
        usize::try_from(metadata.binding_data_len()).map_err(|_| UnitMissReason::ManifestRange)?;
    let (cell_size, binding_count) = match metadata {
        ValidatedUnitMetadata::V2(manifest) => {
            manifest.validate_ranges()?;
            (
                usize::try_from(manifest.cell_size).map_err(|_| UnitMissReason::ManifestRange)?,
                manifest.bindings.len(),
            )
        }
        ValidatedUnitMetadata::V3(mapped) => (
            usize::try_from(mapped.cell_size()).map_err(|_| UnitMissReason::ManifestRange)?,
            mapped.binding_count(),
        ),
    };
    for index in 0..binding_count {
        let binding = match metadata {
            ValidatedUnitMetadata::V2(manifest) => manifest.bindings.get(index).cloned(),
            ValidatedUnitMetadata::V3(mapped) => {
                mapped.binding(index).map(|binding| binding.record())
            }
        }
        .ok_or(UnitMissReason::ManifestRange)?;
        let ordinal =
            usize::try_from(binding.ordinal.get()).map_err(|_| UnitMissReason::ManifestRange)?;
        let offset = ordinal
            .checked_mul(cell_size)
            .ok_or(UnitMissReason::ManifestRange)?;
        let cell_end = offset
            .checked_add(cell_size)
            .ok_or(UnitMissReason::ManifestRange)?;
        if cell_end > binding_len {
            return Err(UnitMissReason::ManifestRange);
        }
        let address = binding_base
            .get()
            .checked_add(offset)
            .ok_or(UnitMissReason::ManifestRange)?;
        let address = DirectBindingCellVa::mapped(address).ok_or(UnitMissReason::ManifestRange)?;
        // SAFETY: the loaded data export and manifest range were validated
        // before this function is called. Checked ordinal arithmetic keeps
        // this address within that live initialized binding-cell mapping.
        let cell = unsafe { DirectBindingCellRef::from_mapped_address(address) }
            .map_err(|_| UnitMissReason::ManifestRange)?;
        if !cell.load_acquire().is_null() {
            return Err(UnitMissReason::ManifestRange);
        }
    }
    Ok(())
}

fn code_word(code: &[u8], offset: u32) -> Result<u32, UnitMissReason> {
    let start = usize::try_from(offset).map_err(|_| UnitMissReason::ManifestRange)?;
    let end = start.checked_add(4).ok_or(UnitMissReason::ManifestRange)?;
    let bytes = code.get(start..end).ok_or(UnitMissReason::ManifestRange)?;
    Ok(u32::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| UnitMissReason::ManifestRange)?,
    ))
}

fn validate_loaded_binding_code(
    metadata: &ValidatedUnitMetadata,
    code: &[u8],
) -> Result<(), UnitMissReason> {
    match metadata {
        ValidatedUnitMetadata::V2(manifest) => manifest.validate_binding_code(code),
        ValidatedUnitMetadata::V3(mapped) => {
            for index in 0..mapped.binding_count() {
                let relocation = mapped
                    .binding(index)
                    .ok_or(UnitMissReason::ManifestRange)?
                    .relocation();
                for (adrp_offset, add_offset) in [
                    (relocation.adrp_offset, relocation.add_offset),
                    (relocation.miss_adrp_offset, relocation.miss_add_offset),
                ] {
                    let adrp = code_word(code, adrp_offset)?;
                    let add = code_word(code, add_offset)?;
                    if adrp & 0x9f00_001f != 0x9000_000f || add & 0xffc0_03ff != 0x9100_01ef {
                        return Err(UnitMissReason::ManifestRange);
                    }
                }
            }
            Ok(())
        }
    }
}

fn manifest_for_pending(
    pending: &PendingTranslationUnit,
    dylib_sha256: [u8; 32],
    base_export: &str,
) -> TranslationUnitManifest {
    TranslationUnitManifest {
        schema: TRANSLATION_UNIT_SCHEMA_V2,
        key: pending.key.clone(),
        dylib_sha256,
        base_export: base_export.to_owned(),
        code_len: pending.code.len() as u64,
        blocks: pending.blocks.clone(),
        binding_layout: pending.binding_layout,
        binding_export: pending.binding_export.clone(),
        binding_data_len: pending.binding_data_len,
        cell_size: pending.cell_size,
        bindings: pending.bindings.clone(),
        binding_relocations: pending.binding_relocations.clone(),
    }
}

/// Identity required to adopt one container's cache directory after host
/// self-reexec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerCacheReexecConfig {
    pub host_fd: i32,
    pub original_host_fd_flags: i32,
    pub host_device: u64,
    pub host_inode: u64,
    pub path: PathBuf,
    pub creator_pid: i32,
    pub authority_nonce: [u8; AUTHORITY_NONCE_LEN],
    pub translator_abi: u32,
}

/// The open-directory capability behind a container-private cache.
#[derive(Debug)]
pub struct ContainerCacheAuthority {
    directory: File,
    path: PathBuf,
    creator_pid: i32,
    authority_nonce: [u8; AUTHORITY_NONCE_LEN],
    cleanup_owner: bool,
}

impl ContainerCacheAuthority {
    fn create() -> std::io::Result<Self> {
        let tempdir = tempfile::Builder::new()
            .prefix("carrick-native-aot-")
            .tempdir()?;
        let path = tempdir.path().to_path_buf();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;

        let mut authority_nonce = [0_u8; AUTHORITY_NONCE_LEN];
        getrandom::fill(&mut authority_nonce)
            .map_err(|error| invalid_data(format!("generate cache authority nonce: {error}")))?;
        let marker_path = path.join(AUTHORITY_MARKER);
        let mut marker = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&marker_path)?;
        marker.write_all(&authority_nonce)?;
        marker.sync_all()?;

        let directory = open_directory(&path)?;
        let kept_path = tempdir.keep();
        debug_assert_eq!(kept_path, path);
        Ok(Self {
            directory,
            path,
            creator_pid: unsafe { libc::getpid() },
            authority_nonce,
            cleanup_owner: true,
        })
    }

    fn adopt(config: &ContainerCacheReexecConfig) -> std::io::Result<Self> {
        if config.host_fd < 0
            || !config.path.is_absolute()
            || config.translator_abi != carrick_dsr_aarch64::shared_cache::TRANSLATOR_ABI_CURRENT
        {
            return Err(invalid_data("invalid inherited cache authority"));
        }

        // The reexec transport transfers ownership of this descriptor. Take
        // it before validation so every rejection closes the inherited fd.
        let directory = unsafe { File::from_raw_fd(config.host_fd) };
        let fd_identity = directory.metadata()?;
        let path_identity = std::fs::symlink_metadata(&config.path)?;
        if !path_identity.is_dir()
            || path_identity.file_type().is_symlink()
            || fd_identity.dev() != config.host_device
            || fd_identity.ino() != config.host_inode
            || path_identity.dev() != config.host_device
            || path_identity.ino() != config.host_inode
            || path_identity.uid() != unsafe { libc::geteuid() }
            || path_identity.mode() & 0o777 != 0o700
        {
            return Err(invalid_data("inherited cache authority identity mismatch"));
        }

        let marker_name = CString::new(AUTHORITY_MARKER)
            .map_err(|_| invalid_data("cache authority marker contains NUL"))?;
        let marker_fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                marker_name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if marker_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut marker = unsafe { File::from_raw_fd(marker_fd) };
        let mut authority_nonce = [0_u8; AUTHORITY_NONCE_LEN];
        marker.read_exact(&mut authority_nonce)?;
        let mut trailing = [0_u8; 1];
        if marker.read(&mut trailing)? != 0 || authority_nonce != config.authority_nonce {
            return Err(invalid_data("inherited cache authority nonce mismatch"));
        }

        if unsafe {
            libc::fcntl(
                directory.as_raw_fd(),
                libc::F_SETFD,
                config.original_host_fd_flags,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self {
            directory,
            path: config.path.clone(),
            creator_pid: config.creator_pid,
            authority_nonce,
            // Only the process that created the directory may remove it. An
            // adopted authority is always a descendant's capability.
            cleanup_owner: false,
        })
    }

    pub fn snapshot(&self) -> std::io::Result<ContainerCacheReexecConfig> {
        let host_fd = self.directory.as_raw_fd();
        let original_host_fd_flags = unsafe { libc::fcntl(host_fd, libc::F_GETFD) };
        if original_host_fd_flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let identity = self.directory.metadata()?;
        Ok(ContainerCacheReexecConfig {
            host_fd,
            original_host_fd_flags,
            host_device: identity.dev(),
            host_inode: identity.ino(),
            path: self.path.clone(),
            creator_pid: self.creator_pid,
            authority_nonce: self.authority_nonce,
            translator_abi: carrick_dsr_aarch64::shared_cache::TRANSLATOR_ABI_CURRENT,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn publish_unit(
        &self,
        pending: &PendingTranslationUnit,
    ) -> Result<PublishOutcome, UnitStoreError> {
        self.publish_unit_with_metadata_mode(pending, mapped_metadata_enabled())
    }

    fn publish_unit_with_metadata_mode(
        &self,
        pending: &PendingTranslationUnit,
        mapped_metadata: bool,
    ) -> Result<PublishOutcome, UnitStoreError> {
        if pending.code.is_empty()
            || pending.code.len() > MAX_TRANSLATION_UNIT_CODE_BYTES
            || !pending.code.len().is_multiple_of(4)
        {
            return Err(UnitStoreError::new(
                "validate pending unit",
                UnitMissReason::ManifestRange,
            ));
        }
        let base_export = translation_unit_base_export(&pending.key).map_err(|error| {
            UnitStoreError::with_source(
                "derive keyed translation export",
                UnitMissReason::Schema,
                error,
            )
        })?;
        let preflight_manifest = manifest_for_pending(pending, [0; 32], &base_export);
        preflight_manifest
            .validate_ranges()
            .and_then(|()| preflight_manifest.validate_binding_data(&pending.binding_data))
            .and_then(|()| preflight_manifest.validate_binding_code(&pending.code))
            .map_err(|reason| UnitStoreError::new("validate pending unit", reason))?;
        let stem = pending.key.file_stem().map_err(|error| {
            UnitStoreError::with_source("derive unit filename", UnitMissReason::Schema, error)
        })?;
        // Winner selection must precede Mach-O emission and codesigning.
        // Toolchain workloads retire many identical siblings at once; taking
        // the per-key lock only after signing made every loser pay the full
        // signing cost even though exactly one pair could be published.
        let _lock = self.lock_unit(&stem)?;
        let (final_dylib, final_metadata) =
            self.final_paths_with_metadata_mode(&stem, mapped_metadata);
        if final_dylib.is_file() && final_metadata.is_file() {
            return Ok(PublishOutcome::Existing);
        }
        if final_dylib.exists() {
            std::fs::remove_file(&final_dylib).map_err(|error| {
                UnitStoreError::with_source(
                    "remove partial dylib",
                    UnitMissReason::MissingPair,
                    error,
                )
            })?;
        }
        if final_metadata.exists() {
            std::fs::remove_file(&final_metadata).map_err(|error| {
                UnitStoreError::with_source(
                    "remove partial metadata",
                    UnitMissReason::MissingPair,
                    error,
                )
            })?;
        }
        let mut exports = vec![crate::aot::AotExport {
            name: &base_export,
            section: crate::aot::AotSection::Text,
            offset: 0,
        }];
        if !pending.binding_data.is_empty() {
            exports.push(crate::aot::AotExport {
                name: &pending.binding_export,
                section: crate::aot::AotSection::Data,
                offset: 0,
            });
        }
        let relocations = pending
            .binding_relocations
            .iter()
            .flat_map(|relocation| {
                [
                    crate::aot::AotCodeToDataRelocation {
                        adrp_offset: relocation.adrp_offset,
                        add_offset: relocation.add_offset,
                        data_offset: relocation.data_offset,
                    },
                    crate::aot::AotCodeToDataRelocation {
                        adrp_offset: relocation.miss_adrp_offset,
                        add_offset: relocation.miss_add_offset,
                        data_offset: relocation.data_offset,
                    },
                ]
            })
            .collect::<Vec<_>>();
        let image = crate::aot::AotImage {
            code: &pending.code,
            data: &pending.binding_data,
            exports: &exports,
            relocations: &relocations,
        };
        let dylib = crate::aot::emit_dylib(&image).map_err(|error| {
            UnitStoreError::with_source(
                "emit translation dylib",
                UnitMissReason::ManifestRange,
                error,
            )
        })?;
        let mut dylib_temp = tempfile::NamedTempFile::new_in(&self.path).map_err(|error| {
            UnitStoreError::with_source(
                "create dylib temporary",
                UnitMissReason::MissingPair,
                error,
            )
        })?;
        dylib_temp.write_all(&dylib).map_err(|error| {
            UnitStoreError::with_source("write dylib temporary", UnitMissReason::MissingPair, error)
        })?;
        dylib_temp.flush().map_err(|error| {
            UnitStoreError::with_source("flush dylib temporary", UnitMissReason::MissingPair, error)
        })?;
        dylib_temp.as_file().sync_all().map_err(|error| {
            UnitStoreError::with_source("sync dylib temporary", UnitMissReason::MissingPair, error)
        })?;
        sign_and_verify(dylib_temp.path())?;
        dylib_temp.as_file().sync_all().map_err(|error| {
            UnitStoreError::with_source(
                "sync signed dylib temporary",
                UnitMissReason::MissingPair,
                error,
            )
        })?;
        let signed_dylib = std::fs::read(dylib_temp.path()).map_err(|error| {
            UnitStoreError::with_source("read signed dylib", UnitMissReason::DylibDigest, error)
        })?;
        let manifest =
            manifest_for_pending(pending, Sha256::digest(&signed_dylib).into(), &base_export);
        manifest
            .validate_ranges()
            .map_err(|reason| UnitStoreError::new("validate manifest", reason))?;
        let metadata_bytes = if mapped_metadata {
            encode_translation_metadata_v3(&manifest)
                .map_err(|error| mapped_metadata_error("encode mapped metadata", error))?
        } else {
            encode_manifest(&manifest).map_err(|error| {
                UnitStoreError::with_source("encode manifest", UnitMissReason::Schema, error)
            })?
        };
        let mut metadata_temp = tempfile::NamedTempFile::new_in(&self.path).map_err(|error| {
            UnitStoreError::with_source(
                "create metadata temporary",
                UnitMissReason::MissingPair,
                error,
            )
        })?;
        metadata_temp.write_all(&metadata_bytes).map_err(|error| {
            UnitStoreError::with_source(
                "write metadata temporary",
                UnitMissReason::MissingPair,
                error,
            )
        })?;
        metadata_temp.flush().map_err(|error| {
            UnitStoreError::with_source(
                "flush metadata temporary",
                UnitMissReason::MissingPair,
                error,
            )
        })?;
        metadata_temp.as_file().sync_all().map_err(|error| {
            UnitStoreError::with_source(
                "sync metadata temporary",
                UnitMissReason::MissingPair,
                error,
            )
        })?;
        if mapped_metadata {
            let temporary_name = metadata_temp
                .path()
                .file_name()
                .ok_or_else(|| {
                    UnitStoreError::new("derive metadata temporary name", UnitMissReason::Schema)
                })?
                .as_bytes();
            let temporary_name = CString::new(temporary_name).map_err(|error| {
                UnitStoreError::with_source(
                    "encode metadata temporary name",
                    UnitMissReason::Schema,
                    error,
                )
            })?;
            let _validated =
                map_and_validate_metadata(&self.directory, &temporary_name, &pending.key)?;
        }

        std::fs::rename(dylib_temp.path(), &final_dylib).map_err(|error| {
            UnitStoreError::with_source("publish dylib", UnitMissReason::MissingPair, error)
        })?;
        std::fs::rename(metadata_temp.path(), &final_metadata).map_err(|error| {
            UnitStoreError::with_source("publish metadata", UnitMissReason::MissingPair, error)
        })?;
        Ok(PublishOutcome::Winner)
    }

    pub fn claim_recording(&self, key: &TranslationUnitKey) -> Result<bool, UnitStoreError> {
        let stem = key.file_stem().map_err(|error| {
            UnitStoreError::with_source("derive unit filename", UnitMissReason::Schema, error)
        })?;
        let _lock = self.lock_unit(&stem)?;
        let (dylib, metadata) =
            self.final_paths_with_metadata_mode(&stem, mapped_metadata_enabled());
        if dylib.is_file() && metadata.is_file() {
            return Ok(false);
        }
        let seen = self.path.join(format!("{stem}.seen"));
        if !seen.exists() {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(seen)
                .map_err(|error| {
                    UnitStoreError::with_source(
                        "mark first unit observation",
                        UnitMissReason::MissingPair,
                        error,
                    )
                })?;
            return Ok(false);
        }
        let builder = self.path.join(format!("{stem}.builder"));
        if let Ok(owner) = std::fs::read_to_string(&builder)
            && let Ok(owner) = owner.trim().parse::<i32>()
        {
            let rc = unsafe { libc::kill(owner, 0) };
            if rc == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
                return Ok(false);
            }
        }
        let mut builder_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(builder)
            .map_err(|error| {
                UnitStoreError::with_source(
                    "claim unit recording",
                    UnitMissReason::MissingPair,
                    error,
                )
            })?;
        write!(builder_file, "{}", unsafe { libc::getpid() }).map_err(|error| {
            UnitStoreError::with_source(
                "write unit recording owner",
                UnitMissReason::MissingPair,
                error,
            )
        })?;
        builder_file.flush().map_err(|error| {
            UnitStoreError::with_source(
                "flush unit recording owner",
                UnitMissReason::MissingPair,
                error,
            )
        })?;
        Ok(true)
    }

    pub fn load_unit(
        &self,
        expected_key: &TranslationUnitKey,
        source_words: &[u32],
    ) -> Result<LoadedTranslationUnit, UnitStoreError> {
        self.load_unit_with_metadata_mode(
            expected_key,
            source_words,
            keyed_dylib_identity_enabled(),
            mapped_metadata_enabled(),
        )
    }

    #[cfg(test)]
    fn load_unit_with_keyed_identity(
        &self,
        expected_key: &TranslationUnitKey,
        source_words: &[u32],
        keyed_identity: bool,
    ) -> Result<LoadedTranslationUnit, UnitStoreError> {
        self.load_unit_with_metadata_mode(
            expected_key,
            source_words,
            keyed_identity,
            mapped_metadata_enabled(),
        )
    }

    fn load_unit_with_metadata_mode(
        &self,
        expected_key: &TranslationUnitKey,
        source_words: &[u32],
        keyed_identity: bool,
        mapped_metadata: bool,
    ) -> Result<LoadedTranslationUnit, UnitStoreError> {
        let stem = expected_key.file_stem().map_err(|error| {
            UnitStoreError::with_source("derive unit filename", UnitMissReason::Schema, error)
        })?;
        let (dylib_path, metadata_path) =
            self.final_paths_with_metadata_mode(&stem, mapped_metadata);
        if !dylib_path.is_file() || !metadata_path.is_file() {
            return Err(UnitStoreError::new(
                "locate translation unit",
                UnitMissReason::MissingPair,
            ));
        }
        let (metadata, load_evidence) = if mapped_metadata {
            let metadata_name = CString::new(format!("{stem}.metadata-v3")).map_err(|error| {
                UnitStoreError::with_source(
                    "encode mapped metadata name",
                    UnitMissReason::Schema,
                    error,
                )
            })?;
            let (metadata, evidence) =
                map_and_validate_metadata(&self.directory, &metadata_name, expected_key)?;
            (ValidatedUnitMetadata::V3(metadata), evidence)
        } else {
            // Exact `CARRICK_DSR_SHARED_MAPPED_METADATA=0` control: retain the
            // established path read, bincode decode, manifest validation, and
            // owned `Arc` construction without routing through V3 helpers.
            let manifest_bytes = std::fs::read(&metadata_path).map_err(|error| {
                UnitStoreError::with_source("read manifest", UnitMissReason::Schema, error)
            })?;
            let manifest: TranslationUnitManifest =
                decode_manifest(&manifest_bytes).map_err(|error| {
                    UnitStoreError::with_source("decode manifest", UnitMissReason::Schema, error)
                })?;
            manifest
                .validate_ranges()
                .map_err(|reason| UnitStoreError::new("validate manifest", reason))?;
            if &manifest.key != expected_key {
                return Err(UnitStoreError::new(
                    "validate unit identity",
                    UnitMissReason::ImageIdentity,
                ));
            }
            let owned_records = owned_immutable_record_count(&manifest)?;
            let bytes_read = u64::try_from(manifest_bytes.len()).map_err(|_| {
                UnitStoreError::new("measure manifest read", UnitMissReason::ManifestRange)
            })?;
            (
                ValidatedUnitMetadata::V2(manifest),
                TranslationMetadataLoadEvidence {
                    mode: TranslationMetadataMode::V2,
                    bytes_read,
                    bytes_mapped: 0,
                    validation_ns: 0,
                    mapped_records: 0,
                    owned_records,
                },
            )
        };
        if !shared_source_fingerprint_reuse_enabled() {
            match &metadata {
                ValidatedUnitMetadata::V2(manifest) => manifest
                    .validate_source(source_words)
                    .map_err(|reason| UnitStoreError::new("validate unit source", reason))?,
                ValidatedUnitMetadata::V3(_) => {
                    if expected_key.source_fingerprint()
                        != SourceFingerprint::from_words(source_words)
                    {
                        return Err(UnitStoreError::new(
                            "validate unit source",
                            UnitMissReason::SourceFingerprint,
                        ));
                    }
                }
            }
        }
        let ranges = if keyed_identity {
            // The exact key is part of the signed Mach-O export name. `dlopen`
            // validates the signed image and the later `dlsym` of that exact
            // export binds it to this already-validated manifest. Reading only
            // the bounded load-command prefix here avoids pulling a 60+ MiB
            // unit through every descendant merely to rediscover its digest.
            translation_ranges_from_file(&dylib_path)?
        } else {
            // Exact opt-out for A/B qualification and diagnosis.
            let dylib = std::fs::read(&dylib_path).map_err(|error| {
                UnitStoreError::with_source("read dylib", UnitMissReason::DylibDigest, error)
            })?;
            let digest: [u8; 32] = Sha256::digest(&dylib).into();
            let expected_digest = match &metadata {
                ValidatedUnitMetadata::V2(manifest) => manifest.dylib_sha256,
                ValidatedUnitMetadata::V3(mapped) => mapped.dylib_sha256(),
            };
            if digest != expected_digest {
                return Err(UnitStoreError::new(
                    "validate dylib digest",
                    UnitMissReason::DylibDigest,
                ));
            }
            translation_ranges(&dylib).map_err(|reason| {
                UnitStoreError::new("validate translation unit sections", reason)
            })?
        };
        let code_len = usize::try_from(metadata.code_len()).map_err(|_| {
            UnitStoreError::new(
                "validate translation code length",
                UnitMissReason::ManifestRange,
            )
        })?;
        let binding_len = usize::try_from(metadata.binding_data_len()).map_err(|_| {
            UnitStoreError::new(
                "validate binding data length",
                UnitMissReason::ManifestRange,
            )
        })?;
        if ranges.text.size != metadata.code_len()
            || match (binding_len, ranges.data) {
                (0, None) => false,
                (0, Some(_)) | (_, None) => true,
                (_, Some(data)) => data.size != metadata.binding_data_len(),
            }
        {
            return Err(UnitStoreError::new(
                "validate translation unit section lengths",
                UnitMissReason::ManifestRange,
            ));
        }
        let c_path = CString::new(dylib_path.as_os_str().as_bytes()).map_err(|error| {
            UnitStoreError::with_source("encode dylib path", UnitMissReason::Dlopen, error)
        })?;
        let handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        let handle = std::ptr::NonNull::new(handle).ok_or_else(|| {
            UnitStoreError::new("dlopen translation unit", UnitMissReason::Dlopen)
        })?;
        let base_export = translation_unit_base_export(expected_key).map_err(|error| {
            UnitStoreError::with_source(
                "derive keyed translation export",
                UnitMissReason::Schema,
                error,
            )
        })?;
        let symbol = CString::new(base_export.as_bytes()).map_err(|error| {
            UnitStoreError::with_source("encode base export", UnitMissReason::Dlopen, error)
        })?;
        let base = unsafe { libc::dlsym(handle.as_ptr(), symbol.as_ptr()) };
        let Some(base) = std::ptr::NonNull::new(base.cast::<u8>()) else {
            let _ = unsafe { libc::dlclose(handle.as_ptr()) };
            return Err(UnitStoreError::new(
                "resolve translation unit base",
                UnitMissReason::Dlopen,
            ));
        };
        let image_base = match image_base_for_symbol(base) {
            Ok(image_base) => image_base,
            Err(reason) => {
                let _ = unsafe { libc::dlclose(handle.as_ptr()) };
                return Err(UnitStoreError::new(
                    "identify translation unit image",
                    reason,
                ));
            }
        };
        if !export_is_in_section(base, code_len, image_base, ranges.image_vmaddr, ranges.text) {
            let _ = unsafe { libc::dlclose(handle.as_ptr()) };
            return Err(UnitStoreError::new(
                "validate translation base export",
                UnitMissReason::ManifestRange,
            ));
        }
        let Some((text_segment, text_segment_len)) =
            loaded_segment_range(image_base, ranges.image_vmaddr, ranges.text)
        else {
            let _ = unsafe { libc::dlclose(handle.as_ptr()) };
            return Err(UnitStoreError::new(
                "validate loaded translation text segment",
                UnitMissReason::ManifestRange,
            ));
        };
        if let Err(status) = unsafe {
            pin_loaded_translation_protection(
                text_segment,
                text_segment_len,
                LoadedTranslationProtection::ImmutableCode,
            )
        } {
            let _ = unsafe { libc::dlclose(handle.as_ptr()) };
            return Err(UnitStoreError::with_source(
                "pin loaded translation text protections",
                UnitMissReason::Dlopen,
                invalid_data(format!("mach_vm_protect returned {status}")),
            ));
        }
        if metadata.binding_count() != 0 {
            // SAFETY: `base` is the validated translation-unit text export and
            // schema validation bounds the declared code length. The mapping
            // remains live under `handle` for this validation.
            let mapped_code = unsafe { std::slice::from_raw_parts(base.as_ptr(), code_len) };
            if let Err(reason) = validate_loaded_binding_code(&metadata, mapped_code) {
                let _ = unsafe { libc::dlclose(handle.as_ptr()) };
                return Err(UnitStoreError::new(
                    "validate mapped translation code",
                    reason,
                ));
            }
        }
        let mut loaded_binding_base = None;
        if metadata.binding_data_len() != 0 {
            let binding_export = match &metadata {
                ValidatedUnitMetadata::V2(manifest) => manifest.binding_export.as_str(),
                ValidatedUnitMetadata::V3(_) => TRANSLATION_UNIT_BINDING_EXPORT,
            };
            let binding_symbol = CString::new(binding_export.as_bytes()).map_err(|error| {
                let _ = unsafe { libc::dlclose(handle.as_ptr()) };
                UnitStoreError::with_source("encode binding export", UnitMissReason::Dlopen, error)
            })?;
            let binding_base =
                unsafe { libc::dlsym(handle.as_ptr(), binding_symbol.as_ptr()) }.cast::<u8>();
            let Some(binding_base) = std::ptr::NonNull::new(binding_base) else {
                let _ = unsafe { libc::dlclose(handle.as_ptr()) };
                return Err(UnitStoreError::new(
                    "resolve translation unit bindings",
                    UnitMissReason::Dlopen,
                ));
            };
            let binding_image_base = match image_base_for_symbol(binding_base) {
                Ok(binding_image_base) => binding_image_base,
                Err(reason) => {
                    let _ = unsafe { libc::dlclose(handle.as_ptr()) };
                    return Err(UnitStoreError::new(
                        "identify translation binding image",
                        reason,
                    ));
                }
            };
            let Some(data_range) = ranges.data else {
                let _ = unsafe { libc::dlclose(handle.as_ptr()) };
                return Err(UnitStoreError::new(
                    "validate translation binding section",
                    UnitMissReason::ManifestRange,
                ));
            };
            if binding_image_base != image_base
                || !export_is_in_section(
                    binding_base,
                    binding_len,
                    image_base,
                    ranges.image_vmaddr,
                    data_range,
                )
            {
                let _ = unsafe { libc::dlclose(handle.as_ptr()) };
                return Err(UnitStoreError::new(
                    "validate translation binding export",
                    UnitMissReason::ManifestRange,
                ));
            }
            let Some(binding_cell_base) =
                DirectBindingCellVa::mapped(binding_base.as_ptr() as usize)
            else {
                let _ = unsafe { libc::dlclose(handle.as_ptr()) };
                return Err(UnitStoreError::new(
                    "validate mapped binding alignment",
                    UnitMissReason::ManifestRange,
                ));
            };
            let Some((data_segment, data_segment_len)) =
                loaded_segment_range(image_base, ranges.image_vmaddr, data_range)
            else {
                let _ = unsafe { libc::dlclose(handle.as_ptr()) };
                return Err(UnitStoreError::new(
                    "validate loaded translation data segment",
                    UnitMissReason::ManifestRange,
                ));
            };
            if let Err(status) = unsafe {
                pin_loaded_translation_protection(
                    data_segment,
                    data_segment_len,
                    LoadedTranslationProtection::BindingCells,
                )
            } {
                let _ = unsafe { libc::dlclose(handle.as_ptr()) };
                return Err(UnitStoreError::with_source(
                    "pin loaded translation data protections",
                    UnitMissReason::Dlopen,
                    invalid_data(format!("mach_vm_protect returned {status}")),
                ));
            }
            if let Err(reason) =
                validate_loaded_binding_cells_atomically(&metadata, binding_cell_base)
            {
                let _ = unsafe { libc::dlclose(handle.as_ptr()) };
                return Err(UnitStoreError::new("validate mapped binding cells", reason));
            }
            loaded_binding_base = Some(binding_cell_base);
        }
        Ok(LoadedTranslationUnit {
            metadata: metadata.into_loaded(),
            base,
            binding_base: loaded_binding_base,
            load_evidence,
            lease: Arc::new(LoadedTranslationLease { handle }),
        })
    }

    fn lock_unit(&self, stem: &str) -> Result<UnitFileLock, UnitStoreError> {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.path.join(format!("{stem}.lock")))
            .map_err(|error| {
                UnitStoreError::with_source("open unit lock", UnitMissReason::MissingPair, error)
            })?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(UnitStoreError::with_source(
                "lock unit",
                UnitMissReason::MissingPair,
                std::io::Error::last_os_error(),
            ));
        }
        Ok(UnitFileLock(lock))
    }

    #[cfg(test)]
    fn final_paths(&self, stem: &str) -> (PathBuf, PathBuf) {
        self.final_paths_with_metadata_mode(stem, mapped_metadata_enabled())
    }

    fn final_paths_with_metadata_mode(
        &self,
        stem: &str,
        mapped_metadata: bool,
    ) -> (PathBuf, PathBuf) {
        let metadata_suffix = if mapped_metadata {
            "metadata-v3"
        } else {
            "manifest"
        };
        (
            self.path.join(format!("{stem}.dylib")),
            self.path.join(format!("{stem}.{metadata_suffix}")),
        )
    }

    #[cfg(test)]
    fn directory(&self) -> &File {
        &self.directory
    }
}

fn sign_and_verify(path: &Path) -> Result<(), UnitStoreError> {
    let signed = std::process::Command::new("/usr/bin/codesign")
        .args(["-s", "-"])
        .arg(path)
        .output()
        .map_err(|error| {
            UnitStoreError::with_source("run codesign", UnitMissReason::Dlopen, error)
        })?;
    if !signed.status.success() {
        return Err(UnitStoreError::new(
            "sign translation unit",
            UnitMissReason::Dlopen,
        ));
    }
    let verified = std::process::Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict"])
        .arg(path)
        .output()
        .map_err(|error| {
            UnitStoreError::with_source("run codesign verification", UnitMissReason::Dlopen, error)
        })?;
    if !verified.status.success() {
        return Err(UnitStoreError::new(
            "verify translation unit signature",
            UnitMissReason::Dlopen,
        ));
    }
    Ok(())
}

impl Drop for ContainerCacheAuthority {
    fn drop(&mut self) {
        if self.cleanup_owner && owns_cleanup(self.creator_pid, unsafe { libc::getpid() }) {
            if std::env::var_os("CARRICK_DSR_KEEP_CONTAINER_CACHE").as_deref()
                == Some(std::ffi::OsStr::new("1"))
            {
                eprintln!("CARRICK_SHARED_CACHE_KEPT path={}", self.path.display());
                return;
            }
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Scope guard owned by the parent process that launched one native
/// container. Dropping it after the root guest exits removes the cache.
#[derive(Debug)]
pub struct ContainerCacheSession {
    creator_pid: i32,
}

impl Drop for ContainerCacheSession {
    fn drop(&mut self) {
        if !owns_cleanup(self.creator_pid, unsafe { libc::getpid() }) {
            return;
        }
        if let Ok(mut authority) = CONTAINER_CACHE.lock()
            && authority
                .as_ref()
                .is_some_and(|cache| cache.creator_pid == self.creator_pid)
        {
            let _ = authority.take();
        }
    }
}

pub fn begin_container_cache() -> std::io::Result<ContainerCacheSession> {
    let authority = ContainerCacheAuthority::create()?;
    let creator_pid = authority.creator_pid;
    let mut active = CONTAINER_CACHE
        .lock()
        .map_err(|_| invalid_data("container cache authority lock poisoned"))?;
    if active.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "a native container cache is already active",
        ));
    }
    *active = Some(authority);
    Ok(ContainerCacheSession { creator_pid })
}

pub fn container_cache_snapshot() -> std::io::Result<Option<ContainerCacheReexecConfig>> {
    CONTAINER_CACHE
        .lock()
        .map_err(|_| invalid_data("container cache authority lock poisoned"))?
        .as_ref()
        .map(ContainerCacheAuthority::snapshot)
        .transpose()
}

pub fn adopt_container_cache(config: &ContainerCacheReexecConfig) -> std::io::Result<()> {
    let authority = ContainerCacheAuthority::adopt(config)?;
    let mut active = CONTAINER_CACHE
        .lock()
        .map_err(|_| invalid_data("container cache authority lock poisoned"))?;
    if active.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "native container cache authority was already initialized",
        ));
    }
    *active = Some(authority);
    Ok(())
}

#[derive(Debug, Default)]
pub struct ActiveContainerUnitStore;

impl carrick_dsr_aarch64::shared_cache::TranslationUnitStore for ActiveContainerUnitStore {
    fn load(
        &self,
        key: &TranslationUnitKey,
        source_words: &[u32],
    ) -> Result<
        Option<carrick_dsr_aarch64::shared_cache::SharedLoadedTranslationUnit>,
        UnitMissReason,
    > {
        let active = CONTAINER_CACHE
            .lock()
            .map_err(|_| UnitMissReason::MissingPair)?;
        let authority = active.as_ref().ok_or(UnitMissReason::MissingPair)?;
        match authority.load_unit(key, source_words) {
            Ok(loaded) => Ok(Some(loaded.into_shared())),
            Err(error) if error.reason() == UnitMissReason::MissingPair => Ok(None),
            Err(error) => Err(error.reason()),
        }
    }

    fn publish(&self, pending: &PendingTranslationUnit) -> Result<PublishOutcome, UnitMissReason> {
        let active = CONTAINER_CACHE
            .lock()
            .map_err(|_| UnitMissReason::MissingPair)?;
        let authority = active.as_ref().ok_or(UnitMissReason::MissingPair)?;
        authority
            .publish_unit(pending)
            .map_err(|error| error.reason())
    }

    fn claim_recording(&self, key: &TranslationUnitKey) -> bool {
        CONTAINER_CACHE
            .lock()
            .ok()
            .and_then(|active| {
                active
                    .as_ref()
                    .and_then(|authority| authority.claim_recording(key).ok())
            })
            .unwrap_or(false)
    }
}

fn open_directory(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
}

fn invalid_data(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

fn owns_cleanup(creator_pid: i32, current_pid: i32) -> bool {
    creator_pid == current_pid
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_dsr::address::NativeHostBias;
    use carrick_dsr_aarch64::artifact_spike::{ArtifactBindings, ArtifactTemplate};
    use carrick_dsr_aarch64::direct_binding::{
        DirectBindingCellRef, DirectBindingOrdinal, DirectBindingTarget, DirectBindingTargetPrefix,
        PrivateJitEpoch,
    };
    use carrick_dsr_aarch64::emit::{DirectLinkKind, PcMapEntry};
    use carrick_dsr_aarch64::shared_cache::{
        AddressModeIdentity, DIRECT_BINDING_CELL_SIZE, DirectBindingLayout,
        DirectBindingRelocation, ExecutableIdentity, GuestCodeLen, ImageFileLen, ImageFileOffset,
        LoadedTranslationMetadata, NativePageProfileIdentity, SharedLoadedTranslationUnit,
        SourceFingerprint, TRANSLATION_UNIT_BINDING_EXPORT, TranslationMetadataMode,
        UnresolvedDirectBindingRecord,
    };
    use carrick_dsr_aarch64::types::{CacheOffset, CodeGeneration};
    use carrick_guest_mem::GuestVa;
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::fs::PermissionsExt;

    const MOV42_RET: [u8; 8] = [0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6];

    fn fixture_pending() -> PendingTranslationUnit {
        let source_words = [u32::from_le_bytes(MOV42_RET[..4].try_into().expect("word"))];
        let template = ArtifactTemplate::normalize(
            Vec::new(),
            vec![PcMapEntry {
                guest: GuestVa(0x400000),
                cache: CacheOffset::published(0),
            }],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            &ArtifactBindings::from_values([]).expect("empty artifact bindings"),
        )
        .expect("fixture block metadata")
        .into_runtime_metadata_only();
        PendingTranslationUnit {
            key: TranslationUnitKey::for_segment(
                ExecutableIdentity::Digest([0x11; 32]),
                ImageFileOffset::new(0),
                ImageFileLen::new(8).expect("nonzero file length"),
                GuestVa(0x400000),
                GuestCodeLen::new(8).expect("nonzero guest length"),
                SourceFingerprint::from_words(&source_words),
                NativePageProfileIdentity::Native16k,
                AddressModeIdentity::biased(
                    NativeHostBias::new(0x8000_0000, 16 * 1024).expect("aligned bias"),
                ),
            ),
            code: MOV42_RET.to_vec(),
            blocks: vec![carrick_dsr_aarch64::shared_cache::PortableBlockRecord {
                guest_start: GuestVa(0x400000),
                generation_binding: 0,
                entry_offset: 0,
                code_len: 8,
                requires_sensitive_metadata: false,
                template,
            }],
            binding_layout: DirectBindingLayout::Disabled,
            binding_export: String::new(),
            binding_data_len: 0,
            cell_size: 0,
            bindings: Vec::new(),
            binding_relocations: Vec::new(),
            binding_data: Vec::new(),
        }
    }

    fn fixture_manifest() -> TranslationUnitManifest {
        let pending = fixture_pending();
        let base_export =
            translation_unit_base_export(&pending.key).expect("keyed translation export");
        TranslationUnitManifest {
            schema: TRANSLATION_UNIT_SCHEMA_V2,
            key: pending.key,
            dylib_sha256: [0x22; 32],
            base_export,
            code_len: pending.code.len() as u64,
            blocks: pending.blocks,
            binding_layout: pending.binding_layout,
            binding_export: pending.binding_export,
            binding_data_len: pending.binding_data_len,
            cell_size: pending.cell_size,
            bindings: pending.bindings,
            binding_relocations: pending.binding_relocations,
        }
    }

    fn fixture_pending_with_binding_sidecar() -> PendingTranslationUnit {
        let mut pending = fixture_pending();
        pending.code.resize(288, 0);
        pending.code[..MOV42_RET.len()].copy_from_slice(&MOV42_RET);
        for offset in [52, 140] {
            pending.code[offset..offset + 4].copy_from_slice(&0x9000_000f_u32.to_le_bytes());
        }
        for offset in [56, 144] {
            pending.code[offset..offset + 4].copy_from_slice(&0x9100_01ef_u32.to_le_bytes());
        }
        pending.binding_layout = DirectBindingLayout::SidecarV1;
        pending.binding_export = TRANSLATION_UNIT_BINDING_EXPORT.to_owned();
        pending.binding_data_len = u64::from(DIRECT_BINDING_CELL_SIZE);
        pending.cell_size = DIRECT_BINDING_CELL_SIZE;
        pending.bindings = vec![UnresolvedDirectBindingRecord {
            source: GuestVa(0x400000),
            target: GuestVa(0x500000),
            kind: DirectLinkKind::Branch,
            ordinal: DirectBindingOrdinal::claimed(0),
            stub_start: 32,
            stub_end: 288,
        }];
        pending.binding_relocations = vec![DirectBindingRelocation {
            ordinal: DirectBindingOrdinal::claimed(0),
            adrp_offset: 52,
            add_offset: 56,
            miss_adrp_offset: 140,
            miss_add_offset: 144,
            data_offset: 0,
        }];
        pending.binding_data = vec![0; DIRECT_BINDING_CELL_SIZE as usize];
        pending
    }

    fn fixture_source_words() -> [u32; 1] {
        [u32::from_le_bytes(MOV42_RET[..4].try_into().expect("word"))]
    }

    fn pipe_pair() -> [RawFd; 2] {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "create pipe");
        fds
    }

    fn close_fd(fd: RawFd) {
        if fd >= 0 {
            assert_eq!(unsafe { libc::close(fd) }, 0, "close fd {fd}");
        }
    }

    fn write_all_fd(fd: RawFd, mut bytes: &[u8]) -> bool {
        while !bytes.is_empty() {
            let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
            if written > 0 {
                bytes = &bytes[written as usize..];
            } else if written < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
            {
                continue;
            } else {
                return false;
            }
        }
        true
    }

    fn read_exact_fd(fd: RawFd, mut bytes: &mut [u8]) -> bool {
        while !bytes.is_empty() {
            let read = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
            if read > 0 {
                let (_, remaining) = bytes.split_at_mut(read as usize);
                bytes = remaining;
            } else if read < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
            {
                continue;
            } else {
                return false;
            }
        }
        true
    }

    fn wait_for_child(pid: libc::pid_t, label: &str) {
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, 0) },
            pid,
            "wait for {label}"
        );
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "{label} exited with wait status 0x{status:x}"
        );
    }

    fn child_exit(status: i32) -> ! {
        unsafe { libc::_exit(status) }
    }

    fn run_binding_child(
        authority: &ContainerCacheAuthority,
        pending: &PendingTranslationUnit,
        control_read: RawFd,
        report_write: RawFd,
        target_address: usize,
    ) -> ! {
        if !write_all_fd(report_write, b"R") {
            child_exit(10);
        }
        let mut command = [0];
        if !read_exact_fd(control_read, &mut command) || command != *b"L" {
            child_exit(11);
        }
        let loaded = match authority.load_unit(&pending.key, &fixture_source_words()) {
            Ok(loaded) => loaded,
            Err(_) => child_exit(12),
        };
        let Some(binding_base) = loaded.binding_base else {
            child_exit(13);
        };
        let cell = match unsafe { DirectBindingCellRef::from_mapped_address(binding_base) } {
            Ok(cell) => cell,
            Err(_) => child_exit(14),
        };
        let target = std::ptr::without_provenance_mut::<DirectBindingTarget>(target_address);
        if cell.publish_null(target).is_err() {
            child_exit(15);
        }
        if !write_all_fd(report_write, b"P") {
            child_exit(16);
        }
        if !read_exact_fd(control_read, &mut command) || command != *b"R" {
            child_exit(17);
        }
        let observed = cell.load_acquire().addr();
        if !write_all_fd(report_write, &observed.to_ne_bytes()) {
            child_exit(18);
        }
        drop(loaded);
        child_exit(0)
    }

    fn duplicated_snapshot(authority: &ContainerCacheAuthority) -> ContainerCacheReexecConfig {
        let mut snapshot = authority.snapshot().expect("snapshot cache authority");
        let duplicate =
            unsafe { libc::fcntl(authority.directory().as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        assert!(duplicate >= 0, "duplicate directory fd");
        snapshot.host_fd = duplicate;
        snapshot
    }

    #[test]
    fn authority_is_private_and_survives_validated_reexec_adoption() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let snapshot = duplicated_snapshot(&authority);
        let adopted = ContainerCacheAuthority::adopt(&snapshot).expect("adopt cache authority");

        assert_eq!(adopted.path(), authority.path());
        assert_eq!(
            adopted.snapshot().expect("snapshot adopted authority"),
            snapshot
        );
        assert_eq!(
            std::fs::metadata(authority.path())
                .expect("stat cache directory")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn authority_rejects_substituted_directory_fd() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let substitute = ContainerCacheAuthority::create().expect("create substitute authority");
        let mut snapshot = duplicated_snapshot(&substitute);
        let expected = authority.snapshot().expect("snapshot expected authority");
        snapshot.host_device = expected.host_device;
        snapshot.host_inode = expected.host_inode;

        let error = ContainerCacheAuthority::adopt(&snapshot)
            .expect_err("substituted directory must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn authority_rejects_substituted_directory_path() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let substitute = ContainerCacheAuthority::create().expect("create substitute authority");
        let mut snapshot = duplicated_snapshot(&authority);
        snapshot.path = substitute.path().to_path_buf();

        let error = ContainerCacheAuthority::adopt(&snapshot)
            .expect_err("substituted path must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn only_the_creator_pid_owns_cleanup() {
        let pid = unsafe { libc::getpid() };
        assert!(owns_cleanup(pid, pid));
        assert!(!owns_cleanup(pid, pid.saturating_add(1)));
    }

    #[test]
    fn creator_session_removes_cache_after_container_exit() {
        let session = begin_container_cache().expect("begin container cache");
        let path = container_cache_snapshot()
            .expect("snapshot container cache")
            .expect("active container cache")
            .path;
        assert!(path.is_dir());

        drop(session);

        assert!(!path.exists());
        assert!(
            container_cache_snapshot()
                .expect("snapshot inactive cache")
                .is_none()
        );
    }

    #[test]
    fn inherited_process_cannot_remove_creator_cache() {
        let mut authority = ContainerCacheAuthority::create().expect("create cache authority");
        let path = authority.path().to_path_buf();
        authority.creator_pid = unsafe { libc::getpid() }.saturating_add(1);

        drop(authority);

        assert!(path.is_dir());
        std::fs::remove_dir_all(path).expect("remove test cache");
    }

    #[test]
    fn adoption_takes_ownership_of_the_inherited_fd() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let snapshot = duplicated_snapshot(&authority);
        let inherited_fd = snapshot.host_fd;
        let adopted = ContainerCacheAuthority::adopt(&snapshot).expect("adopt cache authority");
        drop(adopted);

        let borrowed = unsafe { std::fs::File::from_raw_fd(inherited_fd) };
        let result = unsafe { libc::fcntl(borrowed.as_raw_fd(), libc::F_GETFD) };
        std::mem::forget(borrowed);
        assert_eq!(result, -1);
    }

    #[test]
    fn concurrent_publishers_converge_on_one_signed_unit() {
        let authority =
            std::sync::Arc::new(ContainerCacheAuthority::create().expect("create cache authority"));
        let pending = fixture_pending();
        let threads = (0..2)
            .map(|_| {
                let authority = std::sync::Arc::clone(&authority);
                let pending = pending.clone();
                std::thread::spawn(move || authority.publish_unit(&pending))
            })
            .collect::<Vec<_>>();
        let mut outcomes = threads
            .into_iter()
            .map(|thread| {
                thread
                    .join()
                    .expect("publisher thread")
                    .expect("publish unit")
            })
            .collect::<Vec<_>>();
        outcomes.sort_by_key(|outcome| match outcome {
            PublishOutcome::Winner => 0,
            PublishOutcome::Existing => 1,
        });
        assert_eq!(
            outcomes,
            vec![PublishOutcome::Winner, PublishOutcome::Existing]
        );

        let source_words = [u32::from_le_bytes(MOV42_RET[..4].try_into().expect("word"))];
        let loaded = authority
            .load_unit(&pending.key, &source_words)
            .expect("load published unit");
        assert!(matches!(&loaded.metadata, LoadedTranslationMetadata::V3(_)));
        let stem = pending.key.file_stem().expect("unit stem");
        assert!(
            authority
                .path()
                .join(format!("{stem}.metadata-v3"))
                .is_file()
        );
        let function: extern "C" fn() -> i32 = unsafe { std::mem::transmute(loaded.base.as_ptr()) };
        assert_eq!(function(), 42);
        assert!(
            std::fs::read_dir(authority.path())
                .expect("read cache directory")
                .filter_map(Result::ok)
                .all(|entry| !entry.file_name().to_string_lossy().starts_with(".tmp")),
            "publisher left a temporary file"
        );
    }

    #[test]
    fn published_unit_loads_zero_aligned_binding_cells() {
        fn decoded_cell_address(
            code: &[u8],
            code_addr: usize,
            adrp_offset: usize,
            add_offset: usize,
        ) -> usize {
            let adrp = u32::from_le_bytes(
                code[adrp_offset..adrp_offset + 4]
                    .try_into()
                    .expect("mapped ADRP"),
            );
            let add = u32::from_le_bytes(
                code[add_offset..add_offset + 4]
                    .try_into()
                    .expect("mapped ADD"),
            );
            let immediate = (((adrp >> 5) & 0x7ffff) << 2) | ((adrp >> 29) & 0x3);
            let delta_pages = i128::from(((immediate << 11) as i32) >> 11);
            let pc_page = (code_addr + adrp_offset) & !0xfff;
            (pc_page as i128 + delta_pages * 4096) as usize + ((add >> 10) & 0xfff) as usize
        }

        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let pending = fixture_pending_with_binding_sidecar();

        assert_eq!(
            authority
                .publish_unit(&pending)
                .expect("publish complete sidecar"),
            PublishOutcome::Winner
        );
        let loaded = authority
            .load_unit(&pending.key, &fixture_source_words())
            .expect("load complete sidecar");
        let binding_base = loaded.binding_base.expect("typed binding base");
        assert!(
            binding_base
                .get()
                .is_multiple_of(DIRECT_BINDING_CELL_SIZE as usize)
        );
        let cell = unsafe { DirectBindingCellRef::from_mapped_address(binding_base) }
            .expect("mapped atomic binding cell");
        assert!(cell.load_acquire().is_null());
        // SAFETY: the base export and manifest code length were validated by
        // `load_unit`; the dlopen handle remains owned by `loaded`.
        let mapped_code =
            unsafe { std::slice::from_raw_parts(loaded.base.as_ptr(), pending.code.len()) };
        for (adrp_offset, add_offset) in [(52, 56), (140, 144)] {
            assert_eq!(
                decoded_cell_address(
                    mapped_code,
                    loaded.base.as_ptr() as usize,
                    adrp_offset,
                    add_offset,
                ),
                binding_base.get(),
                "hit and miss sites must both address the same binding cell"
            );
        }
        assert_eq!(
            authority
                .publish_unit(&pending)
                .expect("republish complete sidecar"),
            PublishOutcome::Existing
        );
    }

    #[test]
    fn second_load_rejects_atomically_published_binding_cell() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let pending = fixture_pending_with_binding_sidecar();
        authority
            .publish_unit(&pending)
            .expect("publish binding sidecar");
        let first = authority
            .load_unit(&pending.key, &fixture_source_words())
            .expect("first load");
        let binding_base = first.binding_base.expect("typed binding base");
        let cell = unsafe { DirectBindingCellRef::from_mapped_address(binding_base) }
            .expect("mapped atomic binding cell");
        let epoch = PrivateJitEpoch::process_owner();
        let target = Box::into_raw(Box::new(DirectBindingTarget::private(
            DirectBindingTargetPrefix {
                target_cache_pc: 0x1000,
                cache_start: 0x1000,
                cache_end: 0x2000,
                generation_bindings: 0x3000,
            },
            GuestVa(0x500000),
            CodeGeneration::claimed(1),
            &epoch,
        )));
        assert!(
            (target as usize).is_multiple_of(std::mem::align_of::<DirectBindingTarget>()),
            "published descriptor pointer must be naturally aligned"
        );
        cell.publish_null(target)
            .expect("atomically publish descriptor");

        let validated_metadata = match &first.metadata {
            LoadedTranslationMetadata::V2(manifest) => {
                ValidatedUnitMetadata::V2((**manifest).clone())
            }
            LoadedTranslationMetadata::V3(metadata) => {
                ValidatedUnitMetadata::V3(std::sync::Arc::clone(metadata))
            }
        };
        assert_eq!(
            validate_loaded_binding_cells_atomically(&validated_metadata, binding_base),
            Err(UnitMissReason::ManifestRange),
            "atomic revalidation must observe the published descriptor"
        );
        let error = authority
            .load_unit(&pending.key, &fixture_source_words())
            .expect_err("second load must reject a process-private nonzero cell");
        assert_eq!(error.reason(), UnitMissReason::ManifestRange);

        assert!(cell.clear_if(target), "clear published test descriptor");
        // SAFETY: this test allocated `target`, successfully cleared its sole
        // published cell, and retains no other pointer to the allocation.
        unsafe { drop(Box::from_raw(target)) };
    }

    #[test]
    fn two_independent_processes_bind_the_same_dylib_cell_privately() {
        const CHILD_A_TARGET: usize = 0x1111_0000;
        const CHILD_B_TARGET: usize = 0x2222_0000;

        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let pending = fixture_pending_with_binding_sidecar();
        authority
            .publish_unit(&pending)
            .expect("publish binding sidecar before fork");

        let control_a = pipe_pair();
        let report_a = pipe_pair();
        let control_b = pipe_pair();
        let report_b = pipe_pair();

        let child_a = unsafe { libc::fork() };
        assert!(child_a >= 0, "fork child A");
        if child_a == 0 {
            close_fd(control_a[1]);
            close_fd(report_a[0]);
            run_binding_child(
                &authority,
                &pending,
                control_a[0],
                report_a[1],
                CHILD_A_TARGET,
            );
        }

        let child_b = unsafe { libc::fork() };
        assert!(child_b >= 0, "fork child B");
        if child_b == 0 {
            close_fd(control_b[1]);
            close_fd(report_b[0]);
            run_binding_child(
                &authority,
                &pending,
                control_b[0],
                report_b[1],
                CHILD_B_TARGET,
            );
        }

        close_fd(control_a[0]);
        close_fd(report_a[1]);
        close_fd(control_b[0]);
        close_fd(report_b[1]);

        let mut marker = [0];
        assert!(read_exact_fd(report_a[0], &mut marker) && marker == *b"R");
        assert!(read_exact_fd(report_b[0], &mut marker) && marker == *b"R");
        assert!(write_all_fd(control_a[1], b"L"));
        assert!(write_all_fd(control_b[1], b"L"));
        assert!(read_exact_fd(report_a[0], &mut marker) && marker == *b"P");
        assert!(read_exact_fd(report_b[0], &mut marker) && marker == *b"P");
        assert!(write_all_fd(control_a[1], b"R"));
        assert!(write_all_fd(control_b[1], b"R"));

        let mut child_a_observed = [0; std::mem::size_of::<usize>()];
        let mut child_b_observed = [0; std::mem::size_of::<usize>()];
        assert!(read_exact_fd(report_a[0], &mut child_a_observed));
        assert!(read_exact_fd(report_b[0], &mut child_b_observed));
        assert_eq!(usize::from_ne_bytes(child_a_observed), CHILD_A_TARGET);
        assert_eq!(usize::from_ne_bytes(child_b_observed), CHILD_B_TARGET);

        close_fd(control_a[1]);
        close_fd(report_a[0]);
        close_fd(control_b[1]);
        close_fd(report_b[0]);
        wait_for_child(child_a, "binding child A");
        wait_for_child(child_b, "binding child B");
    }

    #[test]
    fn text_cannot_gain_write_permission_and_data_cannot_gain_execute_permission() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let pending = fixture_pending_with_binding_sidecar();
        authority
            .publish_unit(&pending)
            .expect("publish protected binding sidecar");
        let report = pipe_pair();

        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork protection child");
        if child == 0 {
            close_fd(report[0]);
            let loaded = match authority.load_unit(&pending.key, &fixture_source_words()) {
                Ok(loaded) => loaded,
                Err(_) => unsafe { libc::_exit(20) },
            };
            let Some(binding_base) = loaded.binding_base else {
                unsafe { libc::_exit(21) };
            };
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            if page_size <= 0 {
                unsafe { libc::_exit(22) };
            }
            let page_size = page_size as usize;
            let text_page = (loaded.base.as_ptr() as usize) & !(page_size - 1);
            let data_page = binding_base.get() & !(page_size - 1);
            let text_rc = unsafe {
                libc::mprotect(
                    text_page as *mut libc::c_void,
                    page_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            };
            let text_errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            let data_rc = unsafe {
                libc::mprotect(
                    data_page as *mut libc::c_void,
                    page_size,
                    libc::PROT_READ | libc::PROT_EXEC,
                )
            };
            let data_errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            let mut code_still_executes = 0;
            let mut data_still_writes = 0;
            if text_rc == -1 && data_rc == -1 {
                let function: extern "C" fn() -> i32 =
                    unsafe { std::mem::transmute(loaded.base.as_ptr()) };
                code_still_executes = i32::from(function() == 42);
                let cell = unsafe { DirectBindingCellRef::from_mapped_address(binding_base) }
                    .unwrap_or_else(|_| child_exit(24));
                let target = std::ptr::without_provenance_mut::<DirectBindingTarget>(0x3333_0000);
                if cell.publish_null(target).is_ok() && cell.load_acquire() == target {
                    data_still_writes = 1;
                }
            }
            for value in [
                text_rc,
                text_errno,
                data_rc,
                data_errno,
                code_still_executes,
                data_still_writes,
            ] {
                if !write_all_fd(report[1], &value.to_ne_bytes()) {
                    unsafe { libc::_exit(23) };
                }
            }
            unsafe { libc::_exit(0) };
        }

        close_fd(report[1]);
        let mut values = [0_i32; 6];
        for value in &mut values {
            let mut bytes = [0; std::mem::size_of::<i32>()];
            assert!(read_exact_fd(report[0], &mut bytes));
            *value = i32::from_ne_bytes(bytes);
        }
        close_fd(report[0]);
        wait_for_child(child, "protection child");

        eprintln!(
            "live dylib protection probes: text add-write rc={} errno={}; data add-exec rc={} errno={}; code_exec={}; data_write={}",
            values[0], values[1], values[2], values[3], values[4], values[5]
        );
        assert_eq!(
            values[0], -1,
            "live __TEXT unexpectedly gained write permission (errno={})",
            values[1]
        );
        assert_eq!(
            values[2], -1,
            "live __DATA unexpectedly gained execute permission (errno={})",
            values[3]
        );
        assert_ne!(values[1], 0, "failed text mprotect must report errno");
        assert_ne!(values[3], 0, "failed data mprotect must report errno");
        assert_eq!(
            values[4], 1,
            "text must retain its original execute permission"
        );
        assert_eq!(
            values[5], 1,
            "binding data must retain its original write permission"
        );
    }

    #[test]
    fn loaded_unit_lease_keeps_code_data_and_handle_alive() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let pending = fixture_pending_with_binding_sidecar();
        authority
            .publish_unit(&pending)
            .expect("publish leased binding sidecar");
        let stem = pending.key.file_stem().expect("unit stem");
        let (dylib_path, manifest_path) = authority.final_paths(&stem);
        let loaded = std::sync::Arc::new(
            authority
                .load_unit(&pending.key, &fixture_source_words())
                .expect("load leased binding sidecar"),
        );
        let binding_base = loaded.binding_base.expect("typed binding base");
        let lease: std::sync::Arc<dyn Send + Sync> = loaded.clone();
        let shared = match &loaded.metadata {
            LoadedTranslationMetadata::V2(manifest) => {
                SharedLoadedTranslationUnit::new_with_binding_base(
                    std::sync::Arc::clone(manifest),
                    loaded.base.as_ptr() as usize,
                    Some(binding_base),
                    lease,
                )
            }
            LoadedTranslationMetadata::V3(metadata) => {
                SharedLoadedTranslationUnit::new_mapped_with_binding_base(
                    std::sync::Arc::clone(metadata),
                    loaded.base.as_ptr() as usize,
                    Some(binding_base),
                    loaded.load_evidence,
                    lease,
                )
            }
        };
        drop(loaded);
        std::fs::remove_file(dylib_path).expect("unlink loaded dylib");
        std::fs::remove_file(manifest_path).expect("unlink loaded manifest");

        let function: extern "C" fn() -> i32 = unsafe { std::mem::transmute(shared.base) };
        assert_eq!(function(), 42, "retained lease must keep code mapped");
        let cell = unsafe {
            DirectBindingCellRef::from_mapped_address(
                shared.binding_base.expect("shared typed binding base"),
            )
        }
        .expect("retained lease must keep data mapped");
        assert!(cell.load_acquire().is_null());
    }

    #[test]
    fn manifest_wire_format_is_materially_smaller_than_json() {
        let manifest = fixture_manifest();
        let json = serde_json::to_vec(&manifest).expect("encode comparison JSON");
        let encoded = encode_manifest(&manifest).expect("encode compact manifest");
        let decoded = decode_manifest(&encoded).expect("decode compact manifest");

        assert_eq!(decoded, manifest);
        assert!(
            encoded.len().saturating_mul(2) < json.len(),
            "compact manifest is {} bytes versus {} bytes of JSON",
            encoded.len(),
            json.len(),
        );
    }

    #[test]
    fn fixed_width_manifest_wire_round_trips() {
        let manifest = fixture_manifest();
        let encoded =
            encode_manifest_with_fixed_width(&manifest, true).expect("encode fixed-width manifest");
        let decoded =
            decode_manifest_with_fixed_width(&encoded, true).expect("decode fixed-width manifest");

        assert_eq!(decoded, manifest);
    }

    #[test]
    fn fixed_width_manifest_encoding_is_default_on_with_an_exact_opt_out() {
        assert!(fixed_width_manifest_enabled_from(None));
        assert!(fixed_width_manifest_enabled_from(Some(
            std::ffi::OsStr::new("1")
        )));
        assert!(!fixed_width_manifest_enabled_from(Some(
            std::ffi::OsStr::new("0")
        )));
    }

    #[test]
    fn mapped_metadata_is_default_on_with_an_exact_opt_out() {
        assert!(mapped_metadata_enabled_from(None));
        assert!(mapped_metadata_enabled_from(Some(std::ffi::OsStr::new(
            "1"
        ))));
        assert!(mapped_metadata_enabled_from(Some(std::ffi::OsStr::new(
            "false"
        ))));
        assert!(!mapped_metadata_enabled_from(Some(std::ffi::OsStr::new(
            "0"
        ))));
    }

    #[test]
    fn keyed_dylib_identity_is_default_on_with_an_exact_opt_out() {
        assert!(keyed_dylib_identity_enabled_from(None));
        assert!(keyed_dylib_identity_enabled_from(Some(
            std::ffi::OsStr::new("1")
        )));
        assert!(!keyed_dylib_identity_enabled_from(Some(
            std::ffi::OsStr::new("0")
        )));
    }

    #[test]
    fn keyed_dylib_identity_rejects_another_valid_signed_unit() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let first = fixture_pending();
        let mut second = fixture_pending();
        second.key = TranslationUnitKey::for_segment(
            ExecutableIdentity::Digest([0x33; 32]),
            ImageFileOffset::new(0),
            ImageFileLen::new(8).expect("nonzero file length"),
            GuestVa(0x400000),
            GuestCodeLen::new(8).expect("nonzero guest length"),
            SourceFingerprint::from_words(&fixture_source_words()),
            NativePageProfileIdentity::Native16k,
            AddressModeIdentity::biased(
                NativeHostBias::new(0x8000_0000, 16 * 1024).expect("aligned bias"),
            ),
        );
        authority.publish_unit(&first).expect("publish first unit");
        authority
            .publish_unit(&second)
            .expect("publish second unit");
        let (first_dylib, _) =
            authority.final_paths(&first.key.file_stem().expect("first unit stem"));
        let (second_dylib, _) =
            authority.final_paths(&second.key.file_stem().expect("second unit stem"));
        std::fs::copy(second_dylib, first_dylib).expect("substitute valid signed unit");

        assert_eq!(
            authority
                .load_unit_with_keyed_identity(&first.key, &fixture_source_words(), true)
                .expect_err("another key's signed dylib must not load")
                .reason(),
            UnitMissReason::Dlopen
        );
    }

    #[test]
    fn recurring_unit_elects_exactly_one_recorder() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let key = fixture_pending().key;

        assert!(
            !authority
                .claim_recording(&key)
                .expect("record first observation"),
            "a one-off executable must not pay portable recording cost"
        );
        assert!(
            authority
                .claim_recording(&key)
                .expect("elect second observation"),
            "the second process proves recurrence and owns recording"
        );
        assert!(
            !authority
                .claim_recording(&key)
                .expect("observe live recorder"),
            "a live recorder must exclude the thundering herd"
        );
    }

    #[test]
    fn partial_publish_pair_is_never_loadable() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let pending = fixture_pending();
        let stem = pending.key.file_stem().expect("unit stem");
        let (dylib, manifest) = authority.final_paths(&stem);
        let source_words = [u32::from_le_bytes(MOV42_RET[..4].try_into().expect("word"))];

        std::fs::write(&manifest, b"{}").expect("write lone manifest");
        assert_eq!(
            authority
                .load_unit(&pending.key, &source_words)
                .expect_err("lone manifest must miss")
                .reason(),
            UnitMissReason::MissingPair
        );
        std::fs::remove_file(&manifest).expect("remove lone manifest");
        std::fs::write(&dylib, MOV42_RET).expect("write lone dylib");
        assert_eq!(
            authority
                .load_unit(&pending.key, &source_words)
                .expect_err("lone dylib must miss")
                .reason(),
            UnitMissReason::MissingPair
        );
    }

    #[test]
    fn published_v3_unit_is_mapped_with_zero_read_evidence() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let pending = fixture_pending();

        assert_eq!(
            authority
                .publish_unit_with_metadata_mode(&pending, true)
                .expect("publish V3 unit"),
            PublishOutcome::Winner
        );
        let stem = pending.key.file_stem().expect("unit stem");
        let (_, metadata_path) = authority.final_paths_with_metadata_mode(&stem, true);
        assert_eq!(
            metadata_path.extension().and_then(std::ffi::OsStr::to_str),
            Some("metadata-v3")
        );
        assert!(!authority.path().join(format!("{stem}.manifest")).exists());

        let loaded = authority
            .load_unit_with_metadata_mode(&pending.key, &fixture_source_words(), true, true)
            .expect("load V3 unit");
        let LoadedTranslationMetadata::V3(metadata) = &loaded.metadata else {
            panic!("default mapped load must retain V3 metadata");
        };
        assert_eq!(metadata.block_count(), 1);
        assert_eq!(
            metadata.block(0).expect("mapped block").guest_start(),
            GuestVa(0x400000)
        );
        assert_eq!(loaded.load_evidence.mode, TranslationMetadataMode::V3);
        assert_eq!(loaded.load_evidence.bytes_read, 0);
        assert_eq!(
            loaded.load_evidence.bytes_mapped,
            std::fs::metadata(metadata_path)
                .expect("stat V3 metadata")
                .len()
        );
        assert_eq!(loaded.load_evidence.mapped_records, 2);
        assert_eq!(loaded.load_evidence.owned_records, 0);
    }

    #[test]
    fn exact_mapped_metadata_opt_out_preserves_v2_writer_and_loader() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let pending = fixture_pending();

        authority
            .publish_unit_with_metadata_mode(&pending, false)
            .expect("publish V2 unit");
        let stem = pending.key.file_stem().expect("unit stem");
        let (_, manifest_path) = authority.final_paths_with_metadata_mode(&stem, false);
        let manifest_len = std::fs::metadata(&manifest_path)
            .expect("stat V2 manifest")
            .len();
        assert_eq!(
            manifest_path.extension().and_then(std::ffi::OsStr::to_str),
            Some("manifest")
        );
        assert!(
            !authority
                .path()
                .join(format!("{stem}.metadata-v3"))
                .exists()
        );

        let loaded = authority
            .load_unit_with_metadata_mode(&pending.key, &fixture_source_words(), true, false)
            .expect("load V2 unit");
        assert!(matches!(loaded.metadata, LoadedTranslationMetadata::V2(_)));
        assert_eq!(loaded.load_evidence.mode, TranslationMetadataMode::V2);
        assert_eq!(loaded.load_evidence.bytes_read, manifest_len);
        assert_eq!(loaded.load_evidence.bytes_mapped, 0);
        assert_eq!(loaded.load_evidence.mapped_records, 0);
        assert_eq!(loaded.load_evidence.owned_records, 2);
    }

    #[test]
    fn loaded_unit_conversion_preserves_v2_evidence() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let pending = fixture_pending();
        authority
            .publish_unit_with_metadata_mode(&pending, false)
            .expect("publish V2 unit");
        let loaded = authority
            .load_unit_with_metadata_mode(&pending.key, &fixture_source_words(), true, false)
            .expect("load V2 unit");
        let expected = loaded.load_evidence;

        let shared = loaded.into_shared();

        assert!(matches!(shared.metadata, LoadedTranslationMetadata::V2(_)));
        assert_eq!(shared.load_evidence, expected);
    }

    #[test]
    fn mapped_metadata_and_dylib_pair_rejects_either_lone_half() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let pending = fixture_pending();
        let stem = pending.key.file_stem().expect("unit stem");
        let (dylib, metadata) = authority.final_paths_with_metadata_mode(&stem, true);

        std::fs::write(&metadata, b"metadata only").expect("write lone V3 metadata");
        assert_eq!(
            authority
                .load_unit_with_metadata_mode(&pending.key, &fixture_source_words(), true, true)
                .expect_err("lone V3 metadata must miss")
                .reason(),
            UnitMissReason::MissingPair
        );
        std::fs::remove_file(&metadata).expect("remove lone V3 metadata");
        std::fs::write(&dylib, MOV42_RET).expect("write lone dylib");
        assert_eq!(
            authority
                .load_unit_with_metadata_mode(&pending.key, &fixture_source_words(), true, true)
                .expect_err("lone dylib must miss")
                .reason(),
            UnitMissReason::MissingPair
        );
    }

    #[test]
    fn corrupt_v3_metadata_is_typed_before_dylib_authority() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let pending = fixture_pending();
        authority
            .publish_unit_with_metadata_mode(&pending, true)
            .expect("publish V3 unit");
        let stem = pending.key.file_stem().expect("unit stem");
        let (dylib, metadata) = authority.final_paths_with_metadata_mode(&stem, true);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&metadata)
            .expect("open V3 metadata")
            .write_all(b"BROKEN!!")
            .expect("corrupt V3 magic");
        std::fs::write(dylib, b"not a Mach-O image").expect("corrupt dylib authority");

        assert_eq!(
            authority
                .load_unit_with_metadata_mode(&pending.key, &fixture_source_words(), true, true)
                .expect_err("corrupt V3 metadata must miss before dylib")
                .reason(),
            UnitMissReason::Schema
        );
    }

    #[test]
    fn mapped_metadata_survives_unlink_until_the_final_clone_drops() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let pending = fixture_pending_with_binding_sidecar();
        authority
            .publish_unit_with_metadata_mode(&pending, true)
            .expect("publish V3 sidecar");
        let stem = pending.key.file_stem().expect("unit stem");
        let (dylib_path, metadata_path) = authority.final_paths_with_metadata_mode(&stem, true);
        let loaded = authority
            .load_unit_with_metadata_mode(&pending.key, &fixture_source_words(), true, true)
            .expect("load V3 sidecar");
        let LoadedTranslationMetadata::V3(metadata) = loaded.metadata else {
            panic!("loaded sidecar must retain V3 metadata");
        };
        let metadata_drops = std::sync::Arc::downgrade(&metadata);
        let shared = SharedLoadedTranslationUnit::new_mapped_with_binding_base(
            std::sync::Arc::clone(&metadata),
            loaded.base.as_ptr() as usize,
            loaded.binding_base,
            loaded.load_evidence,
            loaded.lease,
        );
        drop(metadata);
        let clone = shared.clone();
        std::fs::remove_file(dylib_path).expect("unlink loaded dylib");
        std::fs::remove_file(metadata_path).expect("unlink mapped metadata");

        let mapped = clone.metadata.v3().expect("cloned mapped metadata");
        assert_eq!(mapped.block(0).expect("mapped block").code_len(), 8);
        assert_eq!(
            mapped
                .binding(0)
                .expect("mapped binding")
                .record()
                .ordinal
                .get(),
            0
        );
        let function: extern "C" fn() -> i32 = unsafe { std::mem::transmute(clone.base) };
        assert_eq!(function(), 42);
        drop(shared);
        assert!(metadata_drops.upgrade().is_some());
        drop(clone);
        assert!(metadata_drops.upgrade().is_none());
    }
}
