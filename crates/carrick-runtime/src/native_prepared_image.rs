// Task 3 defines and validates the artifact in isolation. Capsule transport and
// fresh-process mapping deliberately activate these crate-private APIs in later
// slices; until then only the shared legacy copy-window helper is called by
// production code.
#![allow(dead_code)]

#[cfg(target_os = "macos")]
use crate::elf::{RoSpan, SegmentPerms};
use crate::memory::MemoryRegion;
#[cfg(target_os = "macos")]
use crate::memory::{AddressSpace, AddressSpaceMetadata, MemoryRegionMetadata};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "macos")]
use std::fs::File;
#[cfg(target_os = "macos")]
use std::os::fd::FromRawFd;
use std::os::fd::RawFd;
#[cfg(target_os = "macos")]
use std::os::unix::fs::FileExt;

const PREPARED_IMAGE_MAGIC: &[u8; 16] = b"CARRICK-PREP-V1\0";
const PREPARED_IMAGE_VERSION: u32 = 1;
const MAX_REGIONS: usize = 256;
const MAX_INITIALIZED_SPANS: usize = 16_384;
const MAX_ARTIFACT_SIZE: u64 = 1_073_741_824;
const MAX_WRITTEN_BYTES: u64 = 536_870_912;
const MAX_AUXV_BYTES: usize = 65_536;

#[derive(Debug, Clone, Copy)]
#[cfg(target_os = "macos")]
struct PreparedImageLimits {
    max_regions: usize,
    max_initialized_spans: usize,
    max_artifact_size: u64,
    max_written_bytes: u64,
    max_auxv_bytes: usize,
}

#[cfg(target_os = "macos")]
impl PreparedImageLimits {
    const fn v1() -> Self {
        Self {
            max_regions: MAX_REGIONS,
            max_initialized_spans: MAX_INITIALIZED_SPANS,
            max_artifact_size: MAX_ARTIFACT_SIZE,
            max_written_bytes: MAX_WRITTEN_BYTES,
            max_auxv_bytes: MAX_AUXV_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PreparedGuestVa(u64);

impl PreparedGuestVa {
    pub(crate) fn new(value: u64) -> Option<Self> {
        (value <= crate::memory::LINUX_STACK_TOP).then_some(Self(value))
    }

    pub(crate) fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PreparedGuestLen(u64);

impl PreparedGuestLen {
    fn new(value: u64) -> Option<Self> {
        (value != 0 && value <= MAX_ARTIFACT_SIZE).then_some(Self(value))
    }

    pub(crate) fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct PreparedGuestOffset(u64);

impl PreparedGuestOffset {
    fn new(value: u64) -> Option<Self> {
        (value <= MAX_ARTIFACT_SIZE).then_some(Self(value))
    }

    fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PreparedArtifactOffset(u64);

impl PreparedArtifactOffset {
    fn new(value: u64) -> Option<Self> {
        (value <= MAX_ARTIFACT_SIZE).then_some(Self(value))
    }

    pub(crate) fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PreparedRegionIndex(u16);

impl PreparedRegionIndex {
    fn new(value: usize) -> Option<Self> {
        if value >= MAX_REGIONS {
            return None;
        }
        u16::try_from(value).ok().map(Self)
    }

    pub(crate) fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeRelativeRelocation {
    address: PreparedGuestVa,
    value: PreparedGuestVa,
}

impl NativeRelativeRelocation {
    pub(crate) fn new(address: PreparedGuestVa, value: PreparedGuestVa) -> Self {
        Self { address, value }
    }

    pub(crate) fn address(self) -> PreparedGuestVa {
        self.address
    }

    pub(crate) fn value(self) -> PreparedGuestVa {
        self.value
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativePreparedRegionV1 {
    guest_start: PreparedGuestVa,
    guest_end: PreparedGuestVa,
    permissions: u8,
    shared: bool,
    artifact_offset: PreparedArtifactOffset,
    artifact_extent: PreparedGuestLen,
}

impl NativePreparedRegionV1 {
    fn guest_len(&self) -> Option<u64> {
        self.guest_end.get().checked_sub(self.guest_start.get())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativePreparedSpanV1 {
    region_index: PreparedRegionIndex,
    guest_offset: PreparedGuestOffset,
    artifact_offset: PreparedArtifactOffset,
    byte_len: PreparedGuestLen,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativePreparedRoSpanV1 {
    start: PreparedGuestVa,
    len: PreparedGuestLen,
    exec: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativePreparedImageV1 {
    artifact_fd: RawFd,
    original_host_fd_flags: i32,
    artifact_device: u64,
    artifact_inode: u64,
    artifact_size: u64,
    version: u32,
    host_page_size: u64,
    entry: PreparedGuestVa,
    initial_stack_pointer: PreparedGuestVa,
    auxv: Vec<u8>,
    regions: Vec<NativePreparedRegionV1>,
    initialized_spans: Vec<NativePreparedSpanV1>,
    ro_spans: Vec<NativePreparedRoSpanV1>,
    relocations: Vec<NativeRelativeRelocation>,
    written_byte_count: u64,
    digest: [u8; 32],
}

#[derive(Debug)]
#[cfg(target_os = "macos")]
pub(crate) struct PreparedImageArtifact {
    pub(crate) record: NativePreparedImageV1,
    pub(crate) file: File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreparedImageFileBacking {
    pub(crate) artifact_offset: PreparedArtifactOffset,
    pub(crate) artifact_extent: PreparedGuestLen,
}

#[derive(Debug)]
#[cfg(target_os = "macos")]
pub(crate) struct ValidatedPreparedImage {
    pub(crate) file: File,
    pub(crate) image: AddressSpace,
    pub(crate) backings: Vec<PreparedImageFileBacking>,
    pub(crate) relocations: Vec<NativeRelativeRelocation>,
}

#[derive(Debug)]
#[cfg(target_os = "macos")]
pub(crate) enum PreparedImageDisposition {
    Prepared(PreparedImageArtifact),
    Ineligible(PreparedImageIneligibleReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PreparedImageIneligibleReason {
    SharedRegion {
        index: usize,
    },
    RepresentationLimit {
        stage: &'static str,
        value: u64,
        limit: u64,
    },
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum NativePreparedImageError {
    #[error("prepared image I/O failed at {stage}: {source}")]
    Io {
        stage: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("prepared image file identity failed at {stage} for fd {fd}: {reason}")]
    FileIdentity {
        stage: &'static str,
        fd: RawFd,
        reason: String,
    },
    #[error("prepared image validation failed at {stage}, index={index:?}, value=0x{value:x}")]
    Validation {
        stage: &'static str,
        index: Option<usize>,
        value: u64,
    },
    #[error("prepared image checksum mismatch: expected {expected:02x?}, actual {actual:02x?}")]
    ChecksumMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    #[error("prepared image metadata reconstruction failed: {0}")]
    AddressSpace(#[from] crate::memory::AddressSpaceError),
}

#[derive(Debug, Clone, Copy)]
#[cfg(target_os = "macos")]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    mode: libc::mode_t,
    fd_flags: i32,
}

#[cfg(target_os = "macos")]
impl FileIdentity {
    fn for_fd(fd: RawFd) -> Result<Self, NativePreparedImageError> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return Err(io_error("fstat-artifact"));
        }
        let stat = unsafe { stat.assume_init() };
        let fd_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if fd_flags < 0 {
            return Err(io_error("get-artifact-fd-flags"));
        }
        Ok(Self {
            device: u64::try_from(stat.st_dev).map_err(|_| {
                file_identity_error("negative-artifact-device", fd, stat.st_dev.to_string())
            })?,
            inode: stat.st_ino,
            size: u64::try_from(stat.st_size).map_err(|_| {
                file_identity_error("negative-artifact-size", fd, stat.st_size.to_string())
            })?,
            mode: stat.st_mode,
            fd_flags,
        })
    }

    fn require_regular(self, fd: RawFd) -> Result<Self, NativePreparedImageError> {
        if self.mode & libc::S_IFMT != libc::S_IFREG {
            return Err(file_identity_error(
                "artifact-file-type",
                fd,
                format!("mode=0o{:o}", self.mode),
            ));
        }
        Ok(self)
    }
}

#[cfg(target_os = "macos")]
struct RawFdGuard(RawFd);

#[cfg(target_os = "macos")]
impl Drop for RawFdGuard {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

pub(crate) fn native_region_copy_window(
    region: &MemoryRegion,
    initial_stack_pointer: Option<u64>,
) -> std::ops::Range<usize> {
    let full = 0..region.bytes().len();
    let stack_start = crate::memory::LINUX_STACK_TOP - crate::memory::LINUX_STACK_SIZE;
    if region.start != stack_start || region.end != crate::memory::LINUX_STACK_TOP {
        return full;
    }
    let Some(stack_pointer) = initial_stack_pointer else {
        return full;
    };
    let Some(offset) = stack_pointer.checked_sub(region.start) else {
        return full;
    };
    let Ok(offset) = usize::try_from(offset) else {
        return full;
    };
    if offset > region.bytes().len() {
        return full;
    }
    offset..region.bytes().len()
}

#[cfg(target_os = "macos")]
pub(crate) fn prepare(
    image: &AddressSpace,
    relocations: &[NativeRelativeRelocation],
    host_page_size: u64,
) -> Result<PreparedImageDisposition, NativePreparedImageError> {
    prepare_with_limits(
        image,
        relocations,
        host_page_size,
        PreparedImageLimits::v1(),
    )
}

#[cfg(target_os = "macos")]
fn prepare_with_limits(
    image: &AddressSpace,
    relocations: &[NativeRelativeRelocation],
    host_page_size: u64,
    limits: PreparedImageLimits,
) -> Result<PreparedImageDisposition, NativePreparedImageError> {
    if image.regions().len() > limits.max_regions {
        return Ok(ineligible_limit(
            "region-count",
            image.regions().len() as u64,
            limits.max_regions as u64,
        ));
    }
    if image.linux_auxv_image().len() > limits.max_auxv_bytes {
        return Ok(ineligible_limit(
            "auxv-bytes",
            image.linux_auxv_image().len() as u64,
            limits.max_auxv_bytes as u64,
        ));
    }
    if host_page_size == 0 || !host_page_size.is_power_of_two() {
        return Err(validation("host-page-geometry", None, host_page_size));
    }
    for (index, region) in image.regions().iter().enumerate() {
        if region.shared {
            return Ok(PreparedImageDisposition::Ineligible(
                PreparedImageIneligibleReason::SharedRegion { index },
            ));
        }
    }

    let mut artifact_size = 0_u64;
    let mut regions = Vec::with_capacity(image.regions().len());
    for (index, region) in image.regions().iter().enumerate() {
        if !region.start.is_multiple_of(host_page_size)
            || !region.end.is_multiple_of(host_page_size)
            || region.start >= region.end
        {
            return Ok(ineligible_limit(
                "region-host-page-geometry",
                index as u64,
                host_page_size,
            ));
        }
        artifact_size = align_up(artifact_size, host_page_size, "artifact-region-offset")?;
        let region_len = region
            .end
            .checked_sub(region.start)
            .ok_or_else(|| validation("region-length", Some(index), region.end))?;
        let extent = align_up(region_len, host_page_size, "artifact-region-extent")?;
        let next_size = artifact_size
            .checked_add(extent)
            .ok_or_else(|| validation("artifact-size-overflow", Some(index), extent))?;
        if next_size > limits.max_artifact_size {
            return Ok(ineligible_limit(
                "artifact-size",
                next_size,
                limits.max_artifact_size,
            ));
        }
        let guest_start = PreparedGuestVa::new(region.start)
            .ok_or_else(|| validation("region-start-representation", Some(index), region.start))?;
        let guest_end = PreparedGuestVa::new(region.end)
            .ok_or_else(|| validation("region-end-representation", Some(index), region.end))?;
        let artifact_offset = PreparedArtifactOffset::new(artifact_size).ok_or_else(|| {
            validation("artifact-offset-representation", Some(index), artifact_size)
        })?;
        let artifact_extent = PreparedGuestLen::new(extent)
            .ok_or_else(|| validation("artifact-extent-representation", Some(index), extent))?;
        regions.push(NativePreparedRegionV1 {
            guest_start,
            guest_end,
            permissions: permissions_to_wire(region.perms),
            shared: region.shared,
            artifact_offset,
            artifact_extent,
        });
        artifact_size = next_size;
    }

    let mut initialized_spans = Vec::new();
    let mut payloads = Vec::<Vec<u8>>::new();
    let mut written_byte_count = 0_u64;
    for (region_index, (region, wire_region)) in image.regions().iter().zip(&regions).enumerate() {
        let window = native_region_copy_window(region, image.initial_stack_pointer());
        let page_size = usize::try_from(host_page_size)
            .map_err(|_| validation("host-page-usize", None, host_page_size))?;
        let mut cursor = window.start;
        let mut run_start = None;
        let mut run_bytes = Vec::new();
        while cursor < window.end {
            let next_boundary = cursor
                .checked_div(page_size)
                .and_then(|page| page.checked_add(1))
                .and_then(|page| page.checked_mul(page_size))
                .unwrap_or(window.end)
                .min(window.end);
            let page = &region.bytes()[cursor..next_boundary];
            if page.iter().any(|byte| *byte != 0) {
                if run_start.is_none() {
                    let projected_spans =
                        initialized_spans.len().checked_add(1).ok_or_else(|| {
                            validation(
                                "initialized-span-count-overflow",
                                Some(region_index),
                                initialized_spans.len() as u64,
                            )
                        })?;
                    if projected_spans > limits.max_initialized_spans {
                        return Ok(ineligible_limit(
                            "initialized-span-count",
                            projected_spans as u64,
                            limits.max_initialized_spans as u64,
                        ));
                    }
                }
                let pending_bytes = u64::try_from(run_bytes.len())
                    .ok()
                    .and_then(|length| {
                        u64::try_from(page.len())
                            .ok()
                            .and_then(|page_length| length.checked_add(page_length))
                    })
                    .ok_or_else(|| {
                        validation(
                            "projected-written-byte-overflow",
                            Some(region_index),
                            written_byte_count,
                        )
                    })?;
                let projected_written =
                    written_byte_count
                        .checked_add(pending_bytes)
                        .ok_or_else(|| {
                            validation(
                                "projected-written-byte-overflow",
                                Some(region_index),
                                written_byte_count,
                            )
                        })?;
                if projected_written > limits.max_written_bytes {
                    return Ok(ineligible_limit(
                        "written-byte-count",
                        projected_written,
                        limits.max_written_bytes,
                    ));
                }
                run_start.get_or_insert(cursor);
                run_bytes.extend_from_slice(page);
            } else if let Some(start) = run_start.take() {
                push_initialized_span(
                    region_index,
                    wire_region,
                    start,
                    std::mem::take(&mut run_bytes),
                    &mut initialized_spans,
                    &mut payloads,
                    &mut written_byte_count,
                )?;
            }
            cursor = next_boundary;
        }
        if let Some(start) = run_start {
            push_initialized_span(
                region_index,
                wire_region,
                start,
                run_bytes,
                &mut initialized_spans,
                &mut payloads,
                &mut written_byte_count,
            )?;
        }
    }

    let file = tempfile::tempfile().map_err(|source| NativePreparedImageError::Io {
        stage: "create-artifact",
        source,
    })?;
    file.set_len(artifact_size)
        .map_err(|source| NativePreparedImageError::Io {
            stage: "size-artifact",
            source,
        })?;
    let identity = FileIdentity::for_fd(std::os::fd::AsRawFd::as_raw_fd(&file))?
        .require_regular(std::os::fd::AsRawFd::as_raw_fd(&file))?;
    let entry = PreparedGuestVa::new(image.entry())
        .ok_or_else(|| validation("entry-representation", None, image.entry()))?;
    let initial_stack_pointer_raw = image
        .initial_stack_pointer()
        .ok_or_else(|| validation("missing-initial-stack-pointer", None, 0))?;
    let initial_stack_pointer =
        PreparedGuestVa::new(initial_stack_pointer_raw).ok_or_else(|| {
            validation(
                "initial-stack-pointer-representation",
                None,
                initial_stack_pointer_raw,
            )
        })?;
    let ro_spans = image
        .ro_spans()
        .iter()
        .enumerate()
        .map(|(index, span)| {
            Ok(NativePreparedRoSpanV1 {
                start: PreparedGuestVa::new(span.start).ok_or_else(|| {
                    validation("ro-span-start-representation", Some(index), span.start)
                })?,
                len: PreparedGuestLen::new(span.len).ok_or_else(|| {
                    validation("ro-span-length-representation", Some(index), span.len)
                })?,
                exec: span.exec,
            })
        })
        .collect::<Result<Vec<_>, NativePreparedImageError>>()?;
    let mut record = NativePreparedImageV1 {
        artifact_fd: std::os::fd::AsRawFd::as_raw_fd(&file),
        original_host_fd_flags: identity.fd_flags,
        artifact_device: identity.device,
        artifact_inode: identity.inode,
        artifact_size,
        version: PREPARED_IMAGE_VERSION,
        host_page_size,
        entry,
        initial_stack_pointer,
        auxv: image.linux_auxv_image().to_vec(),
        regions,
        initialized_spans,
        ro_spans,
        relocations: relocations.to_vec(),
        written_byte_count,
        digest: [0; 32],
    };
    validate_record(&record, &identity)?;

    let mut hasher = digest_metadata(&record);
    for (span, payload) in record.initialized_spans.iter().zip(&payloads) {
        file.write_all_at(payload, span.artifact_offset.get())
            .map_err(|source| NativePreparedImageError::Io {
                stage: "write-initialized-span",
                source,
            })?;
        hasher.update(payload);
    }
    record.digest = hasher.finalize().into();
    let final_identity =
        FileIdentity::for_fd(record.artifact_fd)?.require_regular(record.artifact_fd)?;
    validate_record(&record, &final_identity)?;
    Ok(PreparedImageDisposition::Prepared(PreparedImageArtifact {
        record,
        file,
    }))
}

#[cfg(target_os = "macos")]
pub(crate) fn validate_for_resume(
    record: NativePreparedImageV1,
) -> Result<ValidatedPreparedImage, NativePreparedImageError> {
    let inherited = RawFdGuard(record.artifact_fd);
    let duplicate = unsafe { libc::fcntl(inherited.0, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(io_error("duplicate-artifact-fd"));
    }
    let file = unsafe { File::from_raw_fd(duplicate) };

    let inherited_flags = fd_flags_for_fd(inherited.0, "get-inherited-artifact-fd-flags")?;
    let expected_transit_flags = record.original_host_fd_flags & !libc::FD_CLOEXEC;
    if inherited_flags != expected_transit_flags {
        return Err(file_identity_error(
            "artifact-transit-fd-flags",
            inherited.0,
            format!("expected=0x{expected_transit_flags:x}, actual=0x{inherited_flags:x}"),
        ));
    }

    let duplicate_identity = FileIdentity::for_fd(duplicate)?.require_regular(duplicate)?;
    verify_identity_fields(&record, &duplicate_identity, duplicate, true)?;
    drop(inherited);
    validate_record(&record, &duplicate_identity)?;
    let actual_digest = digest_with_file_payload(&record, &file)?;
    if actual_digest != record.digest {
        return Err(NativePreparedImageError::ChecksumMismatch {
            expected: record.digest,
            actual: actual_digest,
        });
    }

    let metadata = AddressSpaceMetadata {
        entry: carrick_guest_mem::GuestVa(record.entry.get()),
        initial_stack_pointer: carrick_guest_mem::GuestVa(record.initial_stack_pointer.get()),
        linux_auxv_image: record.auxv.clone(),
        regions: record
            .regions
            .iter()
            .enumerate()
            .map(|(index, region)| {
                Ok(MemoryRegionMetadata {
                    start: carrick_guest_mem::GuestVa(region.guest_start.get()),
                    end: carrick_guest_mem::GuestVa(region.guest_end.get()),
                    perms: permissions_from_wire(region.permissions, index)?,
                    shared: region.shared,
                })
            })
            .collect::<Result<Vec<_>, NativePreparedImageError>>()?,
        ro_spans: record
            .ro_spans
            .iter()
            .map(|span| RoSpan {
                start: span.start.get(),
                len: span.len.get(),
                exec: span.exec,
            })
            .collect(),
    };
    let image = AddressSpace::from_metadata(metadata)?;
    let backings = record
        .regions
        .iter()
        .map(|region| PreparedImageFileBacking {
            artifact_offset: region.artifact_offset,
            artifact_extent: region.artifact_extent,
        })
        .collect();
    Ok(ValidatedPreparedImage {
        file,
        image,
        backings,
        relocations: record.relocations,
    })
}

#[cfg(target_os = "macos")]
fn fd_flags_for_fd(fd: RawFd, stage: &'static str) -> Result<i32, NativePreparedImageError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io_error(stage));
    }
    Ok(flags)
}

#[cfg(target_os = "macos")]
fn validate_record(
    record: &NativePreparedImageV1,
    identity: &FileIdentity,
) -> Result<(), NativePreparedImageError> {
    if record.version != PREPARED_IMAGE_VERSION {
        return Err(validation(
            "format-version",
            None,
            u64::from(record.version),
        ));
    }
    let system_page_size = host_page_size()?;
    if record.host_page_size != system_page_size
        || !record.host_page_size.is_power_of_two()
        || record.host_page_size == 0
    {
        return Err(validation(
            "host-page-geometry",
            None,
            record.host_page_size,
        ));
    }
    if PreparedGuestVa::new(record.entry.get()).is_none() {
        return Err(validation("entry-representation", None, record.entry.get()));
    }
    if PreparedGuestVa::new(record.initial_stack_pointer.get()).is_none() {
        return Err(validation(
            "initial-stack-pointer-representation",
            None,
            record.initial_stack_pointer.get(),
        ));
    }
    verify_identity_fields(record, identity, record.artifact_fd, true)?;
    if record.artifact_size == 0
        || record.artifact_size > MAX_ARTIFACT_SIZE
        || !record.artifact_size.is_multiple_of(record.host_page_size)
    {
        return Err(validation(
            "artifact-size-bound",
            None,
            record.artifact_size,
        ));
    }
    if record.written_byte_count > MAX_WRITTEN_BYTES {
        return Err(validation(
            "written-byte-bound",
            None,
            record.written_byte_count,
        ));
    }
    if record.auxv.len() > MAX_AUXV_BYTES {
        return Err(validation("auxv-bound", None, record.auxv.len() as u64));
    }
    if record.regions.is_empty() || record.regions.len() > MAX_REGIONS {
        return Err(validation(
            "region-count",
            None,
            record.regions.len() as u64,
        ));
    }
    if record.initialized_spans.len() > MAX_INITIALIZED_SPANS {
        return Err(validation(
            "initialized-span-count",
            None,
            record.initialized_spans.len() as u64,
        ));
    }

    let mut previous_guest_end = 0_u64;
    let mut previous_artifact_end = 0_u64;
    for (index, region) in record.regions.iter().enumerate() {
        let start = region.guest_start.get();
        let end = region.guest_end.get();
        if PreparedGuestVa::new(start).is_none()
            || PreparedGuestVa::new(end).is_none()
            || start >= end
            || !start.is_multiple_of(record.host_page_size)
            || !end.is_multiple_of(record.host_page_size)
            || (index != 0 && start < previous_guest_end)
        {
            return Err(validation("region-guest-extent", Some(index), start));
        }
        let region_len = end
            .checked_sub(start)
            .ok_or_else(|| validation("region-guest-length", Some(index), end))?;
        let offset = region.artifact_offset.get();
        let extent = region.artifact_extent.get();
        let artifact_end = offset
            .checked_add(extent)
            .ok_or_else(|| validation("region-artifact-overflow", Some(index), offset))?;
        if PreparedArtifactOffset::new(offset).is_none()
            || PreparedGuestLen::new(extent).is_none()
            || !offset.is_multiple_of(record.host_page_size)
            || !extent.is_multiple_of(record.host_page_size)
            || extent != align_up(region_len, record.host_page_size, "region-extent-check")?
            || artifact_end > record.artifact_size
            || (index != 0 && offset < previous_artifact_end)
        {
            return Err(validation("region-artifact-extent", Some(index), offset));
        }
        if region.shared {
            return Err(validation("shared-region-import", Some(index), 1));
        }
        permissions_from_wire(region.permissions, index)?;
        previous_guest_end = end;
        previous_artifact_end = artifact_end;
    }

    let entry_count = record
        .regions
        .iter()
        .filter(|region| {
            region.permissions & 0b100 != 0
                && record.entry.get() >= region.guest_start.get()
                && record.entry.get() < region.guest_end.get()
        })
        .count();
    if entry_count != 1 {
        return Err(validation(
            "entry-executable-region",
            None,
            record.entry.get(),
        ));
    }
    let stack_start = crate::memory::LINUX_STACK_TOP - crate::memory::LINUX_STACK_SIZE;
    let stack_region_index = record
        .regions
        .iter()
        .position(|region| {
            region.guest_start.get() == stack_start
                && region.guest_end.get() == crate::memory::LINUX_STACK_TOP
        })
        .ok_or_else(|| validation("canonical-stack-region", None, stack_start))?;
    let stack_region = &record.regions[stack_region_index];
    if stack_region.permissions & 0b010 == 0
        || record.initial_stack_pointer.get() < stack_start
        || record.initial_stack_pointer.get() >= crate::memory::LINUX_STACK_TOP
    {
        return Err(validation(
            "stack-pointer-canonical-region",
            Some(stack_region_index),
            record.initial_stack_pointer.get(),
        ));
    }
    let stack_initialized_floor = record
        .initial_stack_pointer
        .get()
        .checked_sub(stack_start)
        .ok_or_else(|| {
            validation(
                "stack-initialized-floor",
                Some(stack_region_index),
                record.initial_stack_pointer.get(),
            )
        })?;

    let mut calculated_written = 0_u64;
    let mut previous_span_end = 0_u64;
    for (index, span) in record.initialized_spans.iter().enumerate() {
        if span.byte_len.get() == 0 {
            return Err(validation("span-byte-length", Some(index), 0));
        }
        let region_index = usize::from(span.region_index.get());
        if PreparedRegionIndex::new(region_index).is_none()
            || PreparedGuestOffset::new(span.guest_offset.get()).is_none()
            || PreparedArtifactOffset::new(span.artifact_offset.get()).is_none()
            || PreparedGuestLen::new(span.byte_len.get()).is_none()
        {
            return Err(validation(
                "span-domain-representation",
                Some(index),
                span.artifact_offset.get(),
            ));
        }
        if region_index == stack_region_index && span.guest_offset.get() < stack_initialized_floor {
            return Err(validation(
                "stack-span-before-initial-sp",
                Some(index),
                span.guest_offset.get(),
            ));
        }
        let region = record
            .regions
            .get(region_index)
            .ok_or_else(|| validation("span-region-index", Some(index), region_index as u64))?;
        let guest_end = span
            .guest_offset
            .get()
            .checked_add(span.byte_len.get())
            .ok_or_else(|| {
                validation("span-guest-overflow", Some(index), span.guest_offset.get())
            })?;
        if guest_end > region.guest_len().unwrap_or(0) {
            return Err(validation("span-guest-bound", Some(index), guest_end));
        }
        let expected_offset = region
            .artifact_offset
            .get()
            .checked_add(span.guest_offset.get())
            .ok_or_else(|| {
                validation(
                    "span-offset-overflow",
                    Some(index),
                    span.artifact_offset.get(),
                )
            })?;
        let artifact_end = span
            .artifact_offset
            .get()
            .checked_add(span.byte_len.get())
            .ok_or_else(|| {
                validation(
                    "span-artifact-overflow",
                    Some(index),
                    span.artifact_offset.get(),
                )
            })?;
        if span.artifact_offset.get() != expected_offset
            || artifact_end > record.artifact_size
            || (index != 0 && span.artifact_offset.get() < previous_span_end)
        {
            return Err(validation(
                "span-artifact-bound",
                Some(index),
                span.artifact_offset.get(),
            ));
        }
        previous_span_end = artifact_end;
        calculated_written = calculated_written
            .checked_add(span.byte_len.get())
            .ok_or_else(|| validation("written-byte-overflow", Some(index), span.byte_len.get()))?;
    }
    if calculated_written != record.written_byte_count {
        return Err(validation(
            "written-byte-count",
            None,
            record.written_byte_count,
        ));
    }

    for (index, span) in record.ro_spans.iter().enumerate() {
        let start = span.start.get();
        if PreparedGuestVa::new(start).is_none() || PreparedGuestLen::new(span.len.get()).is_none()
        {
            return Err(validation(
                "ro-span-domain-representation",
                Some(index),
                start,
            ));
        }
        if span.len.get() == 0 {
            return Err(validation("ro-span-length", Some(index), 0));
        }
        let end = start
            .checked_add(span.len.get())
            .ok_or_else(|| validation("ro-span-overflow", Some(index), start))?;
        if !start.is_multiple_of(0x1000) || !span.len.get().is_multiple_of(0x1000) {
            return Err(validation("ro-span-alignment", Some(index), start));
        }
        let contained = record.regions.iter().any(|region| {
            let readable = region.permissions & 0b001 != 0;
            let executable_ok = !span.exec || region.permissions & 0b100 != 0;
            readable
                && executable_ok
                && start >= region.guest_start.get()
                && end <= region.guest_end.get()
        });
        if !contained {
            return Err(validation("ro-span-permission", Some(index), start));
        }
    }
    for (index, relocation) in record.relocations.iter().enumerate() {
        if PreparedGuestVa::new(relocation.address().get()).is_none()
            || PreparedGuestVa::new(relocation.value().get()).is_none()
        {
            return Err(validation(
                "relocation-domain-representation",
                Some(index),
                relocation.address().get(),
            ));
        }
        let end = relocation.address().get().checked_add(8).ok_or_else(|| {
            validation(
                "relocation-target-overflow",
                Some(index),
                relocation.address().get(),
            )
        })?;
        let contained = record.regions.iter().any(|region| {
            region.permissions & 0b010 != 0
                && relocation.address().get() >= region.guest_start.get()
                && end <= region.guest_end.get()
        });
        if !contained {
            return Err(validation(
                "relocation-target-writable",
                Some(index),
                relocation.address().get(),
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn push_initialized_span(
    region_index: usize,
    region: &NativePreparedRegionV1,
    start: usize,
    payload: Vec<u8>,
    spans: &mut Vec<NativePreparedSpanV1>,
    payloads: &mut Vec<Vec<u8>>,
    written: &mut u64,
) -> Result<(), NativePreparedImageError> {
    let guest_offset = u64::try_from(start)
        .map_err(|_| validation("span-guest-offset", Some(region_index), start as u64))?;
    let byte_len = u64::try_from(payload.len())
        .map_err(|_| validation("span-byte-length", Some(region_index), payload.len() as u64))?;
    let artifact_offset = region
        .artifact_offset
        .get()
        .checked_add(guest_offset)
        .ok_or_else(|| validation("span-artifact-offset", Some(region_index), guest_offset))?;
    *written = written
        .checked_add(byte_len)
        .ok_or_else(|| validation("written-byte-overflow", Some(region_index), byte_len))?;
    spans.push(NativePreparedSpanV1 {
        region_index: PreparedRegionIndex::new(region_index).ok_or_else(|| {
            validation(
                "region-index-representation",
                Some(region_index),
                region_index as u64,
            )
        })?,
        guest_offset: PreparedGuestOffset::new(guest_offset)
            .ok_or_else(|| validation("span-guest-offset", Some(region_index), guest_offset))?,
        artifact_offset: PreparedArtifactOffset::new(artifact_offset).ok_or_else(|| {
            validation(
                "span-artifact-offset-representation",
                Some(region_index),
                artifact_offset,
            )
        })?,
        byte_len: PreparedGuestLen::new(byte_len)
            .ok_or_else(|| validation("span-byte-length", Some(region_index), byte_len))?,
    });
    payloads.push(payload);
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_identity_fields(
    record: &NativePreparedImageV1,
    identity: &FileIdentity,
    fd: RawFd,
    check_flags: bool,
) -> Result<(), NativePreparedImageError> {
    if identity.device != record.artifact_device
        || identity.inode != record.artifact_inode
        || identity.size != record.artifact_size
        || (check_flags && identity.fd_flags != record.original_host_fd_flags)
    {
        return Err(file_identity_error(
            "artifact-identity",
            fd,
            format!(
                "expected dev={} ino={} size={} flags=0x{:x}; actual dev={} ino={} size={} flags=0x{:x}",
                record.artifact_device,
                record.artifact_inode,
                record.artifact_size,
                record.original_host_fd_flags,
                identity.device,
                identity.inode,
                identity.size,
                identity.fd_flags
            ),
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn digest_metadata(record: &NativePreparedImageV1) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(PREPARED_IMAGE_MAGIC);
    hash_u32(&mut hasher, record.version);
    hash_u64(&mut hasher, record.host_page_size);
    hash_u64(&mut hasher, record.artifact_size);
    hash_u64(&mut hasher, record.written_byte_count);
    hash_u64(&mut hasher, record.entry.get());
    hash_u64(&mut hasher, record.initial_stack_pointer.get());
    hash_bytes(&mut hasher, &record.auxv);
    hash_u64(&mut hasher, record.regions.len() as u64);
    for region in &record.regions {
        hash_u64(&mut hasher, region.guest_start.get());
        hash_u64(&mut hasher, region.guest_end.get());
        hasher.update([region.permissions, u8::from(region.shared)]);
        hash_u64(&mut hasher, region.artifact_offset.get());
        hash_u64(&mut hasher, region.artifact_extent.get());
    }
    hash_u64(&mut hasher, record.initialized_spans.len() as u64);
    for span in &record.initialized_spans {
        hasher.update(span.region_index.get().to_le_bytes());
        hash_u64(&mut hasher, span.guest_offset.get());
        hash_u64(&mut hasher, span.artifact_offset.get());
        hash_u64(&mut hasher, span.byte_len.get());
    }
    hash_u64(&mut hasher, record.ro_spans.len() as u64);
    for span in &record.ro_spans {
        hash_u64(&mut hasher, span.start.get());
        hash_u64(&mut hasher, span.len.get());
        hasher.update([u8::from(span.exec)]);
    }
    hash_u64(&mut hasher, record.relocations.len() as u64);
    for relocation in &record.relocations {
        hash_u64(&mut hasher, relocation.address().get());
        hash_u64(&mut hasher, relocation.value().get());
    }
    hasher
}

#[cfg(target_os = "macos")]
fn digest_with_file_payload(
    record: &NativePreparedImageV1,
    file: &File,
) -> Result<[u8; 32], NativePreparedImageError> {
    let mut hasher = digest_metadata(record);
    for (index, span) in record.initialized_spans.iter().enumerate() {
        let length = usize::try_from(span.byte_len.get())
            .map_err(|_| validation("digest-span-length", Some(index), span.byte_len.get()))?;
        let mut payload = vec![0_u8; length];
        file.read_exact_at(&mut payload, span.artifact_offset.get())
            .map_err(|source| NativePreparedImageError::Io {
                stage: "read-initialized-span",
                source,
            })?;
        hasher.update(&payload);
    }
    Ok(hasher.finalize().into())
}

#[cfg(target_os = "macos")]
fn permissions_to_wire(perms: SegmentPerms) -> u8 {
    u8::from(perms.read) | (u8::from(perms.write) << 1) | (u8::from(perms.execute) << 2)
}

#[cfg(target_os = "macos")]
fn permissions_from_wire(
    value: u8,
    index: usize,
) -> Result<SegmentPerms, NativePreparedImageError> {
    if value & !0b111 != 0 {
        return Err(validation(
            "region-permissions",
            Some(index),
            u64::from(value),
        ));
    }
    Ok(SegmentPerms {
        read: value & 0b001 != 0,
        write: value & 0b010 != 0,
        execute: value & 0b100 != 0,
    })
}

#[cfg(target_os = "macos")]
fn align_up(
    value: u64,
    alignment: u64,
    stage: &'static str,
) -> Result<u64, NativePreparedImageError> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(validation(stage, None, alignment));
    }
    value
        .checked_add(alignment - 1)
        .map(|sum| sum & !(alignment - 1))
        .ok_or_else(|| validation(stage, None, value))
}

#[cfg(target_os = "macos")]
fn host_page_size() -> Result<u64, NativePreparedImageError> {
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    u64::try_from(value).map_err(|_| io_error("host-page-size"))
}

#[cfg(target_os = "macos")]
fn hash_u32(hasher: &mut Sha256, value: u32) {
    hasher.update(value.to_le_bytes());
}

#[cfg(target_os = "macos")]
fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

#[cfg(target_os = "macos")]
fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hash_u64(hasher, bytes.len() as u64);
    hasher.update(bytes);
}

#[cfg(target_os = "macos")]
fn validation(stage: &'static str, index: Option<usize>, value: u64) -> NativePreparedImageError {
    NativePreparedImageError::Validation {
        stage,
        index,
        value,
    }
}

#[cfg(target_os = "macos")]
fn io_error(stage: &'static str) -> NativePreparedImageError {
    NativePreparedImageError::Io {
        stage,
        source: std::io::Error::last_os_error(),
    }
}

#[cfg(target_os = "macos")]
fn file_identity_error(stage: &'static str, fd: RawFd, reason: String) -> NativePreparedImageError {
    NativePreparedImageError::FileIdentity { stage, fd, reason }
}

#[cfg(target_os = "macos")]
fn ineligible_limit(stage: &'static str, value: u64, limit: u64) -> PreparedImageDisposition {
    PreparedImageDisposition::Ineligible(PreparedImageIneligibleReason::RepresentationLimit {
        stage,
        value,
        limit,
    })
}

#[cfg(test)]
#[cfg(target_os = "macos")]
mod tests {
    use super::*;
    use crate::elf::SegmentPerms;
    use crate::memory::{AddressSpace, LINUX_STACK_SIZE, LINUX_STACK_TOP};
    use std::mem::ManuallyDrop;
    use std::os::fd::IntoRawFd;
    use std::os::unix::fs::{FileExt, MetadataExt};

    const HOST_PAGE_SIZE: u64 = 16 * 1024;

    fn synthetic_elf() -> Vec<u8> {
        const ET_EXEC: u16 = 2;
        const EM_AARCH64: u16 = 183;
        const PT_LOAD: u32 = 1;
        const PF_R_X: u32 = 5;
        let mut elf = vec![0_u8; 0x1000];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        elf[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
        elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
        elf[24..32].copy_from_slice(&0x400000_u64.to_le_bytes());
        elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1_u16.to_le_bytes());
        let ph = 64;
        elf[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        elf[ph + 4..ph + 8].copy_from_slice(&PF_R_X.to_le_bytes());
        elf[ph + 16..ph + 24].copy_from_slice(&0x400000_u64.to_le_bytes());
        elf[ph + 24..ph + 32].copy_from_slice(&0x400000_u64.to_le_bytes());
        let file_len = elf.len() as u64;
        elf[ph + 32..ph + 40].copy_from_slice(&file_len.to_le_bytes());
        elf[ph + 40..ph + 48].copy_from_slice(&0x4000_u64.to_le_bytes());
        elf[ph + 48..ph + 56].copy_from_slice(&0x1000_u64.to_le_bytes());
        elf[0x800..0x808].copy_from_slice(b"carrick!");
        elf
    }

    fn synthetic_image() -> AddressSpace {
        AddressSpace::load_elf_bytes_with_reader_at_pie_base_without_runtime_regions(
            &synthetic_elf(),
            &|_| None,
            0x400000,
            HOST_PAGE_SIZE,
        )
        .expect("load synthetic executable")
        .with_linux_initial_stack_page_size(
            [b"prepared-image".as_slice()],
            [b"MODE=test".as_slice()],
            HOST_PAGE_SIZE,
        )
        .expect("build synthetic stack")
    }

    fn relocations() -> Vec<NativeRelativeRelocation> {
        let stack_target = LINUX_STACK_TOP - 0x100;
        vec![
            NativeRelativeRelocation::new(
                PreparedGuestVa::new(stack_target).unwrap(),
                PreparedGuestVa::new(0x1234).unwrap(),
            ),
            NativeRelativeRelocation::new(
                PreparedGuestVa::new(stack_target - 8).unwrap(),
                PreparedGuestVa::new(0x5678).unwrap(),
            ),
        ]
    }

    fn prepared() -> PreparedImageArtifact {
        match prepare(&synthetic_image(), &relocations(), HOST_PAGE_SIZE)
            .expect("prepare sparse artifact")
        {
            PreparedImageDisposition::Prepared(artifact) => artifact,
            PreparedImageDisposition::Ineligible(reason) => {
                panic!("synthetic image unexpectedly ineligible: {reason:?}")
            }
        }
    }

    fn duplicate_for_resume(artifact: &PreparedImageArtifact) -> NativePreparedImageV1 {
        let mut record = artifact.record.clone();
        let duplicate = unsafe { libc::fcntl(record.artifact_fd, libc::F_DUPFD, 0) };
        assert!(
            duplicate >= 0,
            "duplicate artifact fd: {}",
            std::io::Error::last_os_error()
        );
        record.artifact_fd = duplicate;
        let transit_flags = record.original_host_fd_flags & !libc::FD_CLOEXEC;
        assert_eq!(
            unsafe { libc::fcntl(duplicate, libc::F_SETFD, transit_flags) },
            0
        );
        record
    }

    fn validated_record(artifact: &PreparedImageArtifact) -> NativePreparedImageV1 {
        artifact.record.clone()
    }

    fn assert_invalid(record: &NativePreparedImageV1) {
        let identity = FileIdentity::for_fd(record.artifact_fd).expect("artifact identity");
        assert!(validate_record(record, &identity).is_err());
    }

    #[test]
    fn prepared_image_round_trips_sparse_bytes_and_metadata() {
        let source = synthetic_image();
        let artifact = match prepare(&source, &relocations(), HOST_PAGE_SIZE).unwrap() {
            PreparedImageDisposition::Prepared(artifact) => artifact,
            PreparedImageDisposition::Ineligible(reason) => panic!("ineligible: {reason:?}"),
        };
        let record = duplicate_for_resume(&artifact);
        let validated = validate_for_resume(record).expect("validate inherited artifact");

        assert_eq!(validated.image.entry(), source.entry());
        assert_eq!(
            validated.image.initial_stack_pointer(),
            source.initial_stack_pointer()
        );
        assert_eq!(
            validated.image.linux_auxv_image(),
            source.linux_auxv_image()
        );
        assert_eq!(validated.image.ro_spans(), source.ro_spans());
        assert_eq!(validated.relocations, relocations());
        assert_eq!(validated.image.regions().len(), source.regions().len());
        assert_eq!(validated.backings.len(), source.regions().len());
        for ((metadata, backing), source_region) in validated
            .image
            .regions()
            .iter()
            .zip(&validated.backings)
            .zip(source.regions())
        {
            assert_eq!(
                (metadata.start, metadata.end),
                (source_region.start, source_region.end)
            );
            assert_eq!(metadata.perms, source_region.perms);
            assert_eq!(metadata.shared, source_region.shared);
            let mut bytes = vec![0_u8; usize::try_from(source_region.len()).unwrap()];
            validated
                .file
                .read_exact_at(&mut bytes, backing.artifact_offset.get())
                .unwrap();
            assert_eq!(backing.artifact_extent.get(), source_region.len());
            assert_eq!(bytes, source_region.bytes());
        }
    }

    #[test]
    fn prepared_image_rejects_bad_version_and_host_page_geometry() {
        let artifact = prepared();
        let mut record = validated_record(&artifact);
        record.version += 1;
        assert_invalid(&record);
        let mut record = validated_record(&artifact);
        record.host_page_size = 4096;
        assert_invalid(&record);
    }

    #[test]
    fn prepared_image_rejects_non_regular_artifact_fds() {
        let artifact = prepared();
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let mut record = validated_record(&artifact);
        record.artifact_fd = fds[0];
        let error = validate_for_resume(record).expect_err("pipe must be rejected");
        assert_eq!(
            unsafe { libc::fcntl(fds[0], libc::F_GETFD) },
            -1,
            "the inherited fd must close after an owned duplicate exists"
        );
        unsafe {
            libc::close(fds[1]);
        }
        assert!(matches!(
            error,
            NativePreparedImageError::FileIdentity {
                stage: "artifact-file-type",
                fd,
                ..
            } if fd != fds[0]
        ));
    }

    #[test]
    fn prepared_image_rejects_fd_identity_size_and_flag_mismatches() {
        let artifact = prepared();
        for mutate in [
            |r: &mut NativePreparedImageV1| r.artifact_device ^= 1,
            |r: &mut NativePreparedImageV1| r.artifact_inode ^= 1,
            |r: &mut NativePreparedImageV1| r.artifact_size += HOST_PAGE_SIZE,
            |r: &mut NativePreparedImageV1| r.original_host_fd_flags ^= libc::FD_CLOEXEC,
        ] {
            let mut record = duplicate_for_resume(&artifact);
            mutate(&mut record);
            assert!(validate_for_resume(record).is_err());
        }
    }

    #[test]
    fn prepared_image_rejects_truncated_and_extended_artifacts() {
        for delta in [-1_i64, 1] {
            let artifact = prepared();
            let raw = artifact.file.into_raw_fd();
            let record = ManuallyDrop::new(artifact.record);
            let changed = (record.artifact_size as i64 + delta) as libc::off_t;
            assert_eq!(unsafe { libc::ftruncate(raw, changed) }, 0);
            let mut resume = (*record).clone();
            resume.artifact_fd = raw;
            let flags = resume.original_host_fd_flags & !libc::FD_CLOEXEC;
            assert_eq!(unsafe { libc::fcntl(raw, libc::F_SETFD, flags) }, 0);
            assert!(validate_for_resume(resume).is_err());
        }
    }

    #[test]
    fn prepared_image_rejects_invalid_region_extents() {
        type RecordMutation = Box<dyn Fn(&mut NativePreparedImageV1)>;

        let artifact = prepared();
        let cases: Vec<RecordMutation> = vec![
            Box::new(|r| r.regions[0].artifact_offset = PreparedArtifactOffset(HOST_PAGE_SIZE / 2)),
            Box::new(|r| {
                r.regions[0].guest_start = PreparedGuestVa(r.regions[0].guest_start.get() + 1)
            }),
            Box::new(|r| {
                r.regions[0].guest_end =
                    PreparedGuestVa(r.regions[0].guest_start.get().saturating_sub(1))
            }),
            Box::new(|r| r.regions[1].guest_start = r.regions[0].guest_start),
            Box::new(|r| r.regions[1].artifact_offset = r.regions[0].artifact_offset),
            Box::new(|r| {
                r.regions[0].artifact_extent = PreparedGuestLen(r.artifact_size + HOST_PAGE_SIZE)
            }),
        ];
        for mutate in cases {
            let mut record = validated_record(&artifact);
            mutate(&mut record);
            assert_invalid(&record);
        }
    }

    #[test]
    fn prepared_image_limits_are_ineligible_at_construction_and_invalid_on_import() {
        let shared = AddressSpace::from_metadata(crate::memory::AddressSpaceMetadata {
            entry: carrick_guest_mem::GuestVa(0x4000),
            initial_stack_pointer: carrick_guest_mem::GuestVa(0x8000),
            linux_auxv_image: Vec::new(),
            regions: vec![crate::memory::MemoryRegionMetadata {
                start: carrick_guest_mem::GuestVa(0x4000),
                end: carrick_guest_mem::GuestVa(0xc000),
                perms: SegmentPerms {
                    read: true,
                    write: true,
                    execute: false,
                },
                shared: true,
            }],
            ro_spans: Vec::new(),
        })
        .unwrap();
        assert!(matches!(
            prepare(&shared, &[], HOST_PAGE_SIZE).unwrap(),
            PreparedImageDisposition::Ineligible(
                PreparedImageIneligibleReason::SharedRegion { .. }
            )
        ));

        let regions = (0..257_u64)
            .map(|index| {
                let start = 0x1_0000 + index * HOST_PAGE_SIZE;
                crate::memory::MemoryRegionMetadata {
                    start: carrick_guest_mem::GuestVa(start),
                    end: carrick_guest_mem::GuestVa(start + HOST_PAGE_SIZE),
                    perms: SegmentPerms {
                        read: true,
                        write: index == 1,
                        execute: index == 0,
                    },
                    shared: false,
                }
            })
            .collect();
        let too_many_source_regions =
            AddressSpace::from_metadata(crate::memory::AddressSpaceMetadata {
                entry: carrick_guest_mem::GuestVa(0x1_0000),
                initial_stack_pointer: carrick_guest_mem::GuestVa(0x1_0000 + HOST_PAGE_SIZE),
                linux_auxv_image: Vec::new(),
                regions,
                ro_spans: Vec::new(),
            })
            .unwrap();
        assert!(matches!(
            prepare(&too_many_source_regions, &[], HOST_PAGE_SIZE).unwrap(),
            PreparedImageDisposition::Ineligible(
                PreparedImageIneligibleReason::RepresentationLimit {
                    stage: "region-count",
                    ..
                }
            )
        ));

        let artifact = prepared();
        let mut too_many_regions = validated_record(&artifact);
        too_many_regions
            .regions
            .resize(257, too_many_regions.regions[0].clone());
        assert_invalid(&too_many_regions);
        let mut too_many_spans = validated_record(&artifact);
        too_many_spans
            .initialized_spans
            .resize(16_385, too_many_spans.initialized_spans[0].clone());
        assert_invalid(&too_many_spans);
        let mut sparse = validated_record(&artifact);
        sparse.artifact_size = 1_073_741_824 + HOST_PAGE_SIZE;
        assert_invalid(&sparse);
        let mut written = validated_record(&artifact);
        written.written_byte_count = 536_870_912 + 1;
        assert_invalid(&written);
        let mut auxv = validated_record(&artifact);
        auxv.auxv.resize(65_537, 0);
        assert_invalid(&auxv);
    }

    fn assert_constructor_ineligible_at(limits: PreparedImageLimits, expected_stage: &str) {
        let disposition =
            prepare_with_limits(&synthetic_image(), &relocations(), HOST_PAGE_SIZE, limits)
                .expect("limit selection is not an artifact error");
        assert!(matches!(
            disposition,
            PreparedImageDisposition::Ineligible(
                PreparedImageIneligibleReason::RepresentationLimit { stage, .. }
            ) if stage == expected_stage
        ));
    }

    #[test]
    fn constructor_rejects_sparse_extent_before_artifact_creation() {
        let mut limits = PreparedImageLimits::v1();
        limits.max_artifact_size = LINUX_STACK_SIZE;
        assert_constructor_ineligible_at(limits, "artifact-size");
    }

    #[test]
    fn constructor_rejects_projected_span_before_buffering_it() {
        let mut limits = PreparedImageLimits::v1();
        limits.max_initialized_spans = 1;
        assert_constructor_ineligible_at(limits, "initialized-span-count");
    }

    #[test]
    fn constructor_rejects_projected_payload_before_growing_run_buffer() {
        let mut limits = PreparedImageLimits::v1();
        limits.max_written_bytes = 1;
        assert_constructor_ineligible_at(limits, "written-byte-count");
    }

    #[test]
    fn constructor_rejects_auxv_before_artifact_creation() {
        let mut limits = PreparedImageLimits::v1();
        limits.max_auxv_bytes = 1;
        assert_constructor_ineligible_at(limits, "auxv-bytes");
    }

    #[test]
    fn prepared_image_rejects_spans_outside_region_or_artifact() {
        let artifact = prepared();
        let mut record = validated_record(&artifact);
        record.initialized_spans[0].guest_offset =
            PreparedGuestOffset(record.regions[0].guest_len().unwrap());
        assert_invalid(&record);
        let mut record = validated_record(&artifact);
        record.initialized_spans[0].artifact_offset = PreparedArtifactOffset(record.artifact_size);
        assert_invalid(&record);
    }

    #[test]
    fn prepared_image_rejects_stack_ro_permission_and_relocation_corruption() {
        let artifact = prepared();
        let mut stack = validated_record(&artifact);
        stack.initial_stack_pointer = PreparedGuestVa(0);
        assert_invalid(&stack);
        let mut ro = validated_record(&artifact);
        ro.ro_spans[0].start = PreparedGuestVa(0);
        assert_invalid(&ro);
        let mut ro_escalation = validated_record(&artifact);
        ro_escalation.ro_spans[0] = NativePreparedRoSpanV1 {
            start: PreparedGuestVa(LINUX_STACK_TOP - LINUX_STACK_SIZE),
            len: PreparedGuestLen(0x1000),
            exec: true,
        };
        assert_invalid(&ro_escalation);
        let mut permissions = validated_record(&artifact);
        permissions.regions[0].permissions = 0b1000;
        assert_invalid(&permissions);
        let mut relocation = validated_record(&artifact);
        relocation.relocations[0].address = relocation.regions[0].guest_start;
        assert_invalid(&relocation);
    }

    #[test]
    fn prepared_image_rejects_sp_in_noncanonical_writable_region() {
        let artifact = prepared();
        let mut record = validated_record(&artifact);
        record.regions[0].permissions |= 0b010;
        record.initial_stack_pointer = record.regions[0].guest_start;

        assert_invalid(&record);
    }

    #[test]
    fn prepared_image_rejects_initialized_stack_bytes_before_sp() {
        let artifact = prepared();
        let mut record = validated_record(&artifact);
        let stack_start = LINUX_STACK_TOP - LINUX_STACK_SIZE;
        let stack_index = record
            .regions
            .iter()
            .position(|region| region.guest_start.get() == stack_start)
            .unwrap();
        let span = record
            .initialized_spans
            .iter_mut()
            .find(|span| usize::from(span.region_index.get()) == stack_index)
            .unwrap();
        let before_sp = record.initial_stack_pointer.get() - stack_start - 1;
        span.guest_offset = PreparedGuestOffset(before_sp);
        span.artifact_offset =
            PreparedArtifactOffset(record.regions[stack_index].artifact_offset.get() + before_sp);

        assert_invalid(&record);
    }

    #[test]
    fn prepared_image_checksum_detects_initialized_byte_changes() {
        let artifact = prepared();
        let span = &artifact.record.initialized_spans[0];
        let mut byte = [0_u8; 1];
        artifact
            .file
            .read_exact_at(&mut byte, span.artifact_offset.get())
            .unwrap();
        byte[0] ^= 0xff;
        artifact
            .file
            .write_all_at(&byte, span.artifact_offset.get())
            .unwrap();
        let record = duplicate_for_resume(&artifact);
        assert!(matches!(
            validate_for_resume(record),
            Err(NativePreparedImageError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn prepared_stack_is_sparse_and_preserves_zero_prefix_and_suffix() {
        let source = synthetic_image();
        let artifact = match prepare(&source, &relocations(), HOST_PAGE_SIZE).unwrap() {
            PreparedImageDisposition::Prepared(artifact) => artifact,
            PreparedImageDisposition::Ineligible(reason) => panic!("ineligible: {reason:?}"),
        };
        let stack_start = LINUX_STACK_TOP - LINUX_STACK_SIZE;
        let stack_index = artifact
            .record
            .regions
            .iter()
            .position(|r| r.guest_start.get() == stack_start)
            .unwrap();
        let stack_region = &artifact.record.regions[stack_index];
        let stack_pointer = source.initial_stack_pointer().unwrap();
        let stack_spans: Vec<_> = artifact
            .record
            .initialized_spans
            .iter()
            .filter(|s| usize::from(s.region_index.get()) == stack_index)
            .collect();
        assert!(
            stack_region.artifact_offset.get() + stack_region.artifact_extent.get()
                <= artifact.record.artifact_size
        );
        assert_eq!(stack_region.artifact_extent.get(), LINUX_STACK_SIZE);
        assert!(artifact.record.artifact_size >= LINUX_STACK_SIZE);
        assert!(
            stack_spans
                .iter()
                .all(|span| stack_start + span.guest_offset.get() >= stack_pointer)
        );
        assert!(artifact.record.written_byte_count < LINUX_STACK_SIZE / 4);
        let metadata = artifact.file.metadata().unwrap();
        if metadata.blocks() != 0 {
            assert!(metadata.blocks() * 512 < LINUX_STACK_SIZE / 2);
        }
        let mut stack = vec![0_u8; usize::try_from(LINUX_STACK_SIZE).unwrap()];
        artifact
            .file
            .read_exact_at(&mut stack, stack_region.artifact_offset.get())
            .unwrap();
        let window = native_region_copy_window(
            source
                .regions()
                .iter()
                .find(|r| r.start == stack_start)
                .unwrap(),
            source.initial_stack_pointer(),
        );
        assert!(stack[..window.start].iter().all(|byte| *byte == 0));
        let source_stack = source
            .regions()
            .iter()
            .find(|r| r.start == stack_start)
            .unwrap();
        assert_eq!(&stack[window.clone()], &source_stack.bytes()[window]);
    }

    #[test]
    fn native_region_copy_window_starts_at_exact_stack_pointer() {
        let image = synthetic_image();
        let stack_start = LINUX_STACK_TOP - LINUX_STACK_SIZE;
        let stack = image
            .regions()
            .iter()
            .find(|r| r.start == stack_start)
            .unwrap();
        let sp = image.initial_stack_pointer().unwrap();
        let expected = usize::try_from(sp - stack_start).unwrap();
        assert_eq!(
            native_region_copy_window(stack, Some(sp)),
            expected..stack.bytes().len()
        );
    }

    #[test]
    fn wire_records_are_serde_round_trippable() {
        let artifact = prepared();
        let json = serde_json::to_vec(&artifact.record).unwrap();
        let decoded: NativePreparedImageV1 = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded, artifact.record);
    }

    #[test]
    fn typed_wire_domains_reject_out_of_range_construction() {
        assert!(PreparedGuestVa::new(LINUX_STACK_TOP + 1).is_none());
        assert!(PreparedGuestLen::new(0).is_none());
        assert!(PreparedGuestLen::new(MAX_ARTIFACT_SIZE + 1).is_none());
        assert!(PreparedGuestOffset::new(MAX_ARTIFACT_SIZE + 1).is_none());
        assert!(PreparedArtifactOffset::new(MAX_ARTIFACT_SIZE + 1).is_none());
        assert!(PreparedRegionIndex::new(MAX_REGIONS).is_none());
    }

    #[test]
    fn relative_relocation_keeps_target_and_value_in_guest_va_domain() {
        let target = PreparedGuestVa::new(LINUX_STACK_TOP - 0x100).unwrap();
        let value = PreparedGuestVa::new(0x1234).unwrap();
        let relocation = NativeRelativeRelocation::new(target, value);

        assert_eq!(relocation.address().get(), LINUX_STACK_TOP - 0x100);
        assert_eq!(relocation.value().get(), 0x1234);
    }
}
