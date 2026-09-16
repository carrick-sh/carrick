//! Bounded archive transfer types for the authenticated carrier endpoint.
//!
//! Paths in this module are guest-absolute VFS paths. They never carry host
//! paths, file descriptors, or process identifiers.

use std::collections::HashMap;
use std::path::{Component, Path};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::ControlNonce;

pub const MAX_ARCHIVE_CHUNK_BYTES: usize = 2 * 1024;
const MAX_ARCHIVE_PATH_BYTES: usize = 4 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveRequest {
    pub path: String,
}

impl ArchiveRequest {
    pub fn new(path: impl Into<String>) -> Result<Self, ArchiveControlError> {
        let request = Self { path: path.into() };
        request
            .validate()
            .then_some(request)
            .ok_or(ArchiveControlError::InvalidPath)
    }

    pub fn validate(&self) -> bool {
        let path = Path::new(&self.path);
        !self.path.as_bytes().contains(&0)
            && !self.path.is_empty()
            && self.path.len() <= MAX_ARCHIVE_PATH_BYTES
            && path.is_absolute()
            && !self
                .path
                .split('/')
                .any(|component| matches!(component, "." | ".."))
            && path
                .components()
                .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct ArchiveCapability(ControlNonce);

impl From<ControlNonce> for ArchiveCapability {
    fn from(value: ControlNonce) -> Self {
        Self(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, thiserror::Error)]
#[serde(tag = "kind", content = "message", rename_all = "kebab-case")]
pub enum ArchiveControlError {
    #[error("archive path is invalid")]
    InvalidPath,
    #[error("archive capability table is full")]
    Capacity,
    #[error("archive or archive chunk is too large")]
    TooLarge,
    #[error("archive capability is unknown")]
    UnknownCapability,
    #[error("archive payload is malformed or unsupported")]
    InvalidArchive,
    #[error("archive path does not exist")]
    NotFound,
    #[error("archive path is not a directory")]
    NotDirectory,
    #[error("archive filesystem operation failed: {0}")]
    Filesystem(String),
    #[error("archive control is unavailable in this carrier")]
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveChunk {
    pub bytes: Vec<u8>,
    pub eof: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveMetadata {
    pub name: String,
    pub size: u64,
    pub mode: u32,
    pub mtime_secs: i64,
    pub mtime_nanos: u32,
    pub link_target: Option<String>,
}

impl From<crate::dispatch::ArchiveEntryMetadata> for ArchiveMetadata {
    fn from(value: crate::dispatch::ArchiveEntryMetadata) -> Self {
        Self {
            name: value.name,
            size: value.size,
            mode: value.mode,
            mtime_secs: value.mtime_secs,
            mtime_nanos: value.mtime_nanos,
            link_target: value.link_target,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveReadStart {
    pub capability: ArchiveCapability,
    pub metadata: ArchiveMetadata,
}

#[derive(Debug)]
enum ArchiveRecordState {
    Reserved,
    Read { bytes: Vec<u8>, cursor: usize },
    Write { path: String, bytes: Vec<u8> },
    Applying { bytes: usize },
}

#[derive(Debug)]
struct ArchiveRecord {
    state: ArchiveRecordState,
    last_activity: Instant,
}

impl ArchiveRecord {
    fn new(state: ArchiveRecordState) -> Self {
        Self {
            state,
            last_activity: Instant::now(),
        }
    }

    fn allocated_bytes(&self) -> usize {
        match &self.state {
            ArchiveRecordState::Read { bytes, .. } | ArchiveRecordState::Write { bytes, .. } => {
                bytes.len()
            }
            ArchiveRecordState::Applying { bytes } => *bytes,
            ArchiveRecordState::Reserved => 0,
        }
    }

    fn is_idle_transfer(&self) -> bool {
        matches!(
            self.state,
            ArchiveRecordState::Read { .. } | ArchiveRecordState::Write { .. }
        )
    }
}

#[derive(Debug, Default)]
struct ArchiveTable {
    records: HashMap<ArchiveCapability, ArchiveRecord>,
    total_bytes: usize,
}

pub struct ArchiveRuntime {
    authority: crate::dispatch::ArchiveFsAuthority,
    table: parking_lot::Mutex<ArchiveTable>,
    capacity: usize,
    idle_timeout: Duration,
}

pub trait CarrierArchiveControl: Send + Sync + std::fmt::Debug + 'static {
    fn metadata(&self, request: ArchiveRequest) -> Result<ArchiveMetadata, ArchiveControlError>;
    fn begin_read(
        &self,
        capability: ArchiveCapability,
        request: ArchiveRequest,
    ) -> Result<ArchiveReadStart, ArchiveControlError>;
    fn read_chunk(
        &self,
        capability: ArchiveCapability,
    ) -> Result<ArchiveChunk, ArchiveControlError>;
    fn begin_write(
        &self,
        capability: ArchiveCapability,
        request: ArchiveRequest,
    ) -> Result<ArchiveCapability, ArchiveControlError>;
    fn write_chunk(
        &self,
        capability: ArchiveCapability,
        bytes: Vec<u8>,
        eof: bool,
    ) -> Result<bool, ArchiveControlError>;
    fn abort(&self, capability: ArchiveCapability) -> Result<(), ArchiveControlError>;
}

#[derive(Debug, Default)]
pub struct ArchiveAdmissionSlot {
    installed: parking_lot::RwLock<Option<Arc<dyn CarrierArchiveControl>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("archive control is already installed")]
pub struct ArchiveAdmissionInstallError;

impl ArchiveAdmissionSlot {
    pub fn install(
        &self,
        archive: Arc<dyn CarrierArchiveControl>,
    ) -> Result<(), ArchiveAdmissionInstallError> {
        let mut installed = self.installed.write();
        if installed.is_some() {
            return Err(ArchiveAdmissionInstallError);
        }
        *installed = Some(archive);
        Ok(())
    }

    fn installed(&self) -> Result<Arc<dyn CarrierArchiveControl>, ArchiveControlError> {
        self.installed
            .read()
            .as_ref()
            .cloned()
            .ok_or(ArchiveControlError::Unavailable)
    }
}

impl CarrierArchiveControl for ArchiveAdmissionSlot {
    fn metadata(&self, request: ArchiveRequest) -> Result<ArchiveMetadata, ArchiveControlError> {
        self.installed()?.metadata(request)
    }

    fn begin_read(
        &self,
        capability: ArchiveCapability,
        request: ArchiveRequest,
    ) -> Result<ArchiveReadStart, ArchiveControlError> {
        self.installed()?.begin_read(capability, request)
    }

    fn read_chunk(
        &self,
        capability: ArchiveCapability,
    ) -> Result<ArchiveChunk, ArchiveControlError> {
        self.installed()?.read_chunk(capability)
    }

    fn begin_write(
        &self,
        capability: ArchiveCapability,
        request: ArchiveRequest,
    ) -> Result<ArchiveCapability, ArchiveControlError> {
        self.installed()?.begin_write(capability, request)
    }

    fn write_chunk(
        &self,
        capability: ArchiveCapability,
        bytes: Vec<u8>,
        eof: bool,
    ) -> Result<bool, ArchiveControlError> {
        self.installed()?.write_chunk(capability, bytes, eof)
    }

    fn abort(&self, capability: ArchiveCapability) -> Result<(), ArchiveControlError> {
        self.installed()?.abort(capability)
    }
}

impl std::fmt::Debug for ArchiveRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ArchiveRuntime")
            .field("table", &self.table)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

const MAX_ARCHIVE_TOTAL_BYTES: usize = 32 * 1024 * 1024;
const ARCHIVE_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

impl ArchiveRuntime {
    pub(crate) fn new(authority: crate::dispatch::ArchiveFsAuthority, capacity: usize) -> Self {
        Self::new_with_idle_timeout(authority, capacity, ARCHIVE_IDLE_TIMEOUT)
    }

    fn new_with_idle_timeout(
        authority: crate::dispatch::ArchiveFsAuthority,
        capacity: usize,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            authority,
            table: parking_lot::Mutex::new(ArchiveTable::default()),
            capacity: capacity.max(1),
            idle_timeout,
        }
    }

    fn reap_idle_locked(&self, table: &mut ArchiveTable, now: Instant) {
        let mut released = 0usize;
        table.records.retain(|_, record| {
            let expired = record.is_idle_transfer()
                && now.saturating_duration_since(record.last_activity) >= self.idle_timeout;
            if expired {
                released = released.saturating_add(record.allocated_bytes());
            }
            !expired
        });
        table.total_bytes = table.total_bytes.saturating_sub(released);
    }

    fn remove_record_locked(
        table: &mut ArchiveTable,
        capability: ArchiveCapability,
    ) -> Option<ArchiveRecord> {
        let record = table.records.remove(&capability)?;
        table.total_bytes = table.total_bytes.saturating_sub(record.allocated_bytes());
        Some(record)
    }

    pub fn metadata(
        &self,
        request: ArchiveRequest,
    ) -> Result<ArchiveMetadata, ArchiveControlError> {
        if !request.validate() {
            return Err(ArchiveControlError::InvalidPath);
        }
        self.authority
            .metadata(&request.path)
            .map(ArchiveMetadata::from)
            .map_err(map_fs_error)
    }

    pub fn begin_read(
        &self,
        capability: ArchiveCapability,
        request: ArchiveRequest,
    ) -> Result<ArchiveReadStart, ArchiveControlError> {
        if !request.validate() {
            return Err(ArchiveControlError::InvalidPath);
        }
        {
            let mut table = self.table.lock();
            self.reap_idle_locked(&mut table, Instant::now());
            if table.records.len() >= self.capacity || table.records.contains_key(&capability) {
                return Err(ArchiveControlError::Capacity);
            }
            table
                .records
                .insert(capability, ArchiveRecord::new(ArchiveRecordState::Reserved));
        }
        let metadata = match self.authority.metadata(&request.path) {
            Ok(metadata) => ArchiveMetadata::from(metadata),
            Err(error) => {
                Self::remove_record_locked(&mut self.table.lock(), capability);
                return Err(map_fs_error(error));
            }
        };
        let bytes = match self.authority.export_tar(&request.path) {
            Ok(bytes) => bytes,
            Err(error) => {
                Self::remove_record_locked(&mut self.table.lock(), capability);
                return Err(map_fs_error(error));
            }
        };
        let mut table = self.table.lock();
        let Some(total) = table.total_bytes.checked_add(bytes.len()) else {
            Self::remove_record_locked(&mut table, capability);
            return Err(ArchiveControlError::TooLarge);
        };
        if total > MAX_ARCHIVE_TOTAL_BYTES {
            Self::remove_record_locked(&mut table, capability);
            return Err(ArchiveControlError::Capacity);
        }
        table.total_bytes = total;
        let Some(record) = table.records.get_mut(&capability) else {
            table.total_bytes = table.total_bytes.saturating_sub(bytes.len());
            return Err(ArchiveControlError::UnknownCapability);
        };
        record.state = ArchiveRecordState::Read { bytes, cursor: 0 };
        record.last_activity = Instant::now();
        Ok(ArchiveReadStart {
            capability,
            metadata,
        })
    }

    pub fn read_chunk(
        &self,
        capability: ArchiveCapability,
    ) -> Result<ArchiveChunk, ArchiveControlError> {
        let mut table = self.table.lock();
        self.reap_idle_locked(&mut table, Instant::now());
        let (chunk, eof) = match table.records.get_mut(&capability) {
            Some(ArchiveRecord {
                state: ArchiveRecordState::Read { bytes, cursor },
                last_activity,
            }) => {
                let end = cursor
                    .saturating_add(MAX_ARCHIVE_CHUNK_BYTES)
                    .min(bytes.len());
                let chunk = bytes[*cursor..end].to_vec();
                *cursor = end;
                *last_activity = Instant::now();
                (chunk, end == bytes.len())
            }
            _ => return Err(ArchiveControlError::UnknownCapability),
        };
        if eof {
            Self::remove_record_locked(&mut table, capability);
        }
        Ok(ArchiveChunk { bytes: chunk, eof })
    }

    pub fn begin_write(
        &self,
        capability: ArchiveCapability,
        request: ArchiveRequest,
    ) -> Result<ArchiveCapability, ArchiveControlError> {
        if !request.validate() {
            return Err(ArchiveControlError::InvalidPath);
        }
        let mut table = self.table.lock();
        self.reap_idle_locked(&mut table, Instant::now());
        if table.records.len() >= self.capacity || table.records.contains_key(&capability) {
            return Err(ArchiveControlError::Capacity);
        }
        table.records.insert(
            capability,
            ArchiveRecord::new(ArchiveRecordState::Write {
                path: request.path,
                bytes: Vec::new(),
            }),
        );
        Ok(capability)
    }

    pub fn write_chunk(
        &self,
        capability: ArchiveCapability,
        bytes: Vec<u8>,
        eof: bool,
    ) -> Result<bool, ArchiveControlError> {
        let completed = {
            let mut table = self.table.lock();
            self.reap_idle_locked(&mut table, Instant::now());
            let known = matches!(
                table.records.get(&capability),
                Some(ArchiveRecord {
                    state: ArchiveRecordState::Write { .. },
                    ..
                })
            );
            if !known {
                return Err(ArchiveControlError::UnknownCapability);
            }
            if bytes.len() > MAX_ARCHIVE_CHUNK_BYTES {
                Self::remove_record_locked(&mut table, capability);
                return Err(ArchiveControlError::TooLarge);
            }
            let Some(next_total) = table.total_bytes.checked_add(bytes.len()) else {
                Self::remove_record_locked(&mut table, capability);
                return Err(ArchiveControlError::TooLarge);
            };
            if next_total > MAX_ARCHIVE_TOTAL_BYTES {
                Self::remove_record_locked(&mut table, capability);
                return Err(ArchiveControlError::Capacity);
            }
            {
                let Some(ArchiveRecord {
                    state: ArchiveRecordState::Write { bytes: archive, .. },
                    last_activity,
                }) = table.records.get_mut(&capability)
                else {
                    return Err(ArchiveControlError::UnknownCapability);
                };
                let Some(next_archive) = archive.len().checked_add(bytes.len()) else {
                    Self::remove_record_locked(&mut table, capability);
                    return Err(ArchiveControlError::TooLarge);
                };
                if next_archive > crate::dispatch::MAX_ARCHIVE_BYTES {
                    Self::remove_record_locked(&mut table, capability);
                    return Err(ArchiveControlError::TooLarge);
                }
                archive.extend_from_slice(&bytes);
                *last_activity = Instant::now();
            }
            table.total_bytes = next_total;
            if eof {
                let Some(ArchiveRecord {
                    state: ArchiveRecordState::Write { path, bytes },
                    ..
                }) = table.records.remove(&capability)
                else {
                    return Err(ArchiveControlError::UnknownCapability);
                };
                table.records.insert(
                    capability,
                    ArchiveRecord::new(ArchiveRecordState::Applying { bytes: bytes.len() }),
                );
                Some((path, bytes))
            } else {
                None
            }
        };
        if let Some((path, archive)) = completed {
            let result = self
                .authority
                .import_tar(&path, &archive)
                .map_err(map_fs_error);
            let mut table = self.table.lock();
            if let Some(ArchiveRecord {
                state: ArchiveRecordState::Applying { bytes },
                ..
            }) = table.records.remove(&capability)
            {
                table.total_bytes = table.total_bytes.saturating_sub(bytes);
            }
            return result.map(|()| true);
        }
        Ok(false)
    }

    pub fn abort(&self, capability: ArchiveCapability) -> Result<(), ArchiveControlError> {
        let mut table = self.table.lock();
        self.reap_idle_locked(&mut table, Instant::now());
        Self::remove_record_locked(&mut table, capability)
            .ok_or(ArchiveControlError::UnknownCapability)?;
        Ok(())
    }
}

impl CarrierArchiveControl for ArchiveRuntime {
    fn metadata(&self, request: ArchiveRequest) -> Result<ArchiveMetadata, ArchiveControlError> {
        Self::metadata(self, request)
    }

    fn begin_read(
        &self,
        capability: ArchiveCapability,
        request: ArchiveRequest,
    ) -> Result<ArchiveReadStart, ArchiveControlError> {
        Self::begin_read(self, capability, request)
    }

    fn read_chunk(
        &self,
        capability: ArchiveCapability,
    ) -> Result<ArchiveChunk, ArchiveControlError> {
        Self::read_chunk(self, capability)
    }

    fn begin_write(
        &self,
        capability: ArchiveCapability,
        request: ArchiveRequest,
    ) -> Result<ArchiveCapability, ArchiveControlError> {
        Self::begin_write(self, capability, request)
    }

    fn write_chunk(
        &self,
        capability: ArchiveCapability,
        bytes: Vec<u8>,
        eof: bool,
    ) -> Result<bool, ArchiveControlError> {
        Self::write_chunk(self, capability, bytes, eof)
    }

    fn abort(&self, capability: ArchiveCapability) -> Result<(), ArchiveControlError> {
        Self::abort(self, capability)
    }
}

fn map_fs_error(error: crate::dispatch::ArchiveFsError) -> ArchiveControlError {
    match error {
        crate::dispatch::ArchiveFsError::InvalidDestination
        | crate::dispatch::ArchiveFsError::InvalidEntryPath
        | crate::dispatch::ArchiveFsError::UnsupportedEntry
        | crate::dispatch::ArchiveFsError::Malformed(_) => ArchiveControlError::InvalidArchive,
        crate::dispatch::ArchiveFsError::NotFound => ArchiveControlError::NotFound,
        crate::dispatch::ArchiveFsError::NotDirectory => ArchiveControlError::NotDirectory,
        crate::dispatch::ArchiveFsError::TooLarge => ArchiveControlError::TooLarge,
        crate::dispatch::ArchiveFsError::Io(message) => ArchiveControlError::Filesystem(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability(byte: u8) -> ArchiveCapability {
        ArchiveCapability::from(ControlNonce([byte; 16]))
    }

    fn directory_tar(name: &str) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut dir = tar::Header::new_gnu();
        dir.set_size(0);
        dir.set_mode(0o755);
        dir.set_entry_type(tar::EntryType::Directory);
        dir.set_cksum();
        builder
            .append_data(&mut dir, name, std::io::empty())
            .expect("directory");
        builder.into_inner().expect("fixture")
    }

    #[test]
    fn archive_metadata_does_not_allocate_a_transfer_capability() {
        let dispatcher = crate::dispatch::SyscallDispatcher::new();
        dispatcher
            .archive_import_tar("/", &directory_tar("dest"))
            .expect("destination");
        let runtime = ArchiveRuntime::new(dispatcher.archive_authority(), 1);

        let metadata = runtime
            .metadata(ArchiveRequest::new("/dest").expect("request"))
            .expect("metadata");
        assert_eq!(metadata.name, "dest");
        assert!(runtime.table.lock().records.is_empty());
    }

    #[test]
    fn archive_runtime_transfers_multiple_bounded_chunks_through_real_vfs() {
        let source = crate::dispatch::SyscallDispatcher::new();
        let source_backend = source.archive_authority();
        source
            .archive_import_tar("/", &{
                let mut builder = tar::Builder::new(Vec::new());
                let mut dir = tar::Header::new_gnu();
                dir.set_size(0);
                dir.set_mode(0o755);
                dir.set_entry_type(tar::EntryType::Directory);
                dir.set_cksum();
                builder
                    .append_data(&mut dir, "source", std::io::empty())
                    .expect("source directory");
                let payload = vec![0x5a; MAX_ARCHIVE_CHUNK_BYTES + 17];
                let mut file = tar::Header::new_gnu();
                file.set_size(payload.len() as u64);
                file.set_mode(0o600);
                file.set_entry_type(tar::EntryType::Regular);
                file.set_cksum();
                builder
                    .append_data(&mut file, "source/payload", payload.as_slice())
                    .expect("payload");
                builder.into_inner().expect("fixture")
            })
            .expect("seed source");
        let runtime = ArchiveRuntime::new(source_backend, 4);
        let read_capability = capability(1);
        runtime
            .begin_read(
                read_capability,
                ArchiveRequest::new("/source").expect("source request"),
            )
            .expect("begin read");
        let mut archive = Vec::new();
        loop {
            let chunk = runtime.read_chunk(read_capability).expect("read chunk");
            assert!(chunk.bytes.len() <= MAX_ARCHIVE_CHUNK_BYTES);
            archive.extend_from_slice(&chunk.bytes);
            if chunk.eof {
                break;
            }
        }
        assert_eq!(
            runtime.read_chunk(read_capability),
            Err(ArchiveControlError::UnknownCapability)
        );

        let destination = crate::dispatch::SyscallDispatcher::new();
        destination
            .archive_import_tar("/", &directory_tar("dest"))
            .expect("destination");
        let upload = ArchiveRuntime::new(destination.archive_authority(), 4);
        let write_capability = capability(2);
        upload
            .begin_write(
                write_capability,
                ArchiveRequest::new("/dest").expect("destination request"),
            )
            .expect("begin write");
        for (index, chunk) in archive.chunks(MAX_ARCHIVE_CHUNK_BYTES).enumerate() {
            let eof = (index + 1) * MAX_ARCHIVE_CHUNK_BYTES >= archive.len();
            upload
                .write_chunk(write_capability, chunk.to_vec(), eof)
                .expect("write chunk");
        }
        assert_eq!(
            destination
                .read_exec_file("/dest/source/payload")
                .expect("payload"),
            vec![0x5a; MAX_ARCHIVE_CHUNK_BYTES + 17]
        );
    }

    #[test]
    fn archive_runtime_refuses_table_overflow_and_oversized_chunks() {
        let dispatcher = crate::dispatch::SyscallDispatcher::new();
        dispatcher
            .archive_import_tar("/", &directory_tar("dest"))
            .expect("destination");
        let runtime = ArchiveRuntime::new(dispatcher.archive_authority(), 1);
        runtime
            .begin_write(
                capability(3),
                ArchiveRequest::new("/dest").expect("request"),
            )
            .expect("first slot");
        assert_eq!(
            runtime.begin_write(
                capability(4),
                ArchiveRequest::new("/dest").expect("request"),
            ),
            Err(ArchiveControlError::Capacity)
        );
        assert_eq!(
            runtime.write_chunk(capability(3), vec![0; MAX_ARCHIVE_CHUNK_BYTES + 1], false,),
            Err(ArchiveControlError::TooLarge)
        );
        assert_eq!(runtime.table.lock().total_bytes, 0);
        runtime
            .begin_write(
                capability(4),
                ArchiveRequest::new("/dest").expect("request"),
            )
            .expect("a rejected chunk releases the capability slot");
        assert_eq!(
            runtime.write_chunk(capability(3), Vec::new(), true),
            Err(ArchiveControlError::UnknownCapability)
        );
    }

    #[test]
    fn archive_runtime_reaps_idle_records_before_capacity_admission() {
        let dispatcher = crate::dispatch::SyscallDispatcher::new();
        dispatcher
            .archive_import_tar("/", &directory_tar("dest"))
            .expect("destination");
        let runtime = ArchiveRuntime::new_with_idle_timeout(
            dispatcher.archive_authority(),
            1,
            std::time::Duration::ZERO,
        );
        runtime
            .begin_write(
                capability(10),
                ArchiveRequest::new("/dest").expect("request"),
            )
            .expect("abandoned slot");
        runtime
            .begin_write(
                capability(11),
                ArchiveRequest::new("/dest").expect("request"),
            )
            .expect("expired slot is reclaimed");
        assert_eq!(
            runtime.write_chunk(capability(10), Vec::new(), true),
            Err(ArchiveControlError::UnknownCapability)
        );
    }

    #[test]
    fn archive_runtime_releases_payload_after_failed_final_apply() {
        let dispatcher = crate::dispatch::SyscallDispatcher::new();
        dispatcher
            .archive_import_tar("/", &directory_tar("dest"))
            .expect("destination");
        let runtime = ArchiveRuntime::new(dispatcher.archive_authority(), 1);
        runtime
            .begin_write(
                capability(20),
                ArchiveRequest::new("/dest").expect("request"),
            )
            .expect("slot");
        assert_eq!(
            runtime.write_chunk(capability(20), b"not a tar".to_vec(), true),
            Err(ArchiveControlError::InvalidArchive)
        );
        assert_eq!(runtime.table.lock().total_bytes, 0);
        runtime
            .begin_write(
                capability(21),
                ArchiveRequest::new("/dest").expect("request"),
            )
            .expect("failed apply releases the capability slot");
    }
}
