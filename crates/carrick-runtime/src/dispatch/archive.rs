use std::collections::{HashMap, HashSet};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use super::SyscallDispatcher;
use crate::vfs::{EntryKind, Metadata, Vfs as _};

const MAX_ARCHIVE_ENTRIES: usize = 4_096;
pub(crate) const MAX_ARCHIVE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ArchiveFsError {
    #[error("archive destination path is invalid")]
    InvalidDestination,
    #[error("archive path does not exist")]
    NotFound,
    #[error("archive path is not a directory")]
    NotDirectory,
    #[error("archive contains an invalid or escaping path")]
    InvalidEntryPath,
    #[error("archive contains an unsupported entry type")]
    UnsupportedEntry,
    #[error("archive exceeds its bounded size or entry count")]
    TooLarge,
    #[error("archive is malformed: {0}")]
    Malformed(String),
    #[error("archive filesystem operation failed: {0}")]
    Io(String),
}

#[derive(Debug)]
enum PlannedKind {
    File(Vec<u8>),
    Directory,
    Symlink(String),
}

#[derive(Debug)]
struct PlannedEntry {
    relative: PathBuf,
    kind: PlannedKind,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
}

#[derive(Clone)]
pub(crate) struct ArchiveFsAuthority {
    mounts: Arc<crate::vfs::VfsMounts>,
    root: Arc<crate::vfs::RootFsVfs>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ArchiveEntryMetadata {
    pub name: String,
    pub size: u64,
    pub mode: u32,
    pub mtime_secs: i64,
    pub mtime_nanos: u32,
    pub link_target: Option<String>,
}

impl SyscallDispatcher {
    pub(crate) fn archive_authority(&self) -> ArchiveFsAuthority {
        ArchiveFsAuthority {
            mounts: Arc::clone(&self.fs.vfs_mounts),
            root: Arc::clone(&self.fs.rootfs_vfs),
        }
    }

    #[cfg(test)]
    pub(crate) fn archive_import_tar(
        &self,
        destination: &str,
        bytes: &[u8],
    ) -> Result<(), ArchiveFsError> {
        self.archive_authority().import_tar(destination, bytes)
    }

    #[cfg(test)]
    pub(crate) fn archive_export_tar(&self, source: &str) -> Result<Vec<u8>, ArchiveFsError> {
        self.archive_authority().export_tar(source)
    }
}

impl ArchiveFsAuthority {
    pub(crate) fn metadata(&self, path: &str) -> Result<ArchiveEntryMetadata, ArchiveFsError> {
        validate_absolute_path(path).map_err(|_| ArchiveFsError::InvalidDestination)?;
        let metadata = self.lookup_nofollow(path)?;
        let kind_bits = match metadata.kind {
            EntryKind::File => 0o100000,
            EntryKind::Directory => 0o040000,
            EntryKind::Symlink => 0o120000,
            EntryKind::CharDevice => 0o020000,
            EntryKind::Fifo => 0o010000,
            EntryKind::Socket => 0o140000,
        };
        let name = if path == "/" {
            "/".to_owned()
        } else {
            Path::new(path)
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(ArchiveFsError::InvalidDestination)?
                .to_owned()
        };
        let link_target = if metadata.kind == EntryKind::Symlink {
            Some(
                self.readlink(path)?
                    .to_str()
                    .ok_or(ArchiveFsError::InvalidEntryPath)?
                    .to_owned(),
            )
        } else {
            None
        };
        Ok(ArchiveEntryMetadata {
            name,
            size: metadata.size,
            mode: kind_bits | (metadata.mode & 0o7777),
            mtime_secs: metadata.mtime_secs,
            mtime_nanos: metadata.mtime_nanos,
            link_target,
        })
    }

    pub(crate) fn import_tar(&self, destination: &str, bytes: &[u8]) -> Result<(), ArchiveFsError> {
        validate_absolute_path(destination).map_err(|_| ArchiveFsError::InvalidDestination)?;
        let plan = parse_archive_plan(bytes)?;
        let _transaction = self
            .root
            .overlay
            .archive_mutation_gate()
            .ok_or(ArchiveFsError::UnsupportedEntry)?
            .archive_transaction();
        validate_archive_plan(self, destination, &plan)?;
        apply_archive_plan(self, destination, plan)
    }

    pub(crate) fn export_tar(&self, source: &str) -> Result<Vec<u8>, ArchiveFsError> {
        validate_absolute_path(source).map_err(|_| ArchiveFsError::InvalidDestination)?;
        let archive_root = if source == "/" {
            PathBuf::from(".")
        } else {
            PathBuf::from(
                Path::new(source)
                    .file_name()
                    .ok_or(ArchiveFsError::InvalidDestination)?,
            )
        };
        let writer = BoundedArchiveWriter::default();
        let mut builder = tar::Builder::new(writer);
        let mut remaining_entries = MAX_ARCHIVE_ENTRIES;
        self.append_tree(
            &mut builder,
            source,
            &archive_root,
            0,
            &mut remaining_entries,
        )?;
        builder.finish().map_err(map_archive_write_error)?;
        builder
            .into_inner()
            .map_err(map_archive_write_error)
            .map(BoundedArchiveWriter::into_bytes)
    }

    fn append_tree(
        &self,
        builder: &mut tar::Builder<BoundedArchiveWriter>,
        guest_path: &str,
        archive_path: &Path,
        depth: usize,
        remaining_entries: &mut usize,
    ) -> Result<(), ArchiveFsError> {
        if depth > 256 || *remaining_entries == 0 {
            return Err(ArchiveFsError::TooLarge);
        }
        *remaining_entries -= 1;
        let metadata = self.lookup_nofollow(guest_path)?;
        let mut header = tar_header(&metadata)?;
        match metadata.kind {
            EntryKind::File => {
                let contents = self.read_file(guest_path)?;
                header
                    .set_size(u64::try_from(contents.len()).map_err(|_| ArchiveFsError::TooLarge)?);
                header.set_entry_type(tar::EntryType::Regular);
                header.set_cksum();
                builder
                    .append_data(&mut header, archive_path, contents.as_slice())
                    .map_err(map_archive_write_error)?;
            }
            EntryKind::Directory => {
                header.set_size(0);
                header.set_entry_type(tar::EntryType::Directory);
                header.set_cksum();
                builder
                    .append_data(&mut header, archive_path, std::io::empty())
                    .map_err(map_archive_write_error)?;
                let mut children = self.readdir_bounded(guest_path, *remaining_entries)?;
                children.sort_by(|left, right| left.name.cmp(&right.name));
                for child in children {
                    if matches!(child.name.as_str(), "." | "..")
                        || child.name.contains('/')
                        || child.name.as_bytes().contains(&0)
                    {
                        return Err(ArchiveFsError::InvalidEntryPath);
                    }
                    let child_guest = if guest_path == "/" {
                        format!("/{}", child.name)
                    } else {
                        format!("{guest_path}/{}", child.name)
                    };
                    let child_archive = archive_path.join(&child.name);
                    self.append_tree(
                        builder,
                        &child_guest,
                        &child_archive,
                        depth + 1,
                        remaining_entries,
                    )?;
                }
            }
            EntryKind::Symlink => {
                let target = self.readlink(guest_path)?;
                header.set_size(0);
                header.set_entry_type(tar::EntryType::Symlink);
                header
                    .set_link_name(&target)
                    .map_err(|error| ArchiveFsError::Io(error.to_string()))?;
                header.set_cksum();
                builder
                    .append_data(&mut header, archive_path, std::io::empty())
                    .map_err(map_archive_write_error)?;
            }
            EntryKind::CharDevice | EntryKind::Fifo | EntryKind::Socket => {
                return Err(ArchiveFsError::UnsupportedEntry);
            }
        }
        Ok(())
    }

    fn lookup_nofollow(&self, path: &str) -> Result<Metadata, ArchiveFsError> {
        if path == "/" {
            return Ok(Metadata {
                kind: EntryKind::Directory,
                mode: 0o755,
                size: 0,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            });
        }
        if let Some(mount) = self.mounts.resolve(path) {
            return mount
                .vfs
                .lookup_nofollow(&mount.full_path)
                .map_err(|error| map_lookup_error(&mount.full_path, error));
        }
        self.root
            .lookup_nofollow(path)
            .map_err(|error| map_lookup_error(path, error))
    }

    fn readdir_bounded(
        &self,
        path: &str,
        limit: usize,
    ) -> Result<Vec<crate::vfs::DirEnt>, ArchiveFsError> {
        let map = |display: &str, error| {
            if error == crate::linux_abi::LINUX_E2BIG {
                ArchiveFsError::TooLarge
            } else if error == crate::linux_abi::LINUX_ENOSYS {
                ArchiveFsError::UnsupportedEntry
            } else {
                ArchiveFsError::Io(format!("readdir {display}: {error:?}"))
            }
        };
        if let Some(mount) = self.mounts.resolve(path) {
            let entries = mount
                .vfs
                .readdir_bounded(&mount.full_path, limit)
                .map_err(|error| map(&mount.full_path, error))?;
            return (entries.len() <= limit)
                .then_some(entries)
                .ok_or(ArchiveFsError::TooLarge);
        }
        let entries = self
            .root
            .readdir_bounded(path, limit)
            .map_err(|error| map(path, error))?;
        (entries.len() <= limit)
            .then_some(entries)
            .ok_or(ArchiveFsError::TooLarge)
    }

    fn read_file(&self, path: &str) -> Result<Vec<u8>, ArchiveFsError> {
        if let Some(mount) = self.mounts.resolve(path) {
            return mount.vfs.read_file(&mount.full_path).map_err(|error| {
                ArchiveFsError::Io(format!("read {}: {error:?}", mount.full_path))
            });
        }
        if let Some(contents) = self.root.overlay.file_contents(path) {
            return Ok(contents);
        }
        self.root
            .rootfs
            .as_ref()
            .and_then(|rootfs| rootfs.read(path).ok())
            .ok_or_else(|| ArchiveFsError::Io(format!("read {path}: not found")))
    }

    fn readlink(&self, path: &str) -> Result<PathBuf, ArchiveFsError> {
        if let Some(mount) = self.mounts.resolve(path) {
            return mount.vfs.readlink(&mount.full_path).map_err(|error| {
                ArchiveFsError::Io(format!("readlink {}: {error:?}", mount.full_path))
            });
        }
        self.root
            .readlink(path)
            .map_err(|error| ArchiveFsError::Io(format!("readlink {path}: {error:?}")))
    }
}

fn map_lookup_error(path: &str, error: crate::linux_abi::LinuxErrno) -> ArchiveFsError {
    if error == crate::linux_abi::LINUX_ENOENT {
        ArchiveFsError::NotFound
    } else if error == crate::linux_abi::LINUX_ENOTDIR {
        ArchiveFsError::NotDirectory
    } else {
        ArchiveFsError::Io(format!("lookup {path}: {error:?}"))
    }
}

#[derive(Default)]
struct BoundedArchiveWriter {
    bytes: Vec<u8>,
}

impl BoundedArchiveWriter {
    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl std::io::Write for BoundedArchiveWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::FileTooLarge))?;
        if next > MAX_ARCHIVE_BYTES {
            return Err(std::io::Error::from(std::io::ErrorKind::FileTooLarge));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn map_archive_write_error(error: std::io::Error) -> ArchiveFsError {
    if error.kind() == std::io::ErrorKind::FileTooLarge {
        ArchiveFsError::TooLarge
    } else {
        ArchiveFsError::Io(error.to_string())
    }
}

fn tar_header(metadata: &Metadata) -> Result<tar::Header, ArchiveFsError> {
    let mut header = tar::Header::new_gnu();
    header.set_mode(metadata.mode & 0o7777);
    header.set_uid(u64::from(metadata.uid));
    header.set_gid(u64::from(metadata.gid));
    header.set_mtime(u64::try_from(metadata.mtime_secs.max(0)).unwrap_or(0));
    Ok(header)
}

fn parse_archive_plan(bytes: &[u8]) -> Result<Vec<PlannedEntry>, ArchiveFsError> {
    if bytes.len() > MAX_ARCHIVE_BYTES {
        return Err(ArchiveFsError::TooLarge);
    }
    let mut plan = Vec::new();
    let mut symlinks = HashSet::new();
    let mut archive = tar::Archive::new(bytes);
    let entries = archive
        .entries()
        .map_err(|error| ArchiveFsError::Malformed(error.to_string()))?;
    for entry in entries {
        if plan.len() >= MAX_ARCHIVE_ENTRIES {
            return Err(ArchiveFsError::TooLarge);
        }
        let mut entry = entry.map_err(|error| ArchiveFsError::Malformed(error.to_string()))?;
        let relative = validated_relative_path(entry.path_bytes().as_ref())?;
        if relative
            .ancestors()
            .skip(1)
            .any(|parent| symlinks.contains(parent))
        {
            return Err(ArchiveFsError::InvalidEntryPath);
        }
        let entry_type = entry.header().entry_type();
        let mode = entry
            .header()
            .mode()
            .map_err(|error| ArchiveFsError::Malformed(error.to_string()))?
            & 0o7777;
        let uid = u32::try_from(entry.header().uid().unwrap_or(0))
            .map_err(|_| ArchiveFsError::Malformed("uid exceeds Linux u32".to_owned()))?;
        let gid = u32::try_from(entry.header().gid().unwrap_or(0))
            .map_err(|_| ArchiveFsError::Malformed("gid exceeds Linux u32".to_owned()))?;
        let mtime = i64::try_from(entry.header().mtime().unwrap_or(0))
            .map_err(|_| ArchiveFsError::Malformed("mtime exceeds Linux i64".to_owned()))?;
        let kind = if entry_type.is_file() {
            let size = usize::try_from(entry.size()).map_err(|_| ArchiveFsError::TooLarge)?;
            if size > MAX_ARCHIVE_BYTES {
                return Err(ArchiveFsError::TooLarge);
            }
            let mut contents = Vec::with_capacity(size);
            entry
                .read_to_end(&mut contents)
                .map_err(|error| ArchiveFsError::Malformed(error.to_string()))?;
            PlannedKind::File(contents)
        } else if entry_type.is_dir() {
            PlannedKind::Directory
        } else if entry_type.is_symlink() {
            let target = entry
                .link_name_bytes()
                .ok_or(ArchiveFsError::InvalidEntryPath)?;
            let target = std::str::from_utf8(target.as_ref())
                .map_err(|_| ArchiveFsError::InvalidEntryPath)?
                .to_owned();
            if target.as_bytes().contains(&0) {
                return Err(ArchiveFsError::InvalidEntryPath);
            }
            symlinks.insert(relative.clone());
            PlannedKind::Symlink(target)
        } else {
            // In particular, hard links are refused rather than approximated.
            return Err(ArchiveFsError::UnsupportedEntry);
        };
        plan.push(PlannedEntry {
            relative,
            kind,
            mode,
            uid,
            gid,
            mtime,
        });
    }
    Ok(plan)
}

fn validated_relative_path(bytes: &[u8]) -> Result<PathBuf, ArchiveFsError> {
    let value = std::str::from_utf8(bytes).map_err(|_| ArchiveFsError::InvalidEntryPath)?;
    if value.is_empty() || value.as_bytes().contains(&0) || Path::new(value).is_absolute() {
        return Err(ArchiveFsError::InvalidEntryPath);
    }
    let mut clean = PathBuf::new();
    for component in Path::new(value).components() {
        match component {
            Component::Normal(name) => clean.push(name),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ArchiveFsError::InvalidEntryPath);
            }
        }
    }
    if clean.as_os_str().is_empty() {
        return Err(ArchiveFsError::InvalidEntryPath);
    }
    Ok(clean)
}

fn validate_absolute_path(value: &str) -> Result<(), ArchiveFsError> {
    if value.is_empty()
        || value.as_bytes().contains(&0)
        || !Path::new(value).is_absolute()
        || value
            .split('/')
            .any(|component| matches!(component, "." | ".."))
        || !Path::new(value)
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(ArchiveFsError::InvalidDestination);
    }
    Ok(())
}

fn validate_archive_plan(
    authority: &ArchiveFsAuthority,
    destination: &str,
    plan: &[PlannedEntry],
) -> Result<(), ArchiveFsError> {
    // Archive mutation currently targets the rootfs overlay. Never report a
    // successful write that is hidden behind a synthetic or bind mount, and
    // never let validation consult one authority while apply mutates another.
    // A future writable-mount implementation needs its own typed mutation
    // capability; falling through to the root overlay is not an approximation.
    if authority.mounts.resolve(destination).is_some() {
        return Err(ArchiveFsError::UnsupportedEntry);
    }
    let root_metadata = authority.lookup_nofollow(destination)?;
    if root_metadata.kind != EntryKind::Directory {
        return Err(ArchiveFsError::NotDirectory);
    }

    let mut planned = HashMap::new();
    for entry in plan {
        if planned
            .insert(entry.relative.clone(), &entry.kind)
            .is_some()
        {
            return Err(ArchiveFsError::InvalidEntryPath);
        }
    }
    for entry in plan {
        let mut parent = entry.relative.parent();
        while let Some(relative_parent) = parent {
            if relative_parent.as_os_str().is_empty() {
                break;
            }
            if let Some(kind) = planned.get(relative_parent) {
                if !matches!(kind, PlannedKind::Directory) {
                    return Err(ArchiveFsError::InvalidEntryPath);
                }
            } else {
                let full_parent = destination_path(destination, relative_parent)?;
                if authority.mounts.resolve(&full_parent).is_some() {
                    return Err(ArchiveFsError::UnsupportedEntry);
                }
                match authority.lookup_nofollow(&full_parent) {
                    Ok(metadata) if metadata.kind == EntryKind::Directory => {}
                    Ok(_) => return Err(ArchiveFsError::InvalidEntryPath),
                    Err(ArchiveFsError::NotFound) => {}
                    Err(error) => return Err(error),
                }
            }
            parent = relative_parent.parent();
        }

        let full = destination_path(destination, &entry.relative)?;
        if authority.mounts.resolve(&full).is_some() {
            return Err(ArchiveFsError::UnsupportedEntry);
        }
        match authority.lookup_nofollow(&full) {
            Ok(existing) => {
                let compatible = matches!(
                    (&entry.kind, existing.kind),
                    (PlannedKind::Directory, EntryKind::Directory)
                        | (PlannedKind::File(_), EntryKind::File)
                );
                if !compatible {
                    return Err(ArchiveFsError::InvalidEntryPath);
                }
            }
            Err(ArchiveFsError::NotFound) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn apply_archive_plan(
    authority: &ArchiveFsAuthority,
    destination: &str,
    plan: Vec<PlannedEntry>,
) -> Result<(), ArchiveFsError> {
    let backend = authority.root.overlay.as_ref();
    let mut required_directories = HashSet::new();
    for entry in &plan {
        let mut parent = entry.relative.parent();
        while let Some(relative_parent) = parent {
            if relative_parent.as_os_str().is_empty() {
                break;
            }
            required_directories.insert(relative_parent.to_path_buf());
            parent = relative_parent.parent();
        }
        if matches!(entry.kind, PlannedKind::Directory) {
            required_directories.insert(entry.relative.clone());
        }
    }
    let mut required_directories = required_directories.into_iter().collect::<Vec<_>>();
    required_directories.sort_by_key(|path| path.components().count());
    let mut mutation_paths = required_directories.clone();
    mutation_paths.extend(plan.iter().map(|entry| entry.relative.clone()));
    mutation_paths.sort_by_key(|path| path.components().count());
    mutation_paths.dedup();
    let snapshots = snapshot_archive_paths(authority, destination, &mutation_paths)?;

    let apply_result =
        (|| {
            for relative in required_directories {
                let full = destination_path(destination, &relative)?;
                match authority.lookup_nofollow(&full) {
                    Ok(metadata) if metadata.kind == EntryKind::Directory => {}
                    Ok(_) => return Err(ArchiveFsError::InvalidEntryPath),
                    Err(ArchiveFsError::NotFound) => backend
                        .make_dir(&full)
                        .map_err(|error| ArchiveFsError::Io(format!("{error:?}")))?,
                    Err(error) => return Err(error),
                }
            }

            for entry in &plan {
                let full = destination_path(destination, &entry.relative)?;
                match &entry.kind {
                    PlannedKind::File(contents) => backend
                        .set_file_contents(&full, contents.clone())
                        .map_err(|error| ArchiveFsError::Io(format!("{error:?}")))?,
                    PlannedKind::Directory => {}
                    PlannedKind::Symlink(target) => backend
                        .symlink(target, &full)
                        .map_err(|error| ArchiveFsError::Io(format!("{error:?}")))?,
                }
                if !matches!(entry.kind, PlannedKind::Symlink(_)) {
                    match backend.set_mode(&full, entry.mode) {
                        Ok(()) | Err(crate::fs_backend::BackendError::Unsupported) => {}
                        Err(error) => return Err(ArchiveFsError::Io(format!("{error:?}"))),
                    }
                }
                backend
                    .set_owner(
                        &full,
                        Some(carrick_abi::NsUid(entry.uid)),
                        Some(carrick_abi::NsGid(entry.gid)),
                    )
                    .map_err(|error| ArchiveFsError::Io(format!("{error:?}")))?;
                // MemoryBackend cannot persist timestamps; a host-backed overlay does.
                // Unsupported timestamp storage is metadata degradation, not a reason
                // to report that payload application failed.
                let _ = backend.set_times(&full, None, Some((entry.mtime, 0)), true);
            }
            Ok(())
        })();

    if let Err(apply_error) = apply_result {
        if let Err(rollback_error) = rollback_archive_paths(backend, snapshots) {
            return Err(ArchiveFsError::Io(format!(
                "archive apply failed ({apply_error}); rollback failed ({rollback_error})"
            )));
        }
        return Err(apply_error);
    }
    Ok(())
}

#[derive(Debug)]
enum PreviousArchiveEntry {
    AbsentUpper,
    Tombstone,
    File {
        contents: Vec<u8>,
        metadata: Metadata,
    },
    Directory {
        metadata: Metadata,
    },
    Symlink {
        target: String,
        metadata: Metadata,
    },
}

#[derive(Debug)]
struct ArchivePathSnapshot {
    full: String,
    previous: PreviousArchiveEntry,
}

fn snapshot_archive_paths(
    authority: &ArchiveFsAuthority,
    destination: &str,
    paths: &[PathBuf],
) -> Result<Vec<ArchivePathSnapshot>, ArchiveFsError> {
    let backend = authority.root.overlay.as_ref();
    paths
        .iter()
        .map(|relative| {
            let full = destination_path(destination, relative)?;
            let previous = match backend.lookup_kind(&full) {
                None => PreviousArchiveEntry::AbsentUpper,
                Some(crate::fs_backend::OverlayEntryKind::Deleted) => {
                    PreviousArchiveEntry::Tombstone
                }
                Some(_) => {
                    let metadata = authority.lookup_nofollow(&full)?;
                    match metadata.kind {
                        EntryKind::File => PreviousArchiveEntry::File {
                            contents: backend
                                .file_contents(&full)
                                .ok_or_else(|| ArchiveFsError::Io(format!("snapshot {full}")))?,
                            metadata,
                        },
                        EntryKind::Directory => PreviousArchiveEntry::Directory { metadata },
                        EntryKind::Symlink => PreviousArchiveEntry::Symlink {
                            target: backend
                                .read_link(&full)
                                .ok_or_else(|| ArchiveFsError::Io(format!("snapshot {full}")))?,
                            metadata,
                        },
                        EntryKind::CharDevice | EntryKind::Fifo | EntryKind::Socket => {
                            return Err(ArchiveFsError::UnsupportedEntry);
                        }
                    }
                }
            };
            Ok(ArchivePathSnapshot { full, previous })
        })
        .collect()
}

fn rollback_archive_paths(
    backend: &dyn crate::fs_backend::FsBackend,
    mut snapshots: Vec<ArchivePathSnapshot>,
) -> Result<(), ArchiveFsError> {
    snapshots
        .sort_by_key(|snapshot| std::cmp::Reverse(Path::new(&snapshot.full).components().count()));
    let mut first_error = None;
    for snapshot in snapshots {
        let restored = restore_archive_path(backend, &snapshot.full, snapshot.previous);
        if first_error.is_none() {
            first_error = restored.err();
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn restore_archive_path(
    backend: &dyn crate::fs_backend::FsBackend,
    full: &str,
    previous: PreviousArchiveEntry,
) -> Result<(), ArchiveFsError> {
    let backend_error = |error| ArchiveFsError::Io(format!("rollback {full}: {error:?}"));
    match previous {
        PreviousArchiveEntry::AbsentUpper => {
            backend.remove_entry_checked(full).map_err(backend_error)?;
        }
        PreviousArchiveEntry::Tombstone => {
            backend.remove_entry_checked(full).map_err(backend_error)?;
            backend.mark_deleted(full).map_err(backend_error)?;
        }
        PreviousArchiveEntry::File { contents, metadata } => {
            backend
                .set_file_contents(full, contents)
                .map_err(backend_error)?;
            restore_archive_metadata(backend, full, &metadata)?;
        }
        PreviousArchiveEntry::Directory { metadata } => {
            backend.make_dir(full).map_err(backend_error)?;
            restore_archive_metadata(backend, full, &metadata)?;
        }
        PreviousArchiveEntry::Symlink { target, metadata } => {
            backend.remove_entry_checked(full).map_err(backend_error)?;
            backend.symlink(&target, full).map_err(backend_error)?;
            restore_archive_metadata(backend, full, &metadata)?;
        }
    }
    Ok(())
}

fn restore_archive_metadata(
    backend: &dyn crate::fs_backend::FsBackend,
    full: &str,
    metadata: &Metadata,
) -> Result<(), ArchiveFsError> {
    let map = |error| ArchiveFsError::Io(format!("rollback metadata {full}: {error:?}"));
    match backend.set_mode(full, metadata.mode) {
        Ok(()) | Err(crate::fs_backend::BackendError::Unsupported) => {}
        Err(error) => return Err(map(error)),
    }
    backend
        .set_owner(
            full,
            Some(carrick_abi::NsUid(metadata.uid)),
            Some(carrick_abi::NsGid(metadata.gid)),
        )
        .map_err(map)?;
    match backend.set_times(
        full,
        None,
        Some((metadata.mtime_secs, i64::from(metadata.mtime_nanos))),
        true,
    ) {
        Ok(()) | Err(crate::fs_backend::BackendError::Unsupported) => Ok(()),
        Err(error) => Err(map(error)),
    }
}

fn destination_path(destination: &str, relative: &Path) -> Result<String, ArchiveFsError> {
    let mut full = PathBuf::from(destination);
    full.push(relative);
    full.to_str()
        .map(str::to_owned)
        .ok_or(ArchiveFsError::InvalidEntryPath)
}

#[cfg(test)]
mod tests {
    use super::SyscallDispatcher;
    use crate::fs_backend::FsBackend as _;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct ReadOnlyDirectoryMount;

    struct UnboundedOnlyDirectoryMount {
        visited: Arc<AtomicUsize>,
    }

    struct BoundedLazyDirectoryMount {
        visited: Arc<AtomicUsize>,
    }

    impl crate::vfs::Vfs for BoundedLazyDirectoryMount {
        fn lookup(&self, path: &str) -> Result<crate::vfs::Metadata, crate::vfs::VfsError> {
            if path != "/wide" {
                return Err(crate::linux_abi::LINUX_ENOENT);
            }
            Ok(crate::vfs::Metadata {
                kind: crate::vfs::EntryKind::Directory,
                mode: 0o755,
                size: 0,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            })
        }

        fn readdir_bounded(
            &self,
            path: &str,
            limit: usize,
        ) -> Result<Vec<crate::vfs::DirEnt>, crate::vfs::VfsError> {
            if path != "/wide" {
                return Err(crate::linux_abi::LINUX_ENOTDIR);
            }
            Ok((0..=limit)
                .map(|index| {
                    self.visited.fetch_add(1, Ordering::Relaxed);
                    crate::vfs::DirEnt {
                        name: format!("entry-{index}"),
                        kind: crate::vfs::EntryKind::File,
                    }
                })
                .collect())
        }
    }

    impl crate::vfs::Vfs for UnboundedOnlyDirectoryMount {
        fn lookup(&self, path: &str) -> Result<crate::vfs::Metadata, crate::vfs::VfsError> {
            if path != "/wide" {
                return Err(crate::linux_abi::LINUX_ENOENT);
            }
            Ok(crate::vfs::Metadata {
                kind: crate::vfs::EntryKind::Directory,
                mode: 0o755,
                size: 0,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            })
        }

        fn readdir(&self, path: &str) -> Result<Vec<crate::vfs::DirEnt>, crate::vfs::VfsError> {
            if path != "/wide" {
                return Err(crate::linux_abi::LINUX_ENOTDIR);
            }
            Ok((0..10_000)
                .map(|index| {
                    self.visited.fetch_add(1, Ordering::Relaxed);
                    crate::vfs::DirEnt {
                        name: format!("entry-{index}"),
                        kind: crate::vfs::EntryKind::File,
                    }
                })
                .collect())
        }
    }

    impl crate::vfs::Vfs for ReadOnlyDirectoryMount {
        fn lookup(&self, path: &str) -> Result<crate::vfs::Metadata, crate::vfs::VfsError> {
            if path == "/dest" {
                Ok(crate::vfs::Metadata {
                    kind: crate::vfs::EntryKind::Directory,
                    mode: 0o755,
                    size: 0,
                    uid: 0,
                    gid: 0,
                    mtime_secs: 0,
                    mtime_nanos: 0,
                })
            } else {
                Err(crate::linux_abi::LINUX_ENOENT)
            }
        }
    }

    fn tar_with_parent_traversal() -> Vec<u8> {
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_path("placeholder").expect("placeholder path");
        header.as_mut_bytes()[..10].copy_from_slice(b"../outside");
        header.set_cksum();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(header.as_bytes());
        bytes.extend_from_slice(b"owned");
        bytes.resize(1024, 0);
        bytes.extend_from_slice(&[0; 1024]);
        bytes
    }

    fn tar_with_symlink_pivot() -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut link = tar::Header::new_gnu();
        link.set_size(0);
        link.set_mode(0o777);
        link.set_entry_type(tar::EntryType::Symlink);
        link.set_link_name("/outside").expect("link target");
        link.set_cksum();
        builder
            .append_data(&mut link, "link", std::io::empty())
            .expect("symlink");
        let mut file = tar::Header::new_gnu();
        file.set_size(5);
        file.set_mode(0o644);
        file.set_entry_type(tar::EntryType::Regular);
        file.set_cksum();
        builder
            .append_data(&mut file, "link/pwn", &b"owned"[..])
            .expect("pivot child");
        builder.into_inner().expect("tar bytes")
    }

    fn tar_with_safe_tree() -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut dir = tar::Header::new_gnu();
        dir.set_size(0);
        dir.set_mode(0o750);
        dir.set_uid(12);
        dir.set_gid(34);
        dir.set_mtime(56);
        dir.set_entry_type(tar::EntryType::Directory);
        dir.set_cksum();
        builder
            .append_data(&mut dir, "sub", std::io::empty())
            .expect("directory");
        let mut file = tar::Header::new_gnu();
        file.set_size(7);
        file.set_mode(0o640);
        file.set_uid(12);
        file.set_gid(34);
        file.set_mtime(57);
        file.set_entry_type(tar::EntryType::Regular);
        file.set_cksum();
        builder
            .append_data(&mut file, "sub/file", &b"payload"[..])
            .expect("file");
        builder.into_inner().expect("tar bytes")
    }

    fn tar_with_late_host_path_failure() -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut first = tar::Header::new_gnu();
        first.set_size(7);
        first.set_mode(0o640);
        first.set_entry_type(tar::EntryType::Regular);
        first.set_cksum();
        builder
            .append_data(&mut first, "first", &b"changed"[..])
            .expect("first file");

        let oversized_component = "x".repeat(300);
        let mut late = tar::Header::new_gnu();
        late.set_size(4);
        late.set_mode(0o600);
        late.set_entry_type(tar::EntryType::Regular);
        late.set_cksum();
        builder
            .append_data(&mut late, oversized_component, &b"late"[..])
            .expect("late file");
        builder.into_inner().expect("tar bytes")
    }

    #[test]
    fn archive_import_rejects_parent_traversal_before_mutation() {
        let dispatcher = SyscallDispatcher::new();
        dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .make_dir("/dest")
            .expect("destination");

        assert!(
            dispatcher
                .archive_import_tar("/dest", &tar_with_parent_traversal())
                .is_err()
        );
        assert!(
            dispatcher
                .fs
                .rootfs_vfs
                .overlay
                .file_contents("/outside")
                .is_none()
        );
    }

    #[test]
    fn archive_import_rejects_symlink_pivot_before_mutation() {
        let dispatcher = SyscallDispatcher::new();
        dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .make_dir("/dest")
            .expect("destination");
        dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .make_dir("/outside")
            .expect("outside");

        assert!(
            dispatcher
                .archive_import_tar("/dest", &tar_with_symlink_pivot())
                .is_err()
        );
        assert!(
            dispatcher
                .fs
                .rootfs_vfs
                .overlay
                .file_contents("/outside/pwn")
                .is_none()
        );
        assert!(
            dispatcher
                .fs
                .rootfs_vfs
                .overlay
                .read_link("/dest/link")
                .is_none()
        );
    }

    #[test]
    fn archive_import_never_writes_under_a_mounted_destination() {
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.register_mount("/dest", Box::new(ReadOnlyDirectoryMount));

        assert!(
            dispatcher
                .archive_import_tar("/dest", &tar_with_safe_tree())
                .is_err()
        );
        assert!(
            dispatcher
                .fs
                .rootfs_vfs
                .overlay
                .file_contents("/dest/sub/file")
                .is_none()
        );

        let mut crossing = SyscallDispatcher::new();
        crossing.register_mount("/sub", Box::new(ReadOnlyDirectoryMount));
        assert!(
            crossing
                .archive_import_tar("/", &tar_with_safe_tree())
                .is_err()
        );
        assert!(
            crossing
                .fs
                .rootfs_vfs
                .overlay
                .file_contents("/sub/file")
                .is_none()
        );
    }

    #[test]
    fn archive_import_applies_validated_tree_and_metadata() {
        let dispatcher = SyscallDispatcher::new();
        dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .make_dir("/dest")
            .expect("destination");

        dispatcher
            .archive_import_tar("/dest", &tar_with_safe_tree())
            .expect("import");

        assert_eq!(
            dispatcher
                .fs
                .rootfs_vfs
                .overlay
                .file_contents("/dest/sub/file")
                .as_deref(),
            Some(&b"payload"[..])
        );
        let metadata = dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .metadata("/dest/sub/file")
            .expect("file metadata");
        assert_eq!(metadata.mode & 0o7777, 0o640);
    }

    #[test]
    fn archive_import_rolls_back_earlier_entries_after_late_backend_failure() {
        let scratch = tempfile::tempdir().expect("scratch");
        let root = cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority())
            .expect("scratch authority");
        let backend = crate::fs_backend::HostFsBackend::from_existing_dir(root);
        backend.make_dir("/dest").expect("destination");
        backend
            .set_file_contents("/dest/first", b"original".to_vec())
            .expect("original file");
        let mut dispatcher = SyscallDispatcher::new();
        let _ = dispatcher.set_fs_backend(Box::new(backend));

        assert!(
            dispatcher
                .archive_import_tar("/dest", &tar_with_late_host_path_failure())
                .is_err()
        );
        assert_eq!(
            dispatcher
                .fs
                .rootfs_vfs
                .overlay
                .file_contents("/dest/first")
                .as_deref(),
            Some(&b"original"[..]),
            "a failed PUT must restore every earlier mutation",
        );
    }

    #[test]
    fn archive_import_holds_the_overlay_transaction_during_validation() {
        let dispatcher = SyscallDispatcher::new();
        dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .make_dir("/dest")
            .expect("destination");
        let authority = dispatcher.archive_authority();
        let import_authority = authority.clone();
        let held = authority
            .root
            .overlay
            .archive_mutation_gate()
            .expect("transaction gate")
            .archive_transaction();
        let empty_tar = tar::Builder::new(Vec::new())
            .into_inner()
            .expect("empty tar");
        let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(1);
        let join = std::thread::spawn(move || {
            let result = import_authority.import_tar("/dest", &empty_tar);
            finished_tx.send(result).expect("report import");
        });

        assert!(
            finished_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "validation must participate in the same exclusive transaction as apply"
        );
        drop(held);
        finished_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("import resumed")
            .expect("empty import");
        join.join().expect("import thread");
    }

    #[test]
    fn archive_transaction_blocks_a_concurrent_symlink_pivot() {
        let scratch = tempfile::tempdir().expect("scratch");
        let root = cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority())
            .expect("scratch authority");
        let backend = crate::fs_backend::HostFsBackend::from_existing_dir(root);
        backend.make_dir("/dest").expect("destination");
        backend.make_dir("/outside").expect("outside");
        let mut dispatcher = SyscallDispatcher::new();
        let _ = dispatcher.set_fs_backend(Box::new(backend));
        let authority = dispatcher.archive_authority();
        let mutation_authority = authority.clone();
        let held = authority
            .root
            .overlay
            .archive_mutation_gate()
            .expect("transaction gate")
            .archive_transaction();
        let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(1);
        let join = std::thread::spawn(move || {
            let result = mutation_authority
                .root
                .overlay
                .symlink("/outside", "/dest/link");
            finished_tx.send(result).expect("report mutation");
        });

        assert!(
            finished_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "a guest pivot must wait until the archive transaction ends"
        );
        drop(held);
        finished_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("mutation resumed")
            .expect("symlink mutation");
        join.join().expect("mutation thread");
    }

    #[test]
    fn archive_export_rejects_more_than_the_cumulative_entry_budget() {
        let dispatcher = SyscallDispatcher::new();
        dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .make_dir("/wide")
            .expect("wide root");
        for index in 0..=super::MAX_ARCHIVE_ENTRIES {
            dispatcher
                .fs
                .rootfs_vfs
                .overlay
                .make_dir(&format!("/wide/entry-{index:04}"))
                .expect("wide child");
        }

        assert!(matches!(
            dispatcher.archive_export_tar("/wide"),
            Err(super::ArchiveFsError::TooLarge)
        ));
    }

    #[test]
    fn archive_export_never_falls_back_to_unbounded_mount_readdir() {
        let visited = Arc::new(AtomicUsize::new(0));
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.register_mount(
            "/wide",
            Box::new(UnboundedOnlyDirectoryMount {
                visited: Arc::clone(&visited),
            }),
        );

        assert!(matches!(
            dispatcher.archive_export_tar("/wide"),
            Err(super::ArchiveFsError::UnsupportedEntry)
        ));
        assert_eq!(
            visited.load(Ordering::Relaxed),
            0,
            "archive export must reject a mount that cannot enumerate within a caller bound"
        );
    }

    #[test]
    fn archive_export_stops_lazy_mount_enumeration_at_limit_plus_one() {
        let visited = Arc::new(AtomicUsize::new(0));
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.register_mount(
            "/wide",
            Box::new(BoundedLazyDirectoryMount {
                visited: Arc::clone(&visited),
            }),
        );

        assert!(matches!(
            dispatcher.archive_export_tar("/wide"),
            Err(super::ArchiveFsError::TooLarge)
        ));
        assert_eq!(
            visited.load(Ordering::Relaxed),
            super::MAX_ARCHIVE_ENTRIES,
            "the root entry consumes one slot, so lazy enumeration stops at remaining + 1"
        );
    }

    #[test]
    fn archive_export_stream_contains_requested_tree_and_metadata() {
        let dispatcher = SyscallDispatcher::new();
        let backend = dispatcher.fs.rootfs_vfs.overlay.as_ref();
        backend.make_dir("/dest").expect("destination");
        backend.make_dir("/dest/sub").expect("subdirectory");
        backend
            .set_file_contents("/dest/sub/file", b"payload".to_vec())
            .expect("file");
        backend
            .set_mode("/dest/sub/file", 0o640)
            .expect("file mode");

        let bytes = dispatcher.archive_export_tar("/dest").expect("export");
        let mut archive = tar::Archive::new(bytes.as_slice());
        let mut entries = archive.entries().expect("entries");
        let root = entries.next().expect("root entry").expect("root");
        assert_eq!(
            root.path().expect("root path").as_ref(),
            std::path::Path::new("dest")
        );
        assert!(root.header().entry_type().is_dir());
        let sub = entries.next().expect("sub entry").expect("sub");
        assert_eq!(
            sub.path().expect("sub path").as_ref(),
            std::path::Path::new("dest/sub")
        );
        assert!(sub.header().entry_type().is_dir());
        let mut file = entries.next().expect("file entry").expect("file");
        assert_eq!(
            file.path().expect("file path").as_ref(),
            std::path::Path::new("dest/sub/file")
        );
        assert_eq!(file.header().mode().expect("mode") & 0o7777, 0o640);
        let mut contents = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut contents).expect("contents");
        assert_eq!(contents, b"payload");
        assert!(entries.next().is_none());

        let metadata = dispatcher
            .archive_authority()
            .metadata("/dest/sub/file")
            .expect("archive metadata");
        assert_eq!(metadata.name, "file");
        assert_eq!(metadata.size, 7);
        assert_eq!(metadata.mode, 0o100640);
        assert_eq!(metadata.link_target, None);
    }
}
