//! Exact file-object authority retained for `/proc/<pid>/exe`.
//!
//! A pathname is only a lookup key.  Once exec has selected a regular file,
//! the process retains this object so unlink, rename, or replacement of that
//! pathname cannot retarget the running image.

use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::sync::Arc;

use super::{FsView, SyscallDispatcher};

#[derive(Debug)]
pub(crate) enum ExecSourceError {
    Linux(carrick_abi::LinuxErrno),
    Host(io::Error),
}

impl From<io::Error> for ExecSourceError {
    fn from(error: io::Error) -> Self {
        Self::Host(error)
    }
}

#[derive(Debug)]
enum ExecutableBacking {
    HostFile {
        file: std::fs::File,
        device: u64,
        inode: u64,
    },
    SharedObject(Arc<crate::fs_backend::SharedFileObject>),
    SharedBytes(Arc<[u8]>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ExecutableObjectId {
    Host { device: u64, inode: u64 },
    Memory(u64),
}

#[derive(Debug)]
struct ExecutableDisplay {
    path: String,
    deleted: bool,
}

#[derive(Debug, Default)]
pub(in crate::dispatch) struct ExecutableAuthorityRegistry {
    displays: parking_lot::Mutex<
        std::collections::HashMap<
            ExecutableObjectId,
            Vec<std::sync::Weak<parking_lot::RwLock<ExecutableDisplay>>>,
        >,
    >,
}

impl ExecutableAuthorityRegistry {
    fn register(
        &self,
        object_id: ExecutableObjectId,
        display: &Arc<parking_lot::RwLock<ExecutableDisplay>>,
    ) {
        let mut displays = self.displays.lock();
        let entries = displays.entry(object_id).or_default();
        entries.retain(|entry| entry.strong_count() != 0);
        entries.push(Arc::downgrade(display));
    }

    fn visit(&self, object_id: ExecutableObjectId, mut update: impl FnMut(&mut ExecutableDisplay)) {
        let mut displays = self.displays.lock();
        let Some(entries) = displays.get_mut(&object_id) else {
            return;
        };
        entries.retain(|entry| {
            let Some(display) = entry.upgrade() else {
                return false;
            };
            update(&mut display.write());
            true
        });
    }

    fn rename_prefix(&self, from: &str, to: &str) {
        let mut displays = self.displays.lock();
        for entries in displays.values_mut() {
            entries.retain(|entry| {
                let Some(display) = entry.upgrade() else {
                    return false;
                };
                let mut display = display.write();
                if !display.deleted
                    && display.path.starts_with(from)
                    && display
                        .path
                        .as_bytes()
                        .get(from.len())
                        .is_some_and(|byte| *byte == b'/')
                {
                    display.path = format!("{to}{}", &display.path[from.len()..]);
                }
                true
            });
        }
    }

    fn exchange_prefixes(&self, first: &str, second: &str) {
        let mut displays = self.displays.lock();
        for entries in displays.values_mut() {
            entries.retain(|entry| {
                let Some(display) = entry.upgrade() else {
                    return false;
                };
                let mut display = display.write();
                if display.deleted {
                    return true;
                }
                if display.path.starts_with(first)
                    && display
                        .path
                        .as_bytes()
                        .get(first.len())
                        .is_some_and(|byte| *byte == b'/')
                {
                    display.path = format!("{second}{}", &display.path[first.len()..]);
                } else if display.path.starts_with(second)
                    && display
                        .path
                        .as_bytes()
                        .get(second.len())
                        .is_some_and(|byte| *byte == b'/')
                {
                    display.path = format!("{first}{}", &display.path[second.len()..]);
                }
                true
            });
        }
    }
}

/// The exact object selected by one executable lookup.
#[derive(Clone, Debug)]
pub(crate) struct ExecSource {
    backing: Arc<ExecutableBacking>,
    object_id: ExecutableObjectId,
    resolved_path: String,
    mode: u32,
    uid: carrick_abi::NsUid,
    gid: carrick_abi::NsGid,
}

/// Process-owned executable identity. Fork shares both the object and its live
/// dentry display; a rename by any task in the namespace updates every holder.
#[derive(Clone, Debug)]
pub(crate) struct CurrentExecutable {
    source: ExecSource,
    display: Arc<parking_lot::RwLock<ExecutableDisplay>>,
}

impl ExecSource {
    pub(crate) fn host(file: std::fs::File, resolved_path: String) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        let (guest_mode, uid, gid, _) = crate::fs_backend::host::fd_carrick_meta(file.as_raw_fd());
        Ok(Self {
            object_id: ExecutableObjectId::Host {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            backing: Arc::new(ExecutableBacking::HostFile {
                file,
                device: metadata.dev(),
                inode: metadata.ino(),
            }),
            resolved_path,
            mode: guest_mode.unwrap_or(metadata.mode() as u32 & 0o7777),
            uid: uid.unwrap_or(carrick_abi::NsUid::ROOT),
            gid: gid.unwrap_or(carrick_abi::NsGid::ROOT),
        })
    }

    pub(crate) fn shared(
        bytes: Arc<[u8]>,
        object_id: u64,
        resolved_path: String,
        mode: u32,
        uid: carrick_abi::NsUid,
        gid: carrick_abi::NsGid,
    ) -> Self {
        Self {
            backing: Arc::new(ExecutableBacking::SharedBytes(bytes)),
            object_id: ExecutableObjectId::Memory(object_id),
            resolved_path,
            mode,
            uid,
            gid,
        }
    }

    pub(crate) fn shared_object(
        object: Arc<crate::fs_backend::SharedFileObject>,
        resolved_path: String,
    ) -> Self {
        let object_id = object.object_id();
        Self {
            backing: Arc::new(ExecutableBacking::SharedObject(object)),
            object_id: ExecutableObjectId::Memory(object_id),
            resolved_path,
            mode: 0,
            uid: carrick_abi::NsUid::ROOT,
            gid: carrick_abi::NsGid::ROOT,
        }
    }

    pub(crate) fn exec_access_errno(
        &self,
        uid: carrick_abi::NsUid,
        gid: carrick_abi::NsGid,
    ) -> Result<(), carrick_abi::LinuxErrno> {
        let (file_uid, file_gid, mode) = match self.backing.as_ref() {
            ExecutableBacking::HostFile { file, .. } => {
                let metadata = file.metadata().map_err(|error| {
                    error
                        .raw_os_error()
                        .map(crate::host_to_linux_errno)
                        .unwrap_or(crate::linux_abi::LINUX_EIO)
                })?;
                let (guest_mode, guest_uid, guest_gid, _) =
                    crate::fs_backend::host::fd_carrick_meta(file.as_raw_fd());
                (
                    guest_uid.unwrap_or(carrick_abi::NsUid::ROOT),
                    guest_gid.unwrap_or(carrick_abi::NsGid::ROOT),
                    guest_mode.unwrap_or(metadata.mode() as u32 & 0o7777),
                )
            }
            ExecutableBacking::SharedObject(object) => (self.uid, self.gid, object.mode()),
            ExecutableBacking::SharedBytes(_) => (self.uid, self.gid, self.mode),
        };
        crate::dispatch::dac_check(
            uid,
            gid,
            file_uid,
            file_gid,
            mode,
            false,
            crate::linux_abi::LINUX_X_OK,
        )
        .map(|_| ())
    }

    pub(crate) fn object_id(&self) -> ExecutableObjectId {
        self.object_id
    }

    pub(crate) fn read_head(&self, max: usize) -> io::Result<Vec<u8>> {
        match self.backing.as_ref() {
            ExecutableBacking::SharedObject(object) => Ok(object.read_prefix(max)),
            ExecutableBacking::SharedBytes(bytes) => Ok(bytes[..bytes.len().min(max)].to_vec()),
            ExecutableBacking::HostFile { file, .. } => {
                let mut bytes = vec![0; max];
                let mut filled = 0;
                while filled < max {
                    match file.read_at(&mut bytes[filled..], filled as u64) {
                        Ok(0) => break,
                        Ok(count) => filled += count,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error),
                    }
                }
                bytes.truncate(filled);
                Ok(bytes)
            }
        }
    }

    pub(crate) fn len(&self) -> io::Result<usize> {
        match self.backing.as_ref() {
            ExecutableBacking::SharedObject(object) => Ok(object.len()),
            ExecutableBacking::SharedBytes(bytes) => Ok(bytes.len()),
            ExecutableBacking::HostFile { file, .. } => usize::try_from(file.metadata()?.len())
                .map_err(|_| io::Error::from_raw_os_error(libc::EFBIG)),
        }
    }

    pub(crate) fn stat_fields(
        &self,
    ) -> io::Result<(u64, u32, carrick_abi::NsUid, carrick_abi::NsGid, usize)> {
        match self.backing.as_ref() {
            ExecutableBacking::HostFile { file, inode, .. } => {
                let metadata = file.metadata()?;
                let (mode, uid, gid, _) =
                    crate::fs_backend::host::fd_carrick_meta(file.as_raw_fd());
                Ok((
                    *inode,
                    mode.unwrap_or(metadata.mode() as u32 & 0o7777),
                    uid.unwrap_or(carrick_abi::NsUid::ROOT),
                    gid.unwrap_or(carrick_abi::NsGid::ROOT),
                    usize::try_from(metadata.len())
                        .map_err(|_| io::Error::from_raw_os_error(libc::EFBIG))?,
                ))
            }
            ExecutableBacking::SharedObject(object) => Ok((
                crate::dispatch::inode_for_path(std::path::Path::new(&self.resolved_path)),
                object.mode(),
                self.uid,
                self.gid,
                object.len(),
            )),
            ExecutableBacking::SharedBytes(bytes) => Ok((
                crate::dispatch::inode_for_path(std::path::Path::new(&self.resolved_path)),
                self.mode,
                self.uid,
                self.gid,
                bytes.len(),
            )),
        }
    }

    pub(crate) fn host_fd(&self) -> Option<i32> {
        match self.backing.as_ref() {
            ExecutableBacking::HostFile { file, .. } => Some(file.as_raw_fd()),
            _ => None,
        }
    }

    pub(crate) fn read_range(&self, offset: usize, max: usize) -> io::Result<Vec<u8>> {
        match self.backing.as_ref() {
            ExecutableBacking::SharedObject(object) => Ok(object.read_range(offset, max)),
            ExecutableBacking::SharedBytes(bytes) => Ok(bytes
                .get(offset..)
                .unwrap_or_default()
                .iter()
                .take(max)
                .copied()
                .collect()),
            ExecutableBacking::HostFile { file, .. } => {
                let available = self.len()?.saturating_sub(offset);
                let mut bytes = vec![0; available.min(max)];
                let mut filled = 0;
                while filled < bytes.len() {
                    match file.read_at(&mut bytes[filled..], (offset + filled) as u64) {
                        Ok(0) => break,
                        Ok(count) => filled += count,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error),
                    }
                }
                bytes.truncate(filled);
                Ok(bytes)
            }
        }
    }

    pub(crate) fn read_all(&self) -> io::Result<Vec<u8>> {
        match self.backing.as_ref() {
            ExecutableBacking::SharedObject(object) => Ok(object.read_all()),
            ExecutableBacking::SharedBytes(bytes) => Ok(bytes.as_ref().to_vec()),
            ExecutableBacking::HostFile { file, .. } => {
                let length = usize::try_from(file.metadata()?.len())
                    .map_err(|_| io::Error::from_raw_os_error(libc::EFBIG))?;
                let mut bytes = vec![0; length];
                let mut filled = 0;
                while filled < length {
                    match file.read_at(&mut bytes[filled..], filled as u64) {
                        Ok(0) => {
                            bytes.truncate(filled);
                            break;
                        }
                        Ok(count) => filled += count,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error),
                    }
                }
                Ok(bytes)
            }
        }
    }

    pub(crate) fn host_identity(&self) -> Option<(u64, u64)> {
        match self.backing.as_ref() {
            ExecutableBacking::HostFile { device, inode, .. } => Some((*device, *inode)),
            ExecutableBacking::SharedObject(_) | ExecutableBacking::SharedBytes(_) => None,
        }
    }

    pub(crate) fn hvpatch_cache_key(
        &self,
        linux_page_size: u64,
        vdso: bool,
        requires_syscall_traps: bool,
        needs_at_base: bool,
    ) -> Option<String> {
        let ExecutableBacking::HostFile {
            file,
            device,
            inode,
            ..
        } = self.backing.as_ref()
        else {
            return None;
        };
        let metadata = file.metadata().ok()?;
        let size = metadata.size();
        let mtime = metadata.mtime();
        let mtime_nsec = metadata.mtime_nsec();
        let ctime = metadata.ctime();
        let ctime_nsec = metadata.ctime_nsec();
        Some(format!(
            "{}\0{device}:{inode}:{size}:{mtime}:{mtime_nsec}:{ctime}:{ctime_nsec}\0{linux_page_size}\0{}\0{}\0{}",
            self.resolved_path,
            u8::from(vdso),
            u8::from(requires_syscall_traps),
            u8::from(needs_at_base)
        ))
    }

    pub(in crate::dispatch) fn into_current(
        self,
        registry: &ExecutableAuthorityRegistry,
    ) -> CurrentExecutable {
        let display_path = self.resolved_path.clone();
        let current = CurrentExecutable {
            source: self,
            display: Arc::new(parking_lot::RwLock::new(ExecutableDisplay {
                path: display_path,
                deleted: false,
            })),
        };
        registry.register(current.source.object_id(), &current.display);
        current
    }

    #[cfg(test)]
    fn same_object(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.backing, &other.backing)
    }
}

impl CurrentExecutable {
    pub(crate) fn source(&self) -> &ExecSource {
        &self.source
    }

    pub(crate) fn display_path(&self) -> String {
        let display = self.display.read();
        if display.deleted {
            format!("{} (deleted)", display.path)
        } else {
            display.path.clone()
        }
    }

    pub(crate) fn is_deleted(&self) -> bool {
        self.display.read().deleted
    }

    #[cfg(test)]
    pub(crate) fn unlink_display(&self, object_id: ExecutableObjectId, path: &str) {
        if self.source.object_id != object_id {
            return;
        }
        let mut display = self.display.write();
        if display.path == path {
            display.deleted = true;
        }
    }
}

fn materialize_shared(contents: crate::fs_backend::SharedFileContents) -> Arc<[u8]> {
    if contents.dirty.is_empty() && contents.len == contents.base.len() {
        return contents.base;
    }
    let mut bytes = vec![0; contents.len];
    let base_len = contents.base.len().min(contents.len);
    bytes[..base_len].copy_from_slice(&contents.base[..base_len]);
    for (offset, dirty) in contents.dirty {
        if offset >= bytes.len() {
            continue;
        }
        let count = dirty.len().min(bytes.len() - offset);
        bytes[offset..offset + count].copy_from_slice(&dirty[..count]);
    }
    bytes.into()
}

fn executable_object_id_at(
    fs: &crate::dispatch::fs::FsState,
    path: &str,
) -> Option<ExecutableObjectId> {
    use crate::fs_backend::OverlayEntryKind;
    if fs.rootfs_vfs.overlay.lookup_kind(path) == Some(OverlayEntryKind::File)
        && let Some(file) = fs.rootfs_vfs.overlay.open_file_readonly(path)
    {
        let metadata = file.metadata().ok()?;
        return Some(ExecutableObjectId::Host {
            device: metadata.dev(),
            inode: metadata.ino(),
        });
    }
    if let Some(contents) = fs.rootfs_vfs.overlay.shared_file_contents(path) {
        return Some(ExecutableObjectId::Memory(contents.object_id));
    }
    if fs.rootfs_vfs.overlay.lookup_kind(path).is_some() {
        return None;
    }
    fs.rootfs_vfs.rootfs.as_ref().and_then(|rootfs| {
        rootfs.open_file_readonly(path).and_then(|file| {
            let metadata = file.metadata().ok()?;
            Some(ExecutableObjectId::Host {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        })
    })
}

fn notify_rename(
    fs: &crate::dispatch::fs::FsState,
    object_id: ExecutableObjectId,
    from: &str,
    to: &str,
) {
    fs.executable_authorities.visit(object_id, |display| {
        if !display.deleted && display.path == from {
            display.path = to.to_owned();
        }
    });
}

fn notify_unlink(fs: &crate::dispatch::fs::FsState, object_id: ExecutableObjectId, path: &str) {
    fs.executable_authorities.visit(object_id, |display| {
        if display.path == path {
            display.deleted = true;
        }
    });
}

impl<'a> FsView<'a> {
    pub(super) fn executable_object_id_at(&self, path: &str) -> Option<ExecutableObjectId> {
        executable_object_id_at(self.fs, path)
    }

    pub(super) fn notify_executable_rename(
        &self,
        object_id: ExecutableObjectId,
        from: &str,
        to: &str,
    ) {
        notify_rename(self.fs, object_id, from, to);
    }

    pub(super) fn notify_executable_unlink(&self, object_id: ExecutableObjectId, path: &str) {
        notify_unlink(self.fs, object_id, path);
    }

    pub(super) fn notify_executable_directory_rename(&self, from: &str, to: &str) {
        self.fs.executable_authorities.rename_prefix(from, to);
    }

    pub(super) fn notify_executable_directory_exchange(&self, first: &str, second: &str) {
        self.fs
            .executable_authorities
            .exchange_prefixes(first, second);
    }
}

impl SyscallDispatcher {
    /// Acquire one exact object through the layered executable view.  Every read
    /// made from the returned source is bound to that object, never a later
    /// lookup of `path`.
    pub(crate) fn acquire_exec_source(
        &self,
        context: &crate::kernel::KernelContext,
        path: &str,
    ) -> Result<ExecSource, ExecSourceError> {
        let visible_self = crate::dispatch::fs::proc_synthetic::proc_visible_self(context);
        if crate::dispatch::fs::proc_synthetic::proc_self_magic_link(path, visible_self)
            == Some("exe")
        {
            return self
                .current_executable()
                .map(|current| current.source().clone())
                .ok_or(ExecSourceError::Linux(crate::linux_abi::LINUX_ENOENT));
        }
        if let Some(fd) =
            crate::dispatch::fs::proc_synthetic::proc_self_fd_number(path, visible_self)
        {
            let source = self
                .open_file(fd)
                .and_then(|file| file.description.retained_exec_source());
            if let Some(source) = source {
                return Ok(source);
            }
        }
        let resolved = self
            .canonicalize_following(path)
            .map_err(ExecSourceError::Linux)?;
        if self
            .layered_lstat(&resolved)
            .is_ok_and(|metadata| metadata.kind == crate::rootfs::RootFsEntryKind::Directory)
        {
            return Err(ExecSourceError::Linux(crate::linux_abi::LINUX_EACCES));
        }
        self.acquire_exec_source_at(&resolved)
            .map_err(ExecSourceError::Host)
    }

    fn acquire_exec_source_at(&self, path: &str) -> io::Result<ExecSource> {
        use crate::fs_backend::OverlayEntryKind;

        match self.fs.rootfs_vfs.overlay.lookup_kind(path) {
            Some(OverlayEntryKind::File) => {
                if let Some(file) = self.fs.rootfs_vfs.overlay.open_file_readonly(path) {
                    return ExecSource::host(file, path.to_owned());
                }
                let entry = self
                    .fs
                    .rootfs_vfs
                    .overlay
                    .shared_file_entry(path, false)
                    .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;
                if let Some(object) = entry.object {
                    return Ok(ExecSource::shared_object(object, path.to_owned()));
                }
                return Ok(ExecSource::shared(
                    materialize_shared(entry.contents.clone()),
                    entry.contents.object_id,
                    path.to_owned(),
                    entry.metadata.mode,
                    carrick_abi::NsUid::ROOT,
                    carrick_abi::NsGid::ROOT,
                ));
            }
            Some(OverlayEntryKind::Dir) => {
                return Err(io::Error::from_raw_os_error(libc::EACCES));
            }
            Some(OverlayEntryKind::Deleted) => {
                return Err(io::Error::from_raw_os_error(libc::ENOENT));
            }
            None => {}
        }

        if let Some(rootfs) = self.fs.rootfs_vfs.rootfs.as_ref() {
            if let Some(file) = rootfs.open_file_readonly(path) {
                return ExecSource::host(file, path.to_owned());
            }
            if let Ok(bytes) = rootfs.read_shared(path) {
                let metadata = rootfs
                    .metadata(path)
                    .map_err(|_| io::Error::from_raw_os_error(libc::ENOENT))?;
                return Ok(ExecSource::shared(
                    bytes,
                    crate::fs_backend::fresh_file_object_id(),
                    path.to_owned(),
                    metadata.mode,
                    carrick_abi::NsUid::ROOT,
                    carrick_abi::NsGid::ROOT,
                ));
            }
        }

        if let Some((bytes, metadata)) = self.fs.vfs_mounts.resolve(path).and_then(|mount| {
            let metadata = mount.vfs.lookup(path).ok()?;
            let bytes = mount.vfs.read_file(path).ok()?;
            Some((bytes, metadata))
        }) {
            return Ok(ExecSource::shared(
                bytes.into(),
                crate::fs_backend::fresh_file_object_id(),
                path.to_owned(),
                metadata.mode,
                carrick_abi::NsUid::new(metadata.uid),
                carrick_abi::NsGid::new(metadata.gid),
            ));
        }

        Err(io::Error::from_raw_os_error(libc::ENOENT))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::DispatchOutcome;
    use std::io::Write as _;

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "carrick-exec-authority-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).expect("create authority fixture directory");
        path
    }

    #[test]
    fn retained_host_source_survives_unlink() {
        let dir = temp_dir("unlink");
        let path = dir.join("image");
        std::fs::write(&path, b"original-image").unwrap();
        let source =
            ExecSource::host(std::fs::File::open(&path).unwrap(), "/image".into()).unwrap();

        std::fs::remove_file(&path).unwrap();
        assert_eq!(source.read_all().unwrap(), b"original-image");
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn retained_host_source_survives_rename_and_replacement() {
        let dir = temp_dir("replacement");
        let old = dir.join("image");
        let renamed = dir.join("renamed");
        std::fs::write(&old, b"original-image").unwrap();
        let source = ExecSource::host(std::fs::File::open(&old).unwrap(), "/image".into()).unwrap();
        let identity = source.host_identity().unwrap();

        std::fs::rename(&old, &renamed).unwrap();
        let mut replacement = std::fs::File::create(&old).unwrap();
        replacement.write_all(b"replacement").unwrap();
        assert_eq!(source.read_all().unwrap(), b"original-image");
        assert_ne!(
            identity,
            ExecSource::host(std::fs::File::open(&old).unwrap(), "/image".into())
                .unwrap()
                .host_identity()
                .unwrap()
        );

        std::fs::remove_file(old).unwrap();
        std::fs::remove_file(renamed).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn retained_host_source_rechecks_execute_mode_on_exact_object() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = temp_dir("chmod");
        let path = dir.join("image");
        std::fs::write(&path, b"image").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let source =
            ExecSource::host(std::fs::File::open(&path).unwrap(), "/image".into()).unwrap();
        assert_eq!(
            source.exec_access_errno(carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT),
            Ok(())
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            source.exec_access_errno(carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT),
            Err(crate::linux_abi::LINUX_EACCES)
        );
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn retained_host_source_observes_writes_to_exact_object_after_rename() {
        let dir = temp_dir("write-after-rename");
        let old = dir.join("image");
        let renamed = dir.join("renamed");
        std::fs::write(&old, b"old").unwrap();
        let source = ExecSource::host(std::fs::File::open(&old).unwrap(), "/image".into()).unwrap();
        std::fs::rename(&old, &renamed).unwrap();
        std::fs::write(&renamed, b"new-contents").unwrap();
        assert_eq!(source.read_all().unwrap(), b"new-contents");
        std::fs::remove_file(renamed).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn registry_updates_only_the_affected_hardlink_display() {
        let source = ExecSource::shared(
            Arc::from(&b"elf"[..]),
            crate::fs_backend::fresh_file_object_id(),
            "/first".into(),
            0o755,
            carrick_abi::NsUid::ROOT,
            carrick_abi::NsGid::ROOT,
        );
        let registry = ExecutableAuthorityRegistry::default();
        let first = source.clone().into_current(&registry);
        let mut second_source = source;
        second_source.resolved_path = "/second".into();
        let second = second_source.into_current(&registry);

        registry.visit(first.source.object_id(), |display| {
            if display.path == "/first" {
                display.path = "/renamed".into();
            }
        });
        assert_eq!(first.display_path(), "/renamed");
        assert_eq!(second.display_path(), "/second");
    }

    #[test]
    fn registry_rewrites_executable_beneath_renamed_and_exchanged_directories() {
        let registry = ExecutableAuthorityRegistry::default();
        let first = ExecSource::shared(
            Arc::from(&b"one"[..]),
            crate::fs_backend::fresh_file_object_id(),
            "/a/bin/app".into(),
            0o755,
            carrick_abi::NsUid::ROOT,
            carrick_abi::NsGid::ROOT,
        )
        .into_current(&registry);
        let second = ExecSource::shared(
            Arc::from(&b"two"[..]),
            crate::fs_backend::fresh_file_object_id(),
            "/c/tool".into(),
            0o755,
            carrick_abi::NsUid::ROOT,
            carrick_abi::NsGid::ROOT,
        )
        .into_current(&registry);

        registry.rename_prefix("/a", "/b");
        assert_eq!(first.display_path(), "/b/bin/app");
        registry.exchange_prefixes("/b", "/c");
        assert_eq!(first.display_path(), "/c/bin/app");
        assert_eq!(second.display_path(), "/b/tool");
    }

    #[test]
    fn fork_clone_shares_object_but_copies_display_state() {
        let source = ExecSource::shared(
            Arc::from(&b"elf"[..]),
            crate::fs_backend::fresh_file_object_id(),
            "/old".into(),
            0o755,
            carrick_abi::NsUid::ROOT,
            carrick_abi::NsGid::ROOT,
        );
        let registry = ExecutableAuthorityRegistry::default();
        let parent = source.into_current(&registry);
        let child = parent.clone();
        registry.visit(child.source.object_id(), |display| {
            if display.path == "/old" {
                display.path = "/new".into();
            }
        });

        assert!(parent.source.same_object(child.source()));
        assert_eq!(parent.display_path(), "/new");
        assert_eq!(child.display_path(), "/new");
    }

    #[test]
    fn deleted_display_does_not_retarget_when_name_is_reused() {
        let current = ExecSource::shared(
            Arc::from(&b"old"[..]),
            crate::fs_backend::fresh_file_object_id(),
            "/image".into(),
            0o755,
            carrick_abi::NsUid::ROOT,
            carrick_abi::NsGid::ROOT,
        )
        .into_current(&ExecutableAuthorityRegistry::default());
        current.unlink_display(current.source.object_id(), "/image");
        let replacement = ExecSource::shared(
            Arc::from(&b"new"[..]),
            crate::fs_backend::fresh_file_object_id(),
            "/image".into(),
            0o755,
            carrick_abi::NsUid::ROOT,
            carrick_abi::NsGid::ROOT,
        );

        assert_eq!(current.display_path(), "/image (deleted)");
        assert_eq!(current.source.read_all().unwrap(), b"old");
        assert_eq!(replacement.read_all().unwrap(), b"new");
    }

    #[test]
    fn dispatcher_memory_source_retains_live_inode_across_namespace_changes() {
        use crate::fs_backend::{FsBackend as _, MemoryBackend};

        let backend = MemoryBackend::new();
        backend
            .set_file_contents("/image", b"old".to_vec())
            .unwrap();
        backend.set_mode("/image", 0o755).unwrap();
        let before = backend.shared_file_entry("/image", false).unwrap();
        let stale_snapshot = ExecSource::shared(
            materialize_shared(before.contents.clone()),
            before.contents.object_id,
            "/image".into(),
            before.metadata.mode,
            carrick_abi::NsUid::ROOT,
            carrick_abi::NsGid::ROOT,
        );

        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_fs_backend(Box::new(backend.clone()));
        let context = dispatcher.capture_one_task_context().unwrap();
        let source = dispatcher.acquire_exec_source(&context, "/image").unwrap();
        let original_id = source.object_id();

        assert!(
            backend
                .rename_overlay_entry("/image", "/renamed")
                .unwrap()
                .source_was_owned()
        );
        backend
            .set_file_contents("/renamed", b"updated".to_vec())
            .unwrap();
        backend.set_mode("/renamed", 0o644).unwrap();
        assert_eq!(stale_snapshot.read_all().unwrap(), b"old");
        assert_eq!(source.read_all().unwrap(), b"updated");
        assert_eq!(
            source.exec_access_errno(carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT),
            Err(crate::linux_abi::LINUX_EACCES)
        );

        assert!(dispatcher.fs.rootfs_vfs.overlay.remove_entry("/image"));
        dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .set_file_contents("/image", b"replacement".to_vec())
            .unwrap();
        dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .set_mode("/image", 0o755)
            .unwrap();
        let replacement = dispatcher.acquire_exec_source(&context, "/image").unwrap();
        assert_ne!(replacement.object_id(), original_id);
        assert_eq!(replacement.read_all().unwrap(), b"replacement");
        assert_eq!(source.read_all().unwrap(), b"updated");
    }

    #[test]
    fn in_memory_rootfs_source_preserves_non_executable_mode() {
        use crate::rootfs::{LayerSource, RootFs};
        use tar::{Builder, Header};

        let mut archive = Vec::new();
        {
            let mut builder = Builder::new(&mut archive);
            let bytes = b"not executable";
            let mut header = Header::new_gnu();
            header.set_path("bin/plain").unwrap();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, &bytes[..]).unwrap();
            builder.finish().unwrap();
        }
        let rootfs = RootFs::from_layers([LayerSource::Tar(archive)]).unwrap();
        let dispatcher = SyscallDispatcher::with_rootfs(rootfs);
        let context = dispatcher.capture_one_task_context().unwrap();
        let source = dispatcher
            .acquire_exec_source(&context, "/bin/plain")
            .unwrap();
        assert_eq!(
            source.exec_access_errno(carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT),
            Err(crate::linux_abi::LINUX_EACCES)
        );
    }

    #[test]
    fn proc_exe_fd_keeps_original_source_after_process_exec_identity_changes() {
        let dispatcher = SyscallDispatcher::new();
        let source_a = ExecSource::shared(
            Arc::from(&b"program-a"[..]),
            crate::fs_backend::fresh_file_object_id(),
            "/a".into(),
            0o755,
            carrick_abi::NsUid::ROOT,
            carrick_abi::NsGid::ROOT,
        );
        let source_b = ExecSource::shared(
            Arc::from(&b"program-b"[..]),
            crate::fs_backend::fresh_file_object_id(),
            "/b".into(),
            0o755,
            carrick_abi::NsUid::ROOT,
            carrick_abi::NsGid::ROOT,
        );
        dispatcher.set_executable_identity_with_source(
            "/a",
            vec!["a".into()],
            Vec::new(),
            source_a.clone(),
        );
        let current_a = dispatcher
            .proc
            .lock()
            .current_executable
            .clone()
            .expect("current executable A");
        let outcome =
            dispatcher
                .fs_view()
                .install_proc_executable_source("/proc/self/exe", current_a, 0);
        let DispatchOutcome::Returned { value: fd } = outcome else {
            panic!("proc executable fd installation failed: {outcome:?}");
        };
        dispatcher.set_executable_identity_with_source(
            "/b",
            vec!["b".into()],
            Vec::new(),
            source_b,
        );
        let context = dispatcher.capture_one_task_context().unwrap();
        let retained = dispatcher
            .acquire_exec_source(&context, &format!("/proc/self/fd/{fd}"))
            .unwrap();
        assert_eq!(retained.read_all().unwrap(), b"program-a");
    }
}
