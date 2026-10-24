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
pub enum ExecSourceError {
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
    SharedObject(Arc<carrick_vfs::fs_backend::SharedFileObject>),
    SharedBytes(Arc<[u8]>),
    OpenFile(Arc<crate::kernel::objects::MappedFileReference>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExecutableObjectId {
    Host { device: u64, inode: u64 },
    Memory(u64),
    Description(crate::kernel::FileDescriptionId),
}

#[derive(Debug)]
struct ExecutableDisplay {
    path: String,
    deleted: bool,
}

#[derive(Debug, Default)]
pub(in crate::dispatch) struct ExecutableAuthorityRegistry {
    displays: parking_lot::Mutex<ExecutableDisplayIndex>,
    #[cfg(test)]
    lookup_visited: std::sync::atomic::AtomicU64,
    #[cfg(test)]
    prefix_visited: std::sync::atomic::AtomicU64,
}

type DisplayWeak = std::sync::Weak<parking_lot::RwLock<ExecutableDisplay>>;

#[derive(Debug, Default)]
struct ExecutableDisplayIndex {
    by_object: std::collections::HashMap<ExecutableObjectId, Vec<DisplayWeak>>,
    // Ordered paths bound directory-rename work to displays beneath that
    // directory. Exact file rename/unlink probes one key.
    by_path: std::collections::BTreeMap<String, Vec<DisplayWeak>>,
}

impl ExecutableDisplayIndex {
    fn move_display(&mut self, old: &str, new: &str, display: &DisplayWeak) {
        if let Some(entries) = self.by_path.get_mut(old) {
            entries.retain(|entry| entry.strong_count() != 0 && !entry.ptr_eq(display));
            if entries.is_empty() {
                self.by_path.remove(old);
            }
        }
        self.by_path
            .entry(new.to_owned())
            .or_default()
            .push(display.clone());
    }

    fn rewrite_prefixes(
        &mut self,
        first: &str,
        first_to: &str,
        second: Option<(&str, &str)>,
    ) -> usize {
        let prefix = |path: &str| format!("{}/", path.trim_end_matches('/'));
        let first_prefix = prefix(first);
        let second_prefix = second.map(|(from, to)| (prefix(from), to));
        let keys = self
            .by_path
            .range(first_prefix.clone()..)
            .take_while(|(path, _)| path.starts_with(&first_prefix))
            .map(|(path, _)| path.clone())
            .chain(second_prefix.iter().flat_map(|(prefix, _)| {
                self.by_path
                    .range(prefix.clone()..)
                    .take_while(move |(path, _)| path.starts_with(prefix))
                    .map(|(path, _)| path.clone())
            }))
            .collect::<std::collections::BTreeSet<_>>();
        let mut moved = Vec::new();
        for old in keys {
            if let Some(entries) = self.by_path.remove(&old) {
                moved.push((old, entries));
            }
        }
        let mut visited = 0;
        for (old, entries) in moved {
            let to = if old.starts_with(&first_prefix) {
                Some(format!("{first_to}{}", &old[first.len()..]))
            } else {
                second_prefix.as_ref().and_then(|(prefix, to)| {
                    old.starts_with(prefix)
                        .then(|| format!("{to}{}", &old[prefix.len() - 1..]))
                })
            };
            for entry in entries {
                visited += 1;
                let Some(display) = entry.upgrade() else {
                    continue;
                };
                let mut live = display.write();
                let next = if live.deleted || live.path != old {
                    live.path.clone()
                } else if let Some(ref to) = to {
                    live.path = to.clone();
                    to.clone()
                } else {
                    old.clone()
                };
                drop(live);
                self.by_path.entry(next).or_default().push(entry);
            }
        }
        visited
    }
}

impl ExecutableAuthorityRegistry {
    fn register(
        &self,
        object_id: ExecutableObjectId,
        display: &Arc<parking_lot::RwLock<ExecutableDisplay>>,
    ) {
        let mut displays = self.displays.lock();
        let entries = displays.by_object.entry(object_id).or_default();
        entries.retain(|entry| entry.strong_count() != 0);
        entries.push(Arc::downgrade(display));
        displays
            .by_path
            .entry(display.read().path.clone())
            .or_default()
            .push(Arc::downgrade(display));
    }

    fn visit(&self, object_id: ExecutableObjectId, mut update: impl FnMut(&mut ExecutableDisplay)) {
        let mut displays = self.displays.lock();
        let Some(entries) = displays.by_object.get_mut(&object_id) else {
            return;
        };
        let mut changed = Vec::new();
        entries.retain(|entry| {
            let Some(display) = entry.upgrade() else {
                return false;
            };
            let mut display = display.write();
            let old = display.path.clone();
            update(&mut display);
            if display.path != old {
                changed.push((old, display.path.clone(), entry.clone()));
            }
            true
        });
        for (old, new, entry) in changed {
            displays.move_display(&old, &new, &entry);
        }
    }

    /// Whether any live display currently names exactly `path`.
    ///
    /// `notify_rename` and `notify_unlink` only ever touch a display whose
    /// path equals the name being moved or removed, so when no display names
    /// either side of a namespace operation, the object identity of that name
    /// cannot affect any display and need not be read from the host.
    fn has_display_path(&self, path: &str) -> bool {
        let mut displays = self.displays.lock();
        let Some(entries) = displays.by_path.get_mut(path) else {
            return false;
        };
        let mut found = false;
        entries.retain(|entry| {
            #[cfg(test)]
            self.lookup_visited
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let Some(display) = entry.upgrade() else {
                return false;
            };
            found |= display.read().path == path;
            true
        });
        if entries.is_empty() {
            displays.by_path.remove(path);
        }
        found
    }

    fn rename_prefix(&self, from: &str, to: &str) {
        let visited = self.displays.lock().rewrite_prefixes(from, to, None);
        #[cfg(test)]
        self.prefix_visited
            .fetch_add(visited as u64, std::sync::atomic::Ordering::Relaxed);
        #[cfg(not(test))]
        let _ = visited;
    }

    fn exchange_prefixes(&self, first: &str, second: &str) {
        let visited = self
            .displays
            .lock()
            .rewrite_prefixes(first, second, Some((second, first)));
        #[cfg(test)]
        self.prefix_visited
            .fetch_add(visited as u64, std::sync::atomic::Ordering::Relaxed);
        #[cfg(not(test))]
        let _ = visited;
    }
}

/// The exact object selected by one executable lookup.
#[derive(Clone, Debug)]
pub struct ExecSource {
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
pub struct CurrentExecutable {
    source: ExecSource,
    display: Arc<parking_lot::RwLock<ExecutableDisplay>>,
}

impl ExecSource {
    pub fn host(file: std::fs::File, resolved_path: String) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        let (guest_mode, uid, gid, _) =
            carrick_vfs::fs_backend::host::fd_carrick_meta(file.as_raw_fd());
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

    /// Retain the opened object, never its pathname. Host files duplicate the
    /// owned descriptor; memory files keep their shared description and bytes.
    pub(super) fn from_open_description(
        description: Arc<crate::kernel::FileDescription>,
    ) -> io::Result<Self> {
        use super::fd_table::OpenDescription;
        use std::os::fd::BorrowedFd;
        // Retain backing before acquiring its I/O guard. Final close takes
        // lifecycle custody before the backing lock, so reverse order deadlocks.
        let is_memory_file = description
            .read_for_io()
            .is_some_and(|open| matches!(&*open, OpenDescription::File { .. }));
        let retained = if is_memory_file {
            Some(
                description
                    .retain_mapping()
                    .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?,
            )
        } else {
            None
        };
        let open = description
            .read_for_io()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;
        match &*open {
            OpenDescription::HostFile {
                host_fd, metadata, ..
            } => {
                // SAFETY: the description guard owns the fd throughout duplication.
                let fd = unsafe { BorrowedFd::borrow_raw(host_fd.raw()) }.try_clone_to_owned()?;
                Self::host(fd.into(), metadata.path.to_string_lossy().into_owned())
            }
            OpenDescription::File { path, metadata, .. } => Ok(Self {
                backing: Arc::new(ExecutableBacking::OpenFile(
                    retained.ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?,
                )),
                object_id: ExecutableObjectId::Description(description.id()),
                resolved_path: path.clone(),
                mode: metadata.mode,
                uid: carrick_abi::NsUid::ROOT,
                gid: carrick_abi::NsGid::ROOT,
            }),
            _ => Err(io::Error::from_raw_os_error(libc::EACCES)),
        }
    }

    fn opened_contents(
        description: &crate::kernel::FileDescription,
    ) -> io::Result<(super::fd_table::FileContents, u32)> {
        let open = description
            .read_for_io()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;
        let super::fd_table::OpenDescription::File {
            contents, metadata, ..
        } = &*open
        else {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        };
        Ok((contents.clone(), metadata.mode))
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
        object: Arc<carrick_vfs::fs_backend::SharedFileObject>,
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
                    carrick_vfs::fs_backend::host::fd_carrick_meta(file.as_raw_fd());
                (
                    guest_uid.unwrap_or(carrick_abi::NsUid::ROOT),
                    guest_gid.unwrap_or(carrick_abi::NsGid::ROOT),
                    guest_mode.unwrap_or(metadata.mode() as u32 & 0o7777),
                )
            }
            ExecutableBacking::SharedObject(object) => (self.uid, self.gid, object.mode()),
            ExecutableBacking::SharedBytes(_) => (self.uid, self.gid, self.mode),
            ExecutableBacking::OpenFile(description) => {
                let (_, mode) = Self::opened_contents(description.description())
                    .map_err(|_| carrick_abi::LINUX_EIO)?;
                (self.uid, self.gid, mode)
            }
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

    /// Update the retained in-memory inode when fchmod succeeds after unlink.
    pub(super) fn set_memory_mode(&self, mode: u32) {
        if let ExecutableBacking::SharedObject(object) = self.backing.as_ref() {
            object.set_mode(mode);
        }
    }

    pub(crate) fn object_id(&self) -> ExecutableObjectId {
        self.object_id
    }

    pub fn read_head(&self, max: usize) -> io::Result<Vec<u8>> {
        match self.backing.as_ref() {
            ExecutableBacking::OpenFile(_) => self.read_range(0, max),
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
            ExecutableBacking::OpenFile(description) => usize::try_from(
                Self::opened_contents(description.description())?
                    .0
                    .len()
                    .map_err(|errno| {
                        io::Error::other(format!("executable source errno {}", errno.get()))
                    })?,
            )
            .map_err(io::Error::other),
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
                    carrick_vfs::fs_backend::host::fd_carrick_meta(file.as_raw_fd());
                Ok((
                    *inode,
                    mode.unwrap_or(metadata.mode() as u32 & 0o7777),
                    uid.unwrap_or(carrick_abi::NsUid::ROOT),
                    gid.unwrap_or(carrick_abi::NsGid::ROOT),
                    usize::try_from(metadata.len())
                        .map_err(|_| io::Error::from_raw_os_error(libc::EFBIG))?,
                ))
            }
            ExecutableBacking::OpenFile(description) => Ok((
                crate::dispatch::inode_for_path(std::path::Path::new(&self.resolved_path)),
                Self::opened_contents(description.description())?.1,
                self.uid,
                self.gid,
                self.len()?,
            )),
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
            ExecutableBacking::OpenFile(description) => {
                let contents = Self::opened_contents(description.description())?.0;
                let length = usize::try_from(contents.len().map_err(|errno| {
                    io::Error::other(format!("executable source errno {}", errno.get()))
                })?)
                .map_err(io::Error::other)?;
                let mut bytes = vec![0; length.saturating_sub(offset).min(max)];
                let read = contents
                    .read_at(offset as u64, &mut bytes)
                    .map_err(|errno| {
                        io::Error::other(format!("executable source errno {}", errno.get()))
                    })?;
                bytes.truncate(read);
                Ok(bytes)
            }
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

    pub fn read_all(&self) -> io::Result<Vec<u8>> {
        match self.backing.as_ref() {
            ExecutableBacking::OpenFile(_) => self.read_range(0, usize::MAX),
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
            ExecutableBacking::SharedObject(_)
            | ExecutableBacking::SharedBytes(_)
            | ExecutableBacking::OpenFile(_) => None,
        }
    }

    pub fn hvpatch_cache_key(
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

pub(super) fn materialize_shared(
    contents: carrick_vfs::fs_backend::SharedFileContents,
) -> Arc<[u8]> {
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
    use carrick_vfs::fs_backend::OverlayEntryKind;
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
    /// Identity of the object an unlink of `path` removes, for
    /// [`Self::notify_executable_unlink`]. `None` when no retained executable
    /// display names `path`: the notification could not change any display,
    /// so the host lookup (a `fstatat` plus an `open`/`fstat`/`close` of the
    /// target) is not paid on every guest unlink.
    pub(super) fn executable_object_id_for_unlink(&self, path: &str) -> Option<ExecutableObjectId> {
        if !self.fs.executable_authorities.has_display_path(path) {
            return None;
        }
        executable_object_id_at(self.fs, path)
    }

    /// Identities of the moved (`from`) and replaced (`to`) objects of a
    /// rename or exchange. Both are read, or neither: the pair also decides
    /// `same_executable_object` (a rename between two hardlinks of one image
    /// must not retarget its display), so gating one side alone would change
    /// that answer. When no display names either path, every notification the
    /// caller could issue is a no-op and both are `None`.
    pub(super) fn executable_object_ids_for_rename(
        &self,
        from: &str,
        to: &str,
    ) -> (Option<ExecutableObjectId>, Option<ExecutableObjectId>) {
        let registry = &self.fs.executable_authorities;
        if !registry.has_display_path(from) && !registry.has_display_path(to) {
            return (None, None);
        }
        (
            executable_object_id_at(self.fs, from),
            executable_object_id_at(self.fs, to),
        )
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
    pub fn acquire_exec_source(
        &self,
        context: &crate::kernel::KernelContext,
        path: &str,
    ) -> Result<ExecSource, ExecSourceError> {
        self.capture_exec_files(context)
            .map_err(ExecSourceError::Linux)?
            .without_host_fallback()
            .acquire(path)
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
            carrick_vfs::fs_backend::fresh_file_object_id(),
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
        assert!(!registry.has_display_path("/first"));
        assert!(registry.has_display_path("/renamed"));
        assert!(registry.has_display_path("/second"));
    }

    #[test]
    fn unrelated_executable_displays_do_not_cost_per_name_lookup() {
        use std::sync::atomic::Ordering;

        let registry = ExecutableAuthorityRegistry::default();
        let displays: Vec<_> = (0..256)
            .map(|i| {
                ExecSource::shared(
                    Arc::from(&b"elf"[..]),
                    carrick_vfs::fs_backend::fresh_file_object_id(),
                    format!("/retained/image{i}"),
                    0o755,
                    carrick_abi::NsUid::ROOT,
                    carrick_abi::NsGid::ROOT,
                )
                .into_current(&registry)
            })
            .collect();
        assert!(!registry.has_display_path("/unrelated/leaf"));
        assert!(
            registry.lookup_visited.load(Ordering::Relaxed) <= 1,
            "an unrelated rename/unlink must not inspect retained displays"
        );
        assert_eq!(displays.len(), 256);
    }

    #[test]
    fn directory_rename_visits_only_descendant_displays() {
        use std::sync::atomic::Ordering;

        let registry = ExecutableAuthorityRegistry::default();
        let unrelated: Vec<_> = (0..256)
            .map(|i| {
                ExecSource::shared(
                    Arc::from(&b"elf"[..]),
                    carrick_vfs::fs_backend::fresh_file_object_id(),
                    format!("/other/image{i}"),
                    0o755,
                    carrick_abi::NsUid::ROOT,
                    carrick_abi::NsGid::ROOT,
                )
                .into_current(&registry)
            })
            .collect();
        let child = ExecSource::shared(
            Arc::from(&b"elf"[..]),
            carrick_vfs::fs_backend::fresh_file_object_id(),
            "/old/bin/app".into(),
            0o755,
            carrick_abi::NsUid::ROOT,
            carrick_abi::NsGid::ROOT,
        )
        .into_current(&registry);

        registry.rename_prefix("/old", "/new");
        assert_eq!(child.display_path(), "/new/bin/app");
        assert_eq!(registry.prefix_visited.load(Ordering::Relaxed), 1);
        assert_eq!(unrelated.len(), 256);
    }

    #[test]
    fn registry_rewrites_executable_beneath_renamed_and_exchanged_directories() {
        let registry = ExecutableAuthorityRegistry::default();
        let first = ExecSource::shared(
            Arc::from(&b"one"[..]),
            carrick_vfs::fs_backend::fresh_file_object_id(),
            "/a/bin/app".into(),
            0o755,
            carrick_abi::NsUid::ROOT,
            carrick_abi::NsGid::ROOT,
        )
        .into_current(&registry);
        let second = ExecSource::shared(
            Arc::from(&b"two"[..]),
            carrick_vfs::fs_backend::fresh_file_object_id(),
            "/c/tool".into(),
            0o755,
            carrick_abi::NsUid::ROOT,
            carrick_abi::NsGid::ROOT,
        )
        .into_current(&registry);

        registry.rename_prefix("/a", "/b");
        assert_eq!(first.display_path(), "/b/bin/app");
        assert!(!registry.has_display_path("/a/bin/app"));
        assert!(registry.has_display_path("/b/bin/app"));
        registry.exchange_prefixes("/b", "/c");
        assert_eq!(first.display_path(), "/c/bin/app");
        assert_eq!(second.display_path(), "/b/tool");
        assert!(!registry.has_display_path("/b/bin/app"));
        assert!(registry.has_display_path("/c/bin/app"));
        assert!(registry.has_display_path("/b/tool"));
    }

    #[test]
    fn fork_clone_shares_object_but_copies_display_state() {
        let source = ExecSource::shared(
            Arc::from(&b"elf"[..]),
            carrick_vfs::fs_backend::fresh_file_object_id(),
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
            carrick_vfs::fs_backend::fresh_file_object_id(),
            "/image".into(),
            0o755,
            carrick_abi::NsUid::ROOT,
            carrick_abi::NsGid::ROOT,
        )
        .into_current(&ExecutableAuthorityRegistry::default());
        current.unlink_display(current.source.object_id(), "/image");
        let replacement = ExecSource::shared(
            Arc::from(&b"new"[..]),
            carrick_vfs::fs_backend::fresh_file_object_id(),
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
        use carrick_vfs::fs_backend::{FsBackend as _, MemoryBackend};

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
        use carrick_vfs::rootfs::{LayerSource, RootFs};
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
            carrick_vfs::fs_backend::fresh_file_object_id(),
            "/a".into(),
            0o755,
            carrick_abi::NsUid::ROOT,
            carrick_abi::NsGid::ROOT,
        );
        let source_b = ExecSource::shared(
            Arc::from(&b"program-b"[..]),
            carrick_vfs::fs_backend::fresh_file_object_id(),
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
        let outcome = dispatcher.fs_view().install_proc_executable_source(
            "/proc/self/exe",
            current_a,
            0,
            &mut None,
        );
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
        assert_eq!(
            dispatcher
                .acquire_exec_source(&context, &format!("/dev/fd/{fd}"))
                .unwrap()
                .read_head(9)
                .unwrap(),
            b"program-a"
        );
    }
    #[test]
    fn exec_capabilities_keep_two_callers_without_host_task_bindings() {
        let first = SyscallDispatcher::new();
        let second = SyscallDispatcher::new();
        for (dispatcher, bytes) in [
            (&first, b"first".as_slice()),
            (&second, b"second".as_slice()),
        ] {
            dispatcher
                .fs
                .rootfs_vfs
                .overlay
                .set_file_contents("/image", bytes.to_vec())
                .unwrap();
            dispatcher
                .fs
                .rootfs_vfs
                .overlay
                .set_mode("/image", 0o755)
                .unwrap();
            let context = dispatcher.capture_one_task_context().unwrap();
            let source = dispatcher.acquire_exec_source(&context, "/image").unwrap();
            dispatcher.set_executable_identity_with_source("/image", vec![], vec![], source);
        }
        let first_context = first.capture_one_task_context().unwrap();
        let second_context = second.capture_one_task_context().unwrap();
        let first_task = Arc::downgrade(first_context.task());
        let second_task = Arc::downgrade(second_context.task());
        let a = first.capture_exec_files(&first_context).unwrap();
        let b = second.capture_exec_files(&second_context).unwrap();
        assert_ne!(a.caller(), b.caller());
        drop(first_context);
        drop(second_context);
        let old = a.acquire("/image").unwrap();
        first
            .fs
            .rootfs_vfs
            .overlay
            .set_mode("/image", 0o644)
            .unwrap();
        assert_eq!(a.check_source(&old).unwrap_err().get(), 13);
        assert!(b.check_source(&b.acquire("/image").unwrap()).is_ok());

        drop(first);
        drop(second);
        assert!(first_task.upgrade().is_none());
        assert!(second_task.upgrade().is_none());
        assert_eq!(
            a.acquire("/proc/self/exe").unwrap().read_all().unwrap(),
            b"first"
        );
        for path in [
            "//proc/self/exe",
            "/proc/./self/exe",
            "/proc/self/fd/../exe",
            "/proc/../proc/self/fd/../exe",
        ] {
            assert_eq!(a.acquire(path).unwrap().read_head(5).unwrap(), b"first");
        }
        assert_eq!(
            b.acquire("/proc/self/exe").unwrap().read_all().unwrap(),
            b"second"
        );
        assert_eq!(a.acquire("image").unwrap().read_all().unwrap(), b"first");
        assert!(
            matches!(a.acquire("/absent"), Err(ExecSourceError::Host(error)) if error.raw_os_error() == Some(2))
                || matches!(a.acquire("/absent"), Err(ExecSourceError::Linux(errno)) if errno.get() == 2)
        );
    }
    #[test]
    fn exec_capabilities_resolve_nonleader_thread_self_after_task_release() {
        let dispatcher = SyscallDispatcher::new();
        dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .set_file_contents("/image", b"guest".to_vec())
            .unwrap();
        let leader = dispatcher.capture_one_task_context().unwrap();
        let source = dispatcher.acquire_exec_source(&leader, "/image").unwrap();
        dispatcher.set_executable_identity_with_source("/image", vec![], vec![], source);
        let tid = dispatcher
            .register_one_task_thread(
                &leader,
                crate::thread::ThreadId::synthetic_for_tests(91_342),
            )
            .unwrap();
        let thread = dispatcher.capture_kernel_context(tid).unwrap();
        let files = dispatcher.capture_exec_files(&thread).unwrap();
        let weak = Arc::downgrade(thread.task());
        drop(thread);
        drop(leader);
        drop(dispatcher);
        assert!(weak.upgrade().is_none());
        for path in ["/proc/thread-self/exe", "/proc/thread-self/../../exe"] {
            assert_eq!(files.acquire(path).unwrap().read_head(5).unwrap(), b"guest");
        }
        assert!(matches!(files.acquire("/proc/2147483647/exe"),
            Err(ExecSourceError::Linux(errno)) if errno.get() == 2));
    }

    #[test]
    fn exec_capabilities_reject_foreign_context() {
        let first = SyscallDispatcher::new();
        let second = SyscallDispatcher::new();
        first
            .fs
            .rootfs_vfs
            .overlay
            .set_file_contents("/image", b"first".to_vec())
            .unwrap();
        let context = second.capture_one_task_context().unwrap();
        assert!(matches!(first.acquire_exec_source(&context, "/image"),
            Err(ExecSourceError::Linux(errno)) if errno.get() == 3));
    }

    #[test]
    fn exec_capabilities_validate_raw_path_before_normalization() {
        let dispatcher = SyscallDispatcher::new();
        dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .set_file_contents("/image", b"image".to_vec())
            .unwrap();
        let context = dispatcher.capture_one_task_context().unwrap();
        let path = format!("{}image", "/".repeat(4096));
        assert!(matches!(dispatcher.acquire_exec_source(&context, &path),
            Err(ExecSourceError::Linux(errno)) if errno.get() == 36));
    }

    #[test]
    fn exec_capabilities_proc_fd_retains_open_inode_after_name_replacement() {
        use super::super::fd_table::{HostFdRef, OpenDescription, OpenDescriptionBase};
        use std::os::fd::IntoRawFd;
        let dispatcher = SyscallDispatcher::new();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("image");
        std::fs::write(&path, b"original").unwrap();
        let opened = std::fs::File::open(&path).unwrap();
        let description = OpenDescription::HostFile {
            base: OpenDescriptionBase::new(0),
            host_fd: HostFdRef::new(opened.into_raw_fd()),
            metadata: carrick_vfs::rootfs::RootFsMetadata {
                path: path.clone(),
                kind: carrick_vfs::rootfs::RootFsEntryKind::File,
                mode: 0o755,
                size: 8,
            },
            writable: false,
        };
        let super::super::DispatchOutcome::Returned { value: fd } =
            dispatcher.install_fd(description, 0)
        else {
            panic!("install source");
        };
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        let context = dispatcher.capture_one_task_context().unwrap();
        let source = dispatcher
            .acquire_exec_source(&context, &format!("/proc/self/fd/{fd}"))
            .unwrap();
        assert_eq!(source.read_all().unwrap(), b"original");
    }

    #[test]
    fn exec_capabilities_proc_fd_keeps_memory_file_contents() {
        let dispatcher = SyscallDispatcher::new();
        dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .set_file_contents("/image", b"original".to_vec())
            .unwrap();
        dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .set_mode("/image", 0o755)
            .unwrap();
        let context = dispatcher.capture_one_task_context().unwrap();
        let named = dispatcher.acquire_exec_source(&context, "/image").unwrap();
        let outcome = dispatcher
            .open_at_path_string(
                &context,
                None,
                super::super::fs::OpenAtArgs {
                    dirfd: carrick_abi::LINUX_AT_FDCWD,
                    path: "/image",
                    flags: 0,
                    mode: 0,
                },
                &super::super::CompatReporter::default(),
            )
            .unwrap();
        let super::super::DispatchOutcome::Returned { value: fd } = outcome else {
            panic!("install source");
        };
        let source = dispatcher
            .acquire_exec_source(&context, &format!("/proc/self/fd/{fd}"))
            .unwrap();
        assert_eq!(
            source.object_id(),
            named.object_id(),
            "open must retain the VFS inode identity"
        );
        dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .set_mode("/image", 0o644)
            .unwrap();
        assert_eq!(
            source
                .exec_access_errno(carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT)
                .unwrap_err()
                .get(),
            13
        );
        drop(context);
        drop(dispatcher);
        assert_eq!(source.read_all().unwrap(), b"original");
    }
    #[test]
    fn exec_capabilities_reject_predecessor_context_after_exec() {
        let dispatcher = SyscallDispatcher::new();
        let old = dispatcher.capture_one_task_context().unwrap();
        let prepared = dispatcher.prepare_one_task_kernel_exec(&old).unwrap();
        let successor = dispatcher.commit_one_task_kernel_exec(prepared).unwrap();
        assert!(dispatcher.capture_exec_files(&successor).is_ok());
        assert!(matches!(dispatcher.capture_exec_files(&old), Err(errno) if errno.get() == 3));
    }

    #[test]
    fn exec_capabilities_legacy_file_survives_last_descriptor_close() {
        use super::super::fd_table::{FileContents, OpenDescription, OpenDescriptionBase};
        let dispatcher = SyscallDispatcher::new();
        let outcome = dispatcher.install_fd(
            OpenDescription::File {
                base: OpenDescriptionBase::new(0),
                path: "/anonymous".into(),
                metadata: carrick_vfs::rootfs::RootFsMetadata {
                    path: "/anonymous".into(),
                    kind: carrick_vfs::rootfs::RootFsEntryKind::File,
                    mode: 0o755,
                    size: 8,
                },
                contents: FileContents::dense(b"original".to_vec()),
                offset: 0,
                writable: false,
            },
            0,
        );
        let super::super::DispatchOutcome::Returned { value: fd } = outcome else {
            panic!("install source");
        };
        let context = dispatcher.capture_one_task_context().unwrap();
        let source = dispatcher
            .acquire_exec_source(&context, &format!("/proc/self/fd/{fd}"))
            .unwrap();
        dispatcher.close_fd_for_internal_rollback(fd as i32);
        assert_eq!(source.read_all().unwrap(), b"original");
    }

    #[test]
    fn exec_capabilities_memory_permission_follows_unlinked_inode() {
        use super::super::{
            CompatReporter, DispatchOutcome, LinearMemory, SyscallArgs, SyscallRequest,
        };
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .set_file_contents("/image", b"original".to_vec())
            .unwrap();
        dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .set_mode("/image", 0o755)
            .unwrap();
        let context = dispatcher.capture_one_task_context().unwrap();
        let outcome = dispatcher
            .open_at_path_string(
                &context,
                None,
                super::super::fs::OpenAtArgs {
                    dirfd: carrick_abi::LINUX_AT_FDCWD,
                    path: "/image",
                    flags: 0,
                    mode: 0,
                },
                &CompatReporter::default(),
            )
            .unwrap();
        let DispatchOutcome::Returned { value: fd } = outcome else {
            panic!("install source");
        };
        let source = dispatcher
            .acquire_exec_source(&context, &format!("/proc/self/fd/{fd}"))
            .unwrap();
        assert!(dispatcher.fs.rootfs_vfs.overlay.remove_entry("/image"));
        let mut memory = LinearMemory::new(0, vec![0; 64]);
        assert_eq!(
            dispatcher
                .dispatch(
                    &context,
                    SyscallRequest::new(
                        carrick_abi::syscall::nr::FCHMOD.0,
                        SyscallArgs::from([fd as u64, 0o644, 0, 0, 0, 0])
                    ),
                    &mut memory,
                    &CompatReporter::default()
                )
                .unwrap(),
            DispatchOutcome::Returned { value: 0 }
        );
        assert_eq!(
            source
                .exec_access_errno(carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT)
                .unwrap_err()
                .get(),
            13
        );
    }

    #[test]
    fn exec_capabilities_resolve_dotdot_after_symlink() {
        use carrick_vfs::rootfs::{LayerSource, RootFs};
        let mut archive = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut archive);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            builder
                .append_link(&mut header, "link", "/dir/nested")
                .unwrap();
            for (name, target) in [
                ("dirlink", "/dir"),
                ("exelink", "/proc/self/exe"),
                ("loop", "."),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_size(0);
                header.set_mode(0o777);
                builder.append_link(&mut header, name, target).unwrap();
            }
            for depth in 0..25 {
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_size(0);
                header.set_mode(0o777);
                let target = if depth == 24 {
                    "/dir/nested".to_owned()
                } else {
                    format!("depth{}/..", depth + 1)
                };
                builder
                    .append_link(&mut header, format!("depth{depth}"), target)
                    .unwrap();
            }
            builder.finish().unwrap();
        }
        let dispatcher = SyscallDispatcher::with_rootfs(
            RootFs::from_layers([LayerSource::Tar(archive)]).unwrap(),
        );
        let overlay = &dispatcher.fs.rootfs_vfs.overlay;
        overlay.make_dir("/dir").unwrap();
        overlay.make_dir("/dir/nested").unwrap();
        overlay
            .set_file_contents("/image", b"wrong".to_vec())
            .unwrap();
        overlay
            .set_file_contents("/dir/image", b"correct".to_vec())
            .unwrap();
        let context = dispatcher.capture_one_task_context().unwrap();
        assert_eq!(
            dispatcher
                .capture_exec_files(&context)
                .unwrap()
                .resolve_path("/link/../image"),
            "/link/../image"
        );
        let source = dispatcher
            .acquire_exec_source(&context, "/link/../image")
            .unwrap();
        assert_eq!(source.read_all().unwrap(), b"correct");
        dispatcher.set_executable_identity_with_source("/dir/image", vec![], vec![], source);
        let files = dispatcher.capture_exec_files(&context).unwrap();
        for path in ["/dirlink/image", "/exelink"] {
            assert_eq!(
                files.acquire(path).unwrap().read_head(7).unwrap(),
                b"correct"
            );
        }
        let excessive = format!("/{}/image", vec!["loop"; 41].join("/"));
        assert!(
            matches!(files.acquire(&excessive), Err(ExecSourceError::Linux(errno)) if errno.get() == 40)
        );
        assert_eq!(
            files
                .acquire("/depth0/image")
                .unwrap()
                .read_head(5)
                .unwrap(),
            b"wrong"
        );
        for path in ["/dir/../image/", "/dir/../image/."] {
            assert!(
                matches!(dispatcher.acquire_exec_source(&context, path), Err(ExecSourceError::Linux(errno)) if errno.get() == 20),
                "regular file traversal must report ENOTDIR 20"
            );
        }
    }
    #[test]
    fn exec_capabilities_magic_error_never_falls_back_to_host_alias() {
        use carrick_vfs::rootfs::{LayerSource, RootFs};
        let directory = tempfile::tempdir().unwrap();
        let host_path = directory.path().join("alias");
        std::fs::write(&host_path, b"host must not be selected").unwrap();
        let mut archive = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut archive);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            builder
                .append_link(
                    &mut header,
                    host_path.strip_prefix("/").unwrap(),
                    "/proc/self/fd/999999",
                )
                .unwrap();
            builder.finish().unwrap();
        }
        let mut dispatcher = SyscallDispatcher::with_rootfs(
            RootFs::from_layers([LayerSource::Tar(archive)]).unwrap(),
        );
        dispatcher.exec_host_fs_fallback = true;
        let mut parent = std::path::PathBuf::new();
        for component in directory.path().components() {
            parent.push(component);
            if parent != std::path::Path::new("/") {
                dispatcher
                    .fs
                    .rootfs_vfs
                    .overlay
                    .make_dir(parent.to_str().unwrap())
                    .unwrap();
            }
        }
        let context = dispatcher.capture_one_task_context().unwrap();
        let files = dispatcher.capture_exec_files(&context).unwrap();
        assert!(matches!(files.acquire(host_path.to_str().unwrap()),
            Err(ExecSourceError::Linux(errno)) if errno.get() == 2));
    }
}
