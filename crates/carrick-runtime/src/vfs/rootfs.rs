//! The `/` mount: the OCI rootfs (immutable) plus a writable overlay.
//!
//! # Theory of operation
//!
//! [`RootFsVfs`] is the home of the root filesystem, and it is the one mount
//! that is *not* registered in [`crate::vfs::VfsMounts`]. It is a sibling field
//! on the dispatcher (`fs.rootfs_vfs`) and serves every path the mount table
//! declines — i.e. everything outside `/proc`, `/sys`, `/dev`, the bind mounts,
//! and the synthetic single-file mounts. It is the *fallback* of the routing
//! layer described in [`crate::vfs`].
//!
//! Structurally it is a two-layer stack, mirroring an overlayfs:
//!
//! * **`rootfs`** — the immutable lower layer: the merged OCI image
//!   ([`crate::rootfs::RootFs`]), read-only. Reads of unmodified image files
//!   come from here.
//! * **`overlay`** — the writable upper layer, a [`crate::fs_backend::FsBackend`]
//!   trait object. Two implementations exist: an in-memory `MemoryBackend`
//!   (`--fs memory`) and a host-disk backend (`--fs host`, where the merged
//!   rootfs is materialised onto a real cap-std scratch and the overlay *is*
//!   that scratch). A guest write to an image file copies it up into the
//!   overlay; subsequent reads see the overlay copy; whiteouts in the overlay
//!   hide lower-layer entries — standard copy-up / whiteout overlay semantics.
//!
//! ## Why the dispatcher reaches into the fields directly
//!
//! Every fs syscall (`openat`, `stat`/`statx`, `unlinkat`, `mkdirat`,
//! `renameat2`, `symlinkat`, `linkat`, `readlinkat`, `fchmodat`, `utimensat`, …)
//! touches the overlay+rootfs pair, and on the hot path the dispatcher accesses
//! `rootfs_vfs.rootfs` and `rootfs_vfs.overlay` directly (and through the
//! richer [`RootFsVfs::open_for_dispatch`], which returns the rootfs-shaped
//! [`OpenDispatchResult`] the dispatcher's `OpenDescription` variants consume —
//! including a real host fd for `--fs host` regular files so reads/writes
//! survive `libc::fork`). `RootFsVfs` *also* implements the [`Vfs`] trait, and
//! those trait methods consult exactly the same `overlay`+`rootfs` state, so
//! the two access paths are byte-identical. The direct-field access is a
//! deliberate performance and incrementality choice for the busiest mount, not
//! a correctness fork; the public fields and `open_for_dispatch` are the
//! contract the dispatcher relies on.

use crate::fs_backend::{
    BackendError, FsBackend, ImmutableHostFileOpen, MemoryBackend, OverlayEntry, OverlayEntryKind,
    RealStat, SharedFileContents,
};
use crate::linux_abi::LinuxErrno;
use crate::linux_abi::{
    LINUX_E2BIG, LINUX_EACCES, LINUX_EEXIST, LINUX_EFBIG, LINUX_EINVAL, LINUX_EISDIR, LINUX_ELOOP,
    LINUX_ENOENT, LINUX_ENOSYS, LINUX_ENOTDIR, LINUX_ENOTEMPTY, LINUX_EROFS, LINUX_EXDEV,
    LINUX_S_IFBLK, LINUX_S_IFCHR, LINUX_S_IFMT,
};
use crate::rootfs::{RootFs, RootFsEntryKind, RootFsError, RootFsMetadata};
use std::sync::Arc;

use super::{
    DirEnt, EntryKind, InodeIdentity, MAX_IN_MEMORY_FILE_SIZE, Metadata, OpenContext, OpenFlags,
    Vfs, VfsError, VfsHandle, WatchFd,
};

/// The `/` mount. Owns the immutable OCI rootfs (`rootfs`) and the
/// writable overlay (`overlay`). Direct field access by the
/// dispatcher is intentional for step 4 of the migration — the
/// dispatcher's existing fs syscalls each touch one or both of these
/// state pieces directly, and rewriting them all at once is the
/// follow-up step.
pub struct RootFsVfs {
    pub rootfs: Option<RootFs>,
    pub overlay: Box<dyn FsBackend>,
    pub dentry_cache: Arc<crate::vfs::DentryCache>,
}

/// Richer result from [`RootFsVfs::open_for_dispatch`]. Carries the
/// rootfs-shaped types the dispatcher's existing `OpenDescription`
/// variants consume, plus a `NotFoundCreate` variant signalling that
/// the caller should perform the O_CREAT path.
pub enum OpenDispatchResult {
    File {
        metadata: RootFsMetadata,
        contents: Vec<u8>,
        writable: bool,
    },
    RootFsBackedFile {
        metadata: RootFsMetadata,
        contents: SharedFileContents,
        writable: bool,
    },
    /// A regular file backed by a REAL host fd (disk-backed overlay,
    /// i.e. `--fs host`). The dispatcher wraps this as
    /// `OpenDescription::HostFile`, so reads/writes go to the shared
    /// kernel file and survive `libc::fork`.
    HostFile {
        host_fd: i32,
        metadata: RootFsMetadata,
        writable: bool,
    },
    /// An existing directory. The listing is NOT taken here: the dispatcher
    /// lists a directory when the guest first reads it (`getdents64`), which
    /// is when Linux lists it too, and a walk/`*at` anchor never pays for an
    /// enumeration it never asks for.
    Directory { metadata: RootFsMetadata },
    /// Returned only when `want_create` was true and the path
    /// doesn't exist. The dispatcher creates the entry in the
    /// overlay itself (it knows the right initial contents / mode).
    NotFoundCreate,
}

impl OpenDispatchResult {
    /// Re-anchor the served metadata on the GUEST-ABSOLUTE path this open
    /// resolved to.
    ///
    /// The backends speak a sandbox-RELATIVE path domain (`fs_backend::
    /// normalize` drops `Component::RootDir` so the name can be handed to a
    /// cap-std/`openat` walk), and several arms below hand a backend
    /// `RootFsMetadata` straight through. But the dispatcher turns this
    /// metadata into a guest-visible `OpenDescription`, whose `metadata.path`
    /// IS the guest path the fd was opened at: `OpenDescription::open_path`
    /// serves it to `execveat(AT_EMPTY_PATH)` (glibc `fexecve`), and `fchown`/
    /// `futimens` re-resolve it. A relative path there is silently re-resolved
    /// against the caller's cwd, so `fexecve` of an image-layer binary only
    /// worked while the cwd happened to be `/` — CPython
    /// `test_posix.test_fexecve` chdirs to the executable's directory first and
    /// got ENOENT.
    ///
    /// Converting once here, at the single boundary where a backend result
    /// becomes a guest-facing one, is what keeps the two domains from mixing;
    /// no individual arm can leak the relative form.
    fn anchor_metadata_at(&mut self, guest_path: &str) {
        let metadata = match self {
            Self::File { metadata, .. }
            | Self::RootFsBackedFile { metadata, .. }
            | Self::HostFile { metadata, .. }
            | Self::Directory { metadata, .. } => metadata,
            Self::NotFoundCreate => return,
        };
        metadata.path = std::path::Path::new(guest_path).to_path_buf();
    }
}

impl RootFsVfs {
    pub fn new() -> Self {
        Self {
            rootfs: None,
            overlay: Box::new(MemoryBackend::new()),
            dentry_cache: Arc::new(crate::vfs::DentryCache::new(false)),
        }
    }

    pub fn with_rootfs(rootfs: RootFs) -> Self {
        Self {
            rootfs: Some(rootfs),
            overlay: Box::new(MemoryBackend::new()),
            dentry_cache: Arc::new(crate::vfs::DentryCache::new(false)),
        }
    }

    /// Swap the writable overlay. Returns the previously-installed
    /// backend so the caller can decide what to do with it.
    pub fn set_overlay(&mut self, backend: Box<dyn FsBackend>) -> Box<dyn FsBackend> {
        self.dentry_cache = Arc::new(crate::vfs::DentryCache::new(backend.is_shared()));
        std::mem::replace(&mut self.overlay, backend)
    }

    /// Read stat for `path` via the dentry cache.
    pub fn dentry_stat(&self, path: &str, follow: bool) -> Result<RealStat, LinuxErrno> {
        if !self.overlay.serves_dentry_cache() {
            return Err(LINUX_ENOSYS);
        }
        self.dentry_cache
            .stat(path, follow, &*self.overlay, self.rootfs.as_ref())
    }

    /// Read link target for `path` via the dentry cache.
    pub fn dentry_readlink(&self, path: &str) -> Result<String, LinuxErrno> {
        if !self.overlay.serves_dentry_cache() {
            return Err(LINUX_ENOSYS);
        }
        self.dentry_cache
            .readlink(path, &*self.overlay, self.rootfs.as_ref())
    }

    /// Fast non-creating open for a regular file via the dentry cache.
    pub fn dentry_fast_open(
        &self,
        path: &str,
        write: bool,
    ) -> Result<
        (
            std::os::fd::OwnedFd,
            RealStat,
            String,
            carrick_guest_mem::PrivateFileSource,
        ),
        LinuxErrno,
    > {
        if !self.overlay.serves_dentry_cache() {
            return Err(LINUX_ENOSYS);
        }
        self.dentry_cache
            .fast_open(path, write, &*self.overlay, self.rootfs.as_ref())
    }

    fn host_fd_inode_identity(raw_fd: i32) -> Option<InodeIdentity> {
        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        if unsafe { libc::fstat(raw_fd, &mut st) } == 0 {
            Some(InodeIdentity::new(st.st_dev as u64, st.st_ino as u64))
        } else {
            None
        }
    }

    fn path_inode_identity(&self, path: &str) -> Option<InodeIdentity> {
        if let Ok(dentry) =
            self.dentry_cache
                .lookup_path(path, false, &*self.overlay, self.rootfs.as_ref())
        {
            Some(InodeIdentity::new(dentry.dentry.dev, dentry.dentry.ino))
        } else {
            None
        }
    }

    /// Get or fill cached inode record for an open host fd and its stat.
    pub fn get_or_fill_host_inode(
        &self,
        host_fd: i32,
        st: &libc::stat,
    ) -> crate::vfs::dentry::InodeRecord {
        let dev = st.st_dev as u64;
        let ino = st.st_ino;
        if let Some(record) = self.dentry_cache.get_inode_record(dev, ino) {
            return record;
        }

        // Cache miss: read host metadata xattrs once from host_fd.
        let mode_xattr = crate::fs_backend::fget_mode_xattr(host_fd);
        let (mode, dev_type, rdev) = match mode_xattr {
            Some(m) => {
                let type_bits = m & LINUX_S_IFMT;
                if type_bits == LINUX_S_IFCHR || type_bits == LINUX_S_IFBLK {
                    let rdev = crate::fs_backend::fget_rdev_xattr(host_fd).unwrap_or(0);
                    (m & 0o7777, type_bits, rdev)
                } else {
                    (m & 0o7777, 0, 0)
                }
            }
            None => (st.st_mode as u32 & 0o7777, 0, 0),
        };
        let (uid, gid) = crate::fs_backend::fget_owner_xattr(host_fd);
        let uid = uid.unwrap_or(carrick_abi::NsUid::ROOT);
        let gid = gid.unwrap_or(carrick_abi::NsGid::ROOT);

        let record = crate::vfs::dentry::InodeRecord {
            mode,
            uid,
            gid,
            size: st.st_size as u64,
            atime: (st.st_atime, carrick_portable::stat_atime_nsec(st)),
            mtime: (st.st_mtime, carrick_portable::stat_mtime_nsec(st)),
            ctime: (st.st_ctime, carrick_portable::stat_ctime_nsec(st)),
            nlink: st.st_nlink as u32,
            rdev,
            dev_type,
        };
        self.dentry_cache.insert_inode_record(dev, ino, record);
        record
    }

    /// Invalidate dentry/inode cache entry for an open host fd.
    pub fn invalidate_host_fd(&self, raw_fd: i32) {
        if let Some(inode) = Self::host_fd_inode_identity(raw_fd) {
            self.dentry_cache.inode_changed("", Some(inode));
        }
    }

    /// Notify that an inode's attributes or contents changed.
    pub fn notify_inode_changed(&self, path: &str, inode: Option<InodeIdentity>) {
        self.dentry_cache.inode_changed(path, inode);
    }

    /// Pin a cached directory to prevent eviction while an fd is open on it.
    pub fn pin_dir(&self, path: &str) {
        self.dentry_cache.pin_dir(path);
    }

    /// Unpin a cached directory when an fd opened on it is closed.
    pub fn unpin_dir(&self, path: &str) {
        self.dentry_cache.unpin_dir(path);
    }

    /// Reset dentry cache on rootfs layer mutation.
    pub fn reset_dentry_cache(&mut self) {
        let is_shared = self.dentry_cache.is_shared();
        self.dentry_cache = Arc::new(crate::vfs::DentryCache::new(is_shared));
    }

    /// Create raw host fd in writable overlay and announce creation to dentry cache.
    pub fn create_raw_fd(
        &self,
        path: &str,
        create_mode: u32,
        want_trunc: bool,
    ) -> crate::fs_backend::HostFdOpen<(i32, bool)> {
        let res = self.overlay.create_raw_fd(path, create_mode, want_trunc);
        if let crate::fs_backend::HostFdOpen::Served((host_fd, _)) = &res {
            let inode = Self::host_fd_inode_identity(*host_fd);
            self.dentry_cache.entry_created(path, inode);
            if want_trunc {
                self.dentry_cache.inode_changed(path, inode);
            }
        }
        res
    }

    /// Create regular file in writable overlay and announce creation to dentry cache.
    pub fn create_file(&self, path: &str) -> Result<(), BackendError> {
        self.overlay.create_file(path)?;
        self.dentry_cache.entry_created(path, None);
        Ok(())
    }

    /// Create FIFO in writable overlay and announce creation to dentry cache.
    pub fn create_fifo(&self, path: &str, mode: u32) -> Result<(), BackendError> {
        self.overlay.create_fifo(path, mode)?;
        self.dentry_cache.entry_created(path, None);
        Ok(())
    }

    /// Create socket node in writable overlay and announce creation to dentry cache.
    pub fn create_socket(&self, path: &str, mode: u32) -> Result<(), BackendError> {
        self.overlay.create_socket(path, mode)?;
        self.dentry_cache.entry_created(path, None);
        Ok(())
    }

    /// Create device node in writable overlay and announce creation to dentry cache.
    pub fn create_device(&self, path: &str, full_mode: u32, dev: u64) -> Result<(), BackendError> {
        self.overlay.create_device(path, full_mode, dev)?;
        self.dentry_cache.entry_created(path, None);
        Ok(())
    }

    /// Create hard link in writable overlay and update dentry cache.
    pub fn link(&self, from: &str, to: &str) -> Result<(), LinuxErrno> {
        let inode = self.path_inode_identity(from);
        match self.overlay.hard_link(from, to) {
            Ok(()) => {
                self.dentry_cache.entry_created(to, inode);
                self.dentry_cache.inode_changed(from, inode);
                Ok(())
            }
            Err(crate::fs_backend::BackendError::Unsupported) => {
                let contents = self
                    .overlay
                    .file_contents(from)
                    .or_else(|| self.rootfs.as_ref().and_then(|r| r.read(from).ok()))
                    .unwrap_or_default();
                match self.overlay.set_file_contents(to, contents) {
                    Ok(()) => {
                        self.dentry_cache.entry_created(to, inode);
                        self.dentry_cache.inode_changed(from, inode);
                        Ok(())
                    }
                    Err(_) => Err(LINUX_EROFS),
                }
            }
            Err(_) => Err(LINUX_EROFS),
        }
    }

    /// Create symlink in writable overlay and update dentry cache.
    pub fn symlink(&self, target: &str, link: &str) -> Result<(), LinuxErrno> {
        match self.overlay.symlink(target, link) {
            Ok(()) => {
                self.dentry_cache.entry_created(link, None);
                Ok(())
            }
            Err(crate::fs_backend::BackendError::Unsupported) => Err(LINUX_EROFS),
            Err(_) => Err(LINUX_EROFS),
        }
    }

    /// Truncate path-based file and update dentry cache.
    pub fn truncate_path(&self, path: &str, length: u64) -> Result<(), LinuxErrno> {
        use crate::dispatch::HostSyscallResult as _;
        match self.overlay.open_raw_fd(path, true, false, false) {
            crate::fs_backend::HostFdOpen::Served(host_fd) => {
                let inode = Self::host_fd_inode_identity(host_fd);
                let err = unsafe { libc::ftruncate(host_fd, length as libc::off_t) }
                    .host_syscall_errno()
                    .err();
                unsafe { libc::close(host_fd) };
                if let Some(err) = err {
                    Err(err)
                } else {
                    self.dentry_cache.inode_changed(path, inode);
                    Ok(())
                }
            }
            crate::fs_backend::HostFdOpen::Refused(refused) => Err(refused),
            crate::fs_backend::HostFdOpen::Unavailable => Err(LINUX_EROFS),
        }
    }

    /// Set mode on path and update dentry cache.
    pub fn set_mode(&self, path: &str, mode: u32) -> Result<(), BackendError> {
        let inode = self.path_inode_identity(path);
        let res = self.overlay.set_mode(path, mode);
        match &res {
            Ok(()) | Err(BackendError::Unsupported) => {
                self.dentry_cache.inode_changed(path, inode);
            }
            _ => {}
        }
        res
    }

    /// Set owner on path and update dentry cache.
    pub fn set_owner(
        &self,
        path: &str,
        uid: Option<carrick_abi::NsUid>,
        gid: Option<carrick_abi::NsGid>,
    ) -> Result<(), BackendError> {
        let inode = self.path_inode_identity(path);
        let res = self.overlay.set_owner(path, uid, gid);
        match &res {
            Ok(()) | Err(BackendError::Unsupported) => {
                self.dentry_cache.inode_changed(path, inode);
            }
            _ => {}
        }
        res
    }

    /// Set mode on an open host file descriptor and update dentry cache.
    pub fn fset_mode(&self, raw_fd: std::os::fd::RawFd, mode: u32) {
        crate::fs_backend::fset_mode(raw_fd, mode);
        self.overlay.note_meta_xattr_written();
        self.invalidate_host_fd(raw_fd);
    }

    /// Set owner on an open host file descriptor and update dentry cache.
    pub fn fset_owner(
        &self,
        raw_fd: std::os::fd::RawFd,
        uid: Option<carrick_abi::NsUid>,
        gid: Option<carrick_abi::NsGid>,
    ) {
        crate::fs_backend::fset_owner_xattr(raw_fd, uid, gid);
        self.overlay.note_meta_xattr_written();
        self.invalidate_host_fd(raw_fd);
    }

    /// Set times on path and update dentry cache.
    pub fn set_times(
        &self,
        path: &str,
        atime: Option<(i64, i64)>,
        mtime: Option<(i64, i64)>,
        nofollow: bool,
    ) -> Result<(), BackendError> {
        let inode = self.path_inode_identity(path);
        let res = self.overlay.set_times(path, atime, mtime, nofollow);
        match &res {
            Ok(()) | Err(BackendError::Unsupported) => {
                self.dentry_cache.inode_changed(path, inode);
            }
            _ => {}
        }
        res
    }

    /// Open a metadata file descriptor for `path` via the dentry cache across layers.
    pub fn open_metadata_fd(
        &self,
        path: &str,
        follow: bool,
    ) -> Result<std::sync::Arc<std::os::fd::OwnedFd>, LinuxErrno> {
        if !self.overlay.serves_dentry_cache() {
            return Err(LINUX_ENOSYS);
        }
        self.dentry_cache
            .open_metadata_fd(path, follow, &*self.overlay, self.rootfs.as_ref())
    }

    /// Read xattr for `path` via the dentry cache across layers.
    pub fn get_xattr(&self, path: &str, name: &str, follow: bool) -> Result<Vec<u8>, LinuxErrno> {
        use crate::dispatch::HostSyscallResult as _;
        use crate::fs_backend::{is_guest_xattr_namespace, is_internal_carrick_xattr};

        if !is_guest_xattr_namespace(name) || is_internal_carrick_xattr(name) {
            return Err(crate::linux_abi::LINUX_ENODATA);
        }
        let cname = match std::ffi::CString::new(name) {
            Ok(c) => c,
            Err(_) => return Err(crate::linux_abi::LINUX_EINVAL),
        };

        if self.overlay.serves_dentry_cache() {
            let owned_fd = match self.open_metadata_fd(path, follow) {
                Ok(fd) => fd,
                Err(LINUX_EXDEV) => return self.overlay.get_xattr(path, name, follow),
                Err(e) => return Err(e),
            };
            let host_fd = std::os::fd::AsRawFd::as_raw_fd(&*owned_fd);
            let needed = unsafe {
                carrick_portable::fgetxattr(host_fd, cname.as_ptr(), std::ptr::null_mut(), 0)
            };
            let needed = needed.host_syscall_errno()?;
            let mut buf = vec![0u8; needed as usize];
            let n = unsafe {
                carrick_portable::fgetxattr(
                    host_fd,
                    cname.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len() as libc::size_t,
                )
            };
            n.host_syscall_errno().map(|n| {
                buf.truncate(n as usize);
                buf
            })
        } else {
            self.overlay.get_xattr(path, name, follow)
        }
    }

    /// List xattrs for `path` via the dentry cache across layers.
    pub fn list_xattr(&self, path: &str, follow: bool) -> Result<Vec<String>, LinuxErrno> {
        use crate::dispatch::HostSyscallResult as _;
        use crate::fs_backend::{is_guest_xattr_namespace, is_internal_carrick_xattr};

        fn collect_names(
            needed: isize,
            mut read: impl FnMut(&mut [u8]) -> isize,
        ) -> Result<Vec<String>, LinuxErrno> {
            let needed = match needed.host_syscall_errno() {
                Ok(needed) => needed,
                Err(crate::linux_abi::LINUX_ENODATA) => return Ok(Vec::new()),
                Err(err) => return Err(err),
            };
            let mut buf = vec![0u8; needed as usize];
            let n = match read(&mut buf).host_syscall_errno() {
                Ok(n) => n,
                Err(crate::linux_abi::LINUX_ENODATA) => return Ok(Vec::new()),
                Err(err) => return Err(err),
            };
            buf.truncate(n as usize);
            let names = buf
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .filter_map(|s| std::str::from_utf8(s).ok())
                .filter(|s| is_guest_xattr_namespace(s) && !is_internal_carrick_xattr(s))
                .map(|s| s.to_owned())
                .collect();
            Ok(names)
        }

        if self.overlay.serves_dentry_cache() {
            let owned_fd = match self.open_metadata_fd(path, follow) {
                Ok(fd) => fd,
                Err(LINUX_EXDEV) => return self.overlay.list_xattr(path, follow),
                Err(e) => return Err(e),
            };
            let host_fd = std::os::fd::AsRawFd::as_raw_fd(&*owned_fd);
            let needed = unsafe { carrick_portable::flistxattr(host_fd, std::ptr::null_mut(), 0) };
            collect_names(needed, |buf| unsafe {
                carrick_portable::flistxattr(
                    host_fd,
                    buf.as_mut_ptr() as *mut libc::c_char,
                    buf.len() as libc::size_t,
                )
            })
        } else {
            self.overlay.list_xattr(path, follow)
        }
    }

    /// Remove xattr on path via overlay or dentry cache fallback.
    pub fn remove_xattr(&self, path: &str, name: &str, follow: bool) -> Result<(), LinuxErrno> {
        use crate::dispatch::HostSyscallResult as _;
        use crate::fs_backend::{is_guest_xattr_namespace, is_internal_carrick_xattr};

        if !is_guest_xattr_namespace(name) || is_internal_carrick_xattr(name) {
            return Err(crate::linux_abi::LINUX_ENODATA);
        }
        let inode = self.path_inode_identity(path);
        let overlay_res = self.overlay.remove_xattr(path, name, follow);
        if overlay_res.is_ok() {
            self.dentry_cache.inode_changed(path, inode);
            return Ok(());
        }
        if self.overlay.serves_dentry_cache() && matches!(overlay_res, Err(LINUX_ENOENT)) {
            if let Ok(owned_fd) = self.open_metadata_fd(path, follow) {
                let cname = match std::ffi::CString::new(name) {
                    Ok(c) => c,
                    Err(_) => return Err(crate::linux_abi::LINUX_EINVAL),
                };
                let host_fd = std::os::fd::AsRawFd::as_raw_fd(&*owned_fd);
                let rc = unsafe { carrick_portable::fremovexattr(host_fd, cname.as_ptr()) };
                let res = rc.host_syscall_errno().map(|_| ());
                if res.is_ok() {
                    self.dentry_cache.inode_changed(path, inode);
                }
                return res;
            }
        }
        overlay_res
    }

    /// Set xattr on path and update dentry cache.
    pub fn set_xattr(
        &self,
        path: &str,
        name: &str,
        value: &[u8],
        flags: i32,
        follow: bool,
    ) -> Result<(), LinuxErrno> {
        let inode = self.path_inode_identity(path);
        self.overlay.set_xattr(path, name, value, flags, follow)?;
        self.dentry_cache.inode_changed(path, inode);
        Ok(())
    }

    /// Set file contents and update dentry cache.
    pub fn set_file_contents(&self, path: &str, contents: Vec<u8>) -> Result<(), BackendError> {
        let inode = self.path_inode_identity(path);
        self.overlay.set_file_contents(path, contents)?;
        self.dentry_cache.entry_created(path, inode);
        self.dentry_cache.inode_changed(path, inode);
        Ok(())
    }

    /// Write file range and update dentry cache.
    pub fn write_file_range(
        &self,
        path: &str,
        offset: usize,
        bytes: &[u8],
        final_size: usize,
    ) -> Result<(), BackendError> {
        let inode = self.path_inode_identity(path);
        self.overlay
            .write_file_range(path, offset, bytes, final_size)?;
        self.dentry_cache.inode_changed(path, inode);
        Ok(())
    }

    /// Non-following metadata lookup (the `lstat`/`AT_SYMLINK_NOFOLLOW`
    /// counterpart to the symlink-following [`Vfs::lookup`]). If the final
    /// path component is a symlink, this reports the link itself
    /// (`EntryKind::Symlink`, size = byte length of the target string) rather
    /// than resolving it. Used by `statx`/`newfstatat` when the guest passes
    /// `AT_SYMLINK_NOFOLLOW` and the writable backend can't answer a
    /// `real_stat` (e.g. the in-memory backend).
    pub fn lookup_nofollow(&self, path: &str) -> Result<Metadata, VfsError> {
        if self.overlay.serves_dentry_cache() {
            match self.dentry_stat(path, false) {
                Ok(real) => {
                    let kind = match real.kind {
                        RootFsEntryKind::File => EntryKind::File,
                        RootFsEntryKind::Directory => EntryKind::Directory,
                        RootFsEntryKind::CharDevice => EntryKind::CharDevice,
                        RootFsEntryKind::Fifo => EntryKind::Fifo,
                        RootFsEntryKind::Socket => EntryKind::Socket,
                        RootFsEntryKind::Symlink => EntryKind::Symlink,
                    };
                    return Ok(Metadata {
                        kind,
                        mode: real.mode,
                        size: real.size,
                        uid: real.uid.raw() as libc::uid_t,
                        gid: real.gid.raw() as libc::gid_t,
                        mtime_secs: real.mtime.0,
                        mtime_nanos: real.mtime.1 as u32,
                    });
                }
                Err(LINUX_ENOENT) => return Err(LINUX_ENOENT),
                Err(LINUX_ENOTDIR) => return Err(LINUX_ENOTDIR),
                Err(LINUX_ELOOP) => return Err(LINUX_ELOOP),
                _ => {}
            }
        }
        // Ask backends that can cheaply prove "not a symlink" first. The Darwin
        // host backend answers regular files/directories from one contained fd
        // and returns None for symlinks and exceptional file types, preserving
        // the exact readlink/lstat fallback below.
        if let Some(metadata) = self.overlay.fast_nofollow_metadata(path) {
            let kind = match metadata.kind {
                RootFsEntryKind::File => EntryKind::File,
                RootFsEntryKind::Directory => EntryKind::Directory,
                RootFsEntryKind::CharDevice => EntryKind::CharDevice,
                RootFsEntryKind::Fifo => EntryKind::Fifo,
                RootFsEntryKind::Socket => EntryKind::Socket,
                RootFsEntryKind::Symlink => EntryKind::Symlink,
            };
            return Ok(Metadata {
                kind,
                mode: metadata.mode,
                size: metadata.size as u64,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            });
        }
        let overlay_proven_absent = self.overlay.fast_nofollow_absent(path);
        if !overlay_proven_absent
            && std::path::Path::new(path)
                .ancestors()
                .filter(|ancestor| !ancestor.as_os_str().is_empty())
                .any(|ancestor| self.overlay.is_deleted(ancestor.to_string_lossy().as_ref()))
        {
            return Err(LINUX_ENOENT);
        }
        // A symlink materialised in the writable overlay.
        if !overlay_proven_absent && let Some(target) = self.overlay.read_link(path) {
            return Ok(Metadata {
                kind: EntryKind::Symlink,
                mode: 0o777,
                size: target.len() as u64,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            });
        }
        // A symlink in the immutable rootfs layer: report the link, not its
        // target. Non-symlink entries fall through to the regular (following)
        // lookup, which is identical for them.
        if let Some(rootfs) = self.rootfs.as_ref()
            && let Ok(md) = rootfs.symlink_metadata(path)
            && (overlay_proven_absent || matches!(md.kind, RootFsEntryKind::Symlink))
        {
            let kind = match md.kind {
                RootFsEntryKind::File => EntryKind::File,
                RootFsEntryKind::Directory => EntryKind::Directory,
                RootFsEntryKind::CharDevice => EntryKind::CharDevice,
                RootFsEntryKind::Fifo => EntryKind::Fifo,
                RootFsEntryKind::Socket => EntryKind::Socket,
                RootFsEntryKind::Symlink => EntryKind::Symlink,
            };
            return Ok(Metadata {
                kind,
                mode: md.mode,
                size: md.size as u64,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            });
        }
        if overlay_proven_absent {
            return Err(LINUX_ENOENT);
        }
        self.lookup(path)
    }

    /// Real host identity for a path the writable upper does not hold, read
    /// from the immutable cache lower.
    ///
    /// EXISTENCE is not this method's business — whiteouts, copy-up and
    /// cross-layer symlinks are the layered resolver's job, and a caller must
    /// have already established through it that `path` resolves to the lower.
    /// This only supplies the identity fields ([`crate::vfs::Metadata`] and
    /// [`crate::rootfs::RootFsMetadata`] carry neither an inode nor a link
    /// count nor a timestamp) so the path lane can report the SAME host inode
    /// the fd lane's `fstat` and `getdents64`'s `d_ino` already report.
    pub(crate) fn immutable_lower_real_stat(
        &self,
        path: &str,
        follow: bool,
    ) -> Option<crate::fs_backend::RealStat> {
        self.rootfs.as_ref()?.immutable_real_stat(path, follow)
    }

    /// Open an upper-absent immutable-lower regular file without first
    /// re-walking every intermediate component through the layered resolver.
    ///
    /// The host overlay's sparse-miss proof is authoritative only while it has
    /// no symlink or whiteout markers. The fork-shared generation sampled
    /// around both the upper proof and lower open turns any concurrent
    /// copy-up/create into a failed fast attempt; the caller then takes the
    /// exact resolving path.
    pub(crate) fn open_immutable_lower_readonly(&self, path: &str) -> ImmutableHostFileOpen {
        let generation = self.overlay.structural_generation();
        if !self.overlay.fast_nofollow_absent(path) {
            return ImmutableHostFileOpen::Fallback;
        }
        let Some(rootfs) = self.rootfs.as_ref() else {
            return ImmutableHostFileOpen::Fallback;
        };
        let result = rootfs.open_immutable_file_readonly(path);
        if self.overlay.structural_generation() != generation {
            return ImmutableHostFileOpen::Fallback;
        }
        result
    }

    /// Richer open variant the dispatcher uses for the openat
    /// fallback after VFS-mount routing (/dev /proc /sys). Returns
    /// the full rootfs-shaped metadata + entries / contents that the
    /// dispatcher's `OpenDescription::File` / `Directory` variants
    /// need, including the writable-overlay-promotion semantics for
    /// rootfs files opened with O_WRONLY/O_RDWR.
    ///
    /// The Vfs-trait `open` method returns `VfsHandle::Bytes` for
    /// reads only; this method covers the writable + directory
    /// cases that don't fit neatly into the trait surface yet.
    pub fn open_for_dispatch(
        &self,
        path: &str,
        want_create: bool,
        want_excl: bool,
        want_trunc: bool,
        writable_request: bool,
    ) -> Result<OpenDispatchResult, LinuxErrno> {
        let mut result = self.open_for_dispatch_inner(
            path,
            want_create,
            want_excl,
            want_trunc,
            writable_request,
        )?;
        // Cross from the backends' sandbox-relative path domain into the
        // guest-absolute one exactly once — see `anchor_metadata_at`.
        result.anchor_metadata_at(path);
        if want_trunc && !matches!(result, OpenDispatchResult::NotFoundCreate) {
            let inode = match &result {
                OpenDispatchResult::HostFile { host_fd, .. } => {
                    Self::host_fd_inode_identity(*host_fd)
                }
                _ => self.path_inode_identity(path),
            };
            self.dentry_cache.inode_changed(path, inode);
        }
        Ok(result)
    }

    fn open_for_dispatch_inner(
        &self,
        path: &str,
        want_create: bool,
        want_excl: bool,
        want_trunc: bool,
        writable_request: bool,
    ) -> Result<OpenDispatchResult, LinuxErrno> {
        if !(want_create && want_excl)
            && let Some(entry) = self.overlay.shared_file_entry(path, want_trunc)
        {
            return Ok(OpenDispatchResult::RootFsBackedFile {
                metadata: entry.metadata,
                contents: entry.contents,
                writable: writable_request,
            });
        }

        // Overlay-first: tombstone short-circuits to ENOENT for the
        // non-create case (with O_CREAT we treat it as "no file in
        // the way" and let the caller create).
        let overlay_kind = self.overlay.lookup_kind(path);
        let overlay_deleted = matches!(overlay_kind, Some(OverlayEntryKind::Deleted));
        match overlay_kind {
            Some(OverlayEntryKind::File) => {
                if want_create && want_excl {
                    return Err(LINUX_EEXIST);
                }
                if let Some((host_fd, metadata)) = self
                    .overlay
                    .open_raw_fd_with_metadata(path, writable_request, false, want_trunc)
                    .lowerable()?
                {
                    return Ok(OpenDispatchResult::HostFile {
                        host_fd,
                        metadata,
                        writable: writable_request,
                    });
                }
                let backend_md = self.overlay.metadata(path);
                let mode = backend_md.as_ref().map(|m| m.mode).unwrap_or(0o644);
                // Disk-backed overlay (--fs host): hand back a REAL host
                // fd so reads/writes share the kernel file across fork.
                if let Some(host_fd) = self
                    .overlay
                    .open_raw_fd(path, writable_request, false, want_trunc)
                    .lowerable()?
                {
                    let size = if want_trunc {
                        0
                    } else {
                        backend_md.as_ref().map(|m| m.size).unwrap_or(0)
                    };
                    let metadata = RootFsMetadata {
                        path: std::path::Path::new(path).to_path_buf(),
                        kind: RootFsEntryKind::File,
                        mode,
                        size,
                    };
                    return Ok(OpenDispatchResult::HostFile {
                        host_fd,
                        metadata,
                        writable: writable_request,
                    });
                }
                if let Some(contents) = self.overlay.shared_file_contents(path) {
                    let metadata = RootFsMetadata {
                        path: std::path::Path::new(path).to_path_buf(),
                        kind: RootFsEntryKind::File,
                        mode,
                        size: contents.len,
                    };
                    return Ok(OpenDispatchResult::RootFsBackedFile {
                        metadata,
                        contents,
                        writable: writable_request,
                    });
                }
                // open_raw_fd failed. `lookup` reports a symlink as a File whose
                // "contents" are the link target (for readlink/content reads). A
                // following open(2) must NOT see that — it follows the link, so a
                // BROKEN symlink (target gone) is ENOENT, exactly like stat (and
                // not the lookup hack's target-string). Detect: this path is a
                // symlink AND following it finds no target.
                if matches!(
                    backend_md.as_ref().map(|m| m.kind),
                    Some(RootFsEntryKind::Symlink)
                ) && self.overlay.real_stat(path, true).is_none()
                {
                    return Err(LINUX_ENOENT);
                }
                // In-memory overlay (MemoryBackend): cached-bytes File.
                let mut contents = match self.overlay.lookup(path) {
                    Some(OverlayEntry::File(contents)) => contents,
                    Some(OverlayEntry::Deleted) => return Err(LINUX_ENOENT),
                    Some(OverlayEntry::Dir) => return Err(LINUX_EISDIR),
                    None => return Err(LINUX_ENOENT),
                };
                if want_trunc {
                    contents.clear();
                    self.overlay
                        .set_file_contents(path, contents.clone())
                        .map_err(|_| LINUX_EINVAL)?;
                }
                let metadata = RootFsMetadata {
                    path: std::path::Path::new(path).to_path_buf(),
                    kind: RootFsEntryKind::File,
                    mode,
                    size: contents.len(),
                };
                return Ok(OpenDispatchResult::File {
                    metadata,
                    contents,
                    writable: writable_request,
                });
            }
            Some(OverlayEntryKind::Dir) => {
                // O_EXCL "fail if it already exists" takes priority over EISDIR
                // (Linux open(2)): tempfile.mkstemp relies on EEXIST to retry the
                // next candidate name when it collides with an existing dir.
                if want_create && want_excl {
                    return Err(LINUX_EEXIST);
                }
                if writable_request {
                    return Err(LINUX_EISDIR);
                }
                let metadata = RootFsMetadata {
                    path: std::path::Path::new(path).to_path_buf(),
                    kind: RootFsEntryKind::Directory,
                    mode: 0o755,
                    size: 0,
                };
                return Ok(OpenDispatchResult::Directory { metadata });
            }
            Some(OverlayEntryKind::Deleted) => {}
            _ => {}
        }
        // Rootfs lookup. Tombstoned paths are treated as not-found
        // so O_CREAT can fall through cleanly.
        let rootfs_metadata: Option<RootFsMetadata> = if overlay_deleted {
            None
        } else if let Some(rootfs) = self.rootfs.as_ref() {
            match rootfs.metadata(path) {
                Ok(metadata) => Some(metadata),
                Err(RootFsError::NotFound(_)) => None,
                Err(e) => return Err(crate::dispatch::rootfs_errno(e)),
            }
        } else {
            None
        };
        match rootfs_metadata {
            Some(metadata) => match metadata.kind {
                // CharDevice/Fifo never occur in the / rootfs (only via /dev
                // mounts or the overlay, where guest FIFOs are intercepted
                // before open_for_dispatch); treat like a regular file for the
                // unreachable case.
                RootFsEntryKind::File | RootFsEntryKind::CharDevice | RootFsEntryKind::Fifo => {
                    if want_create && want_excl {
                        return Err(LINUX_EEXIST);
                    }
                    // Disk-backed overlay (--fs host): the whole rootfs is
                    // materialised on the cap-std scratch, so a writable open
                    // of a rootfs file gets a REAL host fd — writes land on
                    // disk and share across fork. Without this, writes went to
                    // an in-memory copy (invisible to forked children and
                    // never persisted), and renames of rootfs files hit EROFS
                    // (dpkg's status/status-old rewrite failed).
                    if let Some(host_fd) = self
                        .overlay
                        .open_raw_fd(path, writable_request, false, want_trunc)
                        .lowerable()?
                    {
                        let size = if want_trunc { 0 } else { metadata.size };
                        let md = RootFsMetadata {
                            path: std::path::Path::new(path).to_path_buf(),
                            kind: RootFsEntryKind::File,
                            mode: metadata.mode,
                            size,
                        };
                        return Ok(OpenDispatchResult::HostFile {
                            host_fd,
                            metadata: md,
                            writable: writable_request,
                        });
                    }
                    // INVARIANT: reaching this branch required reading metadata
                    // from self.rootfs above, so it is necessarily Some here.
                    #[allow(clippy::expect_used)]
                    let rootfs = self
                        .rootfs
                        .as_ref()
                        .expect("rootfs metadata implies rootfs");
                    if !writable_request && let Some(host_file) = rootfs.open_file_readonly(path) {
                        use std::os::fd::IntoRawFd as _;
                        return Ok(OpenDispatchResult::HostFile {
                            host_fd: host_file.into_raw_fd(),
                            metadata,
                            writable: false,
                        });
                    }
                    if writable_request {
                        if want_trunc {
                            self.overlay
                                .set_file_contents(path, Vec::new())
                                .map_err(|_| LINUX_EINVAL)?;
                            let md = RootFsMetadata {
                                path: metadata.path.clone(),
                                kind: metadata.kind,
                                mode: metadata.mode,
                                size: 0,
                            };
                            if let Some((host_fd, host_metadata)) = self
                                .overlay
                                .open_raw_fd_with_metadata(path, true, false, false)
                                .lowerable()?
                            {
                                return Ok(OpenDispatchResult::HostFile {
                                    host_fd,
                                    metadata: host_metadata,
                                    writable: true,
                                });
                            }
                            return Ok(OpenDispatchResult::File {
                                metadata: md,
                                contents: Vec::new(),
                                writable: true,
                            });
                        }
                        let contents = rootfs
                            .read_shared(path)
                            .map_err(crate::dispatch::rootfs_errno)?;
                        self.overlay
                            .create_file_from_rootfs(path, Arc::clone(&contents), metadata.mode)
                            .map_err(|_| LINUX_EINVAL)?;
                        if let Some((host_fd, host_metadata)) = self
                            .overlay
                            .open_raw_fd_with_metadata(path, true, false, false)
                            .lowerable()?
                        {
                            return Ok(OpenDispatchResult::HostFile {
                                host_fd,
                                metadata: host_metadata,
                                writable: true,
                            });
                        }
                        return Ok(OpenDispatchResult::RootFsBackedFile {
                            metadata,
                            contents: SharedFileContents {
                                len: contents.len(),
                                base: contents,
                                dirty: std::collections::BTreeMap::new(),
                            },
                            writable: true,
                        });
                    }
                    let contents = rootfs.read(path).map_err(crate::dispatch::rootfs_errno)?;
                    Ok(OpenDispatchResult::File {
                        metadata,
                        contents,
                        writable: false,
                    })
                }
                RootFsEntryKind::Directory => {
                    // O_EXCL takes priority over EISDIR (see the overlay Dir arm).
                    if want_create && want_excl {
                        return Err(LINUX_EEXIST);
                    }
                    Ok(OpenDispatchResult::Directory { metadata })
                }
                RootFsEntryKind::Symlink => Err(LINUX_EINVAL),
                // open(2) of an AF_UNIX socket node → ENXIO on Linux (no device
                // to open). A socket node only ever lives in the writable
                // overlay (created by bind), not the immutable rootfs, so this
                // is reached only via a guest open of a bound socket path.
                RootFsEntryKind::Socket => Err(crate::linux_abi::LINUX_ENXIO),
            },
            None => {
                if want_create {
                    Ok(OpenDispatchResult::NotFoundCreate)
                } else {
                    Err(LINUX_ENOENT)
                }
            }
        }
    }

    pub fn watch_fds(&self, path: &str) -> Result<Vec<WatchFd>, VfsError> {
        self.overlay.watch_fds(path)
    }

    /// Layered rename with optional `RENAME_NOREPLACE` semantics.
    /// Walks the overlay-then-rootfs view to find the source,
    /// materialises the destination in the overlay (copying bytes
    /// from the rootfs if needed), then tombstones the source so the
    /// layered view shows it as gone.
    pub fn rename_with_flags(
        &self,
        from: &str,
        to: &str,
        no_replace: bool,
    ) -> Result<(), VfsError> {
        let (src_kind, src_contents, src_in_overlay) = match self.overlay.lookup(from) {
            Some(OverlayEntry::Deleted) => return Err(LINUX_ENOENT),
            Some(OverlayEntry::Dir) => (RootFsEntryKind::Directory, None, true),
            Some(OverlayEntry::File(b)) => (RootFsEntryKind::File, Some(b), true),
            None => match self
                .rootfs
                .as_ref()
                .and_then(|r| r.symlink_metadata(from).ok())
            {
                Some(md) => match md.kind {
                    // Socket never lives in the immutable rootfs (bind only
                    // creates it in the writable overlay, handled above), but
                    // the match must be exhaustive — treat it like a file.
                    RootFsEntryKind::File
                    | RootFsEntryKind::Symlink
                    | RootFsEntryKind::CharDevice
                    | RootFsEntryKind::Fifo
                    | RootFsEntryKind::Socket => {
                        // INVARIANT: this arm is reached only via the
                        // `self.rootfs.as_ref().and_then(..symlink_metadata..)`
                        // match above, which already proved rootfs is Some.
                        #[allow(clippy::expect_used)]
                        let bytes = self
                            .rootfs
                            .as_ref()
                            .expect("rootfs metadata implies rootfs")
                            .read(from)
                            .map_err(crate::dispatch::rootfs_errno)?;
                        (RootFsEntryKind::File, Some(bytes), false)
                    }
                    RootFsEntryKind::Directory => (RootFsEntryKind::Directory, None, false),
                },
                None => return Err(LINUX_ENOENT),
            },
        };
        let dst_kind = match self.overlay.lookup(to) {
            Some(OverlayEntry::Deleted) => None,
            Some(OverlayEntry::Dir) => Some(RootFsEntryKind::Directory),
            Some(OverlayEntry::File(_)) => Some(RootFsEntryKind::File),
            None => self
                .rootfs
                .as_ref()
                .and_then(|r| r.symlink_metadata(to).ok())
                .map(|metadata| metadata.kind),
        };
        if dst_kind.is_some() && no_replace {
            return Err(LINUX_EEXIST);
        }
        if from == to {
            return Ok(());
        }
        if let Some(dst_kind) = dst_kind {
            match (
                src_kind == RootFsEntryKind::Directory,
                dst_kind == RootFsEntryKind::Directory,
            ) {
                (false, true) => return Err(LINUX_EISDIR),
                (true, false) => return Err(LINUX_ENOTDIR),
                (true, true) => {
                    let entries = crate::fs_backend::layered_directory_entries(
                        self.overlay.as_ref(),
                        self.rootfs.as_ref(),
                        to,
                    )
                    .map_err(crate::dispatch::rootfs_errno)?;
                    if !entries.is_empty() {
                        return Err(LINUX_ENOTEMPTY);
                    }
                }
                (false, false) => {}
            }
        }
        // Prefer the backend's real rename first. For a writable
        // backend (host: cap-std `dir.rename`; memory: in-place map
        // move) this atomically relocates the WHOLE entry — including a
        // directory's entire subtree/contents — and reports Ok(true)
        // when the source actually lived in the backend. A real
        // directory rename on disk also removes the source, which is
        // exactly the Linux semantics the conformance probe checks
        // (source gone, contents moved). Only fall back to the
        // copy/materialise + tombstone path when the source was NOT in
        // the writable backend (Ok(false)) — e.g. a pure-rootfs entry
        // under --fs memory.
        match self.overlay.rename_overlay_entry(from, to) {
            Ok(true) => {
                // Backend moved the entry (contents included). If the
                // rootfs ALSO has the source path, leave a tombstone so
                // the layered view doesn't resurrect the rootfs copy.
                let rootfs_has_src = self
                    .rootfs
                    .as_ref()
                    .map(|r| r.symlink_metadata(from).is_ok())
                    .unwrap_or(false);
                if rootfs_has_src {
                    self.overlay.mark_deleted(from).map_err(|_| LINUX_EINVAL)?;
                }
                let inode = self.path_inode_identity(to);
                self.dentry_cache.entry_moved(from, to, inode);
                return Ok(());
            }
            Ok(false) => {}
            Err(_) => return Err(LINUX_EINVAL),
        }

        // Fallback: source is not owned by the writable backend
        // (rootfs-only entry). Materialise the destination, then
        // tombstone the rootfs source.
        match src_kind {
            RootFsEntryKind::File
            | RootFsEntryKind::Symlink
            | RootFsEntryKind::CharDevice
            | RootFsEntryKind::Fifo
            | RootFsEntryKind::Socket => {
                self.overlay
                    .set_file_contents(to, src_contents.unwrap_or_default())
                    .map_err(|_| LINUX_EINVAL)?;
            }
            RootFsEntryKind::Directory => {
                self.overlay.make_dir(to).map_err(|_| LINUX_EINVAL)?;
            }
        }
        if src_in_overlay {
            self.overlay.remove_entry(from);
        }
        let rootfs_has_src = self
            .rootfs
            .as_ref()
            .map(|r| r.symlink_metadata(from).is_ok())
            .unwrap_or(false);
        if rootfs_has_src {
            self.overlay.mark_deleted(from).map_err(|_| LINUX_EINVAL)?;
        }
        let inode = self.path_inode_identity(to);
        self.dentry_cache.entry_moved(from, to, inode);
        Ok(())
    }

    /// Atomically EXCHANGE the two entries `a` and `b` (`renameat2(2)`
    /// `RENAME_EXCHANGE`): each path ends up referring to what the other named,
    /// with all metadata following the entry. BOTH must exist in the layered
    /// view (the dispatcher returns ENOENT otherwise); any rootfs-only side is
    /// materialised into the writable backend first so the backend's atomic
    /// swap operates on two backend-owned entries, then a tombstone hides the
    /// resurrectable rootfs copy.
    pub fn exchange_with_flags(&self, a: &str, b: &str) -> Result<(), VfsError> {
        // Materialise a rootfs-only entry into the overlay so the backend owns
        // both names before the swap. Returns the entry's layered kind so a
        // tombstone can be left for the OTHER name's pre-swap rootfs copy.
        let materialise = |path: &str| -> Result<(), VfsError> {
            // Already overlay-owned (not a tombstone)? Nothing to do.
            match self.overlay.lookup(path) {
                Some(OverlayEntry::Deleted) => return Err(LINUX_ENOENT),
                Some(OverlayEntry::Dir) | Some(OverlayEntry::File(_)) => return Ok(()),
                None => {}
            }
            // Pull it from the rootfs into the writable overlay.
            let md = self
                .rootfs
                .as_ref()
                .and_then(|r| r.symlink_metadata(path).ok())
                .ok_or(LINUX_ENOENT)?;
            match md.kind {
                RootFsEntryKind::Directory => {
                    self.overlay.make_dir(path).map_err(|_| LINUX_EINVAL)?;
                }
                RootFsEntryKind::File
                | RootFsEntryKind::Symlink
                | RootFsEntryKind::CharDevice
                | RootFsEntryKind::Fifo
                | RootFsEntryKind::Socket => {
                    let bytes = self
                        .rootfs
                        .as_ref()
                        .and_then(|r| r.read(path).ok())
                        .unwrap_or_default();
                    self.overlay
                        .set_file_contents(path, bytes)
                        .map_err(|_| LINUX_EINVAL)?;
                }
            }
            Ok(())
        };
        materialise(a)?;
        materialise(b)?;
        match self.overlay.exchange_overlay_entries(a, b) {
            Ok(true) => {
                let inode_a = self.path_inode_identity(a);
                let inode_b = self.path_inode_identity(b);
                self.dentry_cache.entry_exchanged(a, b, inode_a, inode_b);
                Ok(())
            }
            // Backend couldn't own both sides even after materialise (Ok(false)),
            // or has no swap primitive (Unsupported), or the swap I/O failed:
            // surface a coherent errno rather than corrupt the namespace.
            Ok(false) | Err(_) => Err(LINUX_EINVAL),
        }
    }

    /// Layered "is this path a directory" check. Used by the
    /// dispatcher to validate mkdir/rename parent paths.
    pub fn is_directory(&self, path: &str) -> bool {
        match self.overlay.lookup(path) {
            Some(OverlayEntry::Dir) => return true,
            Some(OverlayEntry::File(_)) => return false,
            Some(OverlayEntry::Deleted) => return false,
            None => {}
        }
        self.rootfs
            .as_ref()
            .and_then(|r| r.metadata(path).ok())
            .map(|m| m.kind == RootFsEntryKind::Directory)
            .unwrap_or(false)
    }
}

impl Default for RootFsVfs {
    fn default() -> Self {
        Self::new()
    }
}

impl Vfs for RootFsVfs {
    /// Overlay-first lookup. The writable overlay shadows the
    /// rootfs for tombstoned paths and overlay-owned entries; if
    /// neither layer has the path, return ENOENT.
    fn lookup(&self, path: &str) -> Result<Metadata, VfsError> {
        // The filesystem root always exists as a directory. Resolve it
        // here so root-relative metadata (statfs("/"), open("/"),
        // mkdir parent checks) works regardless of whether the rootfs
        // layer is present — under `--fs host` it is dropped after the
        // disk is seeded, and the host backend deliberately refuses to
        // treat its sandbox root as a lookupable entry.
        if path.is_empty() || path == "/" {
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
        if self.overlay.serves_dentry_cache() {
            match self.dentry_stat(path, true) {
                Ok(real) => {
                    let kind = match real.kind {
                        RootFsEntryKind::File => EntryKind::File,
                        RootFsEntryKind::Directory => EntryKind::Directory,
                        RootFsEntryKind::CharDevice => EntryKind::CharDevice,
                        RootFsEntryKind::Fifo => EntryKind::Fifo,
                        RootFsEntryKind::Socket => EntryKind::Socket,
                        RootFsEntryKind::Symlink => EntryKind::Symlink,
                    };
                    return Ok(Metadata {
                        kind,
                        mode: real.mode,
                        size: real.size,
                        uid: real.uid.raw() as libc::uid_t,
                        gid: real.gid.raw() as libc::gid_t,
                        mtime_secs: real.mtime.0,
                        mtime_nanos: real.mtime.1 as u32,
                    });
                }
                Err(LINUX_ENOENT) => return Err(LINUX_ENOENT),
                Err(LINUX_ENOTDIR) => return Err(LINUX_ENOTDIR),
                Err(LINUX_ELOOP) => return Err(LINUX_ELOOP),
                _ => {}
            }
        }
        // One combined backend pass: kind + metadata answered from a single
        // contained open on the host backend (separate `lookup_kind` +
        // `metadata` calls each re-walked the path). Prefer the backend's own
        // metadata (the host backend reads real on-disk mode bits, so
        // executables keep their 0o111); fall back to defaults only if the
        // backend can't produce metadata for an entry it just reported.
        let (entry_kind, backend_md) = self.overlay.lookup_kind_and_metadata(path);
        if let Some(entry) = entry_kind {
            // FIFOs and AF_UNIX socket nodes are reported by the backend as
            // (present, empty) File entries, but their true kind lives in
            // `metadata`. Surface the special kind before the generic File arm.
            if let Some(md) = &backend_md
                && (md.kind == RootFsEntryKind::Fifo || md.kind == RootFsEntryKind::Socket)
            {
                let kind = if md.kind == RootFsEntryKind::Fifo {
                    EntryKind::Fifo
                } else {
                    EntryKind::Socket
                };
                return Ok(Metadata {
                    kind,
                    mode: md.mode,
                    size: 0,
                    uid: 0,
                    gid: 0,
                    mtime_secs: 0,
                    mtime_nanos: 0,
                });
            }
            match entry {
                OverlayEntryKind::Deleted => return Err(LINUX_ENOENT),
                OverlayEntryKind::Dir => {
                    return Ok(Metadata {
                        kind: EntryKind::Directory,
                        mode: backend_md.map(|m| m.mode).unwrap_or(0o755),
                        size: 0,
                        uid: 0,
                        gid: 0,
                        mtime_secs: 0,
                        mtime_nanos: 0,
                    });
                }
                OverlayEntryKind::File => {
                    let size = backend_md
                        .as_ref()
                        .map(|m| m.size as u64)
                        .or_else(|| match self.overlay.lookup(path) {
                            Some(OverlayEntry::File(bytes)) => Some(bytes.len() as u64),
                            _ => None,
                        })
                        .unwrap_or(0);
                    return Ok(Metadata {
                        kind: EntryKind::File,
                        mode: backend_md.map(|m| m.mode).unwrap_or(0o644),
                        size,
                        uid: 0,
                        gid: 0,
                        mtime_secs: 0,
                        mtime_nanos: 0,
                    });
                }
            }
        }
        let rootfs = self.rootfs.as_ref().ok_or(LINUX_ENOENT)?;
        let md = rootfs.metadata(path).map_err(|_| LINUX_ENOENT)?;
        Ok(Metadata {
            kind: match md.kind {
                RootFsEntryKind::File => EntryKind::File,
                RootFsEntryKind::Directory => EntryKind::Directory,
                RootFsEntryKind::Symlink => EntryKind::Symlink,
                RootFsEntryKind::CharDevice => EntryKind::CharDevice,
                RootFsEntryKind::Fifo => EntryKind::Fifo,
                RootFsEntryKind::Socket => EntryKind::Socket,
            },
            mode: md.mode,
            size: md.size as u64,
            uid: 0,
            gid: 0,
            mtime_secs: 0,
            mtime_nanos: 0,
        })
    }

    fn readlink(&self, path: &str) -> Result<std::path::PathBuf, VfsError> {
        // A symlink materialised in the writable overlay (cap-std on
        // --fs host, where the rootfs layer is dropped after seeding).
        if let Some(target) = self.overlay.read_link(path) {
            return Ok(std::path::PathBuf::from(target));
        }
        // A symlink in the immutable rootfs layer (present for --fs memory).
        if let Some(rootfs) = self.rootfs.as_ref() {
            match rootfs.read_link(path) {
                Ok(target) => return Ok(std::path::PathBuf::from(target)),
                Err(crate::rootfs::RootFsError::NotFound(_)) => {}
                Err(_) => return Err(LINUX_ENOENT),
            }
        }
        // Not a symlink in either layer. Linux readlink(2) distinguishes
        // EINVAL (the path EXISTS but isn't a symlink) from ENOENT (no
        // such path) — apt's realpath()/flAbsPath relies on this. Consult
        // the layered view so an existing regular file/dir on the disk
        // overlay yields EINVAL even with the rootfs layer dropped.
        if self.lookup(path).is_ok() {
            Err(crate::linux_abi::LINUX_EINVAL)
        } else {
            Err(LINUX_ENOENT)
        }
    }

    fn open(
        &self,
        path: &str,
        flags: OpenFlags,
        _ctx: &OpenContext<'_>,
    ) -> Result<VfsHandle, VfsError> {
        // Overlay-first: bytes-backed File entries.
        if let Some(entry) = self.overlay.lookup(path) {
            match entry {
                OverlayEntry::Deleted => return Err(LINUX_ENOENT),
                OverlayEntry::Dir => return Err(LINUX_EISDIR),
                OverlayEntry::File(contents) => {
                    if flags.excl && flags.create {
                        return Err(LINUX_EEXIST);
                    }
                    let mut contents = contents;
                    if flags.trunc {
                        contents.clear();
                        if self
                            .overlay
                            .set_file_contents(path, contents.clone())
                            .is_err()
                        {
                            return Err(crate::linux_abi::LINUX_EINVAL);
                        }
                    }
                    return Ok(VfsHandle::Bytes {
                        path: path.to_string(),
                        contents,
                        status_flags: 0,
                    });
                }
            }
        }
        // Rootfs fallthrough — read-only for now.
        if flags.write {
            return Err(LINUX_EROFS);
        }
        let rootfs = self.rootfs.as_ref().ok_or(LINUX_ENOENT)?;
        let bytes = rootfs.read(path).map_err(|_| LINUX_ENOENT)?;
        Ok(VfsHandle::Bytes {
            path: path.to_string(),
            contents: bytes,
            status_flags: 0,
        })
    }

    fn readdir(&self, path: &str) -> Result<Vec<DirEnt>, VfsError> {
        // Layered readdir: rootfs entries minus overlay tombstones,
        // plus overlay-owned entries. Reuse the existing helper.
        match crate::overlay::layered_directory_entries(
            self.overlay.as_ref(),
            self.rootfs.as_ref(),
            path,
        ) {
            Ok(entries) => Ok(entries
                .into_iter()
                .map(|e| DirEnt {
                    name: e.name,
                    kind: match e.metadata.kind {
                        RootFsEntryKind::File => EntryKind::File,
                        RootFsEntryKind::Directory => EntryKind::Directory,
                        RootFsEntryKind::Symlink => EntryKind::Symlink,
                        RootFsEntryKind::CharDevice => EntryKind::CharDevice,
                        RootFsEntryKind::Fifo => EntryKind::Fifo,
                        RootFsEntryKind::Socket => EntryKind::Socket,
                    },
                })
                .collect()),
            Err(_) => Err(LINUX_ENOTDIR),
        }
    }

    fn readdir_bounded(&self, path: &str, limit: usize) -> Result<Vec<DirEnt>, VfsError> {
        let deleted = self
            .overlay
            .deleted_child_names_bounded(path, limit)
            .map_err(|_| LINUX_ENOSYS)?;
        if deleted.len() > limit {
            return Err(LINUX_E2BIG);
        }
        let deleted = deleted
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        let mut seen = std::collections::HashSet::with_capacity(limit.saturating_add(1));
        let mut out = Vec::with_capacity(limit.saturating_add(1));

        if let Some(rootfs) = self.rootfs.as_ref() {
            match rootfs.directory_entries_bounded(path, limit) {
                Ok(entries) => {
                    for entry in entries {
                        if crate::fs_backend::is_internal_sidecar_name(&entry.name)
                            || deleted.contains(&entry.name)
                        {
                            continue;
                        }
                        let child = if path == "/" {
                            format!("/{}", entry.name)
                        } else {
                            format!("{}/{}", path.trim_end_matches('/'), entry.name)
                        };
                        if self.overlay.shadows(&child) {
                            continue;
                        }
                        seen.insert(entry.name.clone());
                        out.push(DirEnt {
                            name: entry.name,
                            kind: match entry.metadata.kind {
                                RootFsEntryKind::File => EntryKind::File,
                                RootFsEntryKind::Directory => EntryKind::Directory,
                                RootFsEntryKind::Symlink => EntryKind::Symlink,
                                RootFsEntryKind::CharDevice => EntryKind::CharDevice,
                                RootFsEntryKind::Fifo => EntryKind::Fifo,
                                RootFsEntryKind::Socket => EntryKind::Socket,
                            },
                        });
                        if out.len() > limit {
                            return Err(LINUX_E2BIG);
                        }
                    }
                }
                Err(RootFsError::NotFound(_)) => {}
                Err(RootFsError::DirectoryTooLarge(_)) => return Err(LINUX_E2BIG),
                Err(_) => return Err(LINUX_ENOTDIR),
            }
        }

        let upper = self
            .overlay
            .child_names_bounded(path, limit)
            .map_err(|_| LINUX_ENOSYS)?;
        if upper.len() > limit {
            return Err(LINUX_E2BIG);
        }
        for (name, kind, _) in upper {
            if crate::fs_backend::is_internal_sidecar_name(&name)
                || seen.contains(&name)
                || deleted.contains(&name)
            {
                continue;
            }
            seen.insert(name.clone());
            out.push(DirEnt {
                name,
                kind: match kind {
                    RootFsEntryKind::File => EntryKind::File,
                    RootFsEntryKind::Directory => EntryKind::Directory,
                    RootFsEntryKind::Symlink => EntryKind::Symlink,
                    RootFsEntryKind::CharDevice => EntryKind::CharDevice,
                    RootFsEntryKind::Fifo => EntryKind::Fifo,
                    RootFsEntryKind::Socket => EntryKind::Socket,
                },
            });
            if out.len() > limit {
                return Err(LINUX_E2BIG);
            }
        }
        Ok(out)
    }

    fn mkdir(&self, path: &str, _mode: u32) -> Result<(), VfsError> {
        // Layered EEXIST: an existing overlay or rootfs entry (file
        // or dir) at `path` blocks mkdir. A tombstone clears the
        // rootfs view so a re-create is allowed.
        match self.overlay.lookup(path) {
            Some(OverlayEntry::Dir) | Some(OverlayEntry::File(_)) => {
                return Err(LINUX_EEXIST);
            }
            Some(OverlayEntry::Deleted) => {}
            None => {
                if let Some(rootfs) = self.rootfs.as_ref()
                    && rootfs.metadata(path).is_ok()
                {
                    return Err(LINUX_EEXIST);
                }
            }
        }
        // Parent must exist as a directory in the layered view.
        if let Some(parent) = std::path::Path::new(path).parent() {
            let parent_str = parent.to_string_lossy();
            let parent_str: &str = if parent_str.is_empty() {
                "/"
            } else {
                parent_str.as_ref()
            };
            if !self.is_directory(parent_str) {
                return Err(LINUX_ENOENT);
            }
        }
        self.overlay
            .make_dir(path)
            .map_err(|_| crate::linux_abi::LINUX_EINVAL)?;
        self.dentry_cache.entry_created(path, None);
        Ok(())
    }

    fn unlink(&self, path: &str) -> Result<(), VfsError> {
        // Layered: overlay first (a tombstone short-circuits to
        // ENOENT). Then rootfs via symlink_metadata so symlinks are
        // identified as such (not followed). Only the KIND is needed here:
        // `lookup` would read the whole file back off disk just to drop it,
        // which for an unlink of a large file is the dominant cost.
        let (kind, in_overlay, in_rootfs) = match self.overlay.lookup_kind(path) {
            Some(OverlayEntryKind::Deleted) => return Err(LINUX_ENOENT),
            Some(OverlayEntryKind::Dir) => (RootFsEntryKind::Directory, true, false),
            Some(OverlayEntryKind::File) => (RootFsEntryKind::File, true, false),
            None => match self
                .rootfs
                .as_ref()
                .and_then(|r| r.symlink_metadata(path).ok())
            {
                Some(md) => (md.kind, false, true),
                None => return Err(LINUX_ENOENT),
            },
        };
        if matches!(kind, RootFsEntryKind::Directory) {
            return Err(LINUX_EISDIR);
        }
        let inode = self.path_inode_identity(path);
        let parent_inode = std::path::Path::new(path)
            .parent()
            .and_then(|p| p.to_str())
            .and_then(|p| self.path_inode_identity(p));
        if in_overlay {
            self.overlay.remove_entry(path);
            // Tombstone only if the rootfs also has this path, so a
            // re-create still works.
            let rootfs_has_it = self
                .rootfs
                .as_ref()
                .map(|r| r.symlink_metadata(path).is_ok())
                .unwrap_or(false);
            if rootfs_has_it {
                self.overlay
                    .mark_deleted(path)
                    .map_err(|_| crate::linux_abi::LINUX_EINVAL)?;
            }
        } else if in_rootfs {
            self.overlay
                .mark_deleted(path)
                .map_err(|_| crate::linux_abi::LINUX_EINVAL)?;
        }
        self.dentry_cache.entry_removed(path, inode);
        if let Some(parent_id) = parent_inode {
            self.dentry_cache.invalidate_inode(parent_id);
        }
        Ok(())
    }

    fn rmdir(&self, path: &str) -> Result<(), VfsError> {
        let (kind, in_overlay, in_rootfs) = match self.overlay.lookup_kind(path) {
            Some(OverlayEntryKind::Deleted) => return Err(LINUX_ENOENT),
            Some(OverlayEntryKind::Dir) => (RootFsEntryKind::Directory, true, false),
            Some(OverlayEntryKind::File) => (RootFsEntryKind::File, true, false),
            None => match self
                .rootfs
                .as_ref()
                .and_then(|r| r.symlink_metadata(path).ok())
            {
                Some(md) => (md.kind, false, true),
                None => return Err(LINUX_ENOENT),
            },
        };
        if !matches!(kind, RootFsEntryKind::Directory) {
            return Err(LINUX_ENOTDIR);
        }
        // Linux rmdir(2) requires the directory to be empty (ENOTEMPTY
        // otherwise). The layered view must show no surviving children:
        // overlay-owned entries plus rootfs entries that aren't tombstoned.
        if let Ok(entries) = crate::overlay::layered_directory_entries(
            self.overlay.as_ref(),
            self.rootfs.as_ref(),
            path,
        ) && !entries.is_empty()
        {
            return Err(LINUX_ENOTEMPTY);
        }
        let inode = self.path_inode_identity(path);
        let parent_inode = std::path::Path::new(path)
            .parent()
            .and_then(|p| p.to_str())
            .and_then(|p| self.path_inode_identity(p));
        if in_overlay {
            self.overlay.remove_entry(path);
            let rootfs_has_it = self
                .rootfs
                .as_ref()
                .map(|r| r.symlink_metadata(path).is_ok())
                .unwrap_or(false);
            if rootfs_has_it {
                self.overlay
                    .mark_deleted(path)
                    .map_err(|_| crate::linux_abi::LINUX_EINVAL)?;
            }
        } else if in_rootfs {
            self.overlay
                .mark_deleted(path)
                .map_err(|_| crate::linux_abi::LINUX_EINVAL)?;
        }
        self.dentry_cache.entry_removed(path, inode);
        if let Some(parent_id) = parent_inode {
            self.dentry_cache.invalidate_inode(parent_id);
        }
        Ok(())
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), VfsError> {
        self.rename_with_flags(from, to, false)
    }

    fn symlink(&self, target: &str, link: &str) -> Result<(), VfsError> {
        self.symlink(target, link).map_err(|e| match e {
            LINUX_EROFS => LINUX_EROFS,
            _ => LINUX_EINVAL,
        })
    }

    fn link(&self, from: &str, to: &str) -> Result<(), VfsError> {
        self.link(from, to).map_err(|e| match e {
            LINUX_EROFS => LINUX_EROFS,
            _ => LINUX_EINVAL,
        })
    }

    fn chmod(&self, path: &str, mode: u32) -> Result<(), VfsError> {
        self.set_mode(path, mode).map_err(|e| match e {
            BackendError::Unsupported => LINUX_EROFS,
            _ => LINUX_EINVAL,
        })
    }

    fn create_socket(&self, path: &str, mode: u32) -> Result<(), VfsError> {
        self.create_socket(path, mode).map_err(|e| match e {
            BackendError::Unsupported => LINUX_EROFS,
            _ => LINUX_EINVAL,
        })
    }

    fn chown(
        &self,
        path: &str,
        uid: Option<carrick_abi::NsUid>,
        gid: Option<carrick_abi::NsGid>,
        _nofollow: bool,
    ) -> Result<(), VfsError> {
        self.set_owner(path, uid, gid).map_err(|e| match e {
            BackendError::Unsupported => LINUX_EROFS,
            _ => LINUX_EINVAL,
        })
    }

    fn set_times(
        &self,
        path: &str,
        atime: Option<(i64, i64)>,
        mtime: Option<(i64, i64)>,
        nofollow: bool,
    ) -> Result<(), VfsError> {
        self.set_times(path, atime, mtime, nofollow)
            .map_err(|e| match e {
                BackendError::Unsupported => LINUX_EROFS,
                _ => LINUX_EINVAL,
            })
    }

    fn truncate(&mut self, path: &str, len: u64) -> Result<(), VfsError> {
        if len > MAX_IN_MEMORY_FILE_SIZE {
            return Err(LINUX_EFBIG);
        }
        let inode = self.path_inode_identity(path);
        // Materialise the file into the overlay (if it's only in
        // rootfs), then truncate.
        let mut contents = match self.overlay.lookup(path) {
            Some(OverlayEntry::Deleted) => return Err(LINUX_ENOENT),
            Some(OverlayEntry::Dir) => return Err(LINUX_EISDIR),
            Some(OverlayEntry::File(b)) => b,
            None => self
                .rootfs
                .as_ref()
                .ok_or(LINUX_ENOENT)?
                .read(path)
                .map_err(|_| LINUX_ENOENT)?,
        };
        let len = len as usize;
        contents.truncate(len);
        contents.resize(len, 0);
        self.overlay
            .set_file_contents(path, contents)
            .map_err(|_| LINUX_EACCES)?;
        self.dentry_cache.inode_changed(path, inode);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "rootfs"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "macos")]
    use crate::fs_backend::HostFsBackend;
    use crate::fs_backend::{BackendError, HostFdOpen, OverlayEntryKind};
    use crate::rootfs::LayerSource;
    use std::os::fd::IntoRawFd;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tar::{Builder, EntryType, Header};

    fn rootfs_with_files() -> RootFs {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut builder = Builder::new(&mut buf);
            for dir in ["etc", "usr", "usr/bin"] {
                let mut h = Header::new_gnu();
                h.set_path(format!("{}/", dir)).unwrap();
                h.set_entry_type(EntryType::Directory);
                h.set_size(0);
                h.set_mode(0o755);
                h.set_cksum();
                builder.append(&h, std::io::empty()).unwrap();
            }
            let entries: &[(&str, &[u8], u32)] = &[
                ("etc/hosts", b"127.0.0.1\tlocalhost\n", 0o644),
                ("usr/bin/true", b"#!/bin/sh\n", 0o755),
            ];
            for (path, body, mode) in entries {
                let mut h = Header::new_gnu();
                h.set_path(path).unwrap();
                h.set_size(body.len() as u64);
                h.set_mode(*mode);
                h.set_cksum();
                builder.append(&h, *body).unwrap();
            }
            builder.finish().unwrap();
        }
        RootFs::from_layers(std::iter::once(LayerSource::Tar(buf))).unwrap()
    }

    #[cfg(target_os = "macos")]
    fn host_lower_vfs(lower: &std::path::Path, upper: &std::path::Path) -> RootFsVfs {
        let rootfs = RootFs::from_immutable_host_dir(lower).unwrap();
        let mut overlay = HostFsBackend::from_path(upper).unwrap();
        overlay.enable_sparse_upper_fast_miss();
        let mut vfs = RootFsVfs::with_rootfs(rootfs);
        vfs.set_overlay(Box::new(overlay));
        vfs
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn immutable_host_lower_merges_shadows_and_tombstones_without_mutation() {
        let lower = tempfile::TempDir::new().unwrap();
        let upper = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(lower.path().join("etc/sub")).unwrap();
        std::fs::write(lower.path().join("etc/hosts"), b"lower-hosts\n").unwrap();
        std::fs::write(lower.path().join("etc/sub/lower"), b"lower\n").unwrap();
        std::os::unix::fs::symlink("hosts", lower.path().join("etc/current")).unwrap();

        let vfs = host_lower_vfs(lower.path(), upper.path());
        assert_eq!(vfs.lookup("/etc/hosts").unwrap().kind, EntryKind::File);
        assert_eq!(
            vfs.lookup_nofollow("/etc/current").unwrap().kind,
            EntryKind::Symlink
        );
        assert_eq!(
            vfs.readlink("/etc/current").unwrap(),
            std::path::Path::new("hosts")
        );

        let initial: std::collections::BTreeSet<_> = vfs
            .readdir("/etc")
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert_eq!(
            initial,
            ["current", "hosts", "sub"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );

        vfs.overlay
            .set_file_contents("/etc/hosts", b"upper-hosts\n".to_vec())
            .unwrap();
        vfs.overlay
            .set_file_contents("/etc/upper", b"upper\n".to_vec())
            .unwrap();
        match vfs
            .open_for_dispatch("/etc/hosts", false, false, false, false)
            .unwrap()
        {
            OpenDispatchResult::HostFile { host_fd, .. } => {
                let mut bytes = [0_u8; 32];
                let count = unsafe { libc::read(host_fd, bytes.as_mut_ptr().cast(), bytes.len()) };
                unsafe { libc::close(host_fd) };
                assert_eq!(&bytes[..count as usize], b"upper-hosts\n");
            }
            _ => panic!("host upper shadow must return a host fd"),
        }

        vfs.unlink("/etc/sub/lower").unwrap();
        assert!(vfs.lookup("/etc/sub/lower").is_err());
        assert_eq!(
            vfs.lookup_nofollow("/etc/sub/lower"),
            Err(LINUX_ENOENT),
            "a sparse-upper whiteout must hide the immutable lower from lstat"
        );
        assert_eq!(
            std::fs::read(lower.path().join("etc/sub/lower")).unwrap(),
            b"lower\n",
            "deleting the layered path must not mutate the immutable cache lower"
        );
        assert!(
            vfs.readdir("/etc/sub").unwrap().is_empty(),
            "the sparse upper tombstone must filter the lower directory entry"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sparse_upper_ancestor_whiteout_hides_the_immutable_lower_subtree() {
        let lower = tempfile::TempDir::new().unwrap();
        let upper = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(lower.path().join("etc/sub")).unwrap();
        std::fs::write(lower.path().join("etc/sub/lower"), b"lower").unwrap();
        let vfs = host_lower_vfs(lower.path(), upper.path());

        vfs.overlay.mark_deleted("/etc").unwrap();

        assert_eq!(
            vfs.lookup_nofollow("/etc/sub/lower"),
            Err(LINUX_ENOENT),
            "a deleted lower directory must hide every descendant"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn writable_host_lower_open_copies_up_to_a_fork_coherent_host_file() {
        let lower = tempfile::TempDir::new().unwrap();
        let upper = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(lower.path().join("work")).unwrap();
        std::fs::write(lower.path().join("work/data"), b"lower-data\n").unwrap();

        let first = host_lower_vfs(lower.path(), upper.path());
        let host_fd = match first
            .open_for_dispatch("/work/data", false, false, false, true)
            .unwrap()
        {
            OpenDispatchResult::HostFile {
                host_fd,
                writable: true,
                ..
            } => host_fd,
            _ => panic!("writable copy-up must return a real host file"),
        };
        assert_eq!(
            unsafe { libc::write(host_fd, b"UPPER".as_ptr().cast(), 5) },
            5
        );
        unsafe { libc::close(host_fd) };

        let second = host_lower_vfs(lower.path(), upper.path());
        let contents = second.overlay.file_contents("/work/data").unwrap();
        assert_eq!(contents, b"UPPER-data\n");
        assert_eq!(
            std::fs::read(lower.path().join("work/data")).unwrap(),
            b"lower-data\n"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn readonly_immutable_host_lower_open_keeps_a_real_host_file() {
        let lower = tempfile::TempDir::new().unwrap();
        let upper = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(lower.path().join("usr/lib")).unwrap();
        std::fs::write(lower.path().join("usr/lib/cache"), b"host-cache\n").unwrap();

        let vfs = host_lower_vfs(lower.path(), upper.path());
        match vfs
            .open_for_dispatch("/usr/lib/cache", false, false, false, false)
            .unwrap()
        {
            OpenDispatchResult::HostFile {
                host_fd,
                writable: false,
                ..
            } => unsafe {
                libc::close(host_fd);
            },
            _ => panic!("immutable host lower reads must preserve the host fd"),
        }
        assert!(
            !upper.path().join("usr/lib/cache").exists(),
            "a read-only open must not copy the immutable lower into the sparse upper"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn fast_readonly_open_uses_the_immutable_lower_when_the_sparse_upper_is_absent() {
        use std::io::Read as _;
        use std::os::fd::AsRawFd as _;

        let lower = tempfile::TempDir::new().unwrap();
        let upper = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(lower.path().join("usr/lib")).unwrap();
        std::fs::write(lower.path().join("usr/lib/cache"), b"lower-cache").unwrap();
        let vfs = host_lower_vfs(lower.path(), upper.path());

        let ImmutableHostFileOpen::Served { mut file, metadata } =
            vfs.open_immutable_lower_readonly("/usr/lib/cache")
        else {
            panic!("upper-absent lower file should open directly");
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"lower-cache");
        assert_eq!(metadata.kind, RootFsEntryKind::File);
        assert_eq!(metadata.size, 11);
        assert_eq!(
            metadata.path,
            std::path::Path::new("/usr/lib/cache"),
            "a served HostFile's metadata path is the GUEST-ABSOLUTE path the fd \
             was opened at (OpenDescription::open_path feeds it to execveat \
             AT_EMPTY_PATH); the sandbox-relative `normalize` form made fexecve \
             re-resolve against the caller's cwd"
        );
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags, -1);
        assert_eq!(
            flags & libc::O_ACCMODE,
            libc::O_RDONLY,
            "an immutable-lower file is served with the guest's read-only access mode"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn fast_readonly_open_refuses_an_upper_shadow() {
        let lower = tempfile::TempDir::new().unwrap();
        let upper = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(lower.path().join("usr/lib")).unwrap();
        std::fs::write(lower.path().join("usr/lib/cache"), b"lower-cache").unwrap();
        let vfs = host_lower_vfs(lower.path(), upper.path());
        vfs.overlay
            .set_file_contents("/usr/lib/cache", b"upper-cache".to_vec())
            .unwrap();

        assert!(
            matches!(
                vfs.open_immutable_lower_readonly("/usr/lib/cache"),
                ImmutableHostFileOpen::Fallback
            ),
            "a direct lower open must never bypass the writable shadow"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn fast_readonly_open_proves_a_missing_leaf_below_a_contained_lower_directory() {
        let lower = tempfile::TempDir::new().unwrap();
        let upper = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(lower.path().join("usr/lib/locale")).unwrap();
        let vfs = host_lower_vfs(lower.path(), upper.path());

        assert!(matches!(
            vfs.open_immutable_lower_readonly("/usr/lib/locale/C.UTF-8/LC_CTYPE"),
            ImmutableHostFileOpen::Missing
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn fast_readonly_open_does_not_infer_a_miss_through_a_lower_symlink() {
        let lower = tempfile::TempDir::new().unwrap();
        let upper = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(lower.path().join("real")).unwrap();
        std::os::unix::fs::symlink("/real", lower.path().join("jump")).unwrap();
        let vfs = host_lower_vfs(lower.path(), upper.path());

        assert!(matches!(
            vfs.open_immutable_lower_readonly("/jump/missing"),
            ImmutableHostFileOpen::Fallback
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn host_lookup_nofollow_fast_path_preserves_symlink_and_fifo_types() {
        let scratch = tempfile::TempDir::new().unwrap();
        std::fs::write(scratch.path().join("file"), b"x").unwrap();
        std::os::unix::fs::symlink("file", scratch.path().join("link")).unwrap();
        let fifo = scratch.path().join("fifo");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);

        let mut vfs = RootFsVfs::new();
        vfs.set_overlay(Box::new(HostFsBackend::from_path(scratch.path()).unwrap()));

        assert_eq!(vfs.lookup_nofollow("/file").unwrap().kind, EntryKind::File);
        assert_eq!(
            vfs.lookup_nofollow("/link").unwrap().kind,
            EntryKind::Symlink
        );
        assert_eq!(vfs.lookup_nofollow("/fifo").unwrap().kind, EntryKind::Fifo);
    }

    struct MetadataOnlyBackend {
        host_path: std::path::PathBuf,
        lookup_payload_reads: Arc<AtomicUsize>,
        metadata_calls: Arc<AtomicUsize>,
        raw_open_calls: Arc<AtomicUsize>,
        combined_open_calls: Arc<AtomicUsize>,
        size: usize,
        fast_absent: bool,
    }

    struct MetadataOnlyBackendCounters {
        payload_reads: Arc<AtomicUsize>,
        metadata_calls: Arc<AtomicUsize>,
        raw_open_calls: Arc<AtomicUsize>,
        combined_open_calls: Arc<AtomicUsize>,
    }

    impl MetadataOnlyBackend {
        fn new(size: usize) -> (Self, Arc<AtomicUsize>) {
            let (backend, counters) = Self::new_with_counters(size);
            (backend, counters.payload_reads)
        }

        fn new_with_counters(size: usize) -> (Self, MetadataOnlyBackendCounters) {
            let host_path = std::env::temp_dir().join(format!(
                "carrick-rootfs-metadata-only-{}-{size}",
                std::process::id()
            ));
            std::fs::write(&host_path, b"x").unwrap();
            let lookup_payload_reads = Arc::new(AtomicUsize::new(0));
            let metadata_calls = Arc::new(AtomicUsize::new(0));
            let raw_open_calls = Arc::new(AtomicUsize::new(0));
            let combined_open_calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    host_path,
                    lookup_payload_reads: Arc::clone(&lookup_payload_reads),
                    metadata_calls: Arc::clone(&metadata_calls),
                    raw_open_calls: Arc::clone(&raw_open_calls),
                    combined_open_calls: Arc::clone(&combined_open_calls),
                    size,
                    fast_absent: false,
                },
                MetadataOnlyBackendCounters {
                    payload_reads: lookup_payload_reads,
                    metadata_calls,
                    raw_open_calls,
                    combined_open_calls,
                },
            )
        }
    }

    impl Drop for MetadataOnlyBackend {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.host_path);
        }
    }

    impl FsBackend for MetadataOnlyBackend {
        fn lookup(&self, _path: &str) -> Option<OverlayEntry> {
            self.lookup_payload_reads.fetch_add(1, Ordering::SeqCst);
            Some(OverlayEntry::File(b"payload".to_vec()))
        }

        fn lookup_kind(&self, _path: &str) -> Option<OverlayEntryKind> {
            Some(OverlayEntryKind::File)
        }

        fn metadata(&self, path: &str) -> Option<RootFsMetadata> {
            self.metadata_calls.fetch_add(1, Ordering::SeqCst);
            Some(RootFsMetadata {
                path: std::path::Path::new(path).to_path_buf(),
                kind: RootFsEntryKind::File,
                mode: 0o644,
                size: self.size,
            })
        }

        fn fast_nofollow_absent(&self, _path: &str) -> bool {
            self.fast_absent
        }

        fn file_contents(&self, _path: &str) -> Option<Vec<u8>> {
            self.lookup_payload_reads.fetch_add(1, Ordering::SeqCst);
            Some(b"payload".to_vec())
        }

        fn make_dir(&self, _path: &str) -> Result<(), BackendError> {
            Err(BackendError::Unsupported)
        }

        fn create_file(&self, _path: &str) -> Result<(), BackendError> {
            Err(BackendError::Unsupported)
        }

        fn set_file_contents(&self, _path: &str, _contents: Vec<u8>) -> Result<(), BackendError> {
            Err(BackendError::Unsupported)
        }

        fn remove_entry(&self, _path: &str) -> bool {
            false
        }

        fn mark_deleted(&self, _path: &str) -> Result<(), BackendError> {
            Err(BackendError::Unsupported)
        }

        fn child_names(&self, _dir: &str) -> Vec<(String, RootFsEntryKind, Option<u64>)> {
            Vec::new()
        }

        fn deleted_child_names(&self, _dir: &str) -> Vec<String> {
            Vec::new()
        }

        fn rename_overlay_entry(&self, _from: &str, _to: &str) -> Result<bool, BackendError> {
            Ok(false)
        }

        fn open_raw_fd(
            &self,
            _path: &str,
            write: bool,
            _create: bool,
            _trunc: bool,
        ) -> HostFdOpen<i32> {
            self.raw_open_calls.fetch_add(1, Ordering::SeqCst);
            let mut opts = std::fs::OpenOptions::new();
            opts.read(true);
            if write {
                opts.write(true);
            }
            match opts.open(&self.host_path) {
                Ok(file) => HostFdOpen::Served(file.into_raw_fd()),
                Err(_) => HostFdOpen::Unavailable,
            }
        }

        fn open_raw_fd_with_metadata(
            &self,
            path: &str,
            write: bool,
            _create: bool,
            _trunc: bool,
        ) -> HostFdOpen<(i32, RootFsMetadata)> {
            self.combined_open_calls.fetch_add(1, Ordering::SeqCst);
            let mut opts = std::fs::OpenOptions::new();
            opts.read(true);
            if write {
                opts.write(true);
            }
            let Ok(file) = opts.open(&self.host_path) else {
                return HostFdOpen::Unavailable;
            };
            HostFdOpen::Served((
                file.into_raw_fd(),
                RootFsMetadata {
                    path: std::path::Path::new(path).to_path_buf(),
                    kind: RootFsEntryKind::File,
                    mode: 0o644,
                    size: self.size,
                },
            ))
        }
    }

    #[test]
    fn lookup_rootfs_file() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        let md = v.lookup("/etc/hosts").unwrap();
        assert_eq!(md.kind, EntryKind::File);
        assert!(md.size > 0);
    }

    #[test]
    fn lookup_rootfs_dir() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        let md = v.lookup("/etc").unwrap();
        assert_eq!(md.kind, EntryKind::Directory);
    }

    #[test]
    fn lookup_missing_is_enoent() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        assert_eq!(v.lookup("/no-such"), Err(LINUX_ENOENT));
    }

    #[test]
    fn lookup_nofollow_uses_authoritative_sparse_upper_miss_without_reprobing_overlay() {
        let (mut backend, counters) = MetadataOnlyBackend::new_with_counters(99);
        backend.fast_absent = true;
        let v = RootFsVfs {
            rootfs: Some(rootfs_with_files()),
            overlay: Box::new(backend),
            dentry_cache: Arc::new(crate::vfs::DentryCache::new(false)),
        };

        let md = v.lookup_nofollow("/etc").unwrap();
        assert_eq!(md.kind, EntryKind::Directory);
        assert_eq!(v.lookup_nofollow("/no-such"), Err(LINUX_ENOENT));
        assert_eq!(counters.payload_reads.load(Ordering::SeqCst), 0);
        assert_eq!(counters.metadata_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn lookup_overlay_file_uses_metadata_without_loading_contents() {
        let (backend, payload_reads) = MetadataOnlyBackend::new(4 * 1024 * 1024);
        let v = RootFsVfs {
            rootfs: None,
            overlay: Box::new(backend),
            dentry_cache: Arc::new(crate::vfs::DentryCache::new(false)),
        };

        let md = v.lookup("/large.bin").unwrap();

        assert_eq!(md.kind, EntryKind::File);
        assert_eq!(
            payload_reads.load(Ordering::SeqCst),
            0,
            "metadata lookup should not load file contents"
        );
        assert_eq!(md.size, 4 * 1024 * 1024);
    }

    #[test]
    fn open_for_dispatch_prefers_combined_host_fd_metadata() {
        let (backend, counters) = MetadataOnlyBackend::new_with_counters(8 * 1024 * 1024);
        let v = RootFsVfs {
            rootfs: None,
            overlay: Box::new(backend),
            dentry_cache: Arc::new(crate::vfs::DentryCache::new(false)),
        };

        let opened = v
            .open_for_dispatch("/large.bin", false, false, false, false)
            .unwrap();

        match opened {
            OpenDispatchResult::HostFile {
                host_fd, metadata, ..
            } => {
                assert_eq!(metadata.kind, RootFsEntryKind::File);
                assert_eq!(metadata.size, 8 * 1024 * 1024);
                unsafe { libc::close(host_fd) };
            }
            _ => panic!("expected host file"),
        }
        assert_eq!(counters.combined_open_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            counters.metadata_calls.load(Ordering::SeqCst),
            0,
            "combined open should provide metadata without a separate metadata lookup"
        );
        assert_eq!(
            counters.raw_open_calls.load(Ordering::SeqCst),
            0,
            "combined open should replace the separate raw-fd open"
        );
    }

    #[test]
    fn truncate_rejects_unbounded_in_memory_file_growth() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());

        assert_eq!(
            v.truncate("/etc/hosts", crate::vfs::MAX_IN_MEMORY_FILE_SIZE + 1),
            Err(LINUX_EFBIG)
        );
    }

    #[test]
    fn open_rootfs_file_returns_bytes() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        let h = v
            .open(
                "/etc/hosts",
                OpenFlags {
                    read: true,
                    ..Default::default()
                },
                &OpenContext::default(),
            )
            .unwrap();
        match h {
            VfsHandle::Bytes { contents, .. } => {
                assert!(String::from_utf8_lossy(&contents).contains("localhost"));
            }
            other => panic!("expected Bytes, got {:?}", other),
        }
    }

    #[test]
    fn open_write_to_rootfs_only_is_erofs() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        let result = v.open(
            "/etc/hosts",
            OpenFlags {
                write: true,
                ..Default::default()
            },
            &OpenContext::default(),
        );
        assert_eq!(result, Err(LINUX_EROFS));
    }

    #[test]
    fn overlay_shadows_rootfs() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.overlay
            .set_file_contents("/etc/hosts", b"10.0.0.1 myhost\n".to_vec())
            .unwrap();
        let h = v
            .open(
                "/etc/hosts",
                OpenFlags {
                    read: true,
                    ..Default::default()
                },
                &OpenContext::default(),
            )
            .unwrap();
        match h {
            VfsHandle::Bytes { contents, .. } => {
                let s = String::from_utf8_lossy(&contents);
                assert!(s.contains("myhost"), "got: {:?}", s);
                assert!(
                    !s.contains("localhost"),
                    "rootfs leaked through overlay: {:?}",
                    s
                );
            }
            other => panic!("expected Bytes, got {:?}", other),
        }
    }

    #[test]
    fn tombstone_shadows_rootfs() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.overlay.mark_deleted("/etc/hosts").unwrap();
        assert_eq!(v.lookup("/etc/hosts"), Err(LINUX_ENOENT));
    }

    #[test]
    fn unlink_tombstones_rootfs_path() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.unlink("/etc/hosts").unwrap();
        assert_eq!(v.lookup("/etc/hosts"), Err(LINUX_ENOENT));
    }

    #[test]
    fn unlink_dir_returns_eisdir() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        assert_eq!(v.unlink("/etc"), Err(LINUX_EISDIR));
    }

    #[test]
    fn unlink_missing_returns_enoent() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        assert_eq!(v.unlink("/no-such"), Err(LINUX_ENOENT));
    }

    #[test]
    fn mkdir_then_lookup() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.mkdir("/tmp", 0o755).unwrap();
        let md = v.lookup("/tmp").unwrap();
        assert_eq!(md.kind, EntryKind::Directory);
    }

    #[test]
    fn readdir_layered() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        // Add an overlay-owned file.
        v.mkdir("/etc/extras", 0o755).unwrap();
        let entries = v.readdir("/etc").unwrap();
        let names: std::collections::BTreeSet<_> = entries.iter().map(|e| e.name.clone()).collect();
        assert!(names.contains("hosts"));
        assert!(names.contains("extras"));
    }

    #[test]
    fn rename_overlay_file_to_new_path() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.overlay
            .set_file_contents("/etc/source", b"hello\n".to_vec())
            .unwrap();
        v.rename_with_flags("/etc/source", "/etc/dest", false)
            .unwrap();
        assert_eq!(v.lookup("/etc/source"), Err(LINUX_ENOENT));
        let md = v.lookup("/etc/dest").unwrap();
        assert_eq!(md.kind, EntryKind::File);
        assert_eq!(md.size, 6);
    }

    #[test]
    fn rename_rootfs_file_promotes_into_overlay() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.rename_with_flags("/etc/hosts", "/etc/renamed_hosts", false)
            .unwrap();
        // Source tombstoned in overlay.
        assert_eq!(v.lookup("/etc/hosts"), Err(LINUX_ENOENT));
        // Destination has the same content as the original rootfs file.
        let md = v.lookup("/etc/renamed_hosts").unwrap();
        assert_eq!(md.kind, EntryKind::File);
        assert!(md.size > 0);
    }

    #[test]
    fn rename_with_no_replace_rejects_existing() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.overlay
            .set_file_contents("/etc/source", b"x".to_vec())
            .unwrap();
        // /etc/hosts already exists in the rootfs.
        let result = v.rename_with_flags("/etc/source", "/etc/hosts", true);
        assert_eq!(result, Err(LINUX_EEXIST));
    }

    #[test]
    fn rename_missing_source_is_enoent() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        let result = v.rename_with_flags("/etc/no-such", "/etc/dest", false);
        assert_eq!(result, Err(LINUX_ENOENT));
    }

    #[test]
    fn rename_file_over_directory_is_eisdir() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.overlay
            .set_file_contents("/etc/source", b"payload".to_vec())
            .unwrap();
        v.overlay.make_dir("/etc/dest").unwrap();

        assert_eq!(
            v.rename_with_flags("/etc/source", "/etc/dest", false),
            Err(LINUX_EISDIR)
        );
    }

    #[test]
    fn rename_directory_over_file_is_enotdir() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.overlay.make_dir("/etc/source").unwrap();
        v.overlay
            .set_file_contents("/etc/dest", b"payload".to_vec())
            .unwrap();

        assert_eq!(
            v.rename_with_flags("/etc/source", "/etc/dest", false),
            Err(LINUX_ENOTDIR)
        );
    }

    #[test]
    fn rename_directory_over_nonempty_directory_is_enotempty() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.overlay.make_dir("/etc/source").unwrap();
        v.overlay.make_dir("/etc/dest").unwrap();
        v.overlay
            .set_file_contents("/etc/dest/child", b"payload".to_vec())
            .unwrap();

        assert_eq!(
            v.rename_with_flags("/etc/source", "/etc/dest", false),
            Err(LINUX_ENOTEMPTY)
        );
    }

    #[test]
    fn open_for_dispatch_overlay_file() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.overlay
            .set_file_contents("/etc/scratch", b"overlay\n".to_vec())
            .unwrap();
        let result = v
            .open_for_dispatch("/etc/scratch", false, false, false, true)
            .unwrap();
        // Memory-overlay opens return a shared, copy-on-write-style
        // RootFsBackedFile (no eager byte clone). A freshly set file is all
        // `base`, with no dirty write deltas yet.
        match result {
            OpenDispatchResult::RootFsBackedFile {
                contents, writable, ..
            } => {
                assert_eq!(String::from_utf8_lossy(&contents.base), "overlay\n");
                assert!(contents.dirty.is_empty());
                assert!(writable);
            }
            _ => panic!("expected RootFsBackedFile"),
        }
    }

    #[test]
    fn open_for_dispatch_rootfs_file_with_writable_promotes() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        let result = v
            .open_for_dispatch("/etc/hosts", false, false, false, true)
            .unwrap();
        // A writable open of a rootfs file is promoted into the overlay, now
        // as a RootFsBackedFile: the overlay entry shares the rootfs bytes
        // (lazy copy-up) instead of eagerly cloning a Vec.
        match result {
            OpenDispatchResult::RootFsBackedFile { writable, .. } => assert!(writable),
            _ => panic!("expected RootFsBackedFile"),
        }
        // Promotion happened: the overlay now has /etc/hosts.
        assert!(matches!(
            v.overlay.lookup("/etc/hosts"),
            Some(OverlayEntry::File(_))
        ));
    }

    #[test]
    fn open_for_dispatch_directory_reports_the_directory_without_listing_it() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.mkdir("/etc/extras", 0o755).unwrap();
        let result = v
            .open_for_dispatch("/etc", false, false, false, false)
            .unwrap();
        match result {
            OpenDispatchResult::Directory { metadata } => {
                assert_eq!(metadata.kind, RootFsEntryKind::Directory);
                assert_eq!(metadata.path, std::path::Path::new("/etc"));
            }
            _ => panic!("expected Directory"),
        }
        // The listing is the dispatcher's job at getdents time; the merge
        // it will take is the layered one.
        let names: std::collections::BTreeSet<_> = crate::overlay::layered_directory_entries(
            v.overlay.as_ref(),
            v.rootfs.as_ref(),
            "/etc",
        )
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
        assert!(names.contains("hosts"));
        assert!(names.contains("extras"));
    }

    #[test]
    fn open_for_dispatch_not_found_create_signals_caller() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        let result = v
            .open_for_dispatch("/etc/new", true, false, false, true)
            .unwrap();
        assert!(matches!(result, OpenDispatchResult::NotFoundCreate));
    }

    #[test]
    fn open_for_dispatch_host_file_uses_raw_fd_without_loading_contents() {
        let (backend, payload_reads) = MetadataOnlyBackend::new(4 * 1024 * 1024);
        let v = RootFsVfs {
            rootfs: None,
            overlay: Box::new(backend),
            dentry_cache: Arc::new(crate::vfs::DentryCache::new(false)),
        };

        let result = v
            .open_for_dispatch("/large.bin", false, false, false, false)
            .unwrap();

        match result {
            OpenDispatchResult::HostFile {
                host_fd, metadata, ..
            } => {
                unsafe {
                    libc::close(host_fd);
                }
                assert_eq!(metadata.size, 4 * 1024 * 1024);
            }
            _ => panic!("expected host-backed file"),
        }
        assert_eq!(
            payload_reads.load(Ordering::SeqCst),
            0,
            "host-backed open should not load file contents before returning the raw fd"
        );
    }

    #[test]
    fn open_for_dispatch_excl_on_existing_is_eexist() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        let result = v.open_for_dispatch("/etc/hosts", true, true, false, true);
        assert_eq!(result.err(), Some(LINUX_EEXIST));
    }

    #[test]
    fn mkdir_layered_eexist() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        // Rootfs has /etc; mkdir of an existing path is EEXIST.
        assert_eq!(v.mkdir("/etc", 0o755), Err(LINUX_EEXIST));
    }

    #[test]
    fn mkdir_no_parent_is_enoent() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        assert_eq!(v.mkdir("/no-such-parent/sub", 0o755), Err(LINUX_ENOENT));
    }

    #[test]
    fn is_directory_layered() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        assert!(v.is_directory("/etc"));
        assert!(!v.is_directory("/etc/hosts"));
        assert!(!v.is_directory("/no-such"));
        v.mkdir("/var/tmp", 0o755).unwrap_or_default();
    }

    #[test]
    fn open_overlay_trunc_clears_bytes() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.overlay
            .set_file_contents("/etc/hosts", b"original\n".to_vec())
            .unwrap();
        let h = v
            .open(
                "/etc/hosts",
                OpenFlags {
                    write: true,
                    trunc: true,
                    ..Default::default()
                },
                &OpenContext::default(),
            )
            .unwrap();
        match h {
            VfsHandle::Bytes { contents, .. } => assert!(contents.is_empty()),
            other => panic!("expected Bytes, got {:?}", other),
        }
        // Confirm the overlay was also truncated.
        let md = v.lookup("/etc/hosts").unwrap();
        assert_eq!(md.size, 0);
    }

    #[test]
    fn test_rootfs_vfs_create_node_kinds_after_negative_lookup() {
        let scratch = tempfile::tempdir().unwrap();
        let mut vfs = RootFsVfs::new();
        vfs.set_overlay(Box::new(HostFsBackend::from_path(scratch.path()).unwrap()));

        // 1. Regular file
        assert!(vfs.dentry_stat("/file", false).is_err());
        vfs.create_file("/file").unwrap();
        vfs.set_mode("/file", 0o644).unwrap();
        let st_file = vfs
            .dentry_stat("/file", false)
            .expect("file must be present immediately after creation");
        assert_eq!(st_file.kind, RootFsEntryKind::File);
        assert_ne!(st_file.ino, 0);
        assert_eq!(st_file.mode & 0o777, 0o644);

        // 2. Directory
        assert!(vfs.dentry_stat("/dir", false).is_err());
        vfs.mkdir("/dir", 0o755).unwrap();
        let st_dir = vfs
            .dentry_stat("/dir", false)
            .expect("dir must be present immediately after creation");
        assert_eq!(st_dir.kind, RootFsEntryKind::Directory);
        assert_ne!(st_dir.ino, 0);
        assert_eq!(st_dir.mode & 0o777, 0o755);

        // 3. Symlink
        assert!(vfs.dentry_stat("/link", false).is_err());
        vfs.symlink("/file", "/link").unwrap();
        let st_link = vfs
            .dentry_stat("/link", false)
            .expect("symlink must be present immediately after creation");
        assert_eq!(st_link.kind, RootFsEntryKind::Symlink);
        assert_ne!(st_link.ino, 0);
        assert_eq!(vfs.dentry_readlink("/link").unwrap(), "/file");

        // 4. FIFO
        assert!(vfs.dentry_stat("/fifo", false).is_err());
        vfs.create_fifo("/fifo", 0o620).unwrap();
        let st_fifo = vfs
            .dentry_stat("/fifo", false)
            .expect("fifo must be present immediately after creation");
        assert_eq!(st_fifo.kind, RootFsEntryKind::Fifo);
        assert_ne!(st_fifo.ino, 0);
        assert_eq!(st_fifo.mode & 0o777, 0o620);

        // 5. Socket
        assert!(vfs.dentry_stat("/sock", false).is_err());
        vfs.create_socket("/sock", 0o660).unwrap();
        let st_sock = vfs
            .dentry_stat("/sock", false)
            .expect("socket must be present immediately after creation");
        assert_eq!(st_sock.kind, RootFsEntryKind::Socket);
        assert_ne!(st_sock.ino, 0);
        assert_eq!(st_sock.mode & 0o777, 0o660);

        // 6. Hard link
        assert!(vfs.dentry_stat("/hardlink", false).is_err());
        vfs.link("/file", "/hardlink").unwrap();
        let st_hl = vfs
            .dentry_stat("/hardlink", false)
            .expect("hardlink must be present");
        assert_eq!(st_hl.ino, st_file.ino);

        // 7. Unlink
        vfs.unlink("/hardlink").unwrap();
        assert!(vfs.dentry_stat("/hardlink", false).is_err());

        // 8. Rmdir
        vfs.rmdir("/dir").unwrap();
        assert!(vfs.dentry_stat("/dir", false).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn lower_layer_xattr_returns_enodata() {
        let lower = tempfile::TempDir::new().unwrap();
        let upper = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(lower.path().join("usr/lib")).unwrap();
        std::fs::write(lower.path().join("usr/lib/libtest.so"), b"elf").unwrap();

        let vfs = host_lower_vfs(lower.path(), upper.path());
        assert_eq!(
            vfs.get_xattr("/usr/lib", "user.x", true),
            Err(crate::linux_abi::LINUX_ENODATA)
        );
        assert_eq!(
            vfs.get_xattr("/usr/lib/libtest.so", "user.x", true),
            Err(crate::linux_abi::LINUX_ENODATA)
        );
        assert_eq!(
            vfs.list_xattr("/usr/lib", true).unwrap(),
            Vec::<String>::new()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_rootfs_vfs_fset_owner_and_fset_mode() {
        use std::os::fd::AsRawFd;
        let scratch = tempfile::tempdir().unwrap();
        let mut vfs = RootFsVfs::new();
        vfs.set_overlay(Box::new(HostFsBackend::from_path(scratch.path()).unwrap()));

        vfs.create_file("/testfile").unwrap();
        let (fd, st, _, _) = vfs.dentry_fast_open("/testfile", true).unwrap();

        // Initial mode and owner
        assert_eq!(st.mode & 0o777, 0o644);
        assert_eq!(st.uid, carrick_abi::NsUid::ROOT);
        assert_eq!(st.gid, carrick_abi::NsGid::ROOT);

        // Mutate mode via fset_mode
        vfs.fset_mode(fd.as_raw_fd(), 0o755);
        let st2 = vfs.dentry_stat("/testfile", false).unwrap();
        assert_eq!(st2.mode & 0o777, 0o755);

        // Mutate owner via fset_owner
        vfs.fset_owner(
            fd.as_raw_fd(),
            Some(carrick_abi::NsUid::new(1001)),
            Some(carrick_abi::NsGid::new(1002)),
        );
        let st3 = vfs.dentry_stat("/testfile", false).unwrap();
        assert_eq!(st3.uid, carrick_abi::NsUid::new(1001));
        assert_eq!(st3.gid, carrick_abi::NsGid::new(1002));
    }
}
