//! Bind mounts: a real macOS path exposed at a guest path.
//!
//! # Theory of operation
//!
//! Unlike the synthetic mounts ([`super::proc`], [`super::sys`]) and the
//! immutable rootfs, a [`BindVfs`] is a thin pass-through to a *real* host
//! directory or file. It is the `docker run -v host:guest` mechanism, and
//! carrick also uses it internally for `/dev/shm` (a per-process host tmpfs
//! stand-in) and for single-file binds such as the `run-elf` executable
//! surfaced at `/proc/self/exe`.
//!
//! The whole job is two translations:
//!
//! * **Path** — `BindVfs::to_host` maps a guest path to a host path by
//!   stripping the mount point and rejoining onto `host_path`. The mount point
//!   *itself* maps to `host_path` verbatim (no trailing-slash join), so a
//!   single-file bind works: joining an empty component would append a `/` and
//!   make `open(2)` return `ENOTDIR` on a regular file.
//! * **Errno** — every host failure is run through
//!   [`crate::host_to_linux_errno`] so the guest sees Linux errno
//!   numbers, not Darwin ones.
//!
//! `readonly` gates the mutators: a read-only bind returns `EROFS` from
//! `open`-for-write, `mkdir`, `unlink`, `rename`, and friends, exactly as a
//! `ro` bind mount would on Linux. Because the backing is a real kernel file,
//! inotify-style watches ([`watch_fd`](Vfs::watch_fd)) open a host
//! `O_EVTONLY`/`O_RDONLY` fd that the dispatcher's epoll/kqueue machinery
//! drives, and `read_file` can serve an executable for the ELF loader (which
//! runs before the guest has any fds).

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use super::{
    DirEnt, EntryKind, Metadata, OpenContext, OpenFlags, Vfs, VfsError, VfsHandle, WatchFd,
};
use crate::host_to_linux_errno;
use crate::linux_abi::{LINUX_EBUSY, LINUX_EINVAL, LINUX_ENOENT, LINUX_ENXIO, LINUX_EROFS};

pub struct BindVfs {
    mount_point: String,
    host_path: PathBuf,
    readonly: bool,
}

impl BindVfs {
    pub fn new(
        mount_point: impl Into<String>,
        host_path: impl Into<PathBuf>,
        readonly: bool,
    ) -> Self {
        Self {
            mount_point: mount_point.into(),
            host_path: host_path.into(),
            readonly,
        }
    }

    /// `true` iff `guest_path` names the mount POINT itself (the directory the
    /// mount is attached at), not something underneath it. A trailing slash is
    /// tolerated so `rmdir("/workspace/")` is recognised too.
    fn is_mount_point(&self, guest_path: &str) -> bool {
        guest_path == self.mount_point
            || guest_path.trim_end_matches('/') == self.mount_point.trim_end_matches('/')
    }

    fn to_host(&self, guest_path: &str) -> Result<PathBuf, VfsError> {
        let relative = if guest_path == self.mount_point {
            // The mount point itself maps to host_path verbatim. Do NOT
            // `join("")` — Path::join with an empty component appends a trailing
            // separator (`…/os.test` → `…/os.test/`), which open(2) rejects with
            // ENOTDIR on a regular file (a single-file bind, e.g. the run-elf
            // /proc/self/exe binary, mounts one file at the mount point).
            return Ok(self.host_path.clone());
        } else if let Some(stripped) = guest_path.strip_prefix(&self.mount_point) {
            let stripped = stripped.strip_prefix('/').unwrap_or(stripped);
            Path::new(stripped)
        } else {
            return Err(LINUX_ENOENT);
        };
        Ok(self.host_path.join(relative))
    }
}

fn map_io_error(e: std::io::Error) -> VfsError {
    let raw = e.raw_os_error().unwrap_or(libc::EIO);
    host_to_linux_errno(raw)
}

fn host_open_errno() -> i32 {
    let raw = carrick_portable::errno();
    host_to_linux_errno(raw)
}

fn open_watch_fd(host: &Path) -> Result<i32, VfsError> {
    let cpath = CString::new(host.to_string_lossy().as_ref()).map_err(|_| LINUX_EINVAL)?;
    #[cfg(target_os = "macos")]
    let host_flags = libc::O_EVTONLY;
    #[cfg(not(target_os = "macos"))]
    let host_flags = libc::O_RDONLY;
    // SAFETY: host path as NUL-terminated string
    let host_fd = unsafe { libc::open(cpath.as_ptr(), host_flags) };
    if host_fd < 0 {
        return Err(host_open_errno());
    }
    Ok(host_fd)
}

/// Prefix for the per-symlink owner SIDECAR file. Linux forbids `user.*` (and
/// even `trusted.*`) xattrs on symlinks at the VFS layer, on every filesystem,
/// so a symlink's carrick-owned uid/gid cannot be stored in an xattr the way a
/// regular file's or directory's is. We instead persist it in a tiny on-disk
/// sidecar placed ADJACENT to the symlink (`<dir>/.carrick-lnkown.<name>`),
/// which is fork-coherent (real host file, inherited across `libc::fork` like
/// the rootfs itself — NOT an in-process map) and needs no root-path threading.
/// macOS allows xattrs on symlinks (XATTR_NOFOLLOW), so the sidecar is only used
/// where the xattr write/read could not carry the owner — see `symlink_owner_*`.
/// The whole sidecar mechanism is therefore `cfg(not(target_os = "macos"))`:
/// macOS keeps the XATTR_NOFOLLOW path unchanged.
#[cfg(not(target_os = "macos"))]
const LINK_OWNER_SIDECAR_PREFIX: &str = ".carrick-lnkown.";

/// True iff `name` is a per-symlink owner sidecar (filtered from `readdir`).
#[cfg(not(target_os = "macos"))]
fn is_link_owner_sidecar_name(name: &str) -> bool {
    name.starts_with(LINK_OWNER_SIDECAR_PREFIX)
}

/// The sidecar path for the symlink at host path `link`: same directory, name
/// prefixed with [`LINK_OWNER_SIDECAR_PREFIX`]. `None` if `link` has no file
/// name (e.g. is the root) — a symlink always has one, so this is defensive.
#[cfg(not(target_os = "macos"))]
fn link_owner_sidecar_path(link: &Path) -> Option<PathBuf> {
    let name = link.file_name()?.to_str()?;
    let dir = link.parent()?;
    Some(dir.join(format!("{LINK_OWNER_SIDECAR_PREFIX}{name}")))
}

/// Persist a symlink's owner (uid/gid, each `Some`/`None`) to its sidecar,
/// merging with any already-stored values so a uid-only then gid-only chown both
/// stick. Returns `Ok(())` on success (or when there is nothing to write).
#[cfg(not(target_os = "macos"))]
fn write_symlink_owner_sidecar(
    link: &Path,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), VfsError> {
    let Some(sidecar) = link_owner_sidecar_path(link) else {
        return Ok(());
    };
    // Merge with any existing owner so a partial chown preserves the other half
    // (Linux lchown(uid, -1) leaves gid untouched; -1 arrives here as `None`).
    let (mut cur_uid, mut cur_gid) = read_symlink_owner_sidecar(link);
    if let Some(u) = uid {
        cur_uid = Some(u);
    }
    if let Some(g) = gid {
        cur_gid = Some(g);
    }
    let mut buf = [0u8; 8];
    buf[0..4].copy_from_slice(&cur_uid.unwrap_or(u32::MAX).to_le_bytes());
    buf[4..8].copy_from_slice(&cur_gid.unwrap_or(u32::MAX).to_le_bytes());
    std::fs::write(&sidecar, buf).map_err(map_io_error)
}

/// Read a symlink's sidecar-stored owner, `(uid, gid)` each `Some` when present.
/// A `u32::MAX` field means "unset" (lchown never sets uid/gid to -1/`u32::MAX`).
#[cfg(not(target_os = "macos"))]
fn read_symlink_owner_sidecar(link: &Path) -> (Option<u32>, Option<u32>) {
    let Some(sidecar) = link_owner_sidecar_path(link) else {
        return (None, None);
    };
    let Ok(buf) = std::fs::read(&sidecar) else {
        return (None, None);
    };
    if buf.len() != 8 {
        return (None, None);
    }
    let uid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let gid = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let unset = |v: u32| (v != u32::MAX).then_some(v);
    (unset(uid), unset(gid))
}

fn read_u32_xattr(host: &Path, name: &str, nofollow: bool) -> Option<u32> {
    let cpath = CString::new(host.as_os_str().as_bytes()).ok()?;
    let cname = CString::new(name).ok()?;
    let mut value = [0u8; 4];
    // Portable path-xattr (macOS getxattr+XATTR_NOFOLLOW / Linux l?getxattr /
    // FreeBSD extattr_get_file|_link). The seam lives in carrick-portable.
    let n = unsafe {
        if nofollow {
            carrick_portable::lgetxattr(
                cpath.as_ptr(),
                cname.as_ptr(),
                value.as_mut_ptr() as *mut libc::c_void,
                value.len(),
            )
        } else {
            carrick_portable::getxattr(
                cpath.as_ptr(),
                cname.as_ptr(),
                value.as_mut_ptr() as *mut libc::c_void,
                value.len(),
            )
        }
    };
    (n == 4).then(|| u32::from_le_bytes(value))
}

fn write_u32_xattr(host: &Path, name: &str, value: u32, nofollow: bool) -> Result<(), VfsError> {
    let cpath = CString::new(host.as_os_str().as_bytes()).map_err(|_| LINUX_EINVAL)?;
    let cname = CString::new(name).map_err(|_| LINUX_EINVAL)?;
    let value = value.to_le_bytes();
    // Portable path-xattr (macOS setxattr+XATTR_NOFOLLOW / Linux l?setxattr /
    // FreeBSD extattr_set_file|_link). The seam lives in carrick-portable.
    let rc = unsafe {
        if nofollow {
            carrick_portable::lsetxattr(
                cpath.as_ptr(),
                cname.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len(),
                0,
            )
        } else {
            carrick_portable::setxattr(
                cpath.as_ptr(),
                cname.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len(),
                0,
            )
        }
    };
    if rc < 0 {
        return Err(host_open_errno());
    }
    Ok(())
}

fn owner_from_host_xattrs(host: &Path, nofollow: bool) -> (Option<u32>, Option<u32>) {
    #[allow(unused_mut)]
    let mut uid = read_u32_xattr(host, crate::fs_backend::CARRICK_UID_XATTR_NAME, nofollow);
    #[allow(unused_mut)]
    let mut gid = read_u32_xattr(host, crate::fs_backend::CARRICK_GID_XATTR_NAME, nofollow);
    // A symlink's owner can't live in an xattr on Linux (the kernel rejects
    // `user.*`/`trusted.*` xattrs on symlinks), so a NOFOLLOW lookup that found
    // no xattr falls back to the adjacent owner sidecar. The sidecar only exists
    // for symlinks `lchown`ed under carrick, so this is a no-op for everything
    // else (the `read` simply misses). macOS carries the owner in the xattr
    // (XATTR_NOFOLLOW), so the sidecar is never written/read there.
    #[cfg(not(target_os = "macos"))]
    if nofollow && (uid.is_none() || gid.is_none()) {
        let (s_uid, s_gid) = read_symlink_owner_sidecar(host);
        uid = uid.or(s_uid);
        gid = gid.or(s_gid);
    }
    (uid, gid)
}

fn is_socket_marker(host: &Path, nofollow: bool) -> bool {
    read_u32_xattr(host, crate::fs_backend::CARRICK_SOCKET_XATTR_NAME, nofollow) == Some(1)
}

fn write_owner_xattrs(
    host: &Path,
    uid: Option<u32>,
    gid: Option<u32>,
    nofollow: bool,
) -> Result<(), VfsError> {
    if let Some(uid) = uid {
        write_u32_xattr(
            host,
            crate::fs_backend::CARRICK_UID_XATTR_NAME,
            uid,
            nofollow,
        )?;
    }
    if let Some(gid) = gid {
        write_u32_xattr(
            host,
            crate::fs_backend::CARRICK_GID_XATTR_NAME,
            gid,
            nofollow,
        )?;
    }
    Ok(())
}

fn metadata_from_host(host: &Path, meta: std::fs::Metadata, nofollow: bool) -> Metadata {
    let kind = if meta.is_dir() {
        EntryKind::Directory
    } else if meta.is_symlink() {
        EntryKind::Symlink
    } else if meta.file_type().is_socket() || is_socket_marker(host, nofollow) {
        EntryKind::Socket
    } else {
        EntryKind::File
    };
    let (uid, gid) = owner_from_host_xattrs(host, nofollow);
    Metadata {
        kind,
        mode: meta.mode() & 0o7777,
        size: meta.len(),
        uid: uid.unwrap_or(meta.uid()),
        gid: gid.unwrap_or(meta.gid()),
        mtime_secs: meta.mtime(),
        mtime_nanos: meta.mtime_nsec() as u32,
    }
}

fn real_stat_from_host(
    host: &Path,
    st: &libc::stat,
    nofollow: bool,
) -> crate::fs_backend::RealStat {
    let kind = match st.st_mode & libc::S_IFMT {
        mode if mode == libc::S_IFDIR => crate::rootfs::RootFsEntryKind::Directory,
        mode if mode == libc::S_IFLNK => crate::rootfs::RootFsEntryKind::Symlink,
        mode if mode == libc::S_IFSOCK => crate::rootfs::RootFsEntryKind::Socket,
        _ if is_socket_marker(host, nofollow) => crate::rootfs::RootFsEntryKind::Socket,
        _ => crate::rootfs::RootFsEntryKind::File,
    };
    let (uid, gid) = owner_from_host_xattrs(host, nofollow);
    crate::fs_backend::RealStat {
        kind,
        ino: st.st_ino,
        nlink: st.st_nlink as u32,
        mode: st.st_mode as u32 & 0o7777,
        uid: uid.unwrap_or(st.st_uid),
        gid: gid.unwrap_or(st.st_gid),
        size: st.st_size.max(0) as u64,
        atime: (st.st_atime, carrick_portable::stat_atime_nsec(st)),
        mtime: (st.st_mtime, carrick_portable::stat_mtime_nsec(st)),
        ctime: (st.st_ctime, carrick_portable::stat_ctime_nsec(st)),
    }
}

impl Vfs for BindVfs {
    fn lookup(&self, path: &str) -> Result<Metadata, VfsError> {
        let host = self.to_host(path)?;
        std::fs::metadata(&host)
            .map(|meta| metadata_from_host(&host, meta, false))
            .map_err(map_io_error)
    }

    fn lookup_nofollow(&self, path: &str) -> Result<Metadata, VfsError> {
        let host = self.to_host(path)?;
        std::fs::symlink_metadata(&host)
            .map(|meta| metadata_from_host(&host, meta, true))
            .map_err(map_io_error)
    }

    fn real_stat(&self, path: &str, follow: bool) -> Option<crate::fs_backend::RealStat> {
        let host = self.to_host(path).ok()?;
        let cpath = CString::new(host.as_os_str().as_bytes()).ok()?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            if follow {
                libc::stat(cpath.as_ptr(), &mut st)
            } else {
                libc::lstat(cpath.as_ptr(), &mut st)
            }
        };
        (rc == 0).then(|| real_stat_from_host(&host, &st, !follow))
    }

    fn readlink(&self, path: &str) -> Result<PathBuf, VfsError> {
        let host = self.to_host(path)?;
        std::fs::read_link(&host).map_err(map_io_error)
    }

    fn read_file(&self, path: &str) -> Result<Vec<u8>, VfsError> {
        let host = self.to_host(path)?;
        std::fs::read(&host).map_err(map_io_error)
    }

    fn readdir(&self, path: &str) -> Result<Vec<DirEnt>, VfsError> {
        let host = self.to_host(path)?;
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&host).map_err(map_io_error)? {
            let entry = entry.map_err(map_io_error)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            // Hide carrick's per-symlink owner sidecars (non-macOS owner store):
            // they are an internal metadata store, not guest-visible entries.
            #[cfg(not(target_os = "macos"))]
            if is_link_owner_sidecar_name(&name) {
                continue;
            }
            let file_type = entry.file_type().map_err(map_io_error)?;
            let kind = if file_type.is_dir() {
                EntryKind::Directory
            } else if file_type.is_symlink() {
                EntryKind::Symlink
            } else if file_type.is_socket() || is_socket_marker(&entry.path(), true) {
                EntryKind::Socket
            } else {
                EntryKind::File
            };
            entries.push(DirEnt { name, kind });
        }
        Ok(entries)
    }

    fn open(
        &self,
        path: &str,
        flags: OpenFlags,
        ctx: &OpenContext<'_>,
    ) -> Result<VfsHandle, VfsError> {
        let host = self.to_host(path)?;
        if is_socket_marker(&host, flags.nofollow) {
            return Err(LINUX_ENXIO);
        }
        if host.is_dir() {
            let entries = self.readdir(path)?;
            return Ok(VfsHandle::Directory {
                path: path.to_owned(),
                entries,
                status_flags: 0,
            });
        }

        if self.readonly && flags.write {
            return Err(LINUX_EROFS);
        }

        let mut host_flags = if flags.read && flags.write {
            libc::O_RDWR
        } else if flags.write {
            libc::O_WRONLY
        } else {
            libc::O_RDONLY
        };
        if flags.nonblock {
            host_flags |= libc::O_NONBLOCK;
        }
        if flags.append {
            host_flags |= libc::O_APPEND;
        }
        if flags.create {
            host_flags |= libc::O_CREAT;
        }
        if flags.excl {
            host_flags |= libc::O_EXCL;
        }
        if flags.trunc {
            host_flags |= libc::O_TRUNC;
        }

        let existed_before_create = flags.create && std::fs::symlink_metadata(&host).is_ok();
        let cpath = CString::new(host.to_string_lossy().as_ref()).map_err(|_| LINUX_EINVAL)?;
        // SAFETY: host path as NUL-terminated string
        let host_fd = unsafe { libc::open(cpath.as_ptr(), host_flags, flags.mode as libc::c_int) };
        if host_fd < 0 {
            return Err(host_open_errno());
        }
        // The macOS open(2) applied the HOST process umask to the create mode,
        // so the on-disk bits can be narrower than the guest asked for. When we
        // just created the file, force the exact guest-requested mode via fchmod
        // — otherwise a 0-mode node (the dispatcher passes the guest's
        // umask-adjusted bits) would deny a later O_RDWR reopen (glibc sem_open's
        // SemLock._rebuild → EACCES under the multiprocessing forkserver).
        if flags.create && flags.mode != 0 {
            unsafe {
                libc::fchmod(host_fd, (flags.mode & 0o7777) as libc::mode_t);
            }
        }
        if flags.create && !existed_before_create {
            let _ = write_owner_xattrs(&host, Some(ctx.euid), Some(ctx.egid), false);
        }

        let status_flags = if flags.nonblock {
            crate::linux_abi::LINUX_O_NONBLOCK as u32
        } else {
            0
        };

        Ok(VfsHandle::HostFd {
            host_fd,
            is_read_end: !flags.write,
            status_flags,
        })
    }

    fn watch_fd(&self, path: &str) -> Result<i32, VfsError> {
        let host = self.to_host(path)?;
        open_watch_fd(&host)
    }

    fn watch_fds(&self, path: &str) -> Result<Vec<WatchFd>, VfsError> {
        let host = self.to_host(path)?;
        let root_fd = open_watch_fd(&host)?;
        let mut fds = if host.is_dir() {
            vec![WatchFd::scanning_directory(root_fd, host.clone())]
        } else {
            vec![WatchFd::unnamed(root_fd)]
        };
        if host.is_dir() {
            for entry in std::fs::read_dir(&host).map_err(map_io_error)? {
                let entry = entry.map_err(map_io_error)?;
                if let Ok(host_fd) = open_watch_fd(&entry.path()) {
                    fds.push(WatchFd::named(
                        host_fd,
                        entry.file_name().as_bytes().to_vec(),
                    ));
                }
            }
        }
        Ok(fds)
    }

    fn mkdir(&self, path: &str, mode: u32) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let host = self.to_host(path)?;
        std::fs::create_dir(&host).map_err(map_io_error)?;
        // Set mode since std::fs::create_dir doesn't take mode
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&host, std::fs::Permissions::from_mode(mode));
        Ok(())
    }

    fn unlink(&self, path: &str) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        // The mount POINT itself is not an ordinary entry: it's the attachment
        // point of a mount. `to_host` maps it to the `-v` host SOURCE directory,
        // so a literal `remove_file`/`remove_dir` here would erase the caller's
        // real source dir. Instead treat removing the mount point as a no-op
        // SUCCESS: the source dir (and the mount) stay, so the mount point
        // remains a present, enumerable (now-empty) directory.
        //
        // Why success and not EBUSY: kaniko's between-stage "Deleting
        // filesystem" does `os.RemoveAll("/workspace")` (delete the children,
        // then rmdir the dir). Returning EBUSY for that rmdir makes RemoveAll —
        // and the whole `DeleteFilesystem` walk — fail, aborting the build. A
        // no-op success matches what kaniko sees under Docker (where /workspace
        // is a plain dir it can remove and the next stage re-creates) AND keeps
        // the host source intact. Previously the host dir WAS deleted, which
        // left a dangling mount: the next full-FS snapshot walk hit ENOENT at
        // /workspace, kaniko's walker aborted silently, and everything after it
        // (notably /lib) was recorded deleted → a spurious `.wh.lib` whiteout.
        if self.is_mount_point(path) {
            return Ok(());
        }
        let host = self.to_host(path)?;
        // If this entry is a symlink it may have an owner sidecar (keyed by name,
        // adjacent on disk); remove it too so a later symlink that reuses the
        // name does not inherit a stale owner. Best-effort: a missing sidecar (the
        // common case — only `lchown`ed symlinks have one) is ignored. macOS keeps
        // the owner in the symlink's xattr, so there is no sidecar to clean up.
        #[cfg(not(target_os = "macos"))]
        if let Some(sidecar) = link_owner_sidecar_path(&host) {
            let _ = std::fs::remove_file(&sidecar);
        }
        std::fs::remove_file(&host).map_err(map_io_error)
    }

    fn rmdir(&self, path: &str) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        // See `unlink`: removing the mount point is a no-op success (the `-v`
        // host source dir and the mount both survive, so the mount point stays a
        // present, enumerable empty directory — matching what kaniko sees for
        // /workspace under Docker).
        if self.is_mount_point(path) {
            return Ok(());
        }
        let host = self.to_host(path)?;
        std::fs::remove_dir(&host).map_err(map_io_error)
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        // Renaming the mount point itself (either direction) would move/replace
        // the host source path — same hazard as unlink/rmdir. Linux returns
        // EBUSY when a rename source or target is a mount point.
        if self.is_mount_point(from) || self.is_mount_point(to) {
            return Err(LINUX_EBUSY);
        }
        let host_from = self.to_host(from)?;
        let host_to = self.to_host(to)?;
        std::fs::rename(&host_from, &host_to).map_err(map_io_error)?;
        // Carry a symlink's owner sidecar across the rename (keyed by name, so it
        // must move with the link). Best-effort: only `lchown`ed symlinks have
        // one; a stale sidecar at the destination name is overwritten/removed.
        // macOS keeps the owner in the symlink's own xattr (no sidecar).
        #[cfg(not(target_os = "macos"))]
        if let (Some(src), Some(dst)) = (
            link_owner_sidecar_path(&host_from),
            link_owner_sidecar_path(&host_to),
        ) {
            if src.exists() {
                let _ = std::fs::rename(&src, &dst);
            } else {
                let _ = std::fs::remove_file(&dst);
            }
        }
        Ok(())
    }

    fn symlink(&self, target: &str, link: &str) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let host_link = self.to_host(link)?;
        std::os::unix::fs::symlink(target, &host_link).map_err(map_io_error)
    }

    fn link(&self, from: &str, to: &str) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let host_from = self.to_host(from)?;
        let host_to = self.to_host(to)?;
        std::fs::hard_link(&host_from, &host_to).map_err(map_io_error)
    }

    fn chmod(&self, path: &str, mode: u32) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let host = self.to_host(path)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&host, std::fs::Permissions::from_mode(mode)).map_err(map_io_error)
    }

    fn create_socket(&self, path: &str, mode: u32) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let host = self.to_host(path)?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&host)
            .map_err(map_io_error)?;
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(mode & 0o7777))
            .map_err(map_io_error)?;
        write_u32_xattr(
            &host,
            crate::fs_backend::CARRICK_SOCKET_XATTR_NAME,
            1,
            false,
        )?;
        Ok(())
    }

    fn chown(
        &self,
        path: &str,
        uid: Option<u32>,
        gid: Option<u32>,
        nofollow: bool,
    ) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let host = self.to_host(path)?;
        let meta = if nofollow {
            std::fs::symlink_metadata(&host)
        } else {
            std::fs::metadata(&host)
        };
        let meta = match meta {
            Ok(m) => m,
            Err(err) => return Err(map_io_error(err)),
        };
        // A symlink's owner cannot be stored in an xattr on a non-macOS host:
        // Linux (and the BSDs) reject `user.*`/`trusted.*` xattrs on symlinks at
        // the VFS layer, on every filesystem. There an `lchown` of a symlink
        // persists the owner in an adjacent on-disk sidecar instead —
        // fork-coherent, read back by `owner_from_host_xattrs`'s NOFOLLOW
        // fallback. macOS allows `setxattr(..., XATTR_NOFOLLOW)` on a symlink, so
        // it keeps the xattr path unchanged (no behavior change on the reference
        // lane). Regular files/dirs always use the xattr path.
        #[cfg(not(target_os = "macos"))]
        if nofollow && meta.file_type().is_symlink() {
            return write_symlink_owner_sidecar(&host, uid, gid);
        }
        let _ = &meta;
        write_owner_xattrs(&host, uid, gid, nofollow)
    }

    fn set_times(
        &self,
        path: &str,
        atime: Option<(i64, i64)>,
        mtime: Option<(i64, i64)>,
        nofollow: bool,
    ) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let host = self.to_host(path)?;
        let cpath = CString::new(host.as_os_str().as_bytes()).map_err(|_| LINUX_EINVAL)?;
        let to_ts = |time: Option<(i64, i64)>| match time {
            Some((sec, nsec)) => libc::timespec {
                tv_sec: sec as libc::time_t,
                tv_nsec: nsec as libc::c_long,
            },
            None => libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
        };
        let times = [to_ts(atime), to_ts(mtime)];
        let flags = if nofollow {
            libc::AT_SYMLINK_NOFOLLOW
        } else {
            0
        };
        let rc = unsafe { libc::utimensat(-100, cpath.as_ptr(), times.as_ptr(), flags) };
        if rc < 0 {
            return Err(host_open_errno());
        }
        Ok(())
    }

    fn truncate(&mut self, path: &str, len: u64) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let host = self.to_host(path)?;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&host)
            .map_err(map_io_error)?;
        file.set_len(len).map_err(map_io_error)
    }

    fn name(&self) -> &'static str {
        "bind"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_abi::LINUX_EBUSY;

    /// A read-write bind mount must let the guest delete the mount's CONTENTS
    /// but must NOT delete the mount POINT itself — that maps to the caller's
    /// real `-v` host source directory. Removing the mount point is a no-op
    /// success (the source dir survives and the now-empty mount point stays
    /// enumerable); a rename of the mount point is EBUSY like Linux.
    ///
    /// This is the invariant behind the multi-stage `carrick build` whiteout
    /// bug: kaniko's between-stage "Deleting filesystem" rmdir'd `/workspace`,
    /// which used to delete the host context dir; the dangling mount then made
    /// kaniko's next full-FS snapshot walk abort at `/workspace` (ENOENT) and
    /// emit a spurious `.wh.lib`.
    #[test]
    fn mount_point_cannot_be_removed_but_contents_can() {
        let src = std::env::temp_dir().join(format!("carrick-bind-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&src);
        std::fs::create_dir_all(&src).expect("create src");
        std::fs::write(src.join("Dockerfile"), b"FROM scratch\n").expect("write child");

        let vfs = BindVfs::new("/workspace", src.clone(), false);

        // The child is an ordinary entry: it can be deleted, and that hits the
        // real host file.
        assert!(src.join("Dockerfile").exists());
        vfs.unlink("/workspace/Dockerfile")
            .expect("unlink child ok");
        assert!(
            !src.join("Dockerfile").exists(),
            "child unlink should remove the host file"
        );

        // The mount point itself: unlink AND rmdir succeed as a no-op (so
        // kaniko's os.RemoveAll(/workspace) doesn't fail the build), and the
        // host source directory must still exist afterwards. Every spelling of
        // the mount point, including a trailing slash.
        for p in ["/workspace", "/workspace/"] {
            assert_eq!(vfs.unlink(p), Ok(()), "unlink({p}) must be no-op success");
            assert_eq!(vfs.rmdir(p), Ok(()), "rmdir({p}) must be no-op success");
        }
        // Renaming the mount point (as source or target) is refused (Linux EBUSY).
        assert_eq!(vfs.rename("/workspace", "/elsewhere"), Err(LINUX_EBUSY));

        assert!(
            src.is_dir(),
            "host source dir must survive guest deletion of the mount point"
        );

        let _ = std::fs::remove_dir_all(&src);
    }

    /// A read-only bind reports EROFS before the mount-point guard even runs —
    /// the guard must not change the read-only contract.
    #[test]
    fn readonly_bind_still_erofs() {
        let src = std::env::temp_dir().join(format!("carrick-bind-ro-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&src);
        std::fs::create_dir_all(&src).expect("create src");
        let vfs = BindVfs::new("/workspace", src.clone(), true);
        assert_eq!(vfs.rmdir("/workspace"), Err(LINUX_EROFS));
        assert_eq!(vfs.unlink("/workspace/x"), Err(LINUX_EROFS));
        let _ = std::fs::remove_dir_all(&src);
    }
}
