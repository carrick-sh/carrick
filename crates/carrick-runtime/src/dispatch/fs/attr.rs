//! File ownership, permissions, and timestamp syscall handlers and helpers:
//! `fchmod`, `fchmodat`, `fchmodat2`, `fchown`, `fchownat`, `utimensat`.
//! Split out of `dispatch/fs.rs` (WS-F3) as `impl SyscallDispatcher` methods.
use super::*;
use crate::linux_abi::{
    LINUX_AT_EMPTY_PATH, LINUX_AT_FDCWD, LINUX_AT_SYMLINK_NOFOLLOW, LINUX_EBADF, LINUX_EFAULT,
    LINUX_EINVAL, LINUX_ENOENT, LINUX_EOPNOTSUPP, LINUX_EPERM, LINUX_EROFS, LinuxErrno,
    LinuxTimespec,
};
use std::path::Path;
use std::sync::Arc;

impl<'a> FsView<'a> {
    /// Linux clears a regular file's set-user-ID (and set-group-ID, when the
    /// file is group-executable) bits on chown — a security measure so a
    /// chowned setuid binary can't grant the new owner's privileges. setgid
    /// without group-exec is a mandatory-locking marker and is left alone.
    fn clear_setid_on_chown(&self, path: &str) {
        let Some(real) = self.fs.rootfs_vfs.overlay.real_stat(path, false) else {
            return;
        };
        if !matches!(real.kind, RootFsEntryKind::File) {
            return;
        }
        let mut mode = real.mode;
        let mut changed = false;
        if mode & 0o4000 != 0 {
            mode &= !0o4000;
            changed = true;
        }
        if mode & 0o2000 != 0 && mode & 0o0010 != 0 {
            mode &= !0o2000;
            changed = true;
        }
        if changed {
            let _ = self.fs.rootfs_vfs.set_mode(path, mode);
        }
    }

    /// Apply atime/mtime to an *open fd* — the `futimens(fd, …)` path.
    /// For a host-backed file we drive `futimens(2)` on the live host fd so a
    /// subsequent fstat/statx (which both read live on-disk times) observes
    /// the set value. For an in-memory `File`, we route through the overlay by
    /// path. `None` entries are UTIME_OMIT (left untouched).
    fn set_fd_times(
        &self,
        fd: i32,
        atime: Option<(i64, i64)>,
        mtime: Option<(i64, i64)>,
    ) -> DispatchOutcome {
        let Some(open_file) = self.open_file(fd) else {
            return DispatchOutcome::errno(LINUX_EBADF);
        };
        let Some(open) = open_file.description.read() else {
            return DispatchOutcome::errno(LINUX_EBADF);
        };
        match &*open {
            OpenDescription::HostFile {
                host_fd, metadata, ..
            } => {
                let to_ts = |t: Option<(i64, i64)>| match t {
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
                let rc = unsafe { libc::futimens(host_fd.raw(), times.as_ptr()) };
                if rc < 0 {
                    // Best-effort: don't abort the caller on a failed
                    // timestamp set (see the path-branch rationale).
                    let e = std::io::Error::last_os_error();
                    crate::probes::fs_op(
                        "set_fd_times:futimens_err_besteffort",
                        &format!("fd={fd} {e}"),
                        e.raw_os_error().unwrap_or(0),
                    );
                } else {
                    let p = metadata.path.to_string_lossy();
                    if !p.is_empty() && !p.starts_with("/__carrick_") {
                        self.fs.rootfs_vfs.notify_inode_changed(&p, None);
                    }
                    self.invalidate_dentry_host_fd(host_fd.raw());
                }
                DispatchOutcome::Returned { value: 0 }
            }
            OpenDescription::File { metadata, .. }
            | OpenDescription::Directory { metadata, .. } => {
                let path = metadata.path.to_string_lossy().into_owned();
                drop(open);
                if let Some(m) = self.fs.vfs_mounts.resolve(&path) {
                    return match m.vfs.set_times(&m.full_path, atime, mtime, false) {
                        Ok(()) => {
                            self.fs.rootfs_vfs.notify_inode_changed(&path, None);
                            DispatchOutcome::Returned { value: 0 }
                        }
                        Err(errno) => DispatchOutcome::errno(errno),
                    };
                }
                // fd-based futimens: the descriptor already refers to the
                // resolved inode, so never re-follow (nofollow = false).
                match self.fs.rootfs_vfs.set_times(&path, atime, mtime, false) {
                    Ok(()) | Err(crate::fs_backend::BackendError::Unsupported) => {
                        DispatchOutcome::Returned { value: 0 }
                    }
                    Err(_) => DispatchOutcome::errno(LINUX_EROFS),
                }
            }
            // Directories, synthetic /proc files, pipes, sockets, anon_inode
            // fds: accept as a no-op (matches Linux's permissive behaviour for
            // the cases tooling actually exercises; we can't persist times for
            // the non-file kinds).
            _ => DispatchOutcome::Returned { value: 0 },
        }
    }

    /// the two callers, so it stays in the syscall wrappers.
    fn chmod_at(
        &self,
        context: &crate::kernel::KernelContext,
        dirfd: u64,
        pathname: u64,
        mode: u64,
        memory: &impl CurrentMmMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let path = read_guest_c_string(memory, pathname)?;
        if path.is_empty() {
            return Ok(DispatchOutcome::errno(LINUX_ENOENT));
        }
        let resolved = self.resolve_at_path(dirfd, &path)?;
        // chmod(2) FOLLOWS a final symlink — it changes the TARGET's mode, not
        // the link's (test_posix.test_chmod_dir_symlink). resolve_at_path stops
        // at the link itself, so dereference it here. (fchmodat2's advisory
        // AT_SYMLINK_NOFOLLOW stays unmodeled on the disk-authoritative backend;
        // a dangling/failed follow falls back to the link path unchanged.)
        let resolved = self.canonicalize_following(&resolved).unwrap_or(resolved);
        if self.is_synthetic_virtual_path(context, &resolved) {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        if let Err(errno) = self.layered_metadata(&resolved) {
            return Ok(DispatchOutcome::errno(errno));
        }
        if let Some(errno) = self.chmod_permission_errno(&resolved) {
            return Ok(DispatchOutcome::errno(errno));
        }
        let mode = self.maybe_clear_setgid(&resolved, (mode & 0o7777) as u32);
        if let Some(m) = self.fs.vfs_mounts.resolve(&resolved) {
            return match m.vfs.chmod(&m.full_path, mode) {
                Ok(()) => {
                    self.inotify_attrib(&resolved);
                    self.dnotify_attrib(context, &resolved);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            };
        }
        match self.fs.rootfs_vfs.set_mode(&resolved, mode) {
            Ok(()) | Err(crate::fs_backend::BackendError::Unsupported) => {
                self.inotify_attrib(&resolved);
                self.dnotify_attrib(context, &resolved);
                Ok(DispatchOutcome::Returned { value: 0 })
            }
            Err(_) => Ok(DispatchOutcome::Returned { value: 0 }),
        }
    }

    /// Linux clears the setgid bit (S_ISGID) on a chmod by an UNPRIVILEGED
    /// process whose effective gid doesn't match the file's group — so a
    /// non-owner-group user can't make a file setgid to a group it isn't in
    /// (chmod05/fchmod05). Root (euid==0) keeps the bit. carrick tracks only the
    /// effective gid (not supplementary groups), which is what the LTP tests
    /// exercise. Returns the mode to actually apply.
    fn maybe_clear_setgid(&self, path: &str, mode: u32) -> u32 {
        const S_ISGID: u32 = 0o2000;
        if mode & S_ISGID == 0 {
            return mode;
        }
        let creds = self.cred_snapshot();
        if creds.euid.is_root() {
            return mode;
        }
        let file_gid = self
            .fs
            .rootfs_vfs
            .overlay
            .get_owner(path)
            .map(|(_, g)| g)
            .unwrap_or(carrick_abi::NsGid::ROOT);
        if file_gid != creds.egid {
            return mode & !S_ISGID;
        }
        mode
    }

    fn chown_uid_arg(arg: u64) -> Option<carrick_abi::NsUid> {
        let value = arg as u32;
        (value != u32::MAX).then_some(carrick_abi::NsUid::new(value))
    }

    fn chown_gid_arg(arg: u64) -> Option<carrick_abi::NsGid> {
        let value = arg as u32;
        (value != u32::MAX).then_some(carrick_abi::NsGid::new(value))
    }

    /// Stamp the owner (and, when inherited, the setgid bit) on a freshly
    /// created special node (mknod FIFO/device/socket), mirroring mkdirat's
    /// rule: a new inode's group is the creator's egid, UNLESS the parent
    /// directory is setgid (S_ISGID), in which case it inherits the parent's
    /// group but preserves its requested mode. Unlike a newly created directory,
    /// a non-directory node does not acquire S_ISGID from its parent. Without
    /// this the host assigns its own gid and a later stat reports the wrong
    /// st_gid (LTP mknod08 expects st_gid == the process egid because the parent
    /// isn't setgid).
    /// Record the creating process as the owner of a just-created node, with
    /// Linux's setgid-parent gid inheritance. Called by every path that
    /// materialises a new node — `openat(O_CREAT)`, `mknod`, and `bind(2)` on an
    /// AF_UNIX socket (`dispatch::net`), which is why this is `pub(super)`.
    pub(crate) fn stamp_new_node_owner(&self, path: &str, node_mode: u32) {
        const S_ISGID: u32 = 0o2000;
        let creds = self.cred_snapshot();
        let mut owner_gid = creds.egid;
        let mut inherited_gid = false;
        if let Some(parent) = Path::new(path).parent() {
            let parent_str = display_rootfs_path(parent);
            if let Ok(pmd) = self.layered_metadata(&parent_str)
                && pmd.mode & S_ISGID != 0
                && let Some((_, pgid)) = self.fs.rootfs_vfs.overlay.get_owner(&parent_str)
            {
                owner_gid = pgid;
                inherited_gid = true;
                let _ = self.fs.rootfs_vfs.set_mode(path, node_mode);
            }
        }
        if !creds.euid.is_root() || !owner_gid.is_root() || inherited_gid {
            let _ = self
                .fs
                .rootfs_vfs
                .set_owner(path, Some(creds.euid), Some(owner_gid));
        }
    }

    fn chown_permission_errno(
        &self,
        uid: Option<carrick_abi::NsUid>,
        gid: Option<carrick_abi::NsGid>,
    ) -> Option<LinuxErrno> {
        let creds = self.cred_snapshot();
        if creds.euid.is_root() {
            return None;
        }
        if uid.is_some() {
            return Some(LINUX_EPERM);
        }
        if gid.is_some_and(|gid| gid != creds.egid) {
            return Some(LINUX_EPERM);
        }
        None
    }

    /// chmod(2)/fchmod(2) permission: only the file owner or a process with
    /// CAP_FOWNER (modeled as euid==0) may change a file's mode; everyone else
    /// gets EPERM (Linux fs/attr.c chmod_common -> inode_owner_or_capable). When
    /// the backend can't supply an owner (the in-memory backend has no real
    /// owner/mode), we don't enforce — matching the legacy root model used
    /// elsewhere on that backend (and mirroring `maybe_clear_setgid`'s lookup).
    fn chmod_permission_errno(&self, path: &str) -> Option<LinuxErrno> {
        let creds = self.cred_snapshot();
        if creds.euid.is_root() {
            return None;
        }
        match self.fs.rootfs_vfs.overlay.get_owner(path) {
            Some((owner_uid, _)) if owner_uid != creds.euid => Some(LINUX_EPERM),
            _ => None,
        }
    }

    /// Apply chown to the file backing an fd, recording the guest-visible owner
    /// on the backend (durable via xattr on `--fs host`). Shared by `fchown` and
    /// `fchownat(..., AT_EMPTY_PATH)` so both record the owner identically.
    /// `fd` must already be validated by the caller.
    fn fchown_by_fd(
        &self,
        context: &crate::kernel::KernelContext,
        fd: i32,
        uid: Option<carrick_abi::NsUid>,
        gid: Option<carrick_abi::NsGid>,
    ) -> DispatchOutcome {
        let (path, raw_host_fd) = self
            .open_file(fd)
            .and_then(|of| match of.description.read().as_deref() {
                Some(OpenDescription::HostFile {
                    metadata, host_fd, ..
                }) => Some((
                    Some(metadata.path.to_string_lossy().into_owned()),
                    Some(host_fd.raw()),
                )),
                Some(
                    OpenDescription::File { metadata, .. }
                    | OpenDescription::Directory { metadata, .. },
                ) => Some((Some(metadata.path.to_string_lossy().into_owned()), None)),
                _ => None,
            })
            .unwrap_or((None, None));
        if let Some(path) = path {
            if let Some(errno) = self.chown_permission_errno(uid, gid) {
                return DispatchOutcome::errno(errno);
            }
            if let Some(m) = self.fs.vfs_mounts.resolve(&path) {
                if let Err(errno) = m.vfs.chown(&m.full_path, uid, gid, false) {
                    return DispatchOutcome::errno(errno);
                }
            } else {
                let _ = self.fs.rootfs_vfs.set_owner(&path, uid, gid);
            }
            self.clear_setid_on_chown(&path);
            self.dnotify_attrib(context, &path);
        }
        if let Some(raw_fd) = raw_host_fd {
            self.fs.rootfs_vfs.fset_owner(raw_fd, uid, gid);
        }
        DispatchOutcome::Returned { value: 0 }
    }

    define_syscall! {
        fn fchmod(this, cx, fd: Fd, mode: u64) {
            let fd: Fd = fd;
            if !this.fd_is_valid(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // An O_PATH descriptor is not open for I/O (open13 → EBADF).
            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            let mode = (mode & 0o7777) as u32;
            // Resolve the fd to its path and route through the backend's set_mode,
            // so the guest-visible mode lands in the carrick mode xattr (what
            // fstat reports) — not just the real fd's mode, which could be the
            // forced-owner-accessible value. Previously this called libc::fchmod
            // directly, so fstat kept reporting the stale creation-time mode.
            let path = this
                .open_file(fd.0)
                .and_then(|of| match of.description.read().as_deref() {
                    Some(
                        OpenDescription::HostFile { metadata, .. }
                        | OpenDescription::File { metadata, .. }
                        | OpenDescription::Directory { metadata, .. },
                    ) => Some(metadata.path.to_string_lossy().into_owned()),
                    _ => None,
                });
            if let Some(path) = path {
                if let Some(errno) = this.chmod_permission_errno(&path) {
                    return Ok(DispatchOutcome::errno(errno));
                }
                let mode = this.maybe_clear_setgid(&path, mode);
                if let Some(m) = this.fs.vfs_mounts.resolve(&path) {
                    if let Err(errno) = m.vfs.chmod(&m.full_path, mode) {
                        return Ok(DispatchOutcome::errno(errno));
                    }
                } else {
                    let _ = this.fs.rootfs_vfs.set_mode(&path, mode);
                }
                // Refresh THIS fd's cached metadata so a subsequent fstat on it
                // sees the new mode. A Directory/File fstat reads the cached
                // metadata (only HostFile re-reads the live xattr), so without
                // this an fchmod(dirfd)+fstat(dirfd) reported the stale
                // open-time mode (LTP fchmod04/05). metadata.mode holds the
                // permission bits; the type comes from `kind`.
                if let Some(of) = this.open_file(fd.0) {
                    if let Some(mut open) = of.description.write() {
                        match &mut *open {
                            OpenDescription::Directory { metadata, .. }
                            | OpenDescription::File { metadata, .. } => {
                                metadata.mode = mode;
                            }
                            OpenDescription::HostFile { host_fd, metadata, .. } => {
                                metadata.mode = mode;
                                this.fs.rootfs_vfs.fset_mode(host_fd.raw(), mode);
                            }
                            _ => {}
                        }
                    }
                }
                // inotify IN_ATTRIB (chmod is a metadata change).
                this.inotify_attrib(&path);
                this.dnotify_attrib_for_tid(cx.kernel, &path, Some(cx.tid()));
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn fchown(this, cx, fd: Fd, owner: u64, group: u64) {
            let fd: Fd = fd;
            if !this.fd_is_valid(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // An O_PATH descriptor is not open for I/O (open13 → EBADF).
            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            let uid = Self::chown_uid_arg(owner);
            let gid = Self::chown_gid_arg(group);
            Ok(this.fchown_by_fd(cx.kernel, fd.0, uid, gid))
        }

        fn fchownat(this, cx, dirfd: u64, pathname: GuestPtr, owner: u64, group: u64, flags: u64) {
            let pathname = pathname.0;
            let Some(at_flags) = carrick_abi::LinuxAtFlags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            if at_flags.bits() & !(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH) != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let path = read_guest_c_string(&*cx.memory, pathname)?;
            if path.is_empty() {
                if !at_flags.contains(carrick_abi::LinuxAtFlags::EMPTY_PATH) {
                    return Ok(DispatchOutcome::errno(LINUX_ENOENT));
                }
                if dirfd == LINUX_AT_FDCWD {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                if !this.fd_is_valid(dirfd as i32) {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                // AT_EMPTY_PATH operates on the fd ITSELF — record the owner like
                // fchown (was a silent no-op success that never set_owner'd).
                let uid = Self::chown_uid_arg(owner);
                let gid = Self::chown_gid_arg(group);
                return Ok(this.fchown_by_fd(cx.kernel, dirfd as i32, uid, gid));
            }
            let uid = Self::chown_uid_arg(owner);
            let gid = Self::chown_gid_arg(group);
            let resolved = this.resolve_at_path(dirfd, &path)?;
            let nofollow = at_flags.contains(carrick_abi::LinuxAtFlags::SYMLINK_NOFOLLOW);
            if this.fs.vfs_mounts.resolve(&resolved).is_some() {
                let lookup = {
                    if let Some(m) = this.fs.vfs_mounts.resolve(&resolved) {
                        if nofollow {
                            m.vfs.lookup_nofollow(&m.full_path)
                        } else {
                            m.vfs.lookup(&m.full_path)
                        }
                    } else {
                        Err(LINUX_ENOENT)
                    }
                };
                if let Err(errno) = lookup {
                    return Ok(DispatchOutcome::errno(errno));
                }
                if let Some(errno) = this.chown_permission_errno(uid, gid) {
                    return Ok(DispatchOutcome::errno(errno));
                }
                let result = {
                    if let Some(m) = this.fs.vfs_mounts.resolve(&resolved) {
                        m.vfs.chown(&m.full_path, uid, gid, nofollow)
                    } else {
                        Err(LINUX_ENOENT)
                    }
                };
                return match result {
                    Ok(()) => {
                        this.clear_setid_on_chown(&resolved);
                        Ok(DispatchOutcome::Returned { value: 0 })
                    }
                    Err(errno) => Ok(DispatchOutcome::errno(errno)),
                };
            }
            // Layered presence check: overlay first (tombstones become ENOENT),
            // synthetic /proc and /sys are no-op success, rootfs is no-op
            // success (tmpfs semantics). Record the guest-visible owner on the
            // backend (durably, via xattr on --fs host) so a later stat reports it.
            let lookup = if nofollow {
                this.layered_lstat(&resolved).map(|_| ())
            } else {
                this.layered_metadata(&resolved).map(|_| ())
            };
            match lookup {
                Ok(_) => {
                    if let Some(errno) = this.chown_permission_errno(uid, gid) {
                        return Ok(DispatchOutcome::errno(errno));
                    }
                    let target_path = if nofollow {
                        resolved.clone()
                    } else {
                        this.canonicalize_following(&resolved)
                            .unwrap_or_else(|_| resolved.clone())
                    };
                    let _ = this.fs.rootfs_vfs.set_owner(
                        &target_path,
                        uid,
                        gid,
                    );
                    this.clear_setid_on_chown(&target_path);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(errno) => {
                    if this.is_synthetic_virtual_path(cx.kernel, &resolved)
                    {
                        Ok(DispatchOutcome::Returned { value: 0 })
                    } else {
                        Ok(DispatchOutcome::errno(errno))
                    }
                }
            }
        }

        fn fchmodat(this, cx, dirfd: u64, pathname: GuestPtr, mode: u64, flags: u64) {
            // The fchmodat syscall (nr 53) is SYSCALL_DEFINE3 in Linux: it takes
            // only (dirfd, path, mode) and IGNORES the 4th register. glibc's
            // AT_SYMLINK_NOFOLLOW path still leaves the flag in that register —
            // `apt-get update` issues fchmodat(AT_FDCWD, path, 0644, 0x100) on
            // every downloaded index — and the real kernel silently ignores it.
            // Rejecting non-zero flags here made every apt download chmod fail
            // ("chmod 0644 of file … failed - 201::URIDone"). Only fchmodat2 (452)
            // validates the flags.
            let _ = flags;
            this.chmod_at(cx.kernel, dirfd, pathname.0, mode, &*cx.memory)
        }

        fn fchmodat2(this, cx, dirfd: u64, pathname: GuestPtr, mode: u64, flags: u64) {
            // fchmodat2 (nr 452) carries a REAL flags argument: only
            // AT_SYMLINK_NOFOLLOW is valid (fchmodat2_02 passes -1 → EINVAL).
            if flags & !LINUX_AT_SYMLINK_NOFOLLOW != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if flags & LINUX_AT_SYMLINK_NOFOLLOW != 0 {
                // Linux cannot change a SYMLINK's mode — no filesystem it ships
                // implements it — so `fchmodat2(..., AT_SYMLINK_NOFOLLOW)` on a
                // symlink is EOPNOTSUPP. On anything else the flag is a no-op,
                // because there is no link to avoid following. Treating the flag
                // as purely advisory instead silently chmod'd the link's TARGET,
                // which is the one thing the caller asked not to happen (Go's
                // `TestFchmodat`, measured against the Docker oracle:
                // `fchmodat2(symlink, AT_SYMLINK_NOFOLLOW)` = -1/EOPNOTSUPP there
                // and 0 here).
                let path = read_guest_c_string(&*cx.memory, pathname.0)?;
                if !path.is_empty() {
                    let resolved = this.resolve_at_path(dirfd, &path)?;
                    if this
                        .layered_lstat(&resolved)
                        .is_ok_and(|md| md.kind == RootFsEntryKind::Symlink)
                    {
                        return Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP));
                    }
                }
            }
            this.chmod_at(cx.kernel, dirfd, pathname.0, mode, &*cx.memory)
        }

        fn utimensat(this, cx, dirfd: u64, pathname: GuestPtr, times: GuestPtr, flags: u64) {
            let pathname = pathname.0;
            let times = times.0;
            let memory = &*cx.memory;
            if flags & !LINUX_AT_SYMLINK_NOFOLLOW != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // `times == NULL` means "set both to now"; otherwise read the two
            // timespecs and resolve UTIME_NOW/UTIME_OMIT into concrete
            // (sec, nsec) pairs or `None` (omit) for the backend.
            #[allow(clippy::type_complexity)]
            let (atime_set, mtime_set): (Option<(i64, i64)>, Option<(i64, i64)>);
            let clock = Arc::clone(cx.kernel.task().container().clock());
            if times != 0 {
                let atime = read_timespec(memory, times)?;
                let mtime_address = times
                    .checked_add(core::mem::size_of::<LinuxTimespec>() as u64)
                    .ok_or(DispatchError::LengthTooLarge(times))?;
                let mtime = read_timespec(memory, mtime_address)?;
                if !linux_utimensat_timespec_is_valid(atime)
                    || !linux_utimensat_timespec_is_valid(mtime)
                {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                atime_set = resolve_utimensat_timespec(&clock, atime);
                mtime_set = resolve_utimensat_timespec(&clock, mtime);
            } else {
                // NULL → set both to the current wall-clock time.
                let now = now_realtime_timespec(&clock);
                atime_set = Some(now);
                mtime_set = Some(now);
            }

            if pathname == 0 {
                // `futimens(fd, times)` lowers to `utimensat(fd, NULL, times, 0)`
                // in musl/glibc: set the times of the *open fd itself*. (This is
                // distinct from the AT_EMPTY_PATH form, which carries an empty —
                // not NULL — path.)
                if dirfd == LINUX_AT_FDCWD {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                if atime_set.is_none() && mtime_set.is_none() {
                    // Both UTIME_OMIT: nothing to persist; just validate the fd.
                    if !this.fd_is_valid(dirfd as i32) {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                return Ok(this.set_fd_times(dirfd as i32, atime_set, mtime_set));
            }

            let path = read_guest_c_string(memory, pathname)?;
            if path.is_empty() {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            let path = match this.resolve_at_path(dirfd, &path) {
                Ok(path) => path,
                Err(errno) => {
                    crate::probes::fs_op("utimensat:resolve_err", &path, errno.get());
                    return Ok(DispatchOutcome::errno(errno));
                }
            };
            // Without AT_SYMLINK_NOFOLLOW, utime()/utimensat FOLLOWS a trailing
            // symlink to its target and updates THAT file's times: a dangling
            // target is ENOENT and a symlink cycle is ELOOP (utime07). Only when
            // the final component is genuinely a symlink — plain paths and
            // synthetic /proc entries are left untouched for the checks below,
            // and resolve_at_path already leaves the final component unfollowed.
            let path = if flags & LINUX_AT_SYMLINK_NOFOLLOW == 0
                && matches!(
                    this.layered_lstat(&path),
                    Ok(md) if md.kind == RootFsEntryKind::Symlink
                ) {
                match this.canonicalize_following(&path) {
                    Ok(resolved) => resolved,
                    Err(errno) => {
                        crate::probes::fs_op("utimensat:follow_err", &path, errno.get());
                        return Ok(DispatchOutcome::errno(errno));
                    }
                }
            } else {
                path
            };
            let exists = if flags & LINUX_AT_SYMLINK_NOFOLLOW != 0 {
                this.layered_lstat(&path).map(|_| ())
            } else {
                this.layered_metadata(&path).map(|_| ())
            };
            match exists {
                Ok(_) => {}
                Err(errno) => {
                    if this.is_synthetic_virtual_path(cx.kernel, &path) {
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    crate::probes::fs_op("utimensat:meta_err", &path, errno.get());
                    return Ok(DispatchOutcome::errno(errno));
                }
            }
            if atime_set.is_none() && mtime_set.is_none() {
                // Both UTIME_OMIT: nothing to persist.
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if let Some(m) = this.fs.vfs_mounts.resolve(&path) {
                return match m.vfs.set_times(
                    &m.full_path,
                    atime_set,
                    mtime_set,
                    flags & LINUX_AT_SYMLINK_NOFOLLOW != 0,
                ) {
                    Ok(()) => {
                        this.fs.rootfs_vfs.notify_inode_changed(&path, None);
                        Ok(DispatchOutcome::Returned { value: 0 })
                    }
                    Err(errno) => Ok(DispatchOutcome::errno(errno)),
                };
            }
            // Persist atime/mtime to the materialised host file (disk-backed
            // overlay). A subsequent stat reads real disk metadata via
            // real_stat and will report the set mtime. MemoryBackend returns
            // Unsupported; accept as a no-op so in-memory guests don't fail.
            match this
                .fs
                .rootfs_vfs
                .set_times(
                    &path,
                    atime_set,
                    mtime_set,
                    flags & LINUX_AT_SYMLINK_NOFOLLOW != 0,
                )
            {
                Ok(()) => {
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(crate::fs_backend::BackendError::Unsupported) => {
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                // Best-effort timestamps: a successful set above persists real
                // mtime (apt's pkgcache x-ref relies on that), but a FAILURE to
                // set times must NOT abort the caller. Linux tools like dpkg treat
                // utimensat failure on a file they just wrote as fatal ("error
                // setting timestamps … Read-only file system"); returning EROFS
                // there breaks `dpkg --unpack` of any package with shared libs.
                // The file content is already correct; timestamps are cosmetic.
                Err(e) => {
                    crate::probes::fs_op("utimensat:set_times_err_besteffort", &path, 0);
                    let _ = e;
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
            }
        }
    }
}
