//! Access-control (DAC) helpers for the fs syscall handlers: `access`/
//! `faccessat` resolution and the real owner+mode permission checks used on
//! `--fs host`. Split out of `dispatch/fs.rs` (WS-F3) as `impl SyscallDispatcher`
//! methods — method resolution is type-based, so the intra-dispatcher `self.…`
//! calls are unaffected by living in a separate file.
use super::*;

impl SyscallDispatcher {
    pub(super) fn access_at(
        &self,
        dirfd: u64,
        pathname: u64,
        mode: u64,
        flags: u64,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        if mode & !(LINUX_R_OK | LINUX_W_OK | LINUX_X_OK) != 0
            || !linux_access_flags_are_supported(flags)
        {
            return Ok(LINUX_EINVAL.into());
        }

        let path = read_guest_c_string(memory, pathname)?;
        if path.is_empty() {
            if flags & LINUX_AT_EMPTY_PATH == 0 {
                return Ok(LINUX_ENOENT.into());
            }
            if dirfd == LINUX_AT_FDCWD {
                let cwd = self.io.cwd.read().clone();
                return Ok(self.access_resolved_path(&cwd, mode, flags));
            }
            return Ok(self.fd_access(dirfd as i32, mode));
        }

        if let Some(outcome) = self.fast_root_f_ok_absolute(dirfd, &path, mode, flags) {
            return Ok(outcome);
        }

        let path = self.resolve_at_path(dirfd, &path)?;
        Ok(self.access_resolved_path(&path, mode, flags))
    }

    fn fast_root_f_ok_absolute(
        &self,
        dirfd: u64,
        path: &str,
        mode: u64,
        flags: u64,
    ) -> Option<DispatchOutcome> {
        if dirfd != LINUX_AT_FDCWD || mode != 0 || flags != 0 {
            return None;
        }
        if !path.starts_with('/')
            || path.starts_with("/proc")
            || path.starts_with("/sys")
            || path.split('/').any(|component| component == "..")
            || self.fs.vfs_mounts.resolve(path).is_some()
        {
            return None;
        }
        if self.cred_snapshot().ruid != 0 {
            return None;
        }
        self.fs
            .rootfs_vfs
            .overlay
            .stat_cache_lookup(path)
            .map(|_| DispatchOutcome::Returned { value: 0 })
    }

    fn access_resolved_path(&self, path: &str, mode: u64, flags: u64) -> DispatchOutcome {
        // Synthetic /proc /sys paths bypass the rootfs/overlay
        // layered view: they have their own permission model.
        if let Some(outcome) = self.synthetic_access(path, mode) {
            return outcome;
        }
        // VFS mounts (e.g. /dev/shm BindVfs) own their lookup — consult them
        // first, otherwise an `access("/dev/shm", F_OK)` falls through to
        // rootfs_vfs which doesn't know about the mounted directory and
        // returns ENOENT. (LTP's tst_test uses this access call to choose
        // /dev/shm vs a tmpdir for its SHM file; ENOENT here makes the
        // tmpdir branch fire spuriously.)
        use crate::vfs::Vfs as _;
        if let Some(m) = self.fs.vfs_mounts.resolve(path) {
            return match m.vfs.lookup(&m.full_path) {
                Ok(md) => access_metadata(&vfs_md_to_rootfs_md(path, &md), mode),
                Err(errno) => DispatchOutcome::errno(errno),
            };
        }
        // Real DAC check when the backend exposes owner+mode (--fs host):
        // access(2) tests the REAL ids, faccessat(AT_EACCESS) the effective.
        if let Some(outcome) = self.dac_access(path, mode, flags & LINUX_AT_EACCESS != 0) {
            return outcome;
        }
        // Fallback (no real owner/mode, e.g. --fs memory): legacy root model.
        // AT_SYMLINK_NOFOLLOW doesn't change the access mask in our compat
        // layer, so we use the default lookup.
        match self.fs.rootfs_vfs.lookup(path) {
            Ok(md) => access_metadata(&vfs_md_to_rootfs_md(path, &md), mode),
            Err(errno) => DispatchOutcome::errno(errno),
        }
    }

    /// DAC check for `path` using the backend's real owner+mode (`--fs host`).
    /// Returns `None` when the backend can't supply owner/mode (so the caller
    /// falls back to the legacy root model). `use_effective` selects effective
    /// vs real caller ids.
    fn dac_access(&self, path: &str, mask: u64, use_effective: bool) -> Option<DispatchOutcome> {
        let real = self.fs.rootfs_vfs.overlay.real_stat(path, true)?;
        let creds = self.cred_snapshot();
        let (uid, gid) = if use_effective {
            (creds.euid, creds.egid)
        } else {
            (creds.ruid, creds.rgid)
        };
        // Pathname resolution requires search (execute) permission on EVERY
        // ancestor directory; a single non-searchable parent denies access to
        // anything beneath it regardless of the leaf's own mode.
        if let Some(errno) = self.dac_ancestors_searchable(path, uid, gid) {
            return Some(DispatchOutcome::errno(errno));
        }
        let is_dir = matches!(real.kind, RootFsEntryKind::Directory);
        Some(
            match crate::dispatch::dac_check(uid, gid, real.uid, real.gid, real.mode, is_dir, mask)
            {
                Ok(()) => DispatchOutcome::Returned { value: 0 },
                Err(errno) => DispatchOutcome::errno(errno),
            },
        )
    }

    /// DAC for `open(2)` on `--fs host`. `access` is the O_ACCMODE bits;
    /// `want_create` is set for O_CREAT. Returns `Some(errno)` to deny.
    /// Root bypasses (so we short-circuit when euid==0).
    pub(super) fn dac_open_check(&self, path: &str, access: u64, want_create: bool) -> Option<i32> {
        let creds = self.cred_snapshot();
        if creds.euid == 0 {
            return None;
        }
        let (uid, gid) = (creds.euid, creds.egid);
        match self.fs.rootfs_vfs.overlay.real_stat(path, true) {
            Some(real) => {
                // Existing file: ancestor search + the requested access.
                if let Some(e) = self.dac_ancestors_searchable(path, uid, gid) {
                    return Some(e);
                }
                let mut mask = 0u64;
                if access != LINUX_O_WRONLY {
                    mask |= LINUX_R_OK;
                }
                if access == LINUX_O_WRONLY || access == LINUX_O_RDWR {
                    mask |= LINUX_W_OK;
                }
                let is_dir = matches!(real.kind, RootFsEntryKind::Directory);
                crate::dispatch::dac_check(uid, gid, real.uid, real.gid, real.mode, is_dir, mask)
                    .err()
            }
            None if want_create => {
                // Creating: need search down to, and write on, the parent dir.
                let parent = std::path::Path::new(path)
                    .parent()
                    .map(|p| {
                        let s = p.to_string_lossy().into_owned();
                        if s.is_empty() { "/".to_string() } else { s }
                    })
                    .unwrap_or_else(|| "/".to_string());
                if let Some(e) = self.dac_ancestors_searchable(&parent, uid, gid) {
                    return Some(e);
                }
                self.fs
                    .rootfs_vfs
                    .overlay
                    .real_stat(&parent, true)
                    .and_then(|p| {
                        crate::dispatch::dac_check(
                            uid,
                            gid,
                            p.uid,
                            p.gid,
                            p.mode,
                            true,
                            LINUX_W_OK | LINUX_X_OK,
                        )
                        .err()
                    })
            }
            None => None,
        }
    }

    /// Verify the caller has search (X) permission on every ancestor directory
    /// of `path`. Returns `Some(EACCES)` on the first non-searchable parent.
    fn dac_ancestors_searchable(&self, path: &str, uid: u32, gid: u32) -> Option<i32> {
        let p = std::path::Path::new(path);
        // ancestors() yields the path itself first; skip it — we only gate the
        // parent directories.
        for anc in p.ancestors().skip(1) {
            let s = anc.to_string_lossy();
            if s.is_empty() || s == "/" {
                continue;
            }
            if let Some(real) = self.fs.rootfs_vfs.overlay.real_stat(&s, true)
                && matches!(real.kind, RootFsEntryKind::Directory)
                && crate::dispatch::dac_check(
                    uid, gid, real.uid, real.gid, real.mode, true, LINUX_X_OK,
                )
                .is_err()
            {
                return Some(LINUX_EACCES);
            }
        }
        None
    }

    fn fd_access(&self, fd: i32, mode: u64) -> DispatchOutcome {
        let Some(open_file) = self.open_file(fd) else {
            return DispatchOutcome::errno(LINUX_EBADF);
        };
        let open = open_file.description.read();
        match &*open {
            OpenDescription::File { metadata, .. }
            | OpenDescription::HostFile { metadata, .. }
            | OpenDescription::Directory { metadata, .. } => access_metadata(metadata, mode),
            OpenDescription::SyntheticFile { path, .. } => self
                .synthetic_access(path, mode)
                .unwrap_or(DispatchOutcome::errno(LINUX_ENOENT)),
            OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::Pidfd { .. }
            | OpenDescription::Inotify { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. }
            | OpenDescription::SignalFd { .. }
            | OpenDescription::Netlink { .. } => synthetic_readonly_access(mode),
        }
    }

    fn synthetic_access(&self, path: &str, mode: u64) -> Option<DispatchOutcome> {
        if !crate::vfs::is_synthetic_virtual_file(path, &self.synthetic_proc_context()) {
            return None;
        }
        Some(synthetic_readonly_access(mode))
    }
}
