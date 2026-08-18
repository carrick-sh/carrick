//! Access-control (DAC) helpers for the fs syscall handlers: `access`/
//! `faccessat` resolution and the real owner+mode permission checks used on
//! `--fs host`. Split out of `dispatch/fs.rs` (WS-F3) as `impl SyscallDispatcher`
//! methods — method resolution is type-based, so the intra-dispatcher `self.…`
//! calls are unaffected by living in a separate file.
use super::*;

impl SyscallDispatcher {
    pub(super) fn access_at(
        &self,
        context: &crate::kernel::KernelContext,
        dirfd: u64,
        pathname: u64,
        mode: u64,
        flags: u64,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        if LinuxAccessMode::from_bits(mode).is_none() || !linux_access_flags_are_supported(flags) {
            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
        }

        let path = read_guest_c_string(memory, pathname)?;
        if path.is_empty() {
            if flags & LINUX_AT_EMPTY_PATH == 0 {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            if dirfd == LINUX_AT_FDCWD {
                let cwd = self.captured_fs_context().cwd();
                return Ok(self.access_resolved_path(context, &cwd, mode, flags));
            }
            return Ok(self.fd_access(context, dirfd as i32, mode));
        }

        if let Some(outcome) = self.fast_root_f_ok_absolute(dirfd, &path, mode, flags) {
            return Ok(outcome);
        }

        if let Some(outcome) = self.fast_trusted_dirfd_f_ok(dirfd, &path, mode, flags) {
            return Ok(outcome);
        }

        let path = self.resolve_at_path(dirfd, &path)?;
        Ok(self.access_resolved_path(context, &path, mode, flags))
    }

    /// Trusted-dirfd sibling of [`Self::fast_root_f_ok_absolute`]: a root
    /// `faccessat(dirfd, name, F_OK)` through a TRUSTED host dirfd is ONE
    /// `fstatat(host_dirfd, name, AT_NOFOLLOW)`. A symlink child falls back —
    /// F_OK follows the link, and following must resolve under the GUEST
    /// root, not the host's. Missing is authoritative (the scratch is the
    /// merged truth and no mount claims the path).
    fn fast_trusted_dirfd_f_ok(
        &self,
        dirfd: u64,
        path: &str,
        mode: u64,
        flags: u64,
    ) -> Option<DispatchOutcome> {
        if mode != 0 || flags != 0 {
            return None;
        }
        let name = Self::trusted_lane_component(path)?;
        let (dir_path, host_dir) = self.trusted_dir_of(dirfd)?;
        if !host_dir.namespace_is_current() {
            return None;
        }
        self.trusted_child_path(&dir_path, name)?;
        // access(2) checks the REAL ids; mirror `fast_root_f_ok_absolute`.
        if !self.cred_snapshot().ruid.is_root() {
            return None;
        }
        let name_c = std::ffi::CString::new(name).ok()?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                host_dir.fd.raw(),
                name_c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Some(DispatchOutcome::errno(LINUX_ENOENT))
            } else {
                None
            };
        }
        if st.st_mode as u32 & libc::S_IFMT as u32 == libc::S_IFLNK as u32 {
            return None;
        }
        Some(DispatchOutcome::Returned { value: 0 })
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
        if !self.cred_snapshot().ruid.is_root() {
            return None;
        }
        self.fs
            .rootfs_vfs
            .overlay
            .stat_cache_lookup(path)
            .map(|_| DispatchOutcome::Returned { value: 0 })
    }

    fn access_resolved_path(
        &self,
        context: &crate::kernel::KernelContext,
        path: &str,
        mode: u64,
        flags: u64,
    ) -> DispatchOutcome {
        // Synthetic /proc /sys paths bypass the rootfs/overlay
        // layered view: they have their own permission model.
        if let Some(outcome) = self.synthetic_access(context, path, mode) {
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

    /// THE identity every file-permission check uses: `fsuid`/`fsgid`, not
    /// `euid`/`egid`.
    ///
    /// setfsuid(2): "All of the file-access permission checks that were
    /// previously performed with the effective UID are now performed with the
    /// fsuid." capabilities(7) adds the half that bites hardest — an fsuid
    /// transition 0 -> nonzero drops `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH`
    /// and `CAP_FOWNER` from the effective set, so the root bypass must key on
    /// fsuid too. Checking `euid.is_root()` let a process that had dropped only
    /// its fsuid keep full root file access (LTP setfsuid04).
    ///
    /// `fsuid`/`fsgid` track `euid`/`egid` through every `set*uid`/`set*gid`
    /// (see `dispatch::creds`), so this differs from the old behaviour ONLY
    /// after a deliberate `setfsuid`/`setfsgid` split — which is exactly the
    /// case that was wrong. Routing every check through one accessor is what
    /// stops the euid and fsuid families drifting apart again: the overlay-side
    /// checks in `fs.rs` already used fsuid while these used euid.
    pub(super) fn dac_identity(&self) -> (carrick_abi::NsUid, carrick_abi::NsGid) {
        let creds = self.cred_snapshot();
        (creds.fsuid, creds.fsgid)
    }

    /// True iff the caller keeps the DAC-override capabilities. See
    /// [`Self::dac_identity`] — this is fsuid, never euid.
    pub(super) fn dac_overrides_permissions(&self) -> bool {
        self.cred_snapshot().fsuid.is_root()
    }

    /// DAC check for `path` using the backend's real owner+mode (`--fs host`).
    /// Returns `None` when the backend can't supply owner/mode (so the caller
    /// falls back to the legacy root model). `use_effective` selects the
    /// filesystem identity (fsuid/fsgid) vs the REAL ids — access(2) is
    /// deliberately different from every other check here: it answers "could
    /// the real user do this", so it keeps ruid/rgid.
    fn dac_access(&self, path: &str, mask: u64, use_effective: bool) -> Option<DispatchOutcome> {
        let real = self.fs.rootfs_vfs.overlay.real_stat(path, true)?;
        let creds = self.cred_snapshot();
        let (uid, gid) = if use_effective {
            (creds.fsuid, creds.fsgid)
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
    pub(super) fn dac_open_check(
        &self,
        path: &str,
        access: u64,
        want_create: bool,
    ) -> Option<LinuxErrno> {
        if self.dac_overrides_permissions() {
            return None;
        }
        let (uid, gid) = self.dac_identity();
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

    /// DAC write-permission check on an EXISTING file, for the path mutators
    /// that need it (truncate; the linkat new-path parent). Returns
    /// `Some(EACCES)` when the caller lacks write on `path`. Root (euid 0)
    /// bypasses — CAP_DAC_OVERRIDE, and the hot path. Returns `None` when the
    /// backend can't supply real owner/mode (e.g. `--fs memory`), leaving the
    /// op to the backend. Ancestor search permission is already enforced by
    /// `resolve_at_path`/`check_search_access`, so this gates only the leaf.
    pub(super) fn may_write(&self, path: &str) -> Option<LinuxErrno> {
        if self.dac_overrides_permissions() {
            return None;
        }
        let (uid, gid) = self.dac_identity();
        let real = self.fs.rootfs_vfs.overlay.real_stat(path, true)?;
        let is_dir = matches!(real.kind, RootFsEntryKind::Directory);
        crate::dispatch::dac_check(uid, gid, real.uid, real.gid, real.mode, is_dir, LINUX_W_OK)
            .err()
    }

    /// Validate an `execve(2)`/`execveat(2)` target the way the kernel does
    /// BEFORE it reads the image: resolve the path (surfacing ENOENT / ENOTDIR /
    /// ELOOP / ENAMETOOLONG and the no-search-permission EACCES) and require
    /// execute permission on the final file. Called before shebang resolution so
    /// that a non-executable `#!` script is EACCES rather than a followed
    /// interpreter (matching Linux). The ELF/shebang FORMAT check (ENOEXEC) is
    /// left to image-load time. (execve03 / execveat02 / execve02.)
    // Called from `runtime/exec.rs` (the macOS/HVF execve path).
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn check_exec_target(&self, path: &str) -> Result<(), LinuxErrno> {
        // Existence via the SAME layered reader the loader uses, so a symlinked
        // executable (busybox/coreutils) is followed identically here — but
        // bounded to a single byte: this is an existence probe, and the full
        // read walked the whole multi-MB tool binary once per exec. A bare
        // RunElf boot may additionally read the literal host path.
        let host_fallback = self.exec_host_fs_fallback();
        let exists = self.read_exec_file_head(path, 1).is_some()
            || (host_fallback
                && std::fs::metadata(path)
                    .map(|m| m.is_file())
                    .unwrap_or(false));
        if exists {
            return self.exec_access_errno(path).map_or(Ok(()), Err);
        }
        // "Unreadable as a file" is NOT the same as "absent", and two of the
        // cases that land here resolve perfectly well — `read_exec_file_head`
        // simply cannot produce a file head for either:
        //   * a DIRECTORY is EACCES on Linux. It exists and resolves; it is
        //     just not an executable image. (Note this is EACCES even for a
        //     mode-0755 directory, so it cannot come from the X_OK DAC check
        //     above, where search permission would pass.)
        //   * a symlink CYCLE is ELOOP, bounded at 40 links as Linux bounds it.
        //     `resolve_at_path` has no cycle detection, so the self-referential
        //     link resolved to "no such entry".
        // Reporting ENOENT for either told the guest the path did not exist.
        // Found by `conformance-probes/src/bin/execfailsurvive.rs`, which
        // diffed carrick's 2/2 against Docker's 13/40.
        match self.canonicalize_following(path) {
            Err(errno) if errno == crate::linux_abi::LINUX_ELOOP => {
                return Err(crate::linux_abi::LINUX_ELOOP);
            }
            Ok(resolved) => {
                if self
                    .layered_lstat(&resolved)
                    .is_ok_and(|md| md.kind == RootFsEntryKind::Directory)
                {
                    return Err(crate::linux_abi::LINUX_EACCES);
                }
            }
            Err(_) => {}
        }
        // Otherwise: resolve_at_path distinguishes ENOTDIR (a non-directory
        // path component) and ENAMETOOLONG (an over-long path/component). A
        // path that resolves but whose leaf is simply absent is ENOENT.
        match self.resolve_at_path(LINUX_AT_FDCWD, path) {
            Ok(_) => Err(LINUX_ENOENT),
            Err(errno) => Err(errno),
        }
    }

    /// Execute-permission (`X_OK`) DAC check on an EXISTING exec target. Uses the
    /// backend's real owner+mode (`--fs host`); falls back to the layered
    /// metadata mode + tracked owner (`--fs memory`). Even root fails a regular
    /// file that carries NO execute bit — `dac_check` encodes the one case where
    /// `CAP_DAC_OVERRIDE` does not apply (`mode & 0o111 == 0 -> EACCES`).
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn exec_access_errno(&self, path: &str) -> Option<LinuxErrno> {
        let (fsuid, fsgid) = self.dac_identity();
        if let Some(real) = self.fs.rootfs_vfs.overlay.real_stat(path, true) {
            let is_dir = matches!(real.kind, RootFsEntryKind::Directory);
            return crate::dispatch::dac_check(
                fsuid, fsgid, real.uid, real.gid, real.mode, is_dir, LINUX_X_OK,
            )
            .err();
        }
        let md = self.layered_metadata(path).ok()?;
        let is_dir = md.kind == RootFsEntryKind::Directory;
        let (uid, gid) = self
            .fs
            .rootfs_vfs
            .overlay
            .get_owner(path)
            .unwrap_or((carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT));
        crate::dispatch::dac_check(fsuid, fsgid, uid, gid, md.mode, is_dir, LINUX_X_OK).err()
    }

    /// Verify the caller has search (X) permission on every ancestor directory
    /// of `path`. Returns `Some(EACCES)` on the first non-searchable parent.
    fn dac_ancestors_searchable(
        &self,
        path: &str,
        uid: carrick_abi::NsUid,
        gid: carrick_abi::NsGid,
    ) -> Option<LinuxErrno> {
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

    fn fd_access(
        &self,
        context: &crate::kernel::KernelContext,
        fd: i32,
        mode: u64,
    ) -> DispatchOutcome {
        let Some(open_file) = self.open_file(fd) else {
            return DispatchOutcome::errno(LINUX_EBADF);
        };
        let open = open_file.description.read();
        match &*open {
            OpenDescription::Closed { .. } => DispatchOutcome::errno(LINUX_EBADF),
            OpenDescription::File { metadata, .. }
            | OpenDescription::HostFile { metadata, .. }
            | OpenDescription::Directory { metadata, .. } => access_metadata(metadata, mode),
            OpenDescription::SyntheticFile { path, .. } => self
                .synthetic_access(context, path, mode)
                .unwrap_or(DispatchOutcome::errno(LINUX_ENOENT)),
            OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::Pidfd { .. }
            | OpenDescription::Inotify { .. }
            | OpenDescription::Fanotify { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. }
            | OpenDescription::SignalFd { .. }
            | OpenDescription::FsContext { .. }
            | OpenDescription::Mqueue { .. }
            | OpenDescription::BpfMap { .. }
            | OpenDescription::BpfProg { .. }
            | OpenDescription::Netlink { .. } => synthetic_readonly_access(mode),
        }
    }

    fn synthetic_access(
        &self,
        context: &crate::kernel::KernelContext,
        path: &str,
        mode: u64,
    ) -> Option<DispatchOutcome> {
        let proc_ctx = self.synthetic_proc_context(context);
        if crate::vfs::is_synthetic_virtual_file(path, &proc_ctx) {
            return Some(synthetic_readonly_access_for_path(path, mode));
        }
        // `/proc/<pid>` and its `task/` tree for a PEER exist only in the
        // kernel task graph — see `path_stat_record`. Without this,
        // `access("/proc/<peer>", F_OK)` fell through to `Vfs::lookup`, which
        // carries no context and asks Darwin's process table.
        if crate::vfs::proc::synthetic_dir_entries(path, &proc_ctx).is_some() {
            // A `/proc` directory is r-xr-xr-x: readable and searchable, never
            // writable (LTP `tgkill03` probes `R_OK`).
            return Some(synthetic_readonly_access_with_errno(mode, LINUX_EACCES));
        }
        None
    }
}

fn synthetic_readonly_access_for_path(path: &str, mode: u64) -> DispatchOutcome {
    let write_errno = if crate::vfs::proc::is_sysctl_leaf_path(path) {
        LINUX_EROFS
    } else {
        LINUX_EACCES
    };
    synthetic_readonly_access_with_errno(mode, write_errno)
}
