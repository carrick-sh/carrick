//! fs syscall handlers. Methods on `SyscallDispatcher`; see
//! `super` for the dispatcher struct and the normalized dispatch table.
use super::*;
mod access;
mod fd_helpers;
mod pathres;
mod sendfile;
mod state;
mod xattr;
use state::*;
pub(super) use state::{FsState, IoState};

/// If `path` is a `/proc/{self,thread-self,curproc,this}/fd/N` magic symlink,
/// return the descriptor number N. Used to serve `open()` of these (Linux
/// re-opens the file behind fd N); Apple Rosetta opens its main-binary fd this
/// way.
fn proc_self_fd_number(path: &str) -> Option<i32> {
    let rest = path
        .strip_prefix("/proc/self/fd/")
        .or_else(|| path.strip_prefix("/proc/thread-self/fd/"))
        .or_else(|| path.strip_prefix("/proc/curproc/fd/"))
        .or_else(|| path.strip_prefix("/proc/this/fd/"))
        .or_else(|| {
            // /proc/<pid>/fd/N — carrick is one guest process, so any numeric
            // pid component refers to "self".
            let after = path.strip_prefix("/proc/")?;
            let (pid, tail) = after.split_once('/')?;
            if pid.chars().all(|c| c.is_ascii_digit()) && !pid.is_empty() {
                tail.strip_prefix("fd/")
            } else {
                None
            }
        })?;
    rest.parse::<i32>().ok()
}

impl SyscallDispatcher {
    pub fn register_mount(
        &mut self,
        point: impl Into<std::path::PathBuf>,
        vfs: Box<dyn crate::vfs::Vfs>,
    ) {
        self.fs.vfs_mounts.mount(point, vfs);
    }

    pub(super) fn write_shared_supported(&self, fd: i32) -> bool {
        let Some(open_file) = self.open_file(fd) else {
            return true;
        };
        let open = open_file.description.read();
        matches!(
            &*open,
            OpenDescription::EventFd { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::HostFile { .. }
        )
    }

    fn record_unimplemented_virtual_file(
        reporter: &CompatReporter,
        path: &str,
    ) -> Option<DispatchOutcome> {
        if path.starts_with("/proc/") {
            reporter.record(CompatEvent::proc_read_unimplemented(path.to_owned()));
            Some(DispatchOutcome::errno(LINUX_ENOENT))
        } else if path.starts_with("/sys/") {
            // /sys paths that are synthesized must not be recorded as unimplemented;
            // they are handled by the synthetic open path before reaching ENOENT.
            if crate::vfs::sys::synthetic_file(path).is_some() {
                return None;
            }
            reporter.record(CompatEvent::sys_read_unimplemented(path.to_owned()));
            Some(DispatchOutcome::errno(LINUX_ENOENT))
        } else {
            None
        }
    }

    fn tty_ioctl_fd_kind(&self, fd: i32) -> Result<TtyFdKind, i32> {
        if is_stdio_fd(fd) {
            Ok(TtyFdKind::Stdio)
        } else if self.fd_table_contains(fd) {
            Ok(TtyFdKind::Other)
        } else {
            Err(LINUX_EBADF)
        }
    }

    /// If `fd` is a pty master/slave end, return its role and the backing
    /// host fd in one fd-table lookup.
    fn pty_info(&self, fd: i32) -> Option<(crate::vfs::PtyRole, i32)> {
        self.open_file(fd)
            .and_then(|of| match &*of.description.read() {
                OpenDescription::HostPipe {
                    host_fd,
                    pty: Some(role),
                    ..
                } => Some((*role, *host_fd)),
                _ => None,
            })
    }

    pub(super) fn fd_is_valid(&self, fd: i32) -> bool {
        is_stdio_fd(fd) || self.fd_table_contains(fd)
    }

    fn statfs(
        &self,
        pathname: GuestPtr,
        buffer: GuestPtr,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let path = match read_guest_c_string(memory, pathname.0) {
            Ok(path) => path,
            Err(errno) => return Ok(errno.into()),
        };
        let path = match self.resolve_at_path(LINUX_AT_FDCWD, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(errno.into()),
        };
        // Consult the layered view (overlay/disk first, then rootfs) so
        // that files the guest created in the overlay are visible here
        // too — a rootfs-direct lookup would miss them.
        if let Err(errno) = self.layered_metadata(&path) {
            return Ok(errno.into());
        }
        Ok(write_statfs(memory, buffer.0))
    }

    fn fstatfs(&self, fd: Fd, buf: GuestPtr, memory: &mut impl GuestMemory) -> DispatchOutcome {
        if !self.fd_table_contains(fd.0) {
            return DispatchOutcome::errno(LINUX_EBADF);
        }
        write_statfs(memory, buf.0)
    }

    fn truncate(
        &self,
        pathname: GuestPtr,
        length: u64,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let length = i64::from_ne_bytes(length.to_ne_bytes());
        if length < 0 {
            return Ok(LINUX_EINVAL.into());
        }
        let path = match read_guest_c_string(memory, pathname.0) {
            Ok(path) => path,
            Err(errno) => return Ok(errno.into()),
        };
        if path.is_empty() {
            return Ok(LINUX_ENOENT.into());
        }
        let resolved = match self.resolve_at_path(LINUX_AT_FDCWD, &path) {
            Ok(resolved) => resolved,
            Err(errno) => return Ok(errno.into()),
        };
        if crate::vfs::is_synthetic_virtual_file(&resolved, &self.synthetic_proc_context()) {
            return Ok(LINUX_EROFS.into());
        }
        // Layered metadata (overlay/disk first, then rootfs) — not rootfs-only,
        // so guest-created files are seen too.
        let kind = match self.layered_metadata(&resolved) {
            Ok(md) => md.kind,
            Err(errno) => return Ok(errno.into()),
        };
        if kind == RootFsEntryKind::Directory {
            return Ok(LINUX_EISDIR.into());
        }
        // Disk-backed: open the real file and ftruncate it. The whole rootfs
        // is materialised on the cap-std scratch under --fs host, so this
        // works for both rootfs and guest-created files. MemoryBackend has no
        // raw fd → EROFS (path-based truncate stays unsupported in-memory).
        match self
            .fs
            .rootfs_vfs
            .overlay
            .open_raw_fd(&resolved, true, false, false)
        {
            Some(host_fd) => {
                let err = unsafe { libc::ftruncate(host_fd, length as libc::off_t) }
                    .host_syscall_errno()
                    .err()
                    .unwrap_or(0);
                unsafe { libc::close(host_fd) };
                if err != 0 {
                    Ok(err.into())
                } else {
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
            }
            None => Ok(LINUX_EROFS.into()),
        }
    }

    fn open_at_path(
        &self,
        dirfd: u64,
        pathname: u64,
        flags: u64,
        mode: u64,
        memory: &impl GuestMemory,
        reporter: &CompatReporter,
    ) -> Result<DispatchOutcome, DispatchError> {
        let access = flags & LINUX_O_ACCMODE;
        if access != LINUX_O_RDONLY && access != LINUX_O_WRONLY && access != LINUX_O_RDWR {
            return Ok(LINUX_EINVAL.into());
        }
        let writable_request = access == LINUX_O_WRONLY || access == LINUX_O_RDWR;
        let want_create = flags & LINUX_O_CREAT != 0;
        let want_excl = flags & LINUX_O_EXCL != 0;
        let want_trunc = flags & LINUX_O_TRUNC != 0;

        // O_TMPFILE: `pathname` names a directory; the result is an unnamed,
        // writable regular file. Model it as an anonymous in-memory File with no
        // overlay/namespace entry — it's never linked anywhere, exactly the
        // "unlinked temp file" semantics tmpfile(3)/build tools rely on. Requires
        // write access (the kernel rejects O_RDONLY|O_TMPFILE with EINVAL).
        // (linkat(AT_EMPTY_PATH) to later materialize it is a separate follow-up.)
        if flags & crate::linux_abi::LINUX_O_TMPFILE != 0 {
            if !writable_request {
                return Ok(LINUX_EINVAL.into());
            }
            let creds = self.cred_snapshot();
            let create_mode = (mode as u32 & 0o7777) & !(creds.umask & 0o777);
            let description = OpenDescription::File {
                path: "/__carrick_o_tmpfile".to_string(),
                metadata: RootFsMetadata {
                    path: Path::new("/__carrick_o_tmpfile").to_path_buf(),
                    kind: RootFsEntryKind::File,
                    mode: create_mode,
                    size: 0,
                },
                contents: Vec::new(),
                offset: 0,
                base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                writable: true,
            };
            return Ok(self.install_fd(description, linux_fd_flags_from_open_flags(flags)));
        }

        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(errno.into()),
        };
        let path = match self.resolve_at_path(dirfd, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(errno.into()),
        };

        // Trace every open attempt. The per-backend `path_open` calls further
        // down only fire for the legacy synthetic/overlay/rootfs chain, so
        // VFS-mount opens (/dev, /proc, /sys) and the /proc/self/{exe,fd}
        // resolutions below were invisible to `carrick trace`.
        crate::probes::path_open(&path, 0, 0);

        // `/proc/self/fd/N` (and the pid/thread-self/curproc aliases) re-open the
        // file behind descriptor N — Linux lets you open() the magic symlink to
        // get a fresh fd referring to the same open file. Rosetta opens its
        // main-binary fd this way. Serve it by duplicating N (works for host-fd
        // backed files, which carry no guest path to re-resolve).
        if let Some(n) = proc_self_fd_number(&path) {
            return Ok(self.duplicate_fd(n, 0, flags & LINUX_O_CLOEXEC));
        }

        // `/proc/self/exe` (and the thread-self/curproc/this aliases) are
        // symlinks to the running executable that Linux lets you open() directly
        // to get an fd on the backing file. Resolve to the executable path so
        // the open hits the real file. Apple's Rosetta opens this at startup
        // (and runs its licensing ioctl on the resulting fd); under translation
        // the executable path points at the bind-mounted Rosetta interpreter.

        let mut path = match path.as_str() {
            "/proc/self/exe" | "/proc/thread-self/exe" | "/proc/this/exe"
            | "/proc/curproc/exe" => {
                let exe = self.proc.lock().executable_path.clone();
                // Avoid the circular default (`executable_path` is itself
                // "/proc/self/exe" until an image is loaded).
                if exe.starts_with("/proc/") { path } else { exe }
            }
            _ => path,
        };

        // Follow a trailing symlink (unless O_NOFOLLOW, or an exclusive create),
        // matching kernel path resolution: opening Alpine's /bin/uname must
        // resolve to /bin/busybox and return the busybox ELF, not the symlink's
        // 12-byte target string. Rosetta open()s its main x86 binary by name and
        // parses the result as an ELF, so a returned symlink corrupts it.
        // Best-effort: a non-symlink or not-yet-existent (O_CREAT) path is left
        // unchanged.
        const LINUX_O_NOFOLLOW: u64 = 0o400000;
        if flags & LINUX_O_NOFOLLOW == 0 && !(want_create && want_excl) {
            if let Ok(resolved) = self.canonicalize_following(&path) {
                path = resolved;
            }
        }

        // VFS-mount routing. DevVfs serves /dev/*, ProcVfs serves
        // /proc/*, SysVfs serves /sys/*. The dispatcher converts each
        // VfsHandle variant into the matching OpenDescription, then
        // falls back to the legacy synthetic-then-overlay-then-rootfs
        // chain for any path no mount claims (or that the mount
        // returns ENOSYS for).
        let vfs_outcome = self.try_vfs_open(&path, access, flags);
        match vfs_outcome {
            VfsOpenAttempt::Installed(fd) => {
                return Ok(DispatchOutcome::Returned { value: fd as i64 });
            }
            VfsOpenAttempt::Errno(errno) => {
                return Ok(errno.into());
            }
            VfsOpenAttempt::FallThrough => {}
        }

        // DAC on open (--fs host, non-root): an existing file needs the
        // requested access (read unless O_WRONLY, write for O_WRONLY/O_RDWR)
        // plus search on every ancestor; creating a new file needs write+search
        // on the parent dir. Root bypasses (handled in dac_check).
        if let Some(errno) = self.dac_open_check(&path, access, want_create) {
            return Ok(errno.into());
        }

        // /proc/* and /sys/* synthetic file opens now flow through
        // ProcVfs / SysVfs (mounted in `SyscallDispatcher::new`). Any
        // unknown /proc or /sys path returns ENOSYS from the mount
        // and falls through to the overlay+rootfs lookup below, which
        // handles directory entries like /proc itself.

        if let Some(outcome) = Self::record_unimplemented_virtual_file(reporter, &path) {
            return Ok(outcome);
        }
        // Layered overlay+rootfs lookup with full openat semantics
        // (O_CREAT/O_EXCL/O_TRUNC, write-promotion of rootfs-only
        // files) lives in RootFsVfs::open_for_dispatch.
        let dispatch_result = self.fs.rootfs_vfs.open_for_dispatch(
            &path,
            want_create,
            want_excl,
            want_trunc,
            writable_request,
        );
        // USDT probe: every guest path-level open, with the resolved
        // path string and resulting size/errno. Lets dtrace operators
        // see exactly what bytes each forked carrick process is
        // serving for paths like /etc/hosts during the apt-resolver
        // run.
        match &dispatch_result {
            Ok(crate::vfs::rootfs::OpenDispatchResult::File { contents, .. }) => {
                crate::probes::path_open(&path, contents.len() as u64, 0);
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::HostFile { metadata, .. }) => {
                crate::probes::path_open(&path, metadata.size as u64, 0);
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::Directory { .. }) => {
                crate::probes::path_open(&path, 0, 0);
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::NotFoundCreate) => {
                crate::probes::path_open(&path, 0, 0);
            }
            Err(errno) => {
                crate::probes::path_open(&path, 0, *errno);
            }
        }
        // Remember the guest path so readlink(/proc/self/fd/N) can recover it
        // (host-fd-backed descriptions store no path of their own).
        let record_path = path.clone();
        let (description, host_fd_owner) = match dispatch_result {
            Ok(crate::vfs::rootfs::OpenDispatchResult::File {
                metadata,
                contents,
                writable,
            }) => (
                OpenDescription::File {
                    path,
                    metadata,
                    contents,
                    offset: 0,
                    base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                    writable,
                },
                None,
            ),
            Ok(crate::vfs::rootfs::OpenDispatchResult::HostFile {
                host_fd,
                metadata,
                writable,
            }) => (
                OpenDescription::HostFile {
                    host_fd,
                    metadata,
                    base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                    writable,
                },
                Some(HostFdRef::new(host_fd)),
            ),
            Ok(crate::vfs::rootfs::OpenDispatchResult::Directory { metadata, entries }) => {
                if writable_request {
                    return Ok(LINUX_EISDIR.into());
                }
                (
                    OpenDescription::Directory {
                        path,
                        metadata,
                        entries,
                        offset: 0,
                        base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                    },
                    None,
                )
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::NotFoundCreate) => {
                // O_CREAT path: validate the parent directory exists,
                // create the empty overlay entry, return a writable
                // File description.
                if let Some(parent) = Path::new(&path).parent() {
                    let parent_str = display_rootfs_path(parent);
                    if !self.path_is_directory(&parent_str) {
                        return Ok(LINUX_ENOENT.into());
                    }
                }
                // O_CREAT mode: the requested mode masked by the guest umask,
                // exactly like the kernel (`mode & ~umask`). Only applies to a
                // freshly-created file (this branch only runs when no file
                // existed). Previously hardcoded to 0o644, so creat(f, 0777)
                // always yielded 644 and umask had no effect.
                let creds = self.cred_snapshot();
                let create_mode = (mode as u32 & 0o7777) & !(creds.umask & 0o777);
                let metadata = RootFsMetadata {
                    path: Path::new(&path).to_path_buf(),
                    kind: RootFsEntryKind::File,
                    mode: create_mode,
                    size: 0,
                };
                // Disk-backed overlay (--fs host): create + open a real
                // host fd so the new file is fork-shareable. Falls back
                // to the in-memory File for MemoryBackend.
                // A new file is owned by the creating process's effective
                // uid/gid (Linux semantics). carrick stamps it so a guest that
                // setuid()'d to e.g. "nobody" before creating sees the right
                // owner. Root (0,0) is the default, so only stamp non-root.
                let create_uid = creds.euid;
                let create_gid = creds.egid;
                let stamp_owner = create_uid != 0 || create_gid != 0;
                if let Some(host_fd) = self
                    .fs
                    .rootfs_vfs
                    .overlay
                    .open_raw_fd(&path, true, true, want_trunc)
                {
                    // The host create used the host process umask; force the
                    // guest-requested mode onto the new file.
                    let _ = self.fs.rootfs_vfs.overlay.set_mode(&path, create_mode);
                    if stamp_owner {
                        let _ = self
                            .fs
                            .rootfs_vfs
                            .overlay
                            .set_owner(&path, create_uid, create_gid);
                    }
                    (
                        OpenDescription::HostFile {
                            host_fd,
                            metadata,
                            base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                            writable: true,
                        },
                        Some(HostFdRef::new(host_fd)),
                    )
                } else {
                    if self.fs.rootfs_vfs.overlay.create_file(&path).is_err() {
                        return Ok(LINUX_EINVAL.into());
                    }
                    let _ = self.fs.rootfs_vfs.overlay.set_mode(&path, create_mode);
                    if stamp_owner {
                        let _ = self
                            .fs
                            .rootfs_vfs
                            .overlay
                            .set_owner(&path, create_uid, create_gid);
                    }
                    (
                        OpenDescription::File {
                            path,
                            metadata,
                            contents: Vec::new(),
                            offset: 0,
                            base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                            writable: writable_request || want_create,
                        },
                        None,
                    )
                }
            }
            Err(errno) => return Ok(errno.into()),
        };

        let open_file = OpenFile {
            description: Arc::new(RwLock::new(description)),
            fd_flags: linux_fd_flags_from_open_flags(flags),
            host_fd_owner,
        };
        let Ok(fd) = self.install_fd_at_or_above(3, open_file) else {
            return Ok(linux_errno::EMFILE.into());
        };
        self.io.fd_open_paths.write().insert(fd, record_path);
        Ok(DispatchOutcome::Returned { value: fd as i64 })
    }

    /// `close_range(first, last, flags)` — close every fd in `[first, last]`
    /// (inclusive). Used by glibc's posix_spawn / apt's pre-fork cleanup
    /// to drop inherited fds in O(1) syscalls instead of an O(N) fcntl
    /// or close loop. Without this, apt walks fd 3..NR_OPEN issuing a
    /// fcntl per fd and burns 100k+ traps before exec.

    fn duplicate_fd(&self, old_fd: i32, min_fd: i32, fd_flags: u64) -> DispatchOutcome {
        let (description, host_fd_owner) = match self.open_file(old_fd).as_ref() {
            Some(open_file) => (
                Arc::clone(&open_file.description),
                open_file.host_fd_owner.clone(),
            ),
            None if is_stdio_fd(old_fd) => {
                // dup/fcntl(F_DUPFD) of the process's bare stdio fds:
                // mirror what dup3 does and grab the host fd into a
                // HostPipe so future reads/writes still hit the right
                // host endpoint (this is what dpkg-query needs at
                // startup to redirect its diagnostic fd, and what most
                // glibc fork+exec helpers expect to succeed).
                let duped = match (unsafe { libc::dup(old_fd) }).host_syscall_errno() {
                    Ok(duped) => duped,
                    Err(errno) => return DispatchOutcome::errno(errno),
                };
                (
                    Arc::new(RwLock::new(OpenDescription::HostPipe {
                        host_fd: duped,
                        is_read_end: old_fd == 0,
                        base: OpenDescriptionBase::new(0),
                        pty: None,
                    })),
                    Some(HostFdRef::new(duped)),
                )
            }
            None => return DispatchOutcome::errno(LINUX_EBADF),
        };
        let open_file = OpenFile {
            description,
            fd_flags,
            host_fd_owner,
        };
        let new_fd = match self.install_fd_at_or_above(min_fd, open_file) {
            Ok(fd) => fd,
            Err(_) => {
                return DispatchOutcome::errno(linux_errno::EMFILE);
            }
        };
        DispatchOutcome::Returned {
            value: new_fd as i64,
        }
    }

    /// Try to satisfy an open via the VFS mount table. Returns
    /// `Installed(fd)` when a mount handled it, `Errno(e)` when a
    /// mount explicitly failed, and `FallThrough` when no mount
    /// claimed the path (or the claiming mount returned ENOSYS). The
    /// caller wraps the legacy lookup chain inside `FallThrough`.
    fn try_vfs_open(&self, path: &str, access: u64, flags: u64) -> VfsOpenAttempt {
        // Build the OpenContext from owned/copy data so the mut
        // borrow of `vfs_mounts` doesn't conflict with reads from
        // sibling fields.
        let proc = self.proc.lock();
        let exec_path = proc.executable_path.clone();
        let argv = proc.argv.clone();
        drop(proc);
        let mem = self.mem_snapshot();
        let ctx = crate::vfs::OpenContext {
            executable_path: Some(exec_path.as_str()),
            argv: Some(argv.as_slice()),
            address_space_regions: mem.address_space_regions.as_deref(),
            brk_current: mem.brk_current,
            mmap_next: mem.mmap_next,
        };
        let vfs_flags = crate::vfs::OpenFlags {
            read: matches!(access, LINUX_O_RDONLY | LINUX_O_RDWR),
            write: matches!(access, LINUX_O_WRONLY | LINUX_O_RDWR),
            nonblock: flags & LINUX_O_NONBLOCK != 0,
            cloexec: flags & LINUX_O_CLOEXEC != 0,
            append: flags & LINUX_O_APPEND != 0,
            trunc: flags & LINUX_O_TRUNC != 0,
            create: flags & LINUX_O_CREAT != 0,
            excl: flags & LINUX_O_EXCL != 0,
            directory: flags & LINUX_O_DIRECTORY != 0,
            nofollow: flags & 0o400000 != 0,
            mode: 0,
        };
        let handle = {
            let Some(m) = self.fs.vfs_mounts.resolve(path) else {
                return VfsOpenAttempt::FallThrough;
            };
            match m.vfs.open(&m.full_path, vfs_flags, &ctx) {
                Ok(h) => h,
                Err(errno) if errno == LINUX_ENOSYS => {
                    return VfsOpenAttempt::FallThrough;
                }
                Err(errno) => {
                    return VfsOpenAttempt::Errno(errno);
                }
            }
        };
        match handle {
            crate::vfs::VfsHandle::HostFd {
                host_fd,
                is_read_end,
                status_flags,
            } => {
                // A VFS-served (e.g. bind-mounted) REGULAR file must become a
                // seekable HostFile, not a HostPipe — otherwise lseek/pread-at-
                // offset and sendfile/splice reject it (EINVAL), since a pipe
                // isn't seekable. Only genuine streams (devices, fifos) stay
                // HostPipe. fstat the real fd to decide.
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                let is_regular = unsafe { libc::fstat(host_fd, &mut st) } == 0
                    && (st.st_mode & libc::S_IFMT) == libc::S_IFREG;
                let description = if is_regular {
                    OpenDescription::HostFile {
                        host_fd,
                        metadata: crate::rootfs::RootFsMetadata {
                            path: std::path::PathBuf::from(path),
                            kind: RootFsEntryKind::File,
                            mode: (st.st_mode & 0o7777) as u32,
                            size: st.st_size.max(0) as usize,
                        },
                        base: OpenDescriptionBase::new(status_flags as u64),
                        writable: !is_read_end,
                    }
                } else {
                    OpenDescription::HostPipe {
                        host_fd,
                        is_read_end,
                        base: OpenDescriptionBase::new(status_flags as u64),
                        pty: None,
                    }
                };
                let open_file = OpenFile::with_host_fd(
                    Arc::new(RwLock::new(description)),
                    linux_fd_flags_from_open_flags(flags),
                    host_fd,
                );
                let new_fd = match self.install_fd_at_or_above(3, open_file) {
                    Ok(fd) => fd,
                    Err(_) => return VfsOpenAttempt::Errno(linux_errno::EMFILE),
                };
                VfsOpenAttempt::Installed(new_fd)
            }
            crate::vfs::VfsHandle::Bytes {
                path,
                contents,
                status_flags,
            } => {
                let open_file = OpenFile::new(
                    Arc::new(RwLock::new(OpenDescription::SyntheticFile {
                        path,
                        contents,
                        offset: 0,
                        base: OpenDescriptionBase::new(
                            ((status_flags as u64) | flags) & !LINUX_O_CLOEXEC,
                        ),
                    })),
                    linux_fd_flags_from_open_flags(flags),
                );
                let new_fd = match self.install_fd_at_or_above(3, open_file) {
                    Ok(fd) => fd,
                    Err(_) => return VfsOpenAttempt::Errno(linux_errno::EMFILE),
                };
                VfsOpenAttempt::Installed(new_fd)
            }
            crate::vfs::VfsHandle::Pty {
                host_fd,
                pts_index,
                is_master,
                status_flags,
            } => {
                let open_file = OpenFile::with_host_fd(
                    Arc::new(RwLock::new(OpenDescription::HostPipe {
                        host_fd,
                        // A pty end is bidirectional; route reads and
                        // writes through the host fd like /dev/null.
                        is_read_end: true,
                        base: OpenDescriptionBase::new(status_flags as u64),
                        pty: Some(crate::vfs::PtyRole {
                            index: pts_index,
                            is_master,
                        }),
                    })),
                    linux_fd_flags_from_open_flags(flags),
                    host_fd,
                );
                let new_fd = match self.install_fd_at_or_above(3, open_file) {
                    Ok(fd) => fd,
                    Err(_) => return VfsOpenAttempt::Errno(linux_errno::EMFILE),
                };
                VfsOpenAttempt::Installed(new_fd)
            }
            crate::vfs::VfsHandle::Directory {
                path,
                entries,
                status_flags,
            } => {
                // Convert synthetic VFS DirEnt entries into the RootFsDirEntry
                // shape that OpenDescription::Directory + getdents64 expects.
                let rootfs_entries: Vec<RootFsDirEntry> = entries
                    .into_iter()
                    .map(|e| {
                        let kind = match e.kind {
                            crate::vfs::EntryKind::Directory => RootFsEntryKind::Directory,
                            crate::vfs::EntryKind::Symlink => RootFsEntryKind::Symlink,
                            crate::vfs::EntryKind::CharDevice => RootFsEntryKind::CharDevice,
                            crate::vfs::EntryKind::File => RootFsEntryKind::File,
                        };
                        RootFsDirEntry {
                            name: e.name.clone(),
                            metadata: RootFsMetadata {
                                path: std::path::Path::new(&path).join(&e.name).to_path_buf(),
                                kind,
                                mode: 0o666,
                                size: 0,
                            },
                        }
                    })
                    .collect();
                let metadata = RootFsMetadata {
                    path: std::path::Path::new(&path).to_path_buf(),
                    kind: RootFsEntryKind::Directory,
                    mode: 0o755,
                    size: 0,
                };
                let open_file = OpenFile::new(
                    Arc::new(RwLock::new(OpenDescription::Directory {
                        path,
                        metadata,
                        entries: rootfs_entries,
                        offset: 0,
                        base: OpenDescriptionBase::new(status_flags as u64),
                    })),
                    linux_fd_flags_from_open_flags(flags),
                );
                let new_fd = match self.install_fd_at_or_above(3, open_file) {
                    Ok(fd) => fd,
                    Err(_) => return VfsOpenAttempt::Errno(linux_errno::EMFILE),
                };
                VfsOpenAttempt::Installed(new_fd)
            }
        }
    }

    fn bootstrap_enosys(&self) -> DispatchOutcome {
        DispatchOutcome::errno(LINUX_ENOSYS)
    }

    // === Normalized shim-wrappers ===
    // Thin adapters giving each remaining legacy handler the uniform
    // SyscallCtx<M> contract so it can live in the `normalized_dispatch!`
    // table. The inner fns are unchanged (already tested); these forward
    // `ctx.request` (Copy) and `ctx.memory`. Once every syscall has a
    // wrapper the legacy match in `dispatch()` is deleted and the macro
    // table becomes the single authoritative syscall registry.

    fn host_file_fd_for_flush(&self, fd: i32) -> Result<Option<i32>, i32> {
        let Some(open_file) = self.open_file(fd) else {
            return if is_stdio_fd(fd) {
                Ok(None)
            } else {
                Err(LINUX_EBADF)
            };
        };
        let open = open_file.description.read();
        Ok(match &*open {
            OpenDescription::HostFile { host_fd, .. } => Some(*host_fd),
            _ => None,
        })
    }

    fn write_output_fd(&self, fd: i32, bytes: &[u8]) -> DispatchOutcome {
        let nonblocking = self.io_is_nonblocking(fd, 0);
        // Mirror `write`/`writev`: any fd present in `open_files` (e.g.
        // after a dup3 over stdio) takes precedence over the built-in
        // stdout/stderr buffers. Without this, `busybox cat`'s
        // `sendfile(1, infile, ...)` writes the file contents to the
        // dispatcher's internal stdout instead of the pipe write end.
        if let Some(open_file) = self.open_file(fd) {
            // Regular-file destinations need the overlay writeback to happen
            // AFTER the description borrow is dropped, so use the same
            // collect-then-write pattern as `write`. Non-file arms return
            // directly. This is what makes splice/copy_file_range/sendfile to a
            // regular file (off_out at the fd's current position) work, matching
            // real Linux (splice pipe->file).
            let outcome: DispatchOutcome;
            let writeback: Option<(String, Vec<u8>)>;
            {
                let mut open = open_file.description.write();
                match &mut *open {
                    OpenDescription::PipeWriter { pipe, .. } => return write_pipe(bytes, pipe),
                    OpenDescription::HostPipe {
                        host_fd,
                        is_read_end,
                        pty,
                        ..
                    } => {
                        // pty ends are bidirectional (O_RDWR); only real one-way
                        // pipe ends are gated by is_read_end.
                        return if *is_read_end && pty.is_none() {
                            DispatchOutcome::errno(LINUX_EBADF)
                        } else {
                            write_host_pipe(bytes, *host_fd, nonblocking)
                        };
                    }
                    OpenDescription::HostSocket { host_fd, .. } => {
                        return write_host_pipe(bytes, *host_fd, nonblocking);
                    }
                    OpenDescription::HostFile {
                        base,
                        host_fd,
                        writable,
                        ..
                    } => {
                        if !*writable {
                            return DispatchOutcome::errno(LINUX_EBADF);
                        }
                        if base.status_flags() & LINUX_O_APPEND != 0 {
                            unsafe { libc::lseek(*host_fd, 0, libc::SEEK_END) };
                        }
                        return write_host_pipe(bytes, *host_fd, nonblocking);
                    }
                    OpenDescription::File {
                        path,
                        contents,
                        offset,
                        writable,
                        metadata,
                        ..
                    } => {
                        if !*writable {
                            return DispatchOutcome::errno(LINUX_EBADF);
                        }
                        if let Err(errno) = write_into_file_contents(contents, offset, bytes) {
                            return DispatchOutcome::errno(errno);
                        }
                        metadata.size = contents.len();
                        outcome = DispatchOutcome::Returned {
                            value: bytes.len() as i64,
                        };
                        writeback = Some((path.clone(), contents.clone()));
                    }
                    _ => return DispatchOutcome::errno(LINUX_EBADF),
                }
            }
            if let Some((path, contents)) = writeback {
                let _ = self
                    .fs
                    .rootfs_vfs
                    .overlay
                    .set_file_contents(&path, contents);
            }
            return outcome;
        }
        if *self.io.stream_stdio.lock() && (fd == 1 || fd == 2) {
            // BLOCKING-IO-OK: streamed write to the inherited stdout/stderr
            // (the user's tty/pipe). Blocking here is the correct backpressure
            // and isn't a guest socket on the server path.
            let n = unsafe { libc::write(fd, bytes.as_ptr() as *const _, bytes.len()) };
            return match n.host_syscall_errno() {
                Ok(value) => DispatchOutcome::Returned {
                    value: value as i64,
                },
                Err(errno) => DispatchOutcome::errno(errno),
            };
        }
        match fd {
            1 => self.io.stdout.lock().extend_from_slice(bytes),
            2 => self.io.stderr.lock().extend_from_slice(bytes),
            _ => return DispatchOutcome::errno(LINUX_EBADF),
        }
        DispatchOutcome::Returned {
            value: bytes.len() as i64,
        }
    }

    /// If `path` is `/proc/self/fd/{0,1,2}` (or `/proc/<pid>/fd/...`) and the
    /// guest's stdio is the `carrick run -t` controlling pty, return its
    /// `/dev/pts/N` path. This is the symlink glibc `ttyname(3)` reads to name
    /// the terminal. Only the three stdio fds are mapped (they're the pty
    /// slave under `-t`).
    fn proc_self_fd_tty_link(&self, path: &str) -> Option<String> {
        let fd_part = path
            .strip_prefix("/proc/self/fd/")
            .or_else(|| path.strip_prefix("/proc/thread-self/fd/"))?;
        if !matches!(fd_part, "0" | "1" | "2") {
            return None;
        }
        let n = self.pty_table().lock().controlling()?;
        Some(format!("/dev/pts/{n}"))
    }

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
            let _ = self.fs.rootfs_vfs.overlay.set_mode(path, mode);
        }
    }

    fn do_renameat(
        &self,
        olddirfd: u64,
        oldpath: u64,
        newdirfd: u64,
        newpath: u64,
        flags: u64,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        const RENAME_NOREPLACE: u64 = 1;
        let old = match read_guest_c_string(memory, oldpath) {
            Ok(path) => path,
            Err(errno) => return Ok(errno.into()),
        };
        let new_path = match read_guest_c_string(memory, newpath) {
            Ok(path) => path,
            Err(errno) => return Ok(errno.into()),
        };
        if old.is_empty() || new_path.is_empty() {
            return Ok(LINUX_ENOENT.into());
        }
        let resolved_old = match self.resolve_at_path(olddirfd, &old) {
            Ok(path) => path,
            Err(errno) => return Ok(errno.into()),
        };
        let resolved_new = match self.resolve_at_path(newdirfd, &new_path) {
            Ok(path) => path,
            Err(errno) => return Ok(errno.into()),
        };
        if crate::vfs::is_synthetic_virtual_file(&resolved_old, &self.synthetic_proc_context())
            || crate::vfs::is_synthetic_virtual_file(&resolved_new, &self.synthetic_proc_context())
        {
            return Ok(LINUX_EROFS.into());
        }
        let no_replace = flags & RENAME_NOREPLACE != 0;
        match self
            .fs
            .rootfs_vfs
            .rename_with_flags(&resolved_old, &resolved_new, no_replace)
        {
            Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
            Err(errno) => Ok(errno.into()),
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
        let open = open_file.description.read();
        match &*open {
            OpenDescription::HostFile { host_fd, .. } => {
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
                let rc = unsafe { libc::futimens(*host_fd, times.as_ptr()) };
                if rc < 0 {
                    // Best-effort: don't abort the caller on a failed
                    // timestamp set (see the path-branch rationale).
                    let e = std::io::Error::last_os_error();
                    crate::probes::fs_op(
                        "set_fd_times:futimens_err_besteffort",
                        &format!("fd={fd} {e}"),
                        e.raw_os_error().unwrap_or(0),
                    );
                }
                DispatchOutcome::Returned { value: 0 }
            }
            OpenDescription::File { metadata, .. } => {
                let path = metadata.path.to_string_lossy().into_owned();
                drop(open);
                match self.fs.rootfs_vfs.overlay.set_times(&path, atime, mtime) {
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

    /// The synthetic `(label, st_mode)` for a bare stdio fd (0/1/2) with no
    /// OpenDescription. Glibc fstat()s stdio on startup to pick its tty/file/
    /// pipe code path, so report the REAL host type (a pty → S_IFCHR, a pipe →
    /// S_IFIFO, a redirect → S_IFREG; the S_IF* values match Linux). When the
    /// fd is the `carrick run -t` controlling tty, label it `/dev/pts/N` so the
    /// synthetic st_ino matches `stat("/dev/pts/N")` — the equality `ttyname(3)`
    /// checks between `fstat(fd)` and the `/proc/self/fd/N` readlink target.
    /// Shared by `write_fd_stat` (fstat) and `write_fd_statx` (statx).
    fn stdio_synthetic_label_mode(&self, fd: i32) -> (String, u32) {
        let label = if crate::host_tty::host_isatty(fd)
            && let Some(n) = self.pty_table().lock().controlling()
        {
            format!("/dev/pts/{n}")
        } else {
            match fd {
                0 => "/dev/stdin",
                1 => "/dev/stdout",
                _ => "/dev/stderr",
            }
            .to_string()
        };
        let mut host_st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fd is a stdio fd; &host_st is a valid stat out-param.
        let mode = if unsafe { libc::fstat(fd, &mut host_st) } == 0 {
            (host_st.st_mode as u32 & LINUX_S_IFMT) | 0o620
        } else {
            LINUX_S_IFCHR | 0o620
        };
        (label, mode)
    }

    fn write_fd_stat(
        &self,
        fd: i32,
        statbuf: u64,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        match self.fd_stat_record(fd) {
            Ok(record) => write_stat_record(memory, statbuf, &record),
            Err(errno) => DispatchOutcome::errno(errno),
        }
    }

    fn write_fd_statx(
        &self,
        fd: i32,
        statxbuf: u64,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        match self.fd_stat_record(fd) {
            Ok(record) => write_statx_record(memory, statxbuf, &record),
            Err(errno) => DispatchOutcome::errno(errno),
        }
    }

    fn fd_stat_record(&self, fd: i32) -> Result<StatRecord, i32> {
        let Some(open_file) = self.open_file(fd) else {
            if is_stdio_fd(fd) {
                let (label, mode) = self.stdio_synthetic_label_mode(fd);
                return Ok(StatRecord::synthetic(&label, 0, mode));
            }
            return Err(LINUX_EBADF);
        };
        let open = open_file.description.read();
        let source = open.stat_source();
        drop(open);
        match source {
            OpenStatSource::Record(record) => Ok(record),
            OpenStatSource::HostFile { host_fd, metadata } => {
                let path = metadata.path.to_string_lossy().into_owned();
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(host_fd, &mut st) } == 0 {
                    let mut real = super::real_stat_from_libc(&st);
                    // The real file's mode was forced owner-accessible; the
                    // guest-visible mode + owner live in xattrs on the same fd.
                    if let Some(m) = crate::fs_backend::fget_mode_xattr(host_fd) {
                        real.mode = m;
                    }
                    let (uid, gid) = crate::fs_backend::fget_owner_xattr(host_fd);
                    real.uid = uid.unwrap_or(0);
                    real.gid = gid.unwrap_or(0);
                    return Ok(StatRecord::from_real(&path, &real));
                }
                Ok(StatRecord::from_metadata(&metadata))
            }
        }
    }

    fn resolve_at_path(&self, dirfd: u64, path: &str) -> Result<String, i32> {
        // dirfd is an `int` in the kernel ABI: only the low 32 bits are
        // meaningful, and AT_FDCWD (-100) may arrive zero-extended (0xFFFFFF9C)
        // or sign-extended (0xFFFF..FF9C) depending on how the guest libc
        // widened it. Canonicalise via i32 so AT_FDCWD is recognised either
        // way (coreutils `ln` passed the zero-extended form → symlinkat/linkat
        // wrongly treated it as a real fd → EBADF).
        let dirfd = (dirfd as i32) as i64 as u64;
        if path.is_empty() {
            return Ok(path.to_owned());
        }
        if Path::new(path).is_absolute() {
            return Ok(join_rootfs_path("/", path));
        }
        if dirfd == LINUX_AT_FDCWD {
            let cwd = self.io.cwd.read().clone();
            return Ok(join_rootfs_path(&cwd, path));
        }

        match self.open_file(dirfd as i32).as_ref() {
            Some(open_file) => match &*open_file.description.read() {
                OpenDescription::Directory { path: dir, .. } => Ok(join_rootfs_path(dir, path)),
                OpenDescription::File { .. }
                | OpenDescription::HostFile { .. }
                | OpenDescription::SyntheticFile { .. }
                | OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. }
                | OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::Netlink { .. } => Err(LINUX_ENOTDIR),
            },
            None => Err(LINUX_EBADF),
        }
    }
}

impl SyscallDispatcher {
    define_syscall! {

        fn getcwd(this, cx, address: GuestPtr, size: u64) {

            let address = address.0;
            let size =
                usize::try_from(size).map_err(|_| DispatchError::LengthTooLarge(size))?;
            let mut bytes = this.io.cwd.read().as_bytes().to_vec();
            bytes.push(0);
            if bytes.len() > size {
                return Ok(LINUX_ERANGE.into());
            }
            if cx.memory.write_bytes(address, &bytes).is_err() {
                return Ok(LINUX_EFAULT.into());
            }
            // Linux getcwd(2) returns the LENGTH of the buffer filled (including
            // the terminating NUL), not the buffer address. glibc tolerates a
            // positive non-length, but tools that use the return value as a
            // length (and the kernel ABI) require the real count.
            Ok(DispatchOutcome::Returned {
                value: bytes.len() as i64,
            })

        }

        fn faccessat(this, cx, dirfd: u64, pathname: GuestPtr, mode: u64) {

            // Linux's `faccessat` (syscall 48) takes only (dirfd, pathname, mode).
            // The 4-arg form with flags is `faccessat2` (syscall 439). We were
            // erroneously reading x3 as flags here, which is whatever uninit
            // register state the caller had — making glibc see EINVAL for normal
            // access(F_OK)-style calls and abort with "stack smashing detected".
            this.access_at(dirfd, pathname.0, mode, 0, &*cx.memory)

        }

        fn faccessat2(this, cx, dirfd: u64, pathname: GuestPtr, mode: u64, flags: u64) {

            this.access_at(dirfd, pathname.0, mode, flags, &*cx.memory)

        }

        fn chdir(this, cx, pathname: GuestPtr) {

            let pathname = pathname.0;
            let path = match read_guest_c_string(&*cx.memory, pathname) {
                Ok(path) => path,
                Err(errno) => return Ok(errno.into()),
            };
            let path = match this.resolve_at_path(LINUX_AT_FDCWD, &path) {
                Ok(path) => path,
                Err(errno) => return Ok(errno.into()),
            };
            // Follow a trailing directory symlink the way Linux chdir(2) does,
            // THROUGH the full VFS — so a symlink whose target lands in a
            // different mount (e.g. a /tmp scratch link → /run bind mount)
            // resolves instead of returning ENOTDIR (the per-backend real_stat
            // only follows within one backend). getcwd then reports the resolved
            // target's canonical path, matching the kernel. Uses the LAYERED
            // lookup so a freshly mkdir'd dir is visible (dpkg-deb chdir).
            let resolved = match this.canonicalize_following(&path) {
                Ok(resolved) => resolved,
                Err(errno) => return Ok(errno.into()),
            };
            let metadata = match this.layered_metadata(&resolved) {
                Ok(metadata) => metadata,
                Err(errno) => return Ok(errno.into()),
            };
            if metadata.kind != RootFsEntryKind::Directory {
                return Ok(LINUX_ENOTDIR.into());
            }
            *this.io.cwd.write() = display_rootfs_path(&metadata.path);
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn fchdir(this, cx, fd: Fd) {

            let fd: Fd = fd;
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(LINUX_EBADF.into());
            };
            let open = open_file.description.read();
            Ok(match &*open {
                OpenDescription::Directory { metadata, .. } => {
                    *this.io.cwd.write() = display_rootfs_path(&metadata.path);
                    DispatchOutcome::Returned { value: 0 }
                }
                OpenDescription::File { .. }
                | OpenDescription::HostFile { .. }
                | OpenDescription::SyntheticFile { .. }
                | OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. }
                | OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::Netlink { .. } => DispatchOutcome::errno(LINUX_ENOTDIR),
            })

        }

        fn pipe2(this, cx, pipefd: GuestPtr, flags: u64) {

            let address = pipefd.0;
            let flags = flags;
            let memory = &mut *cx.memory;
            if flags & !(LINUX_O_CLOEXEC | LINUX_O_NONBLOCK) != 0 {
                return Ok(LINUX_EINVAL.into());
            }

            // Allocate a real host pipe so the two ends share state via the
            // kernel and survive `libc::fork(2)` natively. macOS's `pipe(2)`
            // returns two fds: [0] read end, [1] write end.
            let mut host_fds = [0i32; 2];
            if let Err(errno) = (unsafe { libc::pipe(host_fds.as_mut_ptr()) }).host_syscall_errno() {
                return Ok(errno.into());
            }

            let host_read = host_fds[0];
            let host_write = host_fds[1];

            // The access mode must be encoded per end so fcntl(F_GETFL) reports
            // it: the read end is O_RDONLY (0), the write end O_WRONLY. Without
            // this, glibc's fdopen(write_end, "w") sees O_RDONLY via F_GETFL and
            // fails with EINVAL ("Failed to open new FD - fdopen") — apt's dpkg
            // status pipe hit exactly that.
            let nonblock = flags & LINUX_O_NONBLOCK;
            // pipe2(2)'s O_NONBLOCK must take effect on the actual pipe ends.
            // The read/write path does a raw libc::read/write on the host fd and
            // relies on its blocking mode — `status_flags` is only bookkeeping
            // for F_GETFL. Without applying it here a nonblocking read on an
            // empty pipe blocks the supervisor forever (matches what
            // fcntl(F_SETFL) already does for the apt http-method path).
            if nonblock != 0 {
                for hfd in [host_read, host_write] {
                    unsafe {
                        let cur = libc::fcntl(hfd, libc::F_GETFL, 0);
                        if cur >= 0 {
                            libc::fcntl(hfd, libc::F_SETFL, cur | libc::O_NONBLOCK);
                        }
                    }
                }
            }
            let fd_flags = linux_fd_flags_from_open_flags(flags);
            let read_open = OpenFile::with_host_fd(
                Arc::new(RwLock::new(OpenDescription::HostPipe {
                    host_fd: host_read,
                    is_read_end: true,
                    base: OpenDescriptionBase::new(LINUX_O_RDONLY | nonblock),
                    pty: None,
                })),
                fd_flags,
                host_read,
            );
            let write_open = OpenFile::with_host_fd(
                Arc::new(RwLock::new(OpenDescription::HostPipe {
                    host_fd: host_write,
                    is_read_end: false,
                    base: OpenDescriptionBase::new(LINUX_O_WRONLY | nonblock),
                    pty: None,
                })),
                fd_flags,
                host_write,
            );
            let Ok((read_fd, write_fd)) = this.install_fd_pair_at_or_above(3, read_open, write_open)
            else {
                return Ok(linux_errno::EMFILE.into());
            };
            let pair = LinuxFdPair { read_fd, write_fd };
            if write_kernel_struct_raw(memory, address, &pair).is_err() {
                let removed = {
                    let mut table = this.io.open_files.write();
                    [table.remove(&read_fd), table.remove(&write_fd)]
                };
                for open_file in removed.into_iter().flatten() {
                    this.close_open_file_and_free_pty(&open_file);
                }
                return Ok(LINUX_EFAULT.into());
            }

            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn dup(this, cx, fd: Fd) {

            let old_fd: Fd = fd;
            Ok(this.duplicate_fd(old_fd.0, 3, 0))

        }

        fn dup3(this, cx, oldfd: Fd, newfd: Fd, flags: u64) {

            let old_fd: Fd = oldfd;
            let new_fd: Fd = newfd;
            let flags = flags;
            // Linux dup3 only honours O_CLOEXEC in `flags` (else EINVAL), and
            // new_fd must be a valid descriptor number: out of range (negative or
            // >= RLIMIT_NOFILE soft limit) is EBADF, NOT EINVAL. old_fd == new_fd
            // is EINVAL (dup2 handles that case in glibc without reaching here).
            // new_fd 0/1/2 is allowed — that's how shells redirect std streams.
            const RLIMIT_NOFILE_CUR: i32 = 1024;
            if flags & !LINUX_O_CLOEXEC != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if !(0..RLIMIT_NOFILE_CUR).contains(&new_fd.0) {
                return Ok(LINUX_EBADF.into());
            }
            if old_fd.0 == new_fd.0 {
                return Ok(LINUX_EINVAL.into());
            }
            let (description, host_fd_owner) = match this.open_file(old_fd.0).as_ref() {
                Some(open_file) => (
                    Arc::clone(&open_file.description),
                    open_file.host_fd_owner.clone(),
                ),
                None if is_stdio_fd(old_fd.0) => {
                    // Shell `2>&1` style redirects: the source fd is the
                    // process's real host fd 0/1/2 (no OpenDescription was
                    // ever created for them — writes go straight through
                    // stream_stdio). dup3 onto a different fd needs to
                    // capture that host fd so future writes/reads also
                    // reach the same host endpoint. Duplicate the host fd
                    // and wrap it as a HostPipe so the write path picks it
                    // up before the bare-stdio fallback.
                    let duped = match (unsafe { libc::dup(old_fd.0) }).host_syscall_errno() {
                        Ok(duped) => duped,
                        Err(errno) => return Ok(errno.into()),
                    };
                    (
                        Arc::new(RwLock::new(OpenDescription::HostPipe {
                            host_fd: duped,
                            is_read_end: old_fd.0 == 0,
                            base: OpenDescriptionBase::new(0),
                            pty: None,
                        })),
                        Some(HostFdRef::new(duped)),
                    )
                }
                None => return Ok(LINUX_EBADF.into()),
            };
            let mut table = this.io.open_files.write();
            if let Some(replaced) = table.remove(&new_fd.0) {
                close_open_file(&replaced);
            }
            retain_open_file(&description);
            table.insert(
                new_fd.0,
                OpenFile {
                    description,
                    fd_flags: linux_fd_flags_from_open_flags(flags),
                    host_fd_owner,
                },
            );
            Ok(DispatchOutcome::Returned {
                value: new_fd.0 as i64,
            })

        }

        fn fcntl(this, cx, fd: Fd, cmd: u64, arg: u64) {

            let fd: Fd = fd;
            let command = cmd;
            let arg = arg;
            Ok(match command {
                LINUX_F_DUPFD => match linux_min_fd(arg) {
                    Ok(min_fd) => this.duplicate_fd(fd.0, min_fd, 0),
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_F_DUPFD_CLOEXEC => match linux_min_fd(arg) {
                    Ok(min_fd) => this.duplicate_fd(fd.0, min_fd, LINUX_FD_CLOEXEC),
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_F_GETPIPE_SZ => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(LINUX_EBADF.into());
                    };
                    match &*open_file.description.read() {
                        OpenDescription::PipeReader { .. }
                        | OpenDescription::PipeWriter { .. }
                        | OpenDescription::HostPipe { .. } => DispatchOutcome::Returned {
                            value: LINUX_PIPE_BUF_SIZE,
                        },
                        OpenDescription::HostSocket { .. } => DispatchOutcome::errno(LINUX_EBADF),
                        _ => DispatchOutcome::errno(LINUX_EBADF),
                    }
                }
                LINUX_F_GETFD => {
                    if let Some(open_file) = this.open_file(fd.0) {
                        return Ok(DispatchOutcome::Returned {
                            value: open_file.fd_flags as i64,
                        });
                    }
                    // stdio without an OpenDescription: stdio is not CLOEXEC by
                    // default (Linux: stdio survives exec), but a prior
                    // F_SETFD FD_CLOEXEC must be reflected back. Read the
                    // remembered per-stdio-fd bit.
                    if is_stdio_fd(fd.0) {
                        let bit = if this.io.stdio_cloexec.lock()[fd.0 as usize] {
                            LINUX_FD_CLOEXEC as i64
                        } else {
                            0
                        };
                        return Ok(DispatchOutcome::Returned { value: bit });
                    }
                    DispatchOutcome::errno(LINUX_EBADF)
                }
                LINUX_F_SETFD => {
                    let fd_flags = LinuxFdFlags::from_bits_truncate(arg);
                    if let Some(open_file) = this.io.open_files.write().get_mut(&fd.0) {
                        open_file.fd_flags = fd_flags.bits();
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    // apt's http method fcntl(fd, F_SETFD, FD_CLOEXEC)s its
                    // inherited stdio fds on startup. Returning EBADF here
                    // makes apt abort with "Could not set close on exec".
                    // Carrick's exec inherits stdio via the host fd directly;
                    // CLOEXEC is largely cosmetic for our model (we don't exec
                    // anything host-side after the syscall returns) but we
                    // remember the bit so a subsequent F_GETFD reflects it,
                    // matching real Linux.
                    if is_stdio_fd(fd.0) {
                        this.io.stdio_cloexec.lock()[fd.0 as usize] =
                            fd_flags.contains(LinuxFdFlags::CLOEXEC);
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    DispatchOutcome::errno(LINUX_EBADF)
                }
                LINUX_F_GETFL => {
                    if let Some(open_file) = this.open_file(fd.0) {
                        let open = open_file.description.read();
                        let mut flags = open.status_flags();
                        // A pty end is bidirectional (opened O_RDWR); report the
                        // O_RDWR access mode rather than the default O_RDONLY (0),
                        // so libc/readline see a read-write terminal.
                        if matches!(&*open, OpenDescription::HostPipe { pty: Some(_), .. }) {
                            flags |= LINUX_O_RDWR;
                        }
                        return Ok(DispatchOutcome::Returned {
                            value: flags as i64,
                        });
                    }
                    // stdio without an OpenDescription: glibc cat/head/etc
                    // probe `fcntl(1, F_GETFL)` on startup to decide whether
                    // stdout is append-only. Returning O_RDWR (with the
                    // appropriate direction for fd 0 vs 1/2) keeps them happy
                    // instead of bailing with "Bad file descriptor".
                    if is_stdio_fd(fd.0) {
                        let flags: u64 = if fd.0 == 0 {
                            LINUX_O_RDONLY
                        } else {
                            LINUX_O_WRONLY
                        };
                        return Ok(DispatchOutcome::Returned {
                            value: flags as i64,
                        });
                    }
                    DispatchOutcome::errno(LINUX_EBADF)
                }
                LINUX_F_SETFL => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        // Bare stdio (0/1/2) has no OpenDescription, but real Linux
                        // lets you fcntl(F_SETFL) on stdin/stdout/stderr. apt's dpkg
                        // child sets stdin non-blocking via fcntl(0, F_SETFL,
                        // O_NONBLOCK) before exec and treats EBADF as fatal — it
                        // _exit(100)'d, failing `apt install` ("Sub-process dpkg
                        // returned an error code (100)"). Accept it, propagating
                        // O_NONBLOCK to the real host stdio fd when the guest's
                        // stdio is wired to our host fds (stream_stdio / --raw),
                        // mirroring the F_GETFD/F_SETFD/F_GETFL stdio special-cases.
                        if is_stdio_fd(fd.0) {
                            if *this.io.stream_stdio.lock() {
                                let want_nonblock = arg & LINUX_O_NONBLOCK != 0;
                                unsafe {
                                    let cur = libc::fcntl(fd.0, libc::F_GETFL, 0);
                                    if cur >= 0 {
                                        let next = if want_nonblock {
                                            cur | libc::O_NONBLOCK
                                        } else {
                                            cur & !libc::O_NONBLOCK
                                        };
                                        if next != cur {
                                            libc::fcntl(fd.0, libc::F_SETFL, next);
                                        }
                                    }
                                }
                            }
                            return Ok(DispatchOutcome::Returned { value: 0 });
                        }
                        return Ok(LINUX_EBADF.into());
                    };
                    let next_flags = arg & !LINUX_O_CLOEXEC;
                    // Propagate O_NONBLOCK to the underlying host fd when one
                    // exists. Without this, our libc::read still blocks even
                    // after the guest set O_NONBLOCK — apt's http method
                    // depends on this for the pselect6 wait pattern.
                    let open = open_file.description.read();
                    if let Some(host_fd) = match &*open {
                        OpenDescription::HostPipe { host_fd, .. }
                        | OpenDescription::HostSocket { host_fd, .. } => Some(*host_fd),
                        _ => None,
                    } {
                        let want_nonblock = next_flags & LINUX_O_NONBLOCK != 0;
                        unsafe {
                            let cur = libc::fcntl(host_fd, libc::F_GETFL, 0);
                            if cur >= 0 {
                                let next = if want_nonblock {
                                    cur | libc::O_NONBLOCK
                                } else {
                                    cur & !libc::O_NONBLOCK
                                };
                                if next != cur {
                                    libc::fcntl(host_fd, libc::F_SETFL, next);
                                }
                            }
                        }
                    }
                    drop(open);
                    open_file.description.write().set_status_flags(next_flags);
                    DispatchOutcome::Returned { value: 0 }
                }
                // Advisory record locks: apt uses fcntl(F_SETLK) on
                // /var/lib/apt/lists/lock as its inter-process lock. Carrick
                // runs the guest as a single-tenant VM (no real concurrent
                // apt invocations against the same overlay), so we treat the
                // whole F_*LK family as no-op success. Without this apt
                // reports "Could not get lock ... open (22: Invalid argument)"
                // because the F_SETLK that follows the openat is what
                // actually fails — apt's error message just blames open.
                LINUX_F_SETLK | LINUX_F_SETLKW | LINUX_F_OFD_SETLK | LINUX_F_OFD_SETLKW => {
                    if !this.fd_is_valid(fd.0) {
                        return Ok(LINUX_EBADF.into());
                    }
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_F_GETLK | LINUX_F_OFD_GETLK => {
                    // Indicate "no lock present" by leaving the caller's
                    // struct flock untouched and returning 0. apt only ever
                    // probes after a successful SETLK so it doesn't
                    // re-inspect the buffer.
                    if !this.fd_is_valid(fd.0) {
                        return Ok(LINUX_EBADF.into());
                    }
                    DispatchOutcome::Returned { value: 0 }
                }
                _ => DispatchOutcome::errno(LINUX_EINVAL),
            })

        }

        fn ioctl(this, cx, fd: Fd, request: u64, arg: u64) {

            let fd: Fd = fd;
            let ioctl_request = request;
            let arg = arg;
            if !this.fd_is_valid(fd.0) {
                return Ok(LINUX_EBADF.into());
            }

            // ── Rosetta 2 virtualization handshake ──────────────────────────────────
            // At startup Apple's Rosetta issues a small set of ioctls on its
            // /proc/.../exe fd to confirm it is running inside an Apple
            // virtualization environment. The size field (bits [29:16]) of the
            // request encodes the expected response length. The licensing ioctl
            // (...6125) is `memcmp`'d against a verification string Rosetta keeps
            // embedded in its own binary — so we echo back exactly that blob,
            // read live from the installed Rosetta binary (never embedded in
            // carrick). The info ioctl (...6123) is not compared; Rosetta only
            // requires a non-negative return, so a zeroed buffer suffices.
            if let Some(outcome) =
                rosetta_handshake_ioctl(&mut *cx.memory, ioctl_request, arg)
            {
                return Ok(outcome);
            }

            // ── PTY ioctls ────────────────────────────────────────────────────────
            // If this fd is a pty master or slave, handle all tty ioctls here by
            // passing through to the host fd (real macOS pty). Return early so the
            // stdio-gated arms below never run for pty fds.
            if let Some((role, host_fd)) = this.pty_info(fd.0) {
                return Ok(match ioctl_request {
                    LINUX_TIOCGPTN => write_packed(&mut *cx.memory, arg, &role.index.to_le_bytes()),
                    LINUX_TIOCSPTLCK => {
                        let mut buf = [0u8; 4];
                        match cx.memory.read_bytes(arg, 4) {
                            Ok(b) => buf.copy_from_slice(&b),
                            Err(_) => {
                                return Ok(LINUX_EFAULT.into());
                            }
                        }
                        let lock = i32::from_le_bytes(buf) != 0;
                        this.pty_table().lock().set_locked(role.index, lock);
                        DispatchOutcome::Returned { value: 0 }
                    }
                    LINUX_TCGETS => {
                        let termios = crate::host_tty::get_host_termios(host_fd)
                            .unwrap_or_else(LinuxTermios::default_cooked);
                        write_kernel_struct(&mut *cx.memory, arg, &termios)
                    }
                    LINUX_TCSETS | LINUX_TCSETSW | LINUX_TCSETSF => {
                        match cx.memory.read_bytes(arg, LINUX_TERMIOS_KERNEL_SIZE) {
                            Ok(bytes) => {
                                let mut padded = [0u8; core::mem::size_of::<LinuxTermios>()];
                                padded[..LINUX_TERMIOS_KERNEL_SIZE].copy_from_slice(&bytes);
                                match LinuxTermios::read_from_bytes(&padded) {
                                    Ok(t) => {
                                        let _ = crate::host_tty::set_host_termios(host_fd, &t);
                                        DispatchOutcome::Returned { value: 0 }
                                    }
                                    Err(_) => DispatchOutcome::errno(LINUX_EINVAL),
                                }
                            }
                            Err(_) => DispatchOutcome::errno(LINUX_EFAULT),
                        }
                    }
                    LINUX_TIOCGWINSZ => {
                        let ws = crate::host_tty::get_host_winsize(host_fd)
                            .unwrap_or_else(LinuxWinsize::terminal_80x24);
                        write_kernel_struct(&mut *cx.memory, arg, &ws)
                    }
                    LINUX_TIOCSWINSZ => {
                        match cx.memory.read_bytes(arg, 8) {
                            Ok(b) => {
                                let mut ws: libc::winsize = unsafe { core::mem::zeroed() };
                                ws.ws_row = u16::from_le_bytes([b[0], b[1]]);
                                ws.ws_col = u16::from_le_bytes([b[2], b[3]]);
                                ws.ws_xpixel = u16::from_le_bytes([b[4], b[5]]);
                                ws.ws_ypixel = u16::from_le_bytes([b[6], b[7]]);
                                // SAFETY: host_fd is our live pty fd; &ws is valid.
                                let r = unsafe {
                                    libc::ioctl(host_fd, libc::TIOCSWINSZ as libc::c_ulong, &ws)
                                };
                                if r < 0 {
                                    DispatchOutcome::errno(crate::dispatch::macos_to_linux_errno(
                                        unsafe { *libc::__error() },
                                    ))
                                } else {
                                    DispatchOutcome::Returned { value: 0 }
                                }
                            }
                            Err(_) => DispatchOutcome::errno(LINUX_EFAULT),
                        }
                    }
                    LINUX_TIOCGPGRP => {
                        // SAFETY: host_fd is our live pty fd.
                        let pgrp = unsafe { libc::tcgetpgrp(host_fd) };
                        if pgrp < 0 {
                            DispatchOutcome::errno(crate::dispatch::macos_to_linux_errno(unsafe {
                                *libc::__error()
                            }))
                        } else {
                            write_packed(&mut *cx.memory, arg, &(pgrp as i32).to_le_bytes())
                        }
                    }
                    LINUX_TIOCSPGRP => {
                        let mut buf = [0u8; 4];
                        match cx.memory.read_bytes(arg, 4) {
                            Ok(b) => buf.copy_from_slice(&b),
                            Err(_) => {
                                return Ok(LINUX_EFAULT.into());
                            }
                        }
                        let pgrp = i32::from_le_bytes(buf);
                        // SAFETY: host_fd is our live pty fd.
                        let r = unsafe { libc::tcsetpgrp(host_fd, pgrp) };
                        if r < 0 {
                            DispatchOutcome::errno(crate::dispatch::macos_to_linux_errno(unsafe {
                                *libc::__error()
                            }))
                        } else {
                            DispatchOutcome::Returned { value: 0 }
                        }
                    }
                    LINUX_TIOCSCTTY => {
                        // SAFETY: host_fd is our live pty fd. Best-effort.
                        unsafe { libc::ioctl(host_fd, libc::TIOCSCTTY as libc::c_ulong, 0i32) };
                        DispatchOutcome::Returned { value: 0 }
                    }
                    _ => {
                        cx.reporter
                            .record(CompatEvent::unhandled_ioctl(fd.0, ioctl_request, arg));
                        DispatchOutcome::errno(LINUX_ENOTTY)
                    }
                });
            }

            Ok(match ioctl_request {
                LINUX_TIOCGWINSZ if fd_is_tty(&this.io.open_files.read(), fd.0) => {
                    // Prefer the live host window size when stdin/stdout/stderr
                    // is a real macOS terminal; fall back to the 80x24 stub so
                    // headless invocations (CI, redirected pipes that we still
                    // synthesize a TTY for in tests) keep prior behaviour.
                    let winsize = if crate::host_tty::host_isatty(fd.0) {
                        crate::host_tty::get_host_winsize(fd.0)
                            .unwrap_or_else(LinuxWinsize::terminal_80x24)
                    } else {
                        LinuxWinsize::terminal_80x24()
                    };
                    write_kernel_struct(&mut *cx.memory, arg, &winsize)
                }
                LINUX_TIOCGWINSZ => DispatchOutcome::errno(LINUX_ENOTTY),
                LINUX_TCGETS if fd_is_tty(&this.io.open_files.read(), fd.0) => {
                    // Mirror the live host terminal modes when available so
                    // `less`, `vi`, and an interactive shell see the actual
                    // ICANON/ECHO state the user has configured.
                    let termios = if crate::host_tty::host_isatty(fd.0) {
                        crate::host_tty::get_host_termios(fd.0)
                            .unwrap_or_else(LinuxTermios::default_cooked)
                    } else {
                        LinuxTermios::default_cooked()
                    };
                    // KernelAbi for LinuxTermios pins this at 36 bytes —
                    // the kernel-ABI termios size, NOT our 44-byte Rust
                    // struct (which includes the termios2-only ispeed/ospeed
                    // tail). Going past 36 here is what blew glibc's
                    // tcgetattr canary and crashed ls/dpkg.
                    write_kernel_struct(&mut *cx.memory, arg, &termios)
                }
                LINUX_TCGETS => DispatchOutcome::errno(LINUX_ENOTTY),
                LINUX_TCSETS | LINUX_TCSETSW | LINUX_TCSETSF
                    if fd_is_tty(&this.io.open_files.read(), fd.0) =>
                {
                    // Read 36 bytes (kernel termios), then pad to the
                    // 44-byte zerocopy struct so we can parse it. The guest
                    // only provided a 36-byte buffer; reading 44 would
                    // EFAULT at the boundary of a stack-page allocation.
                    match cx.memory.read_bytes(arg, LINUX_TERMIOS_KERNEL_SIZE) {
                        Ok(bytes) => {
                            if crate::host_tty::host_isatty(fd.0) {
                                let mut padded = [0u8; core::mem::size_of::<LinuxTermios>()];
                                padded[..LINUX_TERMIOS_KERNEL_SIZE].copy_from_slice(&bytes);
                                if let Ok(t) = LinuxTermios::read_from_bytes(&padded) {
                                    let _ = crate::host_tty::set_host_termios_tracking(fd.0, &t);
                                }
                            }
                            DispatchOutcome::Returned { value: 0 }
                        }
                        Err(_) => DispatchOutcome::errno(LINUX_EFAULT),
                    }
                }
                LINUX_TCSETS | LINUX_TCSETSW | LINUX_TCSETSF => DispatchOutcome::errno(LINUX_ENOTTY),
                LINUX_TIOCSCTTY => match this.tty_ioctl_fd_kind(fd.0) {
                    Ok(TtyFdKind::Stdio) => DispatchOutcome::Returned { value: 0 },
                    Ok(TtyFdKind::Other) => DispatchOutcome::errno(LINUX_ENOTTY),
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_TIOCGPGRP => match this.tty_ioctl_fd_kind(fd.0) {
                    Ok(TtyFdKind::Stdio) => {
                        // Under `-t` fd 0/1/2 is a real pty slave: pass through to
                        // the host line discipline so job control works correctly.
                        // Guest pgrps are real macOS pgrps in carrick.
                        if crate::host_tty::host_isatty(fd.0) {
                            match crate::host_tty::host_tty_tcgetpgrp(fd.0) {
                                Ok(pgrp) => write_packed(&mut *cx.memory, arg, &pgrp.to_le_bytes()),
                                Err(raw_errno) => DispatchOutcome::errno(
                                    crate::dispatch::macos_to_linux_errno(raw_errno),
                                ),
                            }
                        } else {
                            // Headless / non-tty fallback: synthesise bootstrap pgid.
                            write_packed(&mut *cx.memory, arg, &LINUX_BOOTSTRAP_PGID.to_le_bytes())
                        }
                    }
                    Ok(TtyFdKind::Other) => DispatchOutcome::errno(LINUX_ENOTTY),
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_TIOCSPGRP => match this.tty_ioctl_fd_kind(fd.0) {
                    Ok(TtyFdKind::Stdio) => {
                        let mut buf = [0u8; 4];
                        match cx.memory.read_bytes(arg, 4) {
                            Ok(bytes) => buf.copy_from_slice(&bytes),
                            Err(_) => {
                                return Ok(LINUX_EFAULT.into());
                            }
                        }
                        let pgid = i32::from_le_bytes(buf);
                        // Under `-t` fd 0/1/2 is a real pty slave: pass through so
                        // the host line discipline tracks the foreground pgrp, enabling
                        // Ctrl-C → SIGINT delivery to the correct guest pgrp.
                        if crate::host_tty::host_isatty(fd.0) {
                            match crate::host_tty::host_tty_tcsetpgrp(fd.0, pgid) {
                                Ok(()) => DispatchOutcome::Returned { value: 0 },
                                Err(raw_errno) => DispatchOutcome::errno(
                                    crate::dispatch::macos_to_linux_errno(raw_errno),
                                ),
                            }
                        } else {
                            // Headless fallback: accept the bootstrap pgid, EPERM others.
                            if pgid == LINUX_BOOTSTRAP_PGID {
                                DispatchOutcome::Returned { value: 0 }
                            } else {
                                DispatchOutcome::errno(LINUX_EPERM)
                            }
                        }
                    }
                    Ok(TtyFdKind::Other) => DispatchOutcome::errno(LINUX_ENOTTY),
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_FIONREAD => {
                    // Stdio, eventfd, timerfd, epoll, pipe writer, directory, regular file,
                    // synthetic file: writing 0 ("nothing pending") is benign. Pipe reader
                    // gets the actual buffered byte count.
                    let available: i32 = match this.open_file(fd.0).as_ref() {
                        Some(open_file) => match &*open_file.description.read() {
                            OpenDescription::PipeReader { pipe, .. } => {
                                let len = pipe.lock().buffer.len();
                                i32::try_from(len).unwrap_or(i32::MAX)
                            }
                            _ => 0,
                        },
                        // stdio fd (already validated above) or any other valid fd: 0.
                        None => 0,
                    };
                    write_packed(&mut *cx.memory, arg, &available.to_le_bytes())
                }
                LINUX_FIONBIO => {
                    let Ok(bytes) = cx.memory.read_bytes(arg, 4) else {
                        return Ok(LINUX_EFAULT.into());
                    };
                    let enable = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) != 0;
                    if let Some(open_file) = this.open_file(fd.0) {
                        let mut open = open_file.description.write();
                        let mut status_flags = open.status_flags();
                        if enable {
                            status_flags |= LINUX_O_NONBLOCK;
                        } else {
                            status_flags &= !LINUX_O_NONBLOCK;
                        }
                        open.set_status_flags(status_flags);
                        let host_fd = match &*open {
                            OpenDescription::HostPipe { host_fd, .. }
                            | OpenDescription::HostSocket { host_fd, .. }
                            | OpenDescription::HostFile { host_fd, .. } => Some(*host_fd),
                            _ => None,
                        };
                        if let Some(host_fd) = host_fd {
                            unsafe {
                                let cur = libc::fcntl(host_fd, libc::F_GETFL, 0);
                                if cur >= 0 {
                                    let next = if enable {
                                        cur | libc::O_NONBLOCK
                                    } else {
                                        cur & !libc::O_NONBLOCK
                                    };
                                    libc::fcntl(host_fd, libc::F_SETFL, next);
                                }
                            }
                        }
                    }
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_TIOCNOTTY => match this.tty_ioctl_fd_kind(fd.0) {
                    Ok(TtyFdKind::Stdio) => DispatchOutcome::Returned { value: 0 },
                    Ok(TtyFdKind::Other) => DispatchOutcome::errno(LINUX_ENOTTY),
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_TIOCGSID => match this.tty_ioctl_fd_kind(fd.0) {
                    Ok(TtyFdKind::Stdio) => {
                        // Under `-t` stdio is a real pty slave. Ask Darwin for
                        // the controlling session instead of returning Carrick's
                        // bootstrap fallback, so interactive job-control probes
                        // see the host pty state when it exists.
                        if crate::host_tty::host_isatty(fd.0) {
                            match crate::host_tty::host_tty_tcgetsid(fd.0) {
                                Ok(sid) => write_packed(&mut *cx.memory, arg, &sid.to_le_bytes()),
                                Err(raw_errno) => DispatchOutcome::errno(
                                    crate::dispatch::macos_to_linux_errno(raw_errno),
                                ),
                            }
                        } else {
                            write_packed(&mut *cx.memory, arg, &LINUX_BOOTSTRAP_SID.to_le_bytes())
                        }
                    }
                    Ok(TtyFdKind::Other) => DispatchOutcome::errno(LINUX_ENOTTY),
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                _ => {
                    cx.reporter
                        .record(CompatEvent::unhandled_ioctl(fd.0, ioctl_request, arg));
                    DispatchOutcome::errno(LINUX_ENOTTY)
                }
            })

        }

        fn flock(this, cx, fd: Fd, operation: u64) {

            let fd: Fd = fd;
            let operation = operation;
            if !this.fd_is_valid(fd.0) {
                return Ok(LINUX_EBADF.into());
            }

            let lock_operation = operation & !LINUX_LOCK_NB;
            Ok(match lock_operation {
                LINUX_LOCK_SH | LINUX_LOCK_EX | LINUX_LOCK_UN => DispatchOutcome::Returned { value: 0 },
                _ => DispatchOutcome::errno(LINUX_EINVAL),
            })

        }

        fn fallocate(this, cx, fd: Fd, mode: u64, offset: u64, len: u64) {

            let fd: Fd = fd;
            let mode = mode;
            let offset = i64::from_ne_bytes(offset.to_ne_bytes());
            let length = i64::from_ne_bytes(len.to_ne_bytes());
            if mode & !LINUX_FALLOC_FL_SUPPORTED != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if length <= 0 || offset < 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if is_stdio_fd(fd.0) {
                return Ok(LINUX_ESPIPE.into());
            }
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(LINUX_EBADF.into());
            };
            // Only mode-0 (default allocation) is implemented as a real grow;
            // FALLOC_FL_KEEP_SIZE preallocates without changing the apparent
            // size, which on a tmpfs/host-backed file is a no-op success.
            let grow = mode & LINUX_FALLOC_FL_KEEP_SIZE == 0;
            let new_size = (offset as u64).saturating_add(length as u64);
            // Snapshot the writeback path/contents in a scope so the borrow
            // drops before we touch this.fs.rootfs_vfs.overlay (mirrors ftruncate).
            let writeback: Option<(String, Vec<u8>)>;
            let outcome: DispatchOutcome;
            {
                let mut open = open_file.description.write();
                match &mut *open {
                    OpenDescription::File {
                        contents, metadata, ..
                    } if grow => {
                        // In-memory model (--fs memory): grow the cached bytes.
                        if new_size > crate::vfs::MAX_IN_MEMORY_FILE_SIZE {
                            return Ok(LINUX_EFBIG.into());
                        }
                        if new_size as usize > contents.len() {
                            contents.resize(new_size as usize, 0);
                            metadata.size = contents.len();
                        }
                        writeback = None;
                        outcome = DispatchOutcome::Returned { value: 0 };
                    }
                    OpenDescription::File { .. } => {
                        // KEEP_SIZE: don't change apparent size.
                        writeback = None;
                        outcome = DispatchOutcome::Returned { value: 0 };
                    }
                    OpenDescription::HostFile { host_fd, .. } => {
                        // Real fd into the cap-std scratch: grow with ftruncate
                        // (the change is visible across fork). KEEP_SIZE → no-op.
                        if grow {
                            let mut st: libc::stat = unsafe { core::mem::zeroed() };
                            if let Err(errno) =
                                (unsafe { libc::fstat(*host_fd, &mut st) }).host_syscall_errno()
                            {
                                return Ok(errno.into());
                            }
                            if new_size > st.st_size as u64 {
                                if let Err(errno) =
                                    (unsafe { libc::ftruncate(*host_fd, new_size as libc::off_t) })
                                        .host_syscall_errno()
                                {
                                    return Ok(errno.into());
                                }
                            }
                        }
                        writeback = None;
                        outcome = DispatchOutcome::Returned { value: 0 };
                    }
                    OpenDescription::SyntheticFile { .. } => {
                        return Ok(LINUX_EROFS.into());
                    }
                    OpenDescription::Directory { .. } => {
                        return Ok(LINUX_EISDIR.into());
                    }
                    _ => {
                        return Ok(LINUX_ESPIPE.into());
                    }
                }
            }
            if let Some((path, contents)) = writeback {
                let _ = this
                    .fs
                    .rootfs_vfs
                    .overlay
                    .set_file_contents(&path, contents);
            }
            Ok(outcome)

        }

        fn ftruncate(this, cx, fd: Fd, length: u64) {

            let fd: Fd = fd;
            let length = i64::from_ne_bytes(length.to_ne_bytes());
            if length < 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if is_stdio_fd(fd.0) {
                return Ok(LINUX_EINVAL.into());
            }
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(LINUX_EBADF.into());
            };
            // Snapshot the path + new contents in a scope so the borrow drops
            // before we touch this.fs.rootfs_vfs.overlay.
            let writeback: Option<(String, Vec<u8>)>;
            let outcome: DispatchOutcome;
            {
                let mut open = open_file.description.write();
                match &mut *open {
                    OpenDescription::File {
                        path,
                        contents,
                        offset,
                        writable,
                        metadata,
                        ..
                    } => {
                        if !*writable {
                            return Ok(LINUX_EBADF.into());
                        }
                        if length as u64 > crate::vfs::MAX_IN_MEMORY_FILE_SIZE {
                            return Ok(LINUX_EFBIG.into());
                        }
                        let new_len = length as usize;
                        if new_len > contents.len() {
                            contents.resize(new_len, 0);
                        } else {
                            contents.truncate(new_len);
                            if *offset > new_len {
                                *offset = new_len;
                            }
                        }
                        metadata.size = contents.len();
                        writeback = Some((path.clone(), contents.clone()));
                        outcome = DispatchOutcome::Returned { value: 0 };
                    }
                    OpenDescription::HostFile {
                        host_fd, writable, ..
                    } => {
                        if !*writable {
                            return Ok(LINUX_EBADF.into());
                        }
                        // Real fd: ftruncate the kernel file directly (the
                        // change is visible across fork).
                        if let Err(errno) =
                            (unsafe { libc::ftruncate(*host_fd, length as libc::off_t) })
                                .host_syscall_errno()
                        {
                            return Ok(errno.into());
                        }
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    OpenDescription::SyntheticFile { .. } => {
                        return Ok(LINUX_EBADF.into());
                    }
                    OpenDescription::Directory { .. } => {
                        return Ok(LINUX_EISDIR.into());
                    }
                    _ => {
                        return Ok(LINUX_EINVAL.into());
                    }
                }
            }
            if let Some((path, contents)) = writeback {
                let _ = this
                    .fs
                    .rootfs_vfs
                    .overlay
                    .set_file_contents(&path, contents);
            }
            Ok(outcome)

        }

        fn openat(this, cx, dirfd: u64, pathname: GuestPtr, flags: u64, mode: u64) {

            let dirfd = dirfd;
            let pathname = pathname.0;
            let flags = flags;
            let mode = mode;
            this.open_at_path(dirfd, pathname, flags, mode, &*cx.memory, cx.reporter)

        }

        fn openat2(this, cx, dirfd: u64, pathname: GuestPtr, how: GuestPtr, size: u64) {

            let how_address = how.0;
            let size = size;
            let arg0 = dirfd;
            let arg1 = pathname.0;
            if size != LINUX_OPEN_HOW_SIZE {
                return Ok(LINUX_EINVAL.into());
            }
            let how = match read_open_how(&*cx.memory, how_address) {
                Ok(how) => how,
                Err(errno) => return Ok(errno.into()),
            };
            if how.mode != 0
                || how.resolve != 0
                || how.flags & !(LINUX_O_CLOEXEC | LINUX_O_NONBLOCK) != 0
            {
                return Ok(LINUX_EINVAL.into());
            }
            this.open_at_path(arg0, arg1, how.flags, how.mode, &*cx.memory, cx.reporter)

        }

        fn close(this, cx, fd: Fd) {

            let fd: Fd = fd;
            Ok(
                if let Some(open_file) = this.io.open_files.write().remove(&fd.0) {
                    // Centralised close: frees the host fd and, for pty masters,
                    // removes the /dev/pts/N entry from the PtyTable so it becomes
                    // ENOENT — mirroring Linux devpts semantics. The same helper is
                    // used by close_range and close_cloexec_fds so every close path
                    // stays in sync.
                    this.close_open_file_and_free_pty(&open_file);
                    DispatchOutcome::Returned { value: 0 }
                } else if is_stdio_fd(fd.0) {
                    // Guest closing its own stdio at exit: there's nothing for
                    // us to do (host fd stays open under stream_stdio so
                    // sibling processes keep working), but reporting EBADF
                    // here makes glibc print "write error: Bad file descriptor"
                    // after the program's real output. Return success.
                    DispatchOutcome::Returned { value: 0 }
                } else {
                    DispatchOutcome::errno(LINUX_EBADF)
                },
            )

        }

        fn close_range(this, cx, first: u64, last: u64, flags: u64) {

            let first = first;
            let last = last;
            let flags = flags;
            // CLOSE_RANGE_UNSHARE=2 is a no-op for us (single fd table);
            // CLOSE_RANGE_CLOEXEC=4 would mark fds CLOEXEC instead of
            // closing — accept the bit and apply CLOEXEC.
            const CLOSE_RANGE_UNSHARE: u64 = 2;
            const CLOSE_RANGE_CLOEXEC: u64 = 4;
            if flags & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 || first > last {
                return Ok(LINUX_EINVAL.into());
            }
            let cloexec_only = flags & CLOSE_RANGE_CLOEXEC != 0;
            // Drain matching fds out of the table so we don't iterate a
            // gigantic [first, last] (callers commonly pass last=u32::MAX).
            let fds: Vec<i32> = this
                .io
                .open_files
                .read()
                .keys()
                .copied()
                .filter(|fd| (*fd as u64) >= first && (*fd as u64) <= last)
                .collect();
            let mut table = this.io.open_files.write();
            for fd in fds {
                if cloexec_only {
                    if let Some(open_file) = table.get_mut(&fd) {
                        open_file.fd_flags |= LINUX_FD_CLOEXEC;
                    }
                } else if let Some(open_file) = table.remove(&fd) {
                    // Use the centralised helper so pty masters freed via
                    // close_range also drop their /dev/pts/N table entry.
                    // open_files write lock and pty_table Mutex are independent
                    // locks; nothing acquires pty_table while holding open_files,
                    // so the nesting order is deadlock-free.
                    this.close_open_file_and_free_pty(&open_file);
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn getdents64(this, cx, fd: Fd, dirp: GuestPtr, count: u64) {

            let fd: Fd = fd;
            let address = dirp.0;
            let length =
                usize::try_from(count).map_err(|_| DispatchError::LengthTooLarge(count))?;
            let memory = &mut *cx.memory;
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(LINUX_EBADF.into());
            };
            let mut open = open_file.description.write();
            let OpenDescription::Directory {
                entries, offset, ..
            } = &mut *open
            else {
                return Ok(LINUX_EBADF.into());
            };

            let mut out = Vec::new();
            while *offset < entries.len() {
                let record = dirent64_record(&entries[*offset], *offset + 1);
                if record.len() > length {
                    return Ok(LINUX_EINVAL.into());
                }
                if out.len() + record.len() > length {
                    break;
                }
                out.extend_from_slice(&record);
                *offset += 1;
            }

            if memory.write_bytes(address, &out).is_err() {
                return Ok(LINUX_EFAULT.into());
            }

            Ok(DispatchOutcome::Returned {
                value: out.len() as i64,
            })

        }

        fn lseek(this, cx, fd: Fd, offset: u64, whence: u64) {

            let fd: Fd = fd;
            let offset = offset as i64;
            let whence = whence;
            let Some(open_file) = this.open_file(fd.0) else {
                // lseek on stdio with no OpenDescription is, on Linux, a
                // valid call on an unseekable pipe/tty — kernel returns
                // ESPIPE, not EBADF. Returning EBADF confuses glibc's
                // ftell/fclose path into reporting "write error: Bad
                // file descriptor" after every successful write.
                if is_stdio_fd(fd.0) {
                    return Ok(LINUX_ESPIPE.into());
                }
                return Ok(LINUX_EBADF.into());
            };
            let mut open = open_file.description.write();

            // HostFile: the kernel owns the offset — delegate straight to
            // libc::lseek on the real fd.
            if let OpenDescription::HostFile { host_fd, .. } = &*open {
                let host_whence = match whence {
                    LINUX_SEEK_SET => libc::SEEK_SET,
                    LINUX_SEEK_CUR => libc::SEEK_CUR,
                    LINUX_SEEK_END => libc::SEEK_END,
                    _ => {
                        return Ok(LINUX_EINVAL.into());
                    }
                };
                let r = match (unsafe { libc::lseek(*host_fd, offset as libc::off_t, host_whence) })
                    .host_syscall_errno()
                {
                    Ok(value) => value,
                    Err(errno) => return Ok(errno.into()),
                };
                return Ok(DispatchOutcome::Returned { value: r as i64 });
            }

            let (current, end) = match &*open {
                OpenDescription::File {
                    contents, offset, ..
                }
                | OpenDescription::SyntheticFile {
                    contents, offset, ..
                } => (*offset as i64, contents.len() as i64),
                OpenDescription::Directory {
                    entries, offset, ..
                } => (*offset as i64, entries.len() as i64),
                // Linux returns ESPIPE for lseek on a pipe / socket / tty
                // (the kernel's POSIX answer for "unseekable stream") and
                // EINVAL only for nonsensical arg combinations. Returning
                // EINVAL here made dpkg-query's ftell() retry-loop spin
                // forever because POSIX says "EINVAL is recoverable" while
                // ESPIPE means "give up, it's a stream".
                OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::Netlink { .. } => {
                    return Ok(LINUX_ESPIPE.into());
                }
                // HostFile is handled by the early libc::lseek above.
                OpenDescription::HostFile { .. } => {
                    return Ok(LINUX_EINVAL.into());
                }
                OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. } => {
                    return Ok(LINUX_EINVAL.into());
                }
            };
            let next = match whence {
                LINUX_SEEK_SET => offset,
                LINUX_SEEK_CUR => current.saturating_add(offset),
                LINUX_SEEK_END => end.saturating_add(offset),
                _ => {
                    return Ok(LINUX_EINVAL.into());
                }
            };
            if next < 0 {
                return Ok(LINUX_EINVAL.into());
            }

            match &mut *open {
                OpenDescription::File { offset, .. }
                | OpenDescription::Directory { offset, .. }
                | OpenDescription::SyntheticFile { offset, .. } => *offset = next as usize,
                OpenDescription::HostFile { .. } => {
                    return Ok(LINUX_EINVAL.into());
                }
                OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. }
                | OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::Netlink { .. } => {}
            }
            Ok(DispatchOutcome::Returned { value: next })

        }

        fn read(this, cx, fd: Fd, buf: GuestPtr, count: u64) {

            let fd: Fd = fd;
            let address = buf.0;
            let length =
                usize::try_from(count).map_err(|_| DispatchError::LengthTooLarge(count))?;
            let memory = &mut *cx.memory;
            // Guest's intended blocking mode for this fd; passed to the host-fd
            // read helper so a blocking-mode fd hands off to the lockless kqueue
            // wait on EAGAIN instead of blocking under the dispatcher lock. (read has no
            // per-call non-blocking flag.) Computed before the open_files borrow.
            let nonblocking = this.io_is_nonblocking(fd.0, 0);
            // fd 0 with no explicit OpenDescription: read from host stdin.
            // This is what makes `read` against the guest's stdin pick up
            // input from the user's terminal (or whatever the carrick host
            // process's stdin is — file, pipe, or terminal).
            if fd.0 == 0 && !this.fd_table_contains(0) {
                return Ok(read_host_pipe(memory, address, length, 0, nonblocking));
            }
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(LINUX_EBADF.into());
            };
            let mut open = open_file.description.write();
            let (contents, offset) = match &mut *open {
                OpenDescription::File {
                    contents, offset, ..
                }
                | OpenDescription::SyntheticFile {
                    contents, offset, ..
                } => (contents, offset),
                OpenDescription::EventFd {
                    base,
                    state,
                    semaphore,
                } => {
                    let state = Arc::clone(state);
                    let semaphore = *semaphore;
                    let nonblocking = base.status_flags() & LINUX_O_NONBLOCK != 0;
                    drop(open);
                    return Ok(read_eventfd(
                        memory,
                        address,
                        length,
                        &state,
                        semaphore,
                        nonblocking,
                    ));
                }
                OpenDescription::TimerFd { base, state } => {
                    let state = Arc::clone(state);
                    let nonblocking = base.status_flags() & LINUX_TFD_NONBLOCK != 0;
                    drop(open);
                    return Ok(read_timerfd(memory, address, length, &state, nonblocking));
                }
                OpenDescription::Inotify { state, .. } => {
                    let state = Arc::clone(state);
                    drop(open);
                    // Drain queued inotify_event records into the guest buffer.
                    // An empty queue is EAGAIN (inotify fds are overwhelmingly
                    // used non-blocking + epoll; a true blocking wait on the
                    // backing kqueue fd is a tracked follow-up).
                    return Ok(match state.read_records(length) {
                        Ok(bytes) if bytes.is_empty() => LINUX_EAGAIN.into(),
                        Ok(bytes) => {
                            if memory.write_bytes(address, &bytes).is_err() {
                                LINUX_EFAULT.into()
                            } else {
                                DispatchOutcome::Returned {
                                    value: bytes.len() as i64,
                                }
                            }
                        }
                        Err(errno) => errno.into(),
                    });
                }
                OpenDescription::PipeReader { base, pipe } => {
                    return Ok(read_pipe(memory, address, length, pipe, base.status_flags()));
                }
                OpenDescription::HostPipe {
                    host_fd,
                    is_read_end,
                    pty,
                    ..
                } => {
                    // pty ends are bidirectional (O_RDWR); only real one-way
                    // pipe ends are gated by is_read_end.
                    if !*is_read_end && pty.is_none() {
                        return Ok(LINUX_EBADF.into());
                    }
                    return Ok(read_host_pipe(
                        memory,
                        address,
                        length,
                        *host_fd,
                        nonblocking,
                    ));
                }
                OpenDescription::Directory { .. } => {
                    return Ok(LINUX_EISDIR.into());
                }
                OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::PipeWriter { .. } => {
                    return Ok(LINUX_EINVAL.into());
                }
                OpenDescription::HostSocket { host_fd, .. } => {
                    return Ok(read_host_pipe(
                        memory,
                        address,
                        length,
                        *host_fd,
                        nonblocking,
                    ));
                }
                // Netlink: drain whatever a prior dump request queued. A bare
                // read(2) is rare on netlink sockets (recvmsg is the norm), but
                // model it as draining the synthetic response so it doesn't
                // wedge a caller.
                OpenDescription::Netlink { recv_queue, .. } => {
                    return Ok(net::drain_netlink_queue(
                        memory, address, length, recv_queue,
                    ));
                }
                // Real host file: libc::read advances the kernel offset
                // (shared across fork). read_host_pipe is just a
                // memory-into-guest read(2) wrapper.
                OpenDescription::HostFile { host_fd, .. } => {
                    return Ok(read_host_pipe(
                        memory,
                        address,
                        length,
                        *host_fd,
                        nonblocking,
                    ));
                }
            };
            let remaining = &contents[*offset..];
            let read_len = remaining.len().min(length);
            let bytes = &remaining[..read_len];
            if memory.write_bytes(address, bytes).is_err() {
                return Ok(LINUX_EFAULT.into());
            }
            *offset += read_len;
            Ok(DispatchOutcome::Returned {
                value: read_len as i64,
            })

        }

        fn readv(this, cx, fd: Fd, iov: GuestPtr, vlen: u64) {

            let fd: Fd = fd;
            let iov = iov.0;
            let iovcnt =
                usize::try_from(vlen).map_err(|_| DispatchError::LengthTooLarge(vlen))?;
            let memory = &mut *cx.memory;
            let iovecs = match read_iovecs(memory, iov, iovcnt) {
                Ok(iovecs) => iovecs,
                Err(errno) => return Ok(errno.into()),
            };
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(LINUX_EBADF.into());
            };
            let mut open = open_file.description.write();
            // Real host file: readv via the kernel fd (advances the shared
            // offset). Fill each iovec sequentially.
            if let OpenDescription::HostFile { host_fd, .. } = &*open {
                let hfd = *host_fd;
                let mut total = 0i64;
                for iov in &iovecs {
                    let len = usize::try_from(iov.iov_len)
                        .map_err(|_| DispatchError::LengthTooLarge(iov.iov_len))?;
                    if len == 0 {
                        continue;
                    }
                    match read_host_pipe(memory, iov.iov_base, len, hfd, /*nonblocking=*/ false) {
                        DispatchOutcome::Returned { value } => {
                            total += value;
                            if (value as usize) < len {
                                break;
                            }
                        }
                        other => return Ok(other),
                    }
                }
                return Ok(DispatchOutcome::Returned { value: total });
            }
            let (contents, offset) = match &mut *open {
                OpenDescription::File {
                    contents, offset, ..
                }
                | OpenDescription::SyntheticFile {
                    contents, offset, ..
                } => (contents, offset),
                OpenDescription::HostFile { .. } => {
                    return Ok(LINUX_EINVAL.into());
                }
                OpenDescription::Directory { .. }
                | OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. }
                | OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::Netlink { .. } => {
                    return Ok(LINUX_EINVAL.into());
                }
            };
            let read_len = read_from_contents_at(memory, contents, *offset, &iovecs)?;
            *offset += read_len;
            Ok(DispatchOutcome::Returned {
                value: read_len as i64,
            })

        }

        fn pread64(this, cx, fd: Fd, buf: GuestPtr, count: u64, offset: u64) {

            let fd: Fd = fd;
            let buffer = buf.0;
            let length =
                usize::try_from(count).map_err(|_| DispatchError::LengthTooLarge(count))?;
            let offset =
                usize::try_from(offset).map_err(|_| DispatchError::LengthTooLarge(offset))?;
            let memory = &mut *cx.memory;
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(LINUX_EBADF.into());
            };
            let open = open_file.description.read();
            // Real host file: positional read via libc::pread (doesn't
            // disturb the shared kernel offset).
            if let OpenDescription::HostFile { host_fd, .. } = &*open {
                let mut buf = vec![0u8; length];
                let n = unsafe {
                    libc::pread(
                        *host_fd,
                        buf.as_mut_ptr() as *mut _,
                        length,
                        offset as libc::off_t,
                    )
                };
                let n = match n.host_syscall_errno() {
                    Ok(value) => value as usize,
                    Err(errno) => return Ok(errno.into()),
                };
                if n > 0 && memory.write_bytes(buffer, &buf[..n]).is_err() {
                    return Ok(LINUX_EFAULT.into());
                }
                return Ok(DispatchOutcome::Returned { value: n as i64 });
            }
            let contents = match &*open {
                OpenDescription::File { contents, .. }
                | OpenDescription::SyntheticFile { contents, .. } => contents,
                OpenDescription::HostFile { .. } => {
                    return Ok(LINUX_EINVAL.into());
                }
                OpenDescription::Directory { .. }
                | OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. }
                | OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::Netlink { .. } => {
                    return Ok(LINUX_EINVAL.into());
                }
            };

            let read_len = if offset < contents.len() {
                let bytes = &contents[offset..][..contents[offset..].len().min(length)];
                if memory.write_bytes(buffer, bytes).is_err() {
                    return Ok(LINUX_EFAULT.into());
                }
                bytes.len()
            } else {
                0
            };
            Ok(DispatchOutcome::Returned {
                value: read_len as i64,
            })

        }

        fn preadv(this, cx, fd: Fd, iov: GuestPtr, vlen: u64, pos_l: u64, pos_h: u64) {

            let fd: Fd = fd;
            let iov = iov.0;
            let iovcnt =
                usize::try_from(vlen).map_err(|_| DispatchError::LengthTooLarge(vlen))?;
            let offset =
                usize::try_from(pos_l).map_err(|_| DispatchError::LengthTooLarge(pos_l))?;
            let memory = &mut *cx.memory;
            let iovecs = match read_iovecs(memory, iov, iovcnt) {
                Ok(iovecs) => iovecs,
                Err(errno) => return Ok(errno.into()),
            };
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(LINUX_EBADF.into());
            };
            let open = open_file.description.read();
            // Real host file: positional readv via libc::pread per iovec
            // (kernel offset untouched).
            if let OpenDescription::HostFile { host_fd, .. } = &*open {
                let hfd = *host_fd;
                let mut total = 0i64;
                let mut cur = offset;
                for iov in &iovecs {
                    let len = usize::try_from(iov.iov_len)
                        .map_err(|_| DispatchError::LengthTooLarge(iov.iov_len))?;
                    if len == 0 {
                        continue;
                    }
                    let mut buf = vec![0u8; len];
                    let n = unsafe {
                        libc::pread(hfd, buf.as_mut_ptr() as *mut _, len, cur as libc::off_t)
                    };
                    let n = match n.host_syscall_errno() {
                        Ok(value) => value as usize,
                        Err(errno) => return Ok(errno.into()),
                    };
                    if n > 0 && memory.write_bytes(iov.iov_base, &buf[..n]).is_err() {
                        return Ok(LINUX_EFAULT.into());
                    }
                    total += n as i64;
                    cur += n;
                    if n < len {
                        break;
                    }
                }
                return Ok(DispatchOutcome::Returned { value: total });
            }
            let contents = match &*open {
                OpenDescription::File { contents, .. }
                | OpenDescription::SyntheticFile { contents, .. } => contents,
                OpenDescription::HostFile { .. } => {
                    return Ok(LINUX_EINVAL.into());
                }
                OpenDescription::Directory { .. }
                | OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. }
                | OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::Netlink { .. } => {
                    return Ok(LINUX_EINVAL.into());
                }
            };
            let read_len = read_from_contents_at(memory, contents, offset, &iovecs)?;
            Ok(DispatchOutcome::Returned {
                value: read_len as i64,
            })

        }

        fn pwrite64(this, cx, fd: Fd, buf: GuestPtr, count: u64, offset: u64) {

            let fd: Fd = fd;
            let address = buf.0;
            let length =
                usize::try_from(count).map_err(|_| DispatchError::LengthTooLarge(count))?;
            let offset = i64::from_ne_bytes(offset.to_ne_bytes());
            if offset < 0 {
                return Ok(LINUX_EINVAL.into());
            }
            let bytes = match (*cx.memory).read_bytes(address, length) {
                Ok(b) => b,
                Err(_) => {
                    return Ok(LINUX_EFAULT.into());
                }
            };
            if is_stdio_fd(fd.0) {
                return Ok(LINUX_ESPIPE.into());
            }
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(LINUX_EBADF.into());
            };
            let open = open_file.description.read();
            // Real host file: positional write via libc::pwrite (visible
            // across fork; kernel offset untouched).
            if let OpenDescription::HostFile {
                host_fd, writable, ..
            } = &*open
            {
                if !*writable {
                    return Ok(LINUX_EBADF.into());
                }
                let n = unsafe {
                    libc::pwrite(
                        *host_fd,
                        bytes.as_ptr() as *const _,
                        length,
                        offset as libc::off_t,
                    )
                };
                let n = match n.host_syscall_errno() {
                    Ok(value) => value,
                    Err(errno) => return Ok(errno.into()),
                };
                return Ok(DispatchOutcome::Returned { value: n as i64 });
            }
            let errno = match &*open {
                OpenDescription::File { .. } | OpenDescription::SyntheticFile { .. } => LINUX_EBADF,
                OpenDescription::HostFile { .. } => LINUX_EINVAL,
                OpenDescription::Directory { .. } => LINUX_EISDIR,
                OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::Netlink { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. } => LINUX_ESPIPE,
            };
            Ok(errno.into())

        }

        fn pwritev(this, cx, fd: Fd, iov: GuestPtr, vlen: u64, pos_l: u64, pos_h: u64) {

            let fd: Fd = fd;
            let iov = iov.0;
            let iovcnt =
                usize::try_from(vlen).map_err(|_| DispatchError::LengthTooLarge(vlen))?;
            let offset = i64::from_ne_bytes(pos_l.to_ne_bytes());
            let memory = &*cx.memory;
            let iovecs = match read_iovecs(memory, iov, iovcnt) {
                Ok(iovecs) => iovecs,
                Err(errno) => return Ok(errno.into()),
            };
            if offset < 0 {
                return Ok(LINUX_EINVAL.into());
            }
            for iovec in &iovecs {
                let iov_len = usize::try_from(iovec.iov_len)
                    .map_err(|_| DispatchError::LengthTooLarge(iovec.iov_len))?;
                if memory.read_bytes(iovec.iov_base, iov_len).is_err() {
                    return Ok(LINUX_EFAULT.into());
                }
            }
            if is_stdio_fd(fd.0) {
                return Ok(LINUX_ESPIPE.into());
            }
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(LINUX_EBADF.into());
            };
            let open = open_file.description.read();
            // Real host file: positional writev via libc::pwrite per iovec.
            if let OpenDescription::HostFile {
                host_fd, writable, ..
            } = &*open
            {
                if !*writable {
                    return Ok(LINUX_EBADF.into());
                }
                let hfd = *host_fd;
                let mut total = 0i64;
                let mut cur = offset;
                for iov in &iovecs {
                    let len = usize::try_from(iov.iov_len)
                        .map_err(|_| DispatchError::LengthTooLarge(iov.iov_len))?;
                    if len == 0 {
                        continue;
                    }
                    let buf = match memory.read_bytes(iov.iov_base, len) {
                        Ok(b) => b,
                        Err(_) => {
                            return Ok(LINUX_EFAULT.into());
                        }
                    };
                    let n =
                        unsafe { libc::pwrite(hfd, buf.as_ptr() as *const _, len, cur as libc::off_t) };
                    let n = match n.host_syscall_errno() {
                        Ok(value) => value,
                        Err(errno) => return Ok(errno.into()),
                    };
                    total += n as i64;
                    cur += n as i64;
                    if (n as usize) < len {
                        break;
                    }
                }
                return Ok(DispatchOutcome::Returned { value: total });
            }
            let errno = match &*open {
                OpenDescription::File { .. } | OpenDescription::SyntheticFile { .. } => LINUX_EBADF,
                OpenDescription::HostFile { .. } => LINUX_EINVAL,
                OpenDescription::Directory { .. } => LINUX_EISDIR,
                OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::Netlink { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. } => LINUX_ESPIPE,
            };
            Ok(errno.into())

        }

        fn sendfile(this, cx, out_fd: Fd, in_fd: Fd, offset: GuestPtr, count: u64) {

            let out_fd: Fd = out_fd;
            let in_fd: Fd = in_fd;
            let offset_address = offset.0;
            let count =
                usize::try_from(count).map_err(|_| DispatchError::LengthTooLarge(count))?;
            let memory = &mut *cx.memory;
            if count == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }

            let mut offset = match this.sendfile_offset(in_fd.0, offset_address, memory)? {
                Ok(offset) => offset,
                Err(errno) => return Ok(errno.into()),
            };

            // Darwin-native fast path: a regular file -> socket uses macOS
            // sendfile(2) (BSD-style, in-kernel, zero-copy). It honors socket
            // backpressure by returning a partial `len` + EAGAIN, which Go's
            // netpoller drives via EPOLLOUT — so a large transfer does NOT hang
            // the way a userspace read-into-buffer-then-write does. Non-socket
            // destinations and in-memory file sources fall through to the buffer
            // path below.
            if let (Some(file_fd), Some(sock_fd)) =
                (this.regular_host_file_fd(in_fd.0), this.host_socket_fd(out_fd.0))
            {
                let mut len: libc::off_t = count as libc::off_t;
                // SAFETY: both are live host fds owned by these guest fds; `len`
                // is in (bytes to send) / out (bytes sent); no header/trailer.
                let rc = unsafe {
                    libc::sendfile(
                        file_fd,
                        sock_fd,
                        offset as libc::off_t,
                        &mut len,
                        std::ptr::null_mut(),
                        0,
                    )
                };
                let sent = len.max(0) as usize;
                let advance_and_return = |offset: usize,
                                          sent: usize,
                                          memory: &mut dyn GuestMemory|
                 -> Result<DispatchOutcome, DispatchError> {
                    let new_off = offset.saturating_add(sent);
                    if offset_address == 0 {
                        // macOS sendfile takes an explicit `offset` and does NOT
                        // advance the file's kernel offset; do it so a follow-up
                        // read/sendfile (no explicit offset) continues correctly.
                        unsafe { libc::lseek(file_fd, new_off as libc::off_t, libc::SEEK_SET) };
                    } else if memory
                        .write_bytes(offset_address, &(new_off as u64).to_ne_bytes())
                        .is_err()
                    {
                        return Ok(LINUX_EFAULT.into());
                    }
                    Ok(DispatchOutcome::Returned { value: sent as i64 })
                };
                match (rc as i64).host_syscall_errno() {
                    Ok(_) => return advance_and_return(offset, sent, memory),
                    Err(e) if e == LINUX_EAGAIN => {
                        if sent > 0 {
                            // Partial transfer before the socket filled: report it
                            // (Go advances and loops).
                            return advance_and_return(offset, sent, memory);
                        }
                        return Ok(if this.io_is_nonblocking(out_fd.0, 0) {
                            DispatchOutcome::errno(LINUX_EAGAIN)
                        } else {
                            DispatchOutcome::WaitOnFds {
                                fds: vec![(sock_fd, libc::POLLOUT as i16)],
                                timeout: None,
                                on_timeout: -(LINUX_EAGAIN as i64),
                                block_signals: 0,
                            }
                        });
                    }
                    Err(e) => return Ok(e.into()),
                }
            }

            let bytes = match this.sendfile_bytes(in_fd.0, offset, count) {
                Ok(bytes) => bytes,
                Err(errno) => return Ok(errno.into()),
            };
            let outcome = this.write_output_fd(out_fd.0, &bytes);
            let DispatchOutcome::Returned { value } = outcome else {
                return Ok(outcome);
            };
            let written = usize::try_from(value).unwrap_or(0);
            offset = offset.saturating_add(written);
            if offset_address == 0 {
                if let Some(open_file) = this.open_file(in_fd.0) {
                    let mut open = open_file.description.write();
                    match &mut *open {
                        OpenDescription::File {
                            offset: current, ..
                        }
                        | OpenDescription::SyntheticFile {
                            offset: current, ..
                        } => *current = offset,
                        _ => {}
                    }
                }
            } else if memory
                .write_bytes(offset_address, &(offset as u64).to_ne_bytes())
                .is_err()
            {
                return Ok(LINUX_EFAULT.into());
            }

            Ok(DispatchOutcome::Returned { value })

        }

        fn copy_file_range(this, cx, fd_in: Fd, off_in: GuestPtr, fd_out: Fd, off_out: GuestPtr, len: u64, flags: u64) {

            let in_fd: Fd = fd_in;
            let off_in_addr = off_in.0;
            let out_fd: Fd = fd_out;
            let off_out_addr = off_out.0;
            // Callers (coreutils `cat`) pass len = SSIZE_MAX and loop until EOF,
            // so cap each call to a bounded chunk rather than trying to allocate
            // a multi-exabyte buffer. A short return is legal for copy_file_range.
            let requested = usize::try_from(len).unwrap_or(usize::MAX);
            let memory = &mut *cx.memory;
            let count = requested.min(8 * 1024 * 1024);
            if count == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }

            let in_offset = match this.sendfile_offset(in_fd.0, off_in_addr, memory)? {
                Ok(o) => o,
                Err(errno) => return Ok(errno.into()),
            };
            #[cfg(target_os = "macos")]
            if let Some(outcome) = this.try_darwin_copyfile_range_fast_path(
                in_fd.0,
                in_offset,
                off_in_addr,
                out_fd.0,
                off_out_addr,
                count,
            )? {
                return Ok(outcome);
            }
            let bytes = match this.sendfile_bytes(in_fd.0, in_offset, count) {
                Ok(b) => b,
                Err(errno) => return Ok(errno.into()),
            };
            if bytes.is_empty() {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }

            // Write side. off_out == NULL → write at out_fd's current position
            // (the common case: cat to a pipe/stdout). Non-NULL → pwrite at the
            // given offset on a real host fd and advance *off_out.
            let written = if off_out_addr == 0 {
                let outcome = this.write_output_fd(out_fd.0, &bytes);
                let DispatchOutcome::Returned { value } = outcome else {
                    return Ok(outcome);
                };
                usize::try_from(value).unwrap_or(0)
            } else {
                let out_off = match read_u64(memory, off_out_addr) {
                    Ok(v) => v,
                    Err(errno) => return Ok(errno.into()),
                };
                let host_fd = match this.open_file(out_fd.0).as_ref() {
                    Some(of) => match &*of.description.read() {
                        OpenDescription::HostFile {
                            host_fd,
                            writable: true,
                            ..
                        } => *host_fd,
                        OpenDescription::HostFile { .. } => {
                            return Ok(LINUX_EBADF.into());
                        }
                        _ => {
                            return Ok(LINUX_EINVAL.into());
                        }
                    },
                    None => return Ok(LINUX_EBADF.into()),
                };
                let n = unsafe {
                    libc::pwrite(
                        host_fd,
                        bytes.as_ptr() as *const _,
                        bytes.len(),
                        out_off as libc::off_t,
                    )
                };
                let n = match n.host_syscall_errno() {
                    Ok(value) => value as usize,
                    Err(errno) => return Ok(errno.into()),
                };
                if memory
                    .write_bytes(off_out_addr, &(out_off + n as u64).to_ne_bytes())
                    .is_err()
                {
                    return Ok(LINUX_EFAULT.into());
                }
                n
            };

            // Advance the input offset (pointer or the fd's own position).
            let new_in = in_offset.saturating_add(written);
            if off_in_addr == 0 {
                if let Some(of) = this.open_file(in_fd.0).as_ref() {
                    let mut open = of.description.write();
                    match &mut *open {
                        OpenDescription::File { offset, .. }
                        | OpenDescription::SyntheticFile { offset, .. } => *offset = new_in,
                        OpenDescription::HostFile { host_fd, .. } => {
                            unsafe { libc::lseek(*host_fd, new_in as libc::off_t, libc::SEEK_SET) };
                        }
                        _ => {}
                    }
                }
            } else if memory
                .write_bytes(off_in_addr, &(new_in as u64).to_ne_bytes())
                .is_err()
            {
                return Ok(LINUX_EFAULT.into());
            }

            Ok(DispatchOutcome::Returned {
                value: written as i64,
            })

        }

        fn splice(this, cx, fd_in: Fd, off_in: GuestPtr, fd_out: Fd, off_out: GuestPtr, len: u64, flags: u64) {

            let in_fd: Fd = fd_in;
            let off_in_address = off_in.0;
            let out_fd: Fd = fd_out;
            let off_out_address = off_out.0;
            let count =
                usize::try_from(len).map_err(|_| DispatchError::LengthTooLarge(len))?;
            let flags = flags;
            let memory = &mut *cx.memory;
            if flags & !LINUX_SPLICE_SUPPORTED_FLAGS != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if count == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }

            if let Some((pipe, status_flags)) = this.pipe_reader(in_fd.0) {
                if off_in_address != 0 || off_out_address != 0 {
                    return Ok(LINUX_EINVAL.into());
                }
                if let Some(errno) = this.splice_output_errno(out_fd.0) {
                    return Ok(errno.into());
                }
                let bytes = match take_pipe_bytes(&pipe, count, status_flags) {
                    Ok(bytes) => bytes,
                    Err(errno) => return Ok(errno.into()),
                };
                let outcome = this.write_output_fd(out_fd.0, &bytes);
                return Ok(outcome);
            }

            // Splice OUT of a real host pipe's read end (the fork-safe pipe model;
            // `pipe2`/`fcntl` now hand back HostPipe descriptions, so splice must
            // recognise them just like the legacy in-memory PipeReader above).
            if let Some(host_fd) = this.host_pipe_read_fd(in_fd.0) {
                if off_in_address != 0 || off_out_address != 0 {
                    return Ok(LINUX_EINVAL.into());
                }
                if let Some(errno) = this.splice_output_errno(out_fd.0) {
                    return Ok(errno.into());
                }
                let mut buf = vec![0u8; count];
                // BLOCKING-IO-OK: splice/sendfile source read. The in fd is a
                // regular file or an already-readable pipe end; converting this
                // niche path to the lockless wait is a tracked follow-up, not a
                // server hot path.
                let n = unsafe { libc::read(host_fd, buf.as_mut_ptr() as *mut _, count) };
                let n = match n.host_syscall_errno() {
                    Ok(value) => value,
                    Err(errno) => return Ok(errno.into()),
                };
                buf.truncate(n as usize);
                let outcome = this.write_output_fd(out_fd.0, &buf);
                return Ok(outcome);
            }

            // Splice OUT of a host socket (socket -> pipe, and socket -> socket).
            // This is the path Go's `io.Copy(pipe, conn)` takes; without it a
            // socket source fell through to the sendfile path below, which treats
            // `in_fd` as a regular file and fails. The host socket fd is
            // non-blocking, so an empty socket yields EAGAIN — which is exactly
            // what a non-blocking guest (the Go netpoller) expects; a true
            // blocking-wait for an empty socket is the same tracked follow-up as
            // the host-pipe branch above.
            if let Some(host_fd) = this.host_socket_fd(in_fd.0) {
                if off_in_address != 0 || off_out_address != 0 {
                    return Ok(LINUX_EINVAL.into());
                }
                if let Some(errno) = this.splice_output_errno(out_fd.0) {
                    return Ok(errno.into());
                }
                let mut buf = vec![0u8; count];
                // MSG_DONTWAIT keeps this off the kernel-lock path: the host
                // socket is already non-blocking, and a non-blocking guest (the
                // Go netpoller) wants the EAGAIN rather than a blocked vCPU.
                let n = unsafe {
                    libc::recv(host_fd, buf.as_mut_ptr() as *mut _, count, libc::MSG_DONTWAIT)
                };
                let n = match n.host_syscall_errno() {
                    Ok(value) => value,
                    Err(errno) => return Ok(errno.into()),
                };
                buf.truncate(n as usize);
                let outcome = this.write_output_fd(out_fd.0, &buf);
                return Ok(outcome);
            }

            if off_out_address != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            match this.fd_is_pipe_writer(out_fd.0) {
                Ok(true) => {}
                Ok(false) => {
                    return Ok(LINUX_EINVAL.into());
                }
                Err(errno) => return Ok(errno.into()),
            }

            let mut offset = match this.sendfile_offset(in_fd.0, off_in_address, memory)? {
                Ok(offset) => offset,
                Err(errno) => return Ok(errno.into()),
            };
            let bytes = match this.sendfile_bytes(in_fd.0, offset, count) {
                Ok(bytes) => bytes,
                Err(errno) => return Ok(errno.into()),
            };
            let outcome = this.write_output_fd(out_fd.0, &bytes);
            let DispatchOutcome::Returned { value } = outcome else {
                return Ok(outcome);
            };
            let written = usize::try_from(value).unwrap_or(0);
            offset = offset.saturating_add(written);
            if off_in_address == 0 {
                if let Some(open_file) = this.open_file(in_fd.0) {
                    let mut open = open_file.description.write();
                    match &mut *open {
                        OpenDescription::File {
                            offset: current, ..
                        }
                        | OpenDescription::SyntheticFile {
                            offset: current, ..
                        } => *current = offset,
                        _ => {}
                    }
                }
            } else if memory
                .write_bytes(off_in_address, &(offset as u64).to_ne_bytes())
                .is_err()
            {
                return Ok(LINUX_EFAULT.into());
            }

            Ok(DispatchOutcome::Returned { value })

        }

        fn inotify_init1(this, cx, flags: u64) {
            let known = crate::inotify::IN_NONBLOCK as u64 | crate::inotify::IN_CLOEXEC as u64;
            if flags & !known != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            let Some(state) = crate::inotify::InotifyState::new() else {
                return Ok(crate::linux_abi::LINUX_EMFILE.into());
            };
            let description = OpenDescription::Inotify {
                base: OpenDescriptionBase::new(flags & LINUX_O_NONBLOCK),
                state: Arc::new(state),
            };
            Ok(this.install_fd(description, linux_fd_flags_from_open_flags(flags)))
        }

        fn inotify_add_watch(this, cx, fd: Fd, pathname: GuestPtr, mask: u64) {
            let Some(state) = this.inotify_state(fd.0) else {
                return Ok(LINUX_EINVAL.into());
            };
            let path = match read_guest_c_string(&*cx.memory, pathname.0) {
                Ok(path) => path,
                Err(errno) => return Ok(errno.into()),
            };
            let path = match this.resolve_at_path(LINUX_AT_FDCWD, &path) {
                Ok(path) => path,
                Err(errno) => return Ok(errno.into()),
            };
            // A watchable host vnode comes from the host fs backend; the
            // in-memory backend and directory targets have no host fd to
            // register, so inotify watches require `--fs host` (ENOSPC
            // otherwise — a documented limitation; dir-entry-name events are a
            // separate kqueue-fidelity follow-up).
            match this
                .fs
                .rootfs_vfs
                .open_for_dispatch(&path, false, false, false, false)
            {
                Ok(crate::vfs::rootfs::OpenDispatchResult::HostFile { host_fd, .. }) => {
                    Ok(match state.add_watch(host_fd, mask as u32) {
                        Ok(wd) => DispatchOutcome::Returned { value: wd as i64 },
                        Err(errno) => errno.into(),
                    })
                }
                Ok(_) => Ok(crate::linux_abi::LINUX_ENOSPC.into()),
                Err(errno) => Ok(errno.into()),
            }
        }

        fn inotify_rm_watch(this, cx, fd: Fd, wd: u64) {
            let Some(state) = this.inotify_state(fd.0) else {
                return Ok(LINUX_EINVAL.into());
            };
            Ok(match state.rm_watch(wd as i32) {
                Ok(()) => DispatchOutcome::Returned { value: 0 },
                Err(errno) => errno.into(),
            })
        }

        fn sync(this, cx) {

            unsafe {
                libc::sync();
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn syncfs(this, cx, fd: Fd) {

            let fd: Fd = fd;
            if !this.fd_is_valid(fd.0) {
                return Ok(LINUX_EBADF.into());
            }
            let host_fd = match this.host_file_fd_for_flush(fd.0) {
                Ok(host_fd) => host_fd,
                Err(errno) => return Ok(errno.into()),
            };
            if let Some(host_fd) = host_fd {
                if let Err(errno) = flush_host_fd(host_fd) {
                    return Ok(errno.into());
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn sys_setxattr_path(this, cx, path: GuestPtr, name: GuestPtr, value: GuestPtr, size: u64, flags: u64, follow: u64) {

            this.setxattr(cx.memory, XattrTarget::Path(path), name, value, size, flags)

        }

        fn sys_setxattr_fd(this, cx, fd: Fd, name: GuestPtr, value: GuestPtr, size: u64, flags: u64) {

            this.setxattr(cx.memory, XattrTarget::Fd(fd), name, value, size, flags)

        }

        fn sys_getxattr_path(this, cx, path: GuestPtr, name: GuestPtr, value: GuestPtr, size: u64, follow: u64) {

            this.getxattr(cx.memory, XattrTarget::Path(path), name, value, size)

        }

        fn sys_getxattr_fd(this, cx, fd: Fd, name: GuestPtr, value: GuestPtr, size: u64) {

            this.getxattr(cx.memory, XattrTarget::Fd(fd), name, value, size)

        }

        fn sys_listxattr_path(this, cx, path: GuestPtr, list: GuestPtr, size: u64, follow: u64) {

            this.listxattr(cx.memory, XattrTarget::Path(path), list, size)

        }

        fn sys_listxattr_fd(this, cx, fd: Fd, list: GuestPtr, size: u64) {

            this.listxattr(cx.memory, XattrTarget::Fd(fd), list, size)

        }

        fn sys_xattr_unsupported(this, cx) {

            Ok(this.xattr_unsupported())

        }

        fn sys_statfs(this, cx, path: GuestPtr, buf: GuestPtr) {

            this.statfs(path, buf, cx.memory)

        }

        fn sys_fstatfs(this, cx, fd: Fd, buf: GuestPtr) {

            Ok(this.fstatfs(fd, buf, cx.memory))

        }

        fn sys_truncate(this, cx, path: GuestPtr, length: u64) {

            this.truncate(path, length, &*cx.memory)

        }

        fn sys_bootstrap_enosys(this, cx) {

            Ok(this.bootstrap_enosys())

        }

        fn fsync(this, cx, fd: Fd) {

            let fd: Fd = fd;
            let host_fd = match this.host_file_fd_for_flush(fd.0) {
                Ok(host_fd) => host_fd,
                Err(errno) => return Ok(errno.into()),
            };
            if let Some(host_fd) = host_fd {
                if let Err(errno) = flush_host_fd(host_fd) {
                    return Ok(errno.into());
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn fdatasync(this, cx, fd: Fd) {

            let fd: Fd = fd;
            let host_fd = match this.host_file_fd_for_flush(fd.0) {
                Ok(host_fd) => host_fd,
                Err(errno) => return Ok(errno.into()),
            };
            if let Some(host_fd) = host_fd {
                if let Err(errno) = flush_host_fd(host_fd) {
                    return Ok(errno.into());
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn write(this, cx, fd: Fd, buf: GuestPtr, count: u64) {

            let fd = fd.0;
            let address = buf.0;
            let length =
                usize::try_from(count).map_err(|_| DispatchError::LengthTooLarge(count))?;
            let bytes = match (*cx.memory).read_bytes(address, length) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Ok(LINUX_EFAULT.into());
                }
            };

            let nonblocking = this.io_is_nonblocking(fd as i32, 0);

            // Check open_files FIRST: dup3 may have redirected fd 1/2 to
            // a pipe, an eventfd, or some other resource. Only after we've
            // confirmed there's no open description do we fall back to the
            // dispatcher's built-in stdout/stderr buffers.
            if let Some(open_file) = this.open_file(fd as i32) {
                // Take an inner scope so the borrow on the description ends
                // before we touch this.fs.rootfs_vfs.overlay (writable File path below).
                #[allow(dead_code)]
                enum FileWriteback {
                    None,
                    Update { path: String, contents: Vec<u8> },
                }
                let outcome: DispatchOutcome;
                let writeback: FileWriteback;
                {
                    let mut open = open_file.description.write();
                    match &mut *open {
                        OpenDescription::EventFd { state, .. } => {
                            return Ok(write_eventfd(&bytes, state));
                        }
                        OpenDescription::PipeWriter { pipe, .. } => {
                            return Ok(write_pipe(&bytes, pipe));
                        }
                        OpenDescription::HostPipe {
                            host_fd,
                            is_read_end,
                            pty,
                            ..
                        } => {
                            // pty ends are bidirectional (O_RDWR); only real one-way
                            // pipe ends are gated by is_read_end.
                            if *is_read_end && pty.is_none() {
                                return Ok(LINUX_EBADF.into());
                            }
                            return Ok(write_host_pipe(&bytes, *host_fd, nonblocking));
                        }
                        OpenDescription::HostSocket { host_fd, .. } => {
                            // write(2) on a connected socket maps directly to a
                            // host write(2). Unconnected sockets will surface
                            // their own ENOTCONN via the host.
                            return Ok(write_host_pipe(&bytes, *host_fd, nonblocking));
                        }
                        OpenDescription::HostFile {
                            base,
                            host_fd,
                            writable,
                            ..
                        } => {
                            if !*writable {
                                return Ok(LINUX_EBADF.into());
                            }
                            // O_APPEND: seek to EOF before writing so `>>` and
                            // log appends don't overwrite from offset 0. (The
                            // host fd isn't opened O_APPEND, so we emulate the
                            // seek-then-write; single-writer, which covers the
                            // shell/dpkg append cases.)
                            if base.status_flags() & LINUX_O_APPEND != 0 {
                                unsafe { libc::lseek(*host_fd, 0, libc::SEEK_END) };
                            }
                            // libc::write to the real fd: advances the
                            // kernel offset and is visible across fork.
                            return Ok(write_host_pipe(&bytes, *host_fd, nonblocking));
                        }
                        OpenDescription::File {
                            path,
                            contents,
                            offset,
                            writable,
                            metadata,
                            ..
                        } => {
                            if !*writable {
                                return Ok(LINUX_EBADF.into());
                            }
                            if let Err(errno) = write_into_file_contents(contents, offset, &bytes) {
                                return Ok(errno.into());
                            }
                            metadata.size = contents.len();
                            outcome = DispatchOutcome::Returned {
                                value: bytes.len() as i64,
                            };
                            writeback = FileWriteback::Update {
                                path: path.clone(),
                                contents: contents.clone(),
                            };
                        }
                        _ => return Ok(LINUX_EBADF.into()),
                    }
                }
                if let FileWriteback::Update { path, contents } = writeback {
                    let _ = this
                        .fs
                        .rootfs_vfs
                        .overlay
                        .set_file_contents(&path, contents);
                }
                return Ok(outcome);
            }
            match fd {
                1 => this.io.stdout.lock().extend_from_slice(&bytes),
                2 => this.io.stderr.lock().extend_from_slice(&bytes),
                _ => return Ok(LINUX_EBADF.into()),
            }

            Ok(DispatchOutcome::Returned {
                value: length as i64,
            })

        }

        fn writev(this, cx, fd: Fd, iov: GuestPtr, vlen: u64) {

            let fd = fd.0;
            let iov = iov.0;
            let iovcnt =
                usize::try_from(vlen).map_err(|_| DispatchError::LengthTooLarge(vlen))?;
            let memory = &*cx.memory;
            let iovecs = match read_iovecs(memory, iov, iovcnt) {
                Ok(iovecs) => iovecs,
                Err(errno) => return Ok(errno.into()),
            };
            let nonblocking = this.io_is_nonblocking(fd as i32, 0);

            let mut total = 0usize;
            for iovec in iovecs {
                let iov_base = iovec.iov_base;
                let iov_len = usize::try_from(iovec.iov_len)
                    .map_err(|_| DispatchError::LengthTooLarge(iovec.iov_len))?;
                let bytes = match memory.read_bytes(iov_base, iov_len) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return Ok(LINUX_EFAULT.into());
                    }
                };
                // Mirror `write`: check open_files FIRST so post-dup3
                // redirects (eg `dup3(pipe_write, 1)`) actually plumb
                // through the redirected description rather than the
                // built-in stdout buffer.
                if let Some(open_file) = this.open_file(fd as i32) {
                    enum FileWriteback {
                        None,
                        Update { path: String, contents: Vec<u8> },
                    }
                    let outcome: DispatchOutcome;
                    let writeback: FileWriteback;
                    {
                        let mut open = open_file.description.write();
                        match &mut *open {
                            OpenDescription::PipeWriter { pipe, .. } => {
                                outcome = write_pipe(&bytes, pipe);
                                writeback = FileWriteback::None;
                            }
                            OpenDescription::HostPipe {
                                host_fd,
                                is_read_end,
                                pty,
                                ..
                            } => {
                                // pty ends are bidirectional (O_RDWR); only real one-way
                                // pipe ends are gated by is_read_end.
                                if *is_read_end && pty.is_none() {
                                    return Ok(LINUX_EBADF.into());
                                }
                                outcome = write_host_pipe(&bytes, *host_fd, nonblocking);
                                writeback = FileWriteback::None;
                            }
                            OpenDescription::HostSocket { host_fd, .. } => {
                                outcome = write_host_pipe(&bytes, *host_fd, nonblocking);
                                writeback = FileWriteback::None;
                            }
                            OpenDescription::HostFile {
                                base,
                                host_fd,
                                writable,
                                ..
                            } => {
                                if !*writable {
                                    return Ok(LINUX_EBADF.into());
                                }
                                // Mirror `write`(64): O_APPEND seeks to EOF, then
                                // libc::write to the real fd advances the shared
                                // kernel offset (visible across fork and to the
                                // readv that follows).
                                if base.status_flags() & LINUX_O_APPEND != 0 {
                                    unsafe { libc::lseek(*host_fd, 0, libc::SEEK_END) };
                                }
                                outcome = write_host_pipe(&bytes, *host_fd, nonblocking);
                                writeback = FileWriteback::None;
                            }
                            OpenDescription::File {
                                path,
                                contents,
                                offset,
                                writable,
                                metadata,
                                ..
                            } => {
                                if !*writable {
                                    return Ok(LINUX_EBADF.into());
                                }
                                if let Err(errno) = write_into_file_contents(contents, offset, &bytes) {
                                    return Ok(errno.into());
                                }
                                metadata.size = contents.len();
                                outcome = DispatchOutcome::Returned {
                                    value: bytes.len() as i64,
                                };
                                writeback = FileWriteback::Update {
                                    path: path.clone(),
                                    contents: contents.clone(),
                                };
                            }
                            _ => return Ok(LINUX_EBADF.into()),
                        }
                    }
                    if let FileWriteback::Update { path, contents } = writeback {
                        let _ = this
                            .fs
                            .rootfs_vfs
                            .overlay
                            .set_file_contents(&path, contents);
                    }
                    let DispatchOutcome::Returned { value } = outcome else {
                        return Ok(outcome);
                    };
                    total = total
                        .checked_add(value as usize)
                        .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
                    continue;
                }
                if *this.io.stream_stdio.lock() && (fd == 1 || fd == 2) {
                    // BLOCKING-IO-OK: streamed writev to the inherited stdout/
                    // stderr (the user's tty/pipe); blocking is correct backpressure.
                    let n = unsafe { libc::write(fd as i32, bytes.as_ptr() as *const _, bytes.len()) };
                    let n = match n.host_syscall_errno() {
                        Ok(value) => value as usize,
                        Err(errno) => return Ok(errno.into()),
                    };
                    total = total
                        .checked_add(n)
                        .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
                    continue;
                }
                match fd {
                    1 => this.io.stdout.lock().extend_from_slice(&bytes),
                    2 => this.io.stderr.lock().extend_from_slice(&bytes),
                    _ => return Ok(LINUX_EBADF.into()),
                }
                total = total
                    .checked_add(bytes.len())
                    .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
            }

            Ok(DispatchOutcome::Returned {
                value: total as i64,
            })

        }

        fn readlinkat(this, cx, dirfd: u64, pathname: GuestPtr, buf: GuestPtr, bufsiz: u64) {

            let dirfd = dirfd;
            let pathname = pathname.0;
            let buffer = buf.0;
            let buffer_size =
                usize::try_from(bufsiz).map_err(|_| DispatchError::LengthTooLarge(bufsiz))?;
            if buffer_size == 0 {
                return Ok(LINUX_EINVAL.into());
            }

            let path = match read_guest_c_string(&*cx.memory, pathname) {
                Ok(path) => path,
                Err(errno) => return Ok(errno.into()),
            };
            let path = match this.resolve_at_path(dirfd, &path) {
                Ok(path) => path,
                Err(errno) => return Ok(errno.into()),
            };

            let target = if path == "/proc/self/exe" || path == "/proc/this/exe" || path == "/proc/curproc/exe" {
                this.proc.lock().executable_path.clone()
            } else if let Some(t) = this.proc_self_fd_tty_link(&path) {
                // /proc/this/fd/{0,1,2} → /dev/pts/N when the guest's stdio is the
                // `carrick run -t` controlling pty. This is what glibc `ttyname(3)`
                // reads, so `tty(1)` and tty-name lookups resolve.
                t
            } else if let Some(t) = proc_self_fd_number(&path).and_then(|n| {
                this.io
                    .fd_open_paths
                    .read()
                    .get(&n)
                    .cloned()
                    .or_else(|| {
                        this.open_file(n)
                            .and_then(|f| f.description.read().open_path().map(str::to_owned))
                    })
            }) {
                // /proc/self/fd/N → the path fd N was opened at. Rosetta readlinks
                // its main-binary fd this way to recover the binary's path.
                t
            } else if let Some(t) = this.fs.rootfs_vfs.overlay.read_link(&path) {
                // Symlink created in the writable backend (cap-std on --fs host).
                t
            } else {
                use crate::vfs::Vfs as _;
                match this.fs.rootfs_vfs.readlink(&path) {
                    Ok(p) => p.to_string_lossy().into_owned(),
                    Err(errno) => return Ok(errno.into()),
                }
            };

            let bytes = target.as_bytes();
            let written = bytes.len().min(buffer_size);
            if cx.memory.write_bytes(buffer, &bytes[..written]).is_err() {
                return Ok(LINUX_EFAULT.into());
            }
            Ok(DispatchOutcome::Returned {
                value: written as i64,
            })

        }

        fn mknodat(this, cx, dirfd: u64, pathname: GuestPtr, mode: u64, dev: u64) {

            let dirfd = dirfd;
            let pathname = pathname.0;
            let mode = mode as u32;
            let path = match read_guest_c_string(&*cx.memory, pathname) {
                Ok(path) => path,
                Err(errno) => return Ok(errno.into()),
            };
            if path.is_empty() {
                return Ok(LINUX_ENOENT.into());
            }
            let resolved = match this.resolve_at_path(dirfd, &path) {
                Ok(resolved) => resolved,
                Err(errno) => return Ok(errno.into()),
            };
            if crate::vfs::is_synthetic_virtual_file(&resolved, &this.synthetic_proc_context()) {
                return Ok(LINUX_EEXIST.into());
            }
            // Existence check must consult the layered view (overlay/disk
            // first, then rootfs) — a rootfs-direct lookup would miss a file
            // the guest already created in the overlay and wrongly report
            // EROFS instead of EEXIST. Mirrors the linkat EEXIST check.
            if this.layered_metadata(&resolved).is_ok() {
                return Ok(LINUX_EEXIST.into());
            }
            // Linux mknod(2): a zero type field means S_IFREG. Only regular
            // files are materialised on the host backend (like open O_CREAT);
            // device/fifo/socket nodes can't be backed by the cap-std scratch,
            // so they report EPERM (matching the unprivileged-mknod errno).
            let type_bits = mode & LINUX_S_IFMT;
            if type_bits != 0 && type_bits != LINUX_S_IFREG {
                return Ok(LINUX_EPERM.into());
            }
            // Create an empty regular file in the writable backend (cap-std).
            // MemoryBackend's create_file works in-memory too. After this the
            // path exists in the layered view.
            match this.fs.rootfs_vfs.overlay.create_file(&resolved) {
                Ok(()) => {
                    if mode & 0o7777 != 0 {
                        let _ = this
                            .fs
                            .rootfs_vfs
                            .overlay
                            .set_mode(&resolved, mode & 0o7777);
                    }
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(crate::fs_backend::BackendError::Unsupported) => Ok(LINUX_EROFS.into()),
                Err(_) => Ok(LINUX_EROFS.into()),
            }

        }

        fn mkdirat(this, cx, dirfd: u64, pathname: GuestPtr, mode: u64) {

            let dirfd = dirfd;
            let pathname = pathname.0;
            let mode = mode;
            let path = match read_guest_c_string(&*cx.memory, pathname) {
                Ok(path) => path,
                Err(errno) => return Ok(errno.into()),
            };
            if path.is_empty() {
                return Ok(LINUX_ENOENT.into());
            }
            let resolved = match this.resolve_at_path(dirfd, &path) {
                Ok(resolved) => resolved,
                Err(errno) => return Ok(errno.into()),
            };
            if crate::vfs::is_synthetic_virtual_file(&resolved, &this.synthetic_proc_context()) {
                return Ok(LINUX_EEXIST.into());
            }
            // Layered existence + parent-exists checks live inside
            // RootFsVfs::mkdir; the dispatcher only handles synthetic
            // path shadowing.
            use crate::vfs::Vfs as _;
            match this.fs.rootfs_vfs.mkdir(&resolved, 0) {
                Ok(()) => {
                    // Apply the requested mode (umask-masked, like the kernel) and
                    // stamp the creating process's owner — mkdir previously dropped
                    // both, so DAC checks against the new dir were wrong.
                    let creds = this.cred_snapshot();
                    let create_mode = (mode as u32 & 0o7777) & !(creds.umask & 0o777);
                    let _ = this.fs.rootfs_vfs.overlay.set_mode(&resolved, create_mode);
                    if creds.euid != 0 || creds.egid != 0 {
                        let _ = this
                            .fs
                            .rootfs_vfs
                            .overlay
                            .set_owner(&resolved, creds.euid, creds.egid);
                    }
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(errno) => Ok(errno.into()),
            }

        }

        fn fchmod(this, cx, fd: Fd, mode: u64) {

            let fd: Fd = fd;
            if !this.fd_is_valid(fd.0) {
                return Ok(LINUX_EBADF.into());
            }
            let mode = (mode & 0o7777) as u32;
            // Resolve the fd to its path and route through the backend's set_mode,
            // so the guest-visible mode lands in the carrick mode xattr (what
            // fstat reports) — not just the real fd's mode, which could be the
            // forced-owner-accessible value. Previously this called libc::fchmod
            // directly, so fstat kept reporting the stale creation-time mode.
            let path = this
                .open_file(fd.0)
                .and_then(|of| match &*of.description.read() {
                    OpenDescription::HostFile { metadata, .. }
                    | OpenDescription::File { metadata, .. }
                    | OpenDescription::Directory { metadata, .. } => {
                        Some(metadata.path.to_string_lossy().into_owned())
                    }
                    _ => None,
                });
            if let Some(path) = path {
                let _ = this.fs.rootfs_vfs.overlay.set_mode(&path, mode);
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn fchown(this, cx, fd: Fd, owner: u64, group: u64) {

            let fd: Fd = fd;
            if !this.fd_is_valid(fd.0) {
                return Ok(LINUX_EBADF.into());
            }
            let uid = owner as u32;
            let gid = group as u32;
            // Resolve the fd's path so we can record the guest-visible owner on the
            // backend (durably via xattr on --fs host), mirroring fchownat.
            let path = this
                .open_file(fd.0)
                .and_then(|of| match &*of.description.read() {
                    OpenDescription::HostFile { metadata, .. }
                    | OpenDescription::File { metadata, .. }
                    | OpenDescription::Directory { metadata, .. } => {
                        Some(metadata.path.to_string_lossy().into_owned())
                    }
                    _ => None,
                });
            if let Some(path) = path {
                let _ = this.fs.rootfs_vfs.overlay.set_owner(&path, uid, gid);
                this.clear_setid_on_chown(&path);
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn fchownat(this, cx, dirfd: u64, pathname: GuestPtr, owner: u64, group: u64, flags: u64) {

            let dirfd = dirfd;
            let pathname = pathname.0;
            let flags = flags;
            if flags & !(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH) != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            let path = match read_guest_c_string(&*cx.memory, pathname) {
                Ok(path) => path,
                Err(errno) => return Ok(errno.into()),
            };
            if path.is_empty() {
                if flags & LINUX_AT_EMPTY_PATH == 0 {
                    return Ok(LINUX_ENOENT.into());
                }
                if dirfd == LINUX_AT_FDCWD {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                if !this.fd_is_valid(dirfd as i32) {
                    return Ok(LINUX_EBADF.into());
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let uid = owner as u32;
            let gid = group as u32;
            let resolved = match this.resolve_at_path(dirfd, &path) {
                Ok(resolved) => resolved,
                Err(errno) => return Ok(errno.into()),
            };
            // Layered presence check: overlay first (tombstones become ENOENT),
            // synthetic /proc and /sys are no-op success, rootfs is no-op
            // success (tmpfs semantics). Record the guest-visible owner on the
            // backend (durably, via xattr on --fs host) so a later stat reports it.
            match this.layered_metadata(&resolved) {
                Ok(_) => {
                    let _ = this.fs.rootfs_vfs.overlay.set_owner(&resolved, uid, gid);
                    this.clear_setid_on_chown(&resolved);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(errno) => {
                    if crate::vfs::is_synthetic_virtual_file(&resolved, &this.synthetic_proc_context())
                    {
                        Ok(DispatchOutcome::Returned { value: 0 })
                    } else {
                        Ok(errno.into())
                    }
                }
            }

        }

        fn fchmodat(this, cx, dirfd: u64, pathname: GuestPtr, mode: u64, flags: u64) {

            let dirfd = dirfd;
            let pathname = pathname.0;
            // The fchmodat syscall (nr 53) is SYSCALL_DEFINE3 in Linux: it takes
            // only (dirfd, path, mode) and IGNORES the 4th register. glibc's
            // AT_SYMLINK_NOFOLLOW path still leaves the flag in that register —
            // `apt-get update` issues fchmodat(AT_FDCWD, path, 0644, 0x100) on
            // every downloaded index — and the real kernel silently ignores it.
            // Rejecting non-zero flags here made every apt download chmod fail
            // with EINVAL ("chmod 0644 of file … failed - 201::URIDone"). Only
            // fchmodat2 (452) carries a real flags argument; on the
            // disk-authoritative host backend its mode-setting is best-effort, so
            // AT_SYMLINK_NOFOLLOW stays advisory.
            let path = match read_guest_c_string(&*cx.memory, pathname) {
                Ok(path) => path,
                Err(errno) => return Ok(errno.into()),
            };
            if path.is_empty() {
                return Ok(LINUX_ENOENT.into());
            }
            let resolved = match this.resolve_at_path(dirfd, &path) {
                Ok(resolved) => resolved,
                Err(errno) => return Ok(errno.into()),
            };
            // Apply the mode to the writable backend (cap-std set_permissions on
            // --fs host). Synthetic /proc /sys paths and the in-memory backend
            // (Unsupported) accept it as a no-op as long as the path exists.
            if crate::vfs::is_synthetic_virtual_file(&resolved, &this.synthetic_proc_context()) {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if let Err(errno) = this.layered_metadata(&resolved) {
                return Ok(errno.into());
            }
            let mode = (mode & 0o7777) as u32;
            match this.fs.rootfs_vfs.overlay.set_mode(&resolved, mode) {
                Ok(()) | Err(crate::fs_backend::BackendError::Unsupported) => {
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(_) => Ok(DispatchOutcome::Returned { value: 0 }),
            }

        }

        fn linkat(this, cx, olddirfd: u64, oldpath: GuestPtr, newdirfd: u64, newpath: GuestPtr, flags: u64) {

            let olddirfd = olddirfd;
            let oldpath = oldpath.0;
            let newdirfd = newdirfd;
            let newpath = newpath.0;
            let flags = flags;
            if flags & !(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH) != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            let old = match read_guest_c_string(&*cx.memory, oldpath) {
                Ok(path) => path,
                Err(errno) => return Ok(errno.into()),
            };
            let new_path = match read_guest_c_string(&*cx.memory, newpath) {
                Ok(path) => path,
                Err(errno) => return Ok(errno.into()),
            };
            if new_path.is_empty() {
                return Ok(LINUX_ENOENT.into());
            }
            if old.is_empty() && flags & LINUX_AT_EMPTY_PATH == 0 {
                return Ok(LINUX_ENOENT.into());
            }
            let resolved_old = if old.is_empty() {
                if !this.fd_is_valid(olddirfd as i32) {
                    return Ok(LINUX_EBADF.into());
                }
                None
            } else {
                let resolved = match this.resolve_at_path(olddirfd, &old) {
                    Ok(resolved) => resolved,
                    Err(errno) => return Ok(errno.into()),
                };
                let exists =
                    crate::vfs::is_synthetic_virtual_file(&resolved, &this.synthetic_proc_context())
                        || this.layered_metadata(&resolved).is_ok();
                if !exists {
                    return Ok(LINUX_ENOENT.into());
                }
                Some(resolved)
            };
            let resolved_new = match this.resolve_at_path(newdirfd, &new_path) {
                Ok(resolved) => resolved,
                Err(errno) => return Ok(errno.into()),
            };
            if crate::vfs::is_synthetic_virtual_file(&resolved_new, &this.synthetic_proc_context())
                || this.layered_metadata(&resolved_new).is_ok()
            {
                return Ok(LINUX_EEXIST.into());
            }
            // Create a real hard link in the writable backend (cap-std
            // hard_link). dpkg link()s e.g. /var/lib/dpkg/status -> status-old.
            // AT_EMPTY_PATH (link by fd) isn't supported. MemoryBackend can't
            // hard-link an in-memory file, so it falls back to a content copy.
            let Some(src) = resolved_old else {
                return Ok(LINUX_EROFS.into());
            };
            match this.fs.rootfs_vfs.overlay.hard_link(&src, &resolved_new) {
                Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
                Err(crate::fs_backend::BackendError::Unsupported) => {
                    // In-memory backend: emulate with a content copy (callers
                    // like dpkg only need the data, not shared inodes).
                    let contents = this
                        .fs
                        .rootfs_vfs
                        .overlay
                        .file_contents(&src)
                        .or_else(|| {
                            this.fs
                                .rootfs_vfs
                                .rootfs
                                .as_ref()
                                .and_then(|r| r.read(&src).ok())
                        })
                        .unwrap_or_default();
                    match this
                        .fs
                        .rootfs_vfs
                        .overlay
                        .set_file_contents(&resolved_new, contents)
                    {
                        Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
                        Err(_) => Ok(LINUX_EROFS.into()),
                    }
                }
                Err(_) => Ok(LINUX_EROFS.into()),
            }

        }

        fn symlinkat(this, cx, target: GuestPtr, newdirfd: u64, linkpath: GuestPtr) {

            let target = target.0;
            let newdirfd = newdirfd;
            let linkpath = linkpath.0;
            let target_path = match read_guest_c_string(&*cx.memory, target) {
                Ok(target) => target,
                Err(errno) => return Ok(errno.into()),
            };
            if target_path.is_empty() {
                return Ok(LINUX_ENOENT.into());
            }
            let link = match read_guest_c_string(&*cx.memory, linkpath) {
                Ok(link) => link,
                Err(errno) => return Ok(errno.into()),
            };
            if link.is_empty() {
                return Ok(LINUX_ENOENT.into());
            }
            let resolved_link = match this.resolve_at_path(newdirfd, &link) {
                Ok(resolved) => resolved,
                Err(errno) => return Ok(errno.into()),
            };
            if crate::vfs::is_synthetic_virtual_file(&resolved_link, &this.synthetic_proc_context()) {
                return Ok(LINUX_EEXIST.into());
            }
            // If the link path already exists (anywhere in the layered
            // view), report EEXIST. Otherwise the overlay can't create
            // symlinks today, so we return EROFS.
            if this.layered_metadata(&resolved_link).is_ok() {
                return Ok(LINUX_EEXIST.into());
            }
            // Create a real symlink in the writable backend (cap-std). The
            // target is stored verbatim, matching symlinkat(2). MemoryBackend
            // returns Unsupported → EROFS.
            match this
                .fs
                .rootfs_vfs
                .overlay
                .symlink(&target_path, &resolved_link)
            {
                Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
                Err(crate::fs_backend::BackendError::Unsupported) => Ok(LINUX_EROFS.into()),
                Err(_) => Ok(LINUX_EROFS.into()),
            }

        }

        fn renameat(this, cx, olddirfd: u64, oldpath: GuestPtr, newdirfd: u64, newpath: GuestPtr) {

            this.do_renameat(
                olddirfd,
                oldpath.0,
                newdirfd,
                newpath.0,
                0,
                &*cx.memory,
            )

        }

        fn renameat2(this, cx, olddirfd: u64, oldpath: GuestPtr, newdirfd: u64, newpath: GuestPtr, flags: u64) {

            // RENAME_NOREPLACE=1, RENAME_EXCHANGE=2, RENAME_WHITEOUT=4. We
            // implement the common subset (no flags or NOREPLACE). EXCHANGE
            // and WHITEOUT are not supported by overlayfs in our limited
            // mode either, so reject them.
            const RENAME_NOREPLACE: u64 = 1;
            const RENAME_EXCHANGE: u64 = 2;
            let flags = flags;
            if flags & !RENAME_NOREPLACE != 0 {
                if flags & RENAME_EXCHANGE != 0 {
                    return Ok(LINUX_EINVAL.into());
                }
                return Ok(LINUX_EINVAL.into());
            }
            this.do_renameat(
                olddirfd,
                oldpath.0,
                newdirfd,
                newpath.0,
                flags,
                &*cx.memory,
            )

        }

        fn unlinkat(this, cx, dirfd: u64, pathname: GuestPtr, flags: u64) {

            let dirfd = dirfd;
            let pathname = pathname.0;
            let flags = flags;
            if flags & !LINUX_AT_REMOVEDIR != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            let path = match read_guest_c_string(&*cx.memory, pathname) {
                Ok(path) => path,
                Err(errno) => return Ok(errno.into()),
            };
            if path.is_empty() {
                return Ok(LINUX_ENOENT.into());
            }
            let resolved = match this.resolve_at_path(dirfd, &path) {
                Ok(resolved) => resolved,
                Err(errno) => return Ok(errno.into()),
            };
            let remove_dir = flags & LINUX_AT_REMOVEDIR != 0;
            // Synthetic /proc /sys paths can't be unlinked.
            if crate::vfs::is_synthetic_virtual_file(&resolved, &this.synthetic_proc_context()) {
                return Ok(LINUX_EROFS.into());
            }
            use crate::vfs::Vfs as _;
            let result = if remove_dir {
                this.fs.rootfs_vfs.rmdir(&resolved)
            } else {
                this.fs.rootfs_vfs.unlink(&resolved)
            };
            match result {
                Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
                Err(errno) => Ok(errno.into()),
            }

        }

        fn utimensat(this, cx, dirfd: u64, pathname: GuestPtr, times: GuestPtr, flags: u64) {

            let dirfd = dirfd;
            let pathname = pathname.0;
            let times = times.0;
            let flags = flags;
            let memory = &*cx.memory;
            if flags & !LINUX_AT_SYMLINK_NOFOLLOW != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            // `times == NULL` means "set both to now"; otherwise read the two
            // timespecs and resolve UTIME_NOW/UTIME_OMIT into concrete
            // (sec, nsec) pairs or `None` (omit) for the backend.
            #[allow(clippy::type_complexity)]
            let (atime_set, mtime_set): (Option<(i64, i64)>, Option<(i64, i64)>);
            if times != 0 {
                let atime = match read_timespec(memory, times) {
                    Ok(timespec) => timespec,
                    Err(errno) => return Ok(errno.into()),
                };
                let mtime_address = times
                    .checked_add(core::mem::size_of::<LinuxTimespec>() as u64)
                    .ok_or(DispatchError::LengthTooLarge(times))?;
                let mtime = match read_timespec(memory, mtime_address) {
                    Ok(timespec) => timespec,
                    Err(errno) => return Ok(errno.into()),
                };
                if !linux_utimensat_timespec_is_valid(atime)
                    || !linux_utimensat_timespec_is_valid(mtime)
                {
                    return Ok(LINUX_EINVAL.into());
                }
                atime_set = resolve_utimensat_timespec(atime);
                mtime_set = resolve_utimensat_timespec(mtime);
            } else {
                // NULL → set both to the current wall-clock time.
                let now = now_realtime_timespec();
                atime_set = Some(now);
                mtime_set = Some(now);
            }

            if pathname == 0 {
                // `futimens(fd, times)` lowers to `utimensat(fd, NULL, times, 0)`
                // in musl/glibc: set the times of the *open fd itself*. (This is
                // distinct from the AT_EMPTY_PATH form, which carries an empty —
                // not NULL — path.)
                if dirfd == LINUX_AT_FDCWD {
                    return Ok(LINUX_EFAULT.into());
                }
                if atime_set.is_none() && mtime_set.is_none() {
                    // Both UTIME_OMIT: nothing to persist; just validate the fd.
                    if !this.fd_is_valid(dirfd as i32) {
                        return Ok(LINUX_EBADF.into());
                    }
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                return Ok(this.set_fd_times(dirfd as i32, atime_set, mtime_set));
            }

            let path = match read_guest_c_string(memory, pathname) {
                Ok(path) => path,
                Err(errno) => return Ok(errno.into()),
            };
            if path.is_empty() {
                return Ok(LINUX_ENOENT.into());
            }
            let path = match this.resolve_at_path(dirfd, &path) {
                Ok(path) => path,
                Err(errno) => {
                    crate::probes::fs_op("utimensat:resolve_err", &path, errno);
                    return Ok(errno.into());
                }
            };
            // The path must exist in the layered view, else NotFound (or a
            // no-op success for synthetic /proc paths whose times we can't
            // back).
            match this.layered_metadata(&path) {
                Ok(_) => {}
                Err(errno) => {
                    if crate::vfs::is_synthetic_virtual_file(&path, &this.synthetic_proc_context()) {
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    crate::probes::fs_op("utimensat:meta_err", &path, errno);
                    return Ok(errno.into());
                }
            }
            if atime_set.is_none() && mtime_set.is_none() {
                // Both UTIME_OMIT: nothing to persist.
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // Persist atime/mtime to the materialised host file (disk-backed
            // overlay). A subsequent stat reads real disk metadata via
            // real_stat and will report the set mtime. MemoryBackend returns
            // Unsupported; accept as a no-op so in-memory guests don't fail.
            match this
                .fs
                .rootfs_vfs
                .overlay
                .set_times(&path, atime_set, mtime_set)
            {
                Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
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

        fn newfstatat(this, cx, dirfd: u64, pathname: GuestPtr, statbuf: GuestPtr, flags: u64) {

            let dirfd = dirfd;
            let pathname = pathname.0;
            let statbuf = statbuf.0;
            let flags = flags;
            let memory = &mut *cx.memory;
            let path = match read_guest_c_string(memory, pathname) {
                Ok(path) => path,
                Err(errno) => return Ok(errno.into()),
            };

            if path.is_empty() && flags & LINUX_AT_EMPTY_PATH != 0 {
                return Ok(this.write_fd_stat(dirfd as i32, statbuf, memory));
            }

            let path = match this.resolve_at_path(dirfd, &path) {
                Ok(path) => path,
                Err(errno) => return Ok(errno.into()),
            };
            // Synthetic /proc /sys paths first.
            if let Some(contents) =
                crate::vfs::proc::synthetic_file(&path, &this.synthetic_proc_context())
            {
                return Ok(write_synthetic_stat(
                    memory,
                    statbuf,
                    &path,
                    contents.len(),
                    LINUX_S_IFREG | 0o444,
                ));
            }
            if let Some(contents) = crate::vfs::sys::synthetic_file(&path) {
                return Ok(write_synthetic_stat(
                    memory,
                    statbuf,
                    &path,
                    contents.len(),
                    LINUX_S_IFREG | 0o444,
                ));
            }
            // Disk-backed overlay (--fs host): prefer the REAL on-disk stat
            // so the type bits (S_IFLNK for a symlink) and st_nlink (a true
            // hard link reports >1) reflect what the kernel would report.
            // `AT_SYMLINK_NOFOLLOW` selects lstat (report the link) vs stat
            // (report the target) semantics.
            let follow = flags & LINUX_AT_SYMLINK_NOFOLLOW == 0;
            if let Some(real) = this.fs.rootfs_vfs.overlay.real_stat(&path, follow) {
                return Ok(write_stat_real(memory, statbuf, &path, &real));
            }
            // real_stat couldn't answer. If following and `path` is a symlink
            // whose target lands in ANOTHER mount, resolve it through the full
            // VFS and stat the target — so its dev/ino matches a direct stat of
            // the target (Go os.Getwd's $PWD trust check stats $PWD and ".", and
            // a /tmp-scratch link → /run-bind-mount target must agree). No-op for
            // non-symlinks and AT_SYMLINK_NOFOLLOW (lstat).
            let path = if follow {
                this.canonicalize_following(&path).unwrap_or(path)
            } else {
                path
            };
            // Retry the fast path in case the resolved target is in the scratch.
            if let Some(real) = this.fs.rootfs_vfs.overlay.real_stat(&path, follow) {
                return Ok(write_stat_real(memory, statbuf, &path, &real));
            }
            use crate::vfs::Vfs as _;
            // VFS mounts (/dev, /dev/pts, /proc, /sys): stat their nodes so e.g.
            // /dev/ptmx, /dev/pts/N, /dev/tty resolve (mirrors the open path).
            if let Some(m) = this.fs.vfs_mounts.resolve(&path)
                && let Ok(md) = m.vfs.lookup(&m.full_path)
            {
                // RootFsEntryKind::CharDevice → S_IFCHR via linux_mode, so e.g.
                // /dev/pts/N reports a char device (ttyname(3)'s chardev check).
                return Ok(write_stat(
                    memory,
                    statbuf,
                    &vfs_md_to_rootfs_md(&path, &md),
                ));
            }
            // Layered overlay+rootfs lookup via RootFsVfs. Honour
            // AT_SYMLINK_NOFOLLOW (lstat) on backends without real_stat.
            let lookup = if follow {
                this.fs.rootfs_vfs.lookup(&path)
            } else {
                this.fs.rootfs_vfs.lookup_nofollow(&path)
            };
            match lookup {
                Ok(md) => Ok(write_stat(
                    memory,
                    statbuf,
                    &vfs_md_to_rootfs_md(&path, &md),
                )),
                Err(errno) => Ok(errno.into()),
            }

        }

        fn statx(this, cx, dirfd: u64, pathname: GuestPtr, flags: u64, mask: u64, statxbuf: GuestPtr) {

            let dirfd = dirfd;
            let pathname = pathname.0;
            let flags = flags;
            let mask = mask;
            let statxbuf = statxbuf.0;
            let memory = &mut *cx.memory;

            if !linux_statx_flags_are_supported(flags) || mask & LINUX_STATX_RESERVED != 0 {
                return Ok(LINUX_EINVAL.into());
            }

            let path = match read_guest_c_string(memory, pathname) {
                Ok(path) => path,
                Err(errno) => return Ok(errno.into()),
            };

            if path.is_empty() {
                if flags & LINUX_AT_EMPTY_PATH == 0 {
                    return Ok(LINUX_ENOENT.into());
                }
                return Ok(this.write_fd_statx(dirfd as i32, statxbuf, memory));
            }

            let path = match this.resolve_at_path(dirfd, &path) {
                Ok(path) => path,
                Err(errno) => return Ok(errno.into()),
            };
            if let Some(contents) =
                crate::vfs::proc::synthetic_file(&path, &this.synthetic_proc_context())
            {
                return Ok(write_synthetic_statx(
                    memory,
                    statxbuf,
                    &path,
                    contents.len(),
                ));
            }
            if let Some(contents) = crate::vfs::sys::synthetic_file(&path) {
                return Ok(write_synthetic_statx(
                    memory,
                    statxbuf,
                    &path,
                    contents.len(),
                ));
            }
            // Disk-backed overlay (--fs host): prefer the REAL on-disk stat
            // (S_IFLNK + true st_nlink). `AT_SYMLINK_NOFOLLOW` selects lstat
            // (the link) vs stat (the target).
            let follow = flags & LINUX_AT_SYMLINK_NOFOLLOW == 0;
            if let Some(real) = this.fs.rootfs_vfs.overlay.real_stat(&path, follow) {
                return Ok(write_statx_real(memory, statxbuf, &path, &real));
            }
            use crate::vfs::Vfs as _;
            // VFS mounts (/dev, /dev/pts, /proc, /sys): stat their nodes so e.g.
            // /dev/ptmx, /dev/pts/N, /dev/tty resolve (mirrors the open path).
            if let Some(m) = this.fs.vfs_mounts.resolve(&path)
                && let Ok(md) = m.vfs.lookup(&m.full_path)
            {
                return Ok(write_statx(
                    memory,
                    statxbuf,
                    &vfs_md_to_rootfs_md(&path, &md),
                ));
            }
            // Fallback for backends without real_stat (e.g. the in-memory
            // overlay): honour AT_SYMLINK_NOFOLLOW by reporting the link itself
            // rather than its target.
            let lookup = if follow {
                this.fs.rootfs_vfs.lookup(&path)
            } else {
                this.fs.rootfs_vfs.lookup_nofollow(&path)
            };
            match lookup {
                Ok(md) => Ok(write_statx(
                    memory,
                    statxbuf,
                    &vfs_md_to_rootfs_md(&path, &md),
                )),
                Err(errno) => Ok(errno.into()),
            }

        }

        fn fstat(this, cx, fd: Fd, statbuf: GuestPtr) {

            let fd: Fd = fd;
            let statbuf = statbuf.0;
            Ok(this.write_fd_stat(fd.0, statbuf, &mut *cx.memory))

        }

    }
}
