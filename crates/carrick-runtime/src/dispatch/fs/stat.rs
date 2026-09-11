//! fd stat/statx record assembly split out of dispatch/fs.rs (WS-F3):
//! the synthetic stdio (label, st_mode) probe and the fstat/statx
//! buffer writers + StatRecord builder. Pure `impl SyscallDispatcher` move.
use super::*;
use crate::linux_abi::LinuxErrno;

impl<'a> FsView<'a> {
    /// The synthetic `(label, st_mode)` for a bare stdio fd (0/1/2) with no
    /// OpenDescription. Glibc fstat()s stdio on startup to pick its tty/file/
    /// pipe code path, so report the REAL host type (a pty → S_IFCHR, a pipe →
    /// S_IFIFO, a redirect → S_IFREG; the S_IF* values match Linux). When the
    /// fd is the `carrick run -t` controlling tty, label it `/dev/pts/N` so the
    /// synthetic st_ino matches `stat("/dev/pts/N")` — the equality `ttyname(3)`
    /// checks between `fstat(fd)` and the `/proc/self/fd/N` readlink target.
    /// Shared by `write_fd_stat` (fstat) and `write_fd_statx` (statx).
    pub(super) fn stdio_synthetic_label_mode(&self, fd: i32) -> (String, u32) {
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

    pub(super) fn write_fd_stat(
        &self,
        fd: i32,
        statbuf: u64,
        memory: &mut impl CurrentMmMemory,
    ) -> DispatchOutcome {
        match self.fd_stat_record(fd) {
            Ok(record) => write_stat_record(memory, statbuf, &record),
            Err(errno) => DispatchOutcome::errno(errno),
        }
    }

    pub(super) fn write_fd_statx(
        &self,
        fd: i32,
        statxbuf: u64,
        memory: &mut impl CurrentMmMemory,
    ) -> DispatchOutcome {
        match self.fd_stat_record(fd) {
            Ok(record) => write_statx_record(memory, statxbuf, &record),
            Err(errno) => DispatchOutcome::errno(errno),
        }
    }

    pub(super) fn fd_stat_record(&self, fd: i32) -> Result<StatRecord, LinuxErrno> {
        let Some(open_file) = self.open_file(fd) else {
            // A stdio fd the guest explicitly closed (and did not reopen) is
            // genuinely closed: report EBADF, not our still-open host stream.
            if is_stdio_fd(fd) && !self.stdio_is_closed(fd) {
                let (label, mode) = self.stdio_synthetic_label_mode(fd);
                return Ok(StatRecord::synthetic(&label, 0, mode));
            }
            return Err(LINUX_EBADF);
        };
        if open_file
            .description
            .concrete_backing::<crate::dispatch::ioring::IoUringBacking>()
            .is_some()
        {
            return Ok(StatRecord::synthetic("anon_inode:[io_uring]", 0, 0o600));
        }
        let Some(open) = open_file.description.read() else {
            return Err(LINUX_EBADF);
        };
        // A named FIFO opened by path is modelled as a `HostPipe` (no pty),
        // whose `stat_source` hands back a SYNTHETIC record (hashed inode,
        // mode 0o600). But a path-stat (lstat) of the same FIFO reports the
        // REAL on-disk inode/mode, so `os.path.samestat(lstat(fifo),
        // fstat(open(fifo)))` was False — shutil.rmtree's safe-fd walk then
        // mis-classified the pipe as a symlink ("Cannot call rmtree on a
        // symbolic link") instead of raising NotADirectoryError
        // (test_rmtree_on_named_pipe). Anonymous pipe2() ends are also
        // `HostPipe` but carry no recorded path, so they keep the synthetic
        // record. Recover the real FIFO stat from the fd's recorded path.
        let is_named_pipe = matches!(&*open, OpenDescription::HostPipe { pty: None, .. });
        let source = open.stat_source();
        drop(open);
        if is_named_pipe
            && let Some(path) = self.lookup_recorded_fd_open_path(fd)
            && let Some(real) = self.fs.rootfs_vfs.overlay.real_stat(&path, false)
            && real.kind == RootFsEntryKind::Fifo
        {
            return Ok(StatRecord::from_real(&path, &real));
        }
        match source {
            OpenStatSource::Record(record) => Ok(record),
            OpenStatSource::HostStream {
                host_fd,
                identity,
                fallback_mode,
            } => {
                // fstat the real host fd to recover the Linux file type: a host
                // character device (/dev/null, /dev/zero, …) reports S_IFCHR
                // (mode 0o666, like Linux), a host pipe end reports S_IFIFO
                // (mode 0o600). The S_IF* type bits match between macOS and
                // Linux. Falls back to `fallback_mode` if the host fstat fails.
                let mut host_st: libc::stat = unsafe { std::mem::zeroed() };
                // SAFETY: host_fd is a live host fd; &host_st is a valid out-param.
                let mode = if unsafe { libc::fstat(host_fd.get(), &mut host_st) } == 0 {
                    let type_bits = host_st.st_mode as u32 & LINUX_S_IFMT;
                    let perms = if type_bits == LINUX_S_IFCHR {
                        0o666
                    } else {
                        0o600
                    };
                    type_bits | perms
                } else {
                    fallback_mode
                };
                // Preserve open-description identity in guest stat records.
                // A constant label made every HostPipe-backed object share one
                // synthetic inode: after `2>&1 >/dev/null`, GNU m4 therefore
                // mistook stderr's pipe for stdout's /dev/null and discarded
                // `dumpdef`, leaving autom4te with an empty builtin table.
                // Include the Linux file type because host inode numbers can
                // collide across devices; use `pipe_id` for identity because
                // BSD gives the two ends of one pipe different host inodes.
                let label = host_stream_stat_label(identity, mode & LINUX_S_IFMT);
                Ok(StatRecord::synthetic(&label, 0, mode))
            }
            // An open Directory or in-memory File: its fd-stat must report the
            // SAME st_ino/st_dev as a path-stat of the same path. Under
            // `--fs host` the path-stat (newfstatat/statx) uses the REAL host
            // inode via `overlay.real_stat`; mirror it here so
            // `os.path.samestat(lstat(dir), fstat(open(dir)))` is True (the
            // synthetic `fallback` hashes the path to a DIFFERENT inode). When
            // no host stat exists (MemoryBackend), the path-stat is ALSO the
            // synthetic record, so the `fallback` already matches.
            OpenStatSource::PathRecord { path, fallback } => {
                if let Some(real) = self.fs.rootfs_vfs.overlay.real_stat(&path, true) {
                    Ok(StatRecord::from_real(&path, &real))
                } else if let Some(real) = self
                    .fs
                    .vfs_mounts
                    .resolve(&path)
                    .and_then(|m| m.vfs.real_stat(&m.full_path, true))
                {
                    // The path-stat (newfstatat) falls through to the VFS mount
                    // table when the overlay misses — a bind mount (`-v`), /proc,
                    // /dev. Mirror it so a bind-mounted DIRECTORY's fstat reports
                    // the SAME (real host) inode as its path-stat; otherwise
                    // SameFile(fstat(open(dir)), stat(dir)) is false (Go os
                    // TestFileChdir; Python os.path.samestat). Without this the
                    // fd fell back to the path-HASH inode while the path-stat
                    // returned the real host inode.
                    Ok(StatRecord::from_real(&path, &real))
                } else if let Some(real) = self
                    .fs
                    .rootfs_vfs
                    .immutable_lower_real_stat(&path, true)
                    .map(|real| StatRecord::from_real(&path, &real))
                    .filter(|real| real.mode & LINUX_S_IFMT == fallback.mode & LINUX_S_IFMT)
                {
                    // A DIRECTORY only the immutable cache lower holds. Its
                    // path-stat now reports the lower's real host inode (see
                    // `layered_identity_record`), so this lane must too —
                    // otherwise fixing the regular-file case would simply move
                    // the `samestat` disagreement onto directories. Regular
                    // files never reach here: they open as a real `HostFile`.
                    Ok(real)
                } else {
                    Ok(fallback)
                }
            }
            OpenStatSource::HostFile { host_fd, metadata } => {
                let path = metadata.path.to_string_lossy().into_owned();
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(host_fd.get(), &mut st) } == 0 {
                    let inode_rec = self
                        .fs
                        .rootfs_vfs
                        .get_or_fill_host_inode(host_fd.get(), &st);
                    let device = if inode_rec.dev_type != 0 {
                        Some((inode_rec.dev_type, inode_rec.rdev))
                    } else {
                        None
                    };
                    let mut real = super::real_stat_from_libc(&st);
                    real.mode = inode_rec.mode & 0o7777;
                    real.uid = inode_rec.uid;
                    real.gid = inode_rec.gid;
                    let mut record = StatRecord::from_real(&path, &real);
                    record.apply_device_node(device);
                    return Ok(record);
                }
                Ok(StatRecord::from_metadata(&metadata))
            }
        }
    }

    /// Build a [`StatRecord`] from a real backing stat, applying the `mknod(2)`
    /// device-node override (S_IFCHR/S_IFBLK type + st_rdev) when `path` is a
    /// device marker. The marker's FULL guest mode (including the device type
    /// bits) is carried VERBATIM in `RealStat.mode` (the host backend stores it
    /// raw in `CARRICK_MODE_XATTR`); `from_real`/`linux_mode` masks those type
    /// bits off, so we recover the device type from `real.mode` here WITHOUT a
    /// second xattr read — the common stat hot path pays nothing. Only when the
    /// type bits actually name a device do we fetch the (rare) `st_rdev` xattr.
    /// A plain regular file (no device type bits) is returned unchanged.
    pub(super) fn stat_record_with_device(
        &self,
        path: &str,
        real: &crate::fs_backend::RealStat,
    ) -> StatRecord {
        let mut record = StatRecord::from_real(path, real);
        let type_bits = real.mode & LINUX_S_IFMT;
        if type_bits == LINUX_S_IFCHR || type_bits == LINUX_S_IFBLK {
            let rdev = self
                .fs
                .rootfs_vfs
                .overlay
                .device_node(path)
                .map(|(_, dev)| dev)
                .unwrap_or(0);
            record.apply_device_node(Some((type_bits, rdev)));
        }
        record
    }

    /// Give a layered-lookup result the identity of the host inode that
    /// actually backs it.
    ///
    /// The layered resolver owns EXISTENCE and kind — whiteouts, copy-up,
    /// cross-layer symlinks. It cannot own identity: `vfs::Metadata` and
    /// `RootFsMetadata` carry no inode, no link count and no timestamps, so
    /// `StatRecord::from_metadata` hashes the path instead. That is fine for a
    /// synthetic entry, but an entry only the immutable cache lower holds is a
    /// REAL host file — `open()` hands back its host fd, `fstat` reports its
    /// APFS inode and `getdents64` already publishes that inode as `d_ino`.
    /// A path hash here made `stat(p).st_ino != fstat(open(p)).st_ino`, which
    /// GNU coreutils `cp` reads as the source being replaced mid-copy
    /// (`cp: skipping file '…', as it was replaced while being copied` →
    /// LTP `execve02` TBROK once the cached lower was enabled for HvPatch).
    ///
    /// Kind agreement gates the adoption: a mismatch means the resolver landed
    /// on something other than the lower entry of that name, so its answer
    /// stands.
    pub(super) fn layered_identity_record(
        &self,
        path: &str,
        follow: bool,
        metadata: &RootFsMetadata,
    ) -> StatRecord {
        match self.fs.rootfs_vfs.immutable_lower_real_stat(path, follow) {
            Some(real) if real.kind == metadata.kind => StatRecord::from_real(path, &real),
            _ => StatRecord::from_metadata(metadata),
        }
    }

    /// `statx` twin of [`stat_record_with_device`](Self::stat_record_with_device):
    pub(super) fn path_stat_record(
        &self,
        context: &crate::kernel::KernelContext,
        dirfd: u64,
        path: &str,
        flags: u64,
    ) -> Result<StatRecord, LinuxErrno> {
        let at_flags = carrick_abi::LinuxAtFlags::from_bits_retain(flags);
        let lookup = self.lookup_path(dirfd, path, at_flags, LookupIntent::Stat { context })?;
        let _ = &lookup.resolved_path;
        let _ = lookup.fast_path();
        let _ = lookup.resolved_path();
        lookup.into_stat()
    }

    fn statfs(
        &self,
        pathname: GuestPtr,
        buffer: GuestPtr,
        memory: &mut impl CurrentMmMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let path = read_guest_c_string(memory, pathname.0)?;
        // An empty pathname is ENOENT (statfs has no AT_EMPTY_PATH form). glibc
        // pathconf(path, _PC_LINK_MAX) validates the path via statfs, so
        // statfs("") must fail rather than succeed and yield LINK_MAX
        // (pathconf02 empty-string case).
        if path.is_empty() {
            return Ok(DispatchOutcome::errno(LINUX_ENOENT));
        }
        let path = self.resolve_at_path(LINUX_AT_FDCWD, &path)?;
        // statfs(2) follows symlinks; a symlink CYCLE is ELOOP. resolve_at_path
        // doesn't cap symlink depth, so canonicalize here to surface a cycle as
        // ELOOP (LTP statfs02/statvfs02). Other resolution errors fall through to
        // layered_metadata, which reports ENOENT/ENOTDIR/ENAMETOOLONG as before.
        let path = match self.canonicalize_following(&path) {
            Ok(resolved) => resolved,
            Err(e) if e == crate::linux_abi::LINUX_ELOOP => return Ok(DispatchOutcome::errno(e)),
            Err(_) => path,
        };
        // Consult the layered view (overlay/disk first, then rootfs) so
        // that files the guest created in the overlay are visible here
        // too — a rootfs-direct lookup would miss them.
        if let Err(errno) = self.layered_metadata(&path) {
            return Ok(DispatchOutcome::errno(errno));
        }
        Ok(write_statfs(memory, buffer.0))
    }

    fn fstatfs(&self, fd: Fd, buf: GuestPtr, memory: &mut impl CurrentMmMemory) -> DispatchOutcome {
        if !self.fd_table_contains(fd.0) {
            return DispatchOutcome::errno(LINUX_EBADF);
        }
        write_statfs(memory, buf.0)
    }

    /// Single-component `newfstatat`/`statx` through a TRUSTED host dirfd:
    /// one `fstatat(host_dirfd, name, AT_SYMLINK_NOFOLLOW)` plus (on a
    /// regular-file/dir hit) one no-atime leaf open for the carrick xattr
    /// metadata — replacing the anchor re-verify + parent validation + the
    /// layered stat stack. A non-symlink hit makes follow and no-follow
    /// coincide, so the caller's AT_SYMLINK_NOFOLLOW needs no case split; a
    /// symlink child falls back (exact lstat semantics INCLUDING the
    /// link-owner xattrs stay on the slow path). Missing is authoritative
    /// (`Some(Err(ENOENT))`); `None` ⇒ take the full path.
    pub(super) fn try_trusted_dirfd_stat(
        &self,
        dirfd: u64,
        path: &str,
    ) -> Option<Result<StatRecord, LinuxErrno>> {
        use std::os::fd::{FromRawFd, OwnedFd};
        // fts walkers (GNU find, and every fts-based tool) stat each
        // directory they descend as "." relative to the directory's OWN fd.
        // The trusted dir IS the object: serve fstat(host_dirfd) directly —
        // no component gate, no leaf probe (the metadata pass reads the
        // already-open fd when metadata xattrs may exist anywhere).
        if path == "." {
            let (dir_path, host_dir) = self.trusted_dir_of(dirfd)?;
            if !host_dir
                .namespace_is_current_against(self.fs.rootfs_vfs.overlay.structural_generation())
            {
                return None;
            }
            if !host_dir.is_merged_upper() {
                // A lower dirfd's own identity is now the cache directory's
                // real host inode either way (`layered_identity_record`), so
                // this is no longer about which inode to report — it is that
                // the anchor may have been whiteout-shadowed or copied up
                // since it was opened, which only the layered walk can see.
                return None;
            }
            if !self.cred_snapshot().euid.is_root() {
                return None;
            }
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(host_dir.fd.raw(), &mut st) } != 0 {
                return None;
            }
            if st.st_mode as u32 & libc::S_IFMT as u32 != libc::S_IFDIR as u32 {
                return None;
            }
            let (override_mode, uid, gid, _) = if self.fs.rootfs_vfs.overlay.serves_plain_metadata()
            {
                (None, None, None, false)
            } else {
                crate::fs_backend::fd_carrick_meta(host_dir.fd.raw())
            };
            let on_disk_mode = st.st_mode as u32 & 0o7777;
            let real = crate::fs_backend::RealStat {
                kind: RootFsEntryKind::Directory,
                ino: st.st_ino,
                nlink: st.st_nlink as u32,
                mode: override_mode
                    .map(|m| m & 0o7777)
                    .unwrap_or(if on_disk_mode == 0 {
                        0o755
                    } else {
                        on_disk_mode
                    }),
                uid: uid.unwrap_or(carrick_abi::NsUid::ROOT),
                gid: gid.unwrap_or(carrick_abi::NsGid::ROOT),
                size: st.st_size as u64,
                blocks: Some(st.st_blocks.max(0) as u64),
                atime: (st.st_atime, carrick_portable::stat_atime_nsec(&st)),
                mtime: (st.st_mtime, carrick_portable::stat_mtime_nsec(&st)),
                ctime: (st.st_ctime, carrick_portable::stat_ctime_nsec(&st)),
            };
            return Some(Ok(self.stat_record_with_device(&dir_path, &real)));
        }
        let name = Self::trusted_lane_component(path)?;
        let (dir_path, host_dir) = self.trusted_dir_of(dirfd)?;
        if !host_dir
            .namespace_is_current_against(self.fs.rootfs_vfs.overlay.structural_generation())
        {
            return None;
        }
        if !host_dir.is_merged_upper() {
            return None;
        }
        let full = self.trusted_child_path(&dir_path, name)?;
        // A non-root fsuid needs the ancestor search-permission checks. fsuid,
        // not euid: it is the identity every DAC check uses (setfsuid(2)), and
        // a bypass keyed on the other one is how a permission check gets
        // skipped for a caller that has genuinely dropped privilege.
        if !self.dac_overrides_permissions() {
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
                Some(Err(LINUX_ENOENT))
            } else {
                None
            };
        }
        let typ = st.st_mode as u32 & libc::S_IFMT as u32;
        let is_dir = typ == libc::S_IFDIR as u32;
        if !is_dir && typ != libc::S_IFREG as u32 {
            // Symlink (follow-vs-lstat + link-owner xattrs), FIFO (must never
            // be opened), real device: exact slow path.
            return None;
        }
        // Carrick metadata (mode/owner/socket) via one flistxattr-gated pass
        // on a no-atime fd — the same fill pattern (and the same benign
        // fstatat→openat window) as the stat cache's
        // `stat_cache_get_or_fill`. Skipped entirely when the root markers
        // prove NO entry anywhere carries metadata xattrs or marker nodes:
        // the fstatat above is then the complete guest answer, and the whole
        // stat costs ONE host syscall.
        let (override_mode, uid, gid, is_socket) =
            if self.fs.rootfs_vfs.overlay.serves_plain_metadata() {
                (None, None, None, false)
            } else {
                #[cfg(target_os = "macos")]
                const O_EVTONLY: libc::c_int = 0x8000;
                #[cfg(not(target_os = "macos"))]
                const O_EVTONLY: libc::c_int = libc::O_RDONLY;
                let leaf_flags = O_EVTONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
                let raw =
                    unsafe { libc::openat(host_dir.fd.raw(), name_c.as_ptr(), leaf_flags, 0) };
                if raw < 0 {
                    return None;
                }
                // SAFETY: freshly-opened owned fd, closed on drop.
                let leaf = unsafe { OwnedFd::from_raw_fd(raw) };
                let meta = crate::fs_backend::fd_carrick_meta(raw);
                drop(leaf);
                meta
            };
        let kind = if is_dir {
            RootFsEntryKind::Directory
        } else if is_socket {
            RootFsEntryKind::Socket
        } else {
            RootFsEntryKind::File
        };
        let on_disk_mode = st.st_mode as u32 & 0o7777;
        let default_mode = if is_dir { 0o755 } else { 0o644 };
        let real = crate::fs_backend::RealStat {
            kind,
            ino: st.st_ino,
            nlink: st.st_nlink as u32,
            // The override is carried VERBATIM (device markers keep their
            // type bits) — `stat_record_with_device` below recovers them,
            // exactly like the stat-cache hit path.
            mode: override_mode.unwrap_or(if on_disk_mode == 0 {
                default_mode
            } else {
                on_disk_mode
            }),
            uid: uid.unwrap_or(carrick_abi::NsUid::ROOT),
            gid: gid.unwrap_or(carrick_abi::NsGid::ROOT),
            size: st.st_size as u64,
            blocks: Some(st.st_blocks.max(0) as u64),
            atime: (st.st_atime, carrick_portable::stat_atime_nsec(&st)),
            mtime: (st.st_mtime, carrick_portable::stat_mtime_nsec(&st)),
            ctime: (st.st_ctime, carrick_portable::stat_ctime_nsec(&st)),
        };
        Some(Ok(self.stat_record_with_device(&full, &real)))
    }

    define_syscall! {
        fn sys_statfs(this, cx, path: GuestPtr, buf: GuestPtr) {

            this.statfs(path, buf, cx.memory)

        }

        fn sys_fstatfs(this, cx, fd: Fd, buf: GuestPtr) {

            Ok(this.fstatfs(fd, buf, cx.memory))

        }


        fn newfstatat(this, cx, dirfd: u64, pathname: GuestPtr, statbuf: GuestPtr, flags: u64) {
            let Some(at_flags) = carrick_abi::LinuxAtFlags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            // Only AT_SYMLINK_NOFOLLOW, AT_NO_AUTOMOUNT and AT_EMPTY_PATH are
            // valid; any other bit is EINVAL (fstatat01 case 4 passes flags=9999).
            if at_flags.bits() & !(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_NO_AUTOMOUNT | LINUX_AT_EMPTY_PATH) != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let pathname = pathname.0;
            let statbuf = statbuf.0;
            let memory = &mut *cx.memory;
            let path = read_guest_c_string(memory, pathname)?;
            match this.path_stat_record(cx.kernel, dirfd, &path, flags) {
                Ok(record) => Ok(write_stat_record(memory, statbuf, &record)),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }

        }

        fn x86_stat(this, cx, pathname: GuestPtr, statbuf: GuestPtr) {

            let pathname = pathname.0;
            let statbuf = statbuf.0;
            let memory = &mut *cx.memory;
            let path = read_guest_c_string(memory, pathname)?;
            match this.path_stat_record(cx.kernel, LINUX_AT_FDCWD, &path, 0) {
                Ok(record) => Ok(write_x8664_stat_record(memory, statbuf, &record)),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }

        }

        fn x86_fstat(this, cx, fd: Fd, statbuf: GuestPtr) {

            let statbuf = statbuf.0;
            let memory = &mut *cx.memory;
            match this.fd_stat_record(fd.0) {
                Ok(record) => Ok(write_x8664_stat_record(memory, statbuf, &record)),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }

        }

        fn x86_lstat(this, cx, pathname: GuestPtr, statbuf: GuestPtr) {

            let pathname = pathname.0;
            let statbuf = statbuf.0;
            let memory = &mut *cx.memory;
            let path = read_guest_c_string(memory, pathname)?;
            match this.path_stat_record(
                cx.kernel,
                LINUX_AT_FDCWD,
                &path,
                LINUX_AT_SYMLINK_NOFOLLOW,
            ) {
                Ok(record) => Ok(write_x8664_stat_record(memory, statbuf, &record)),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }

        }

        fn x86_newfstatat(this, cx, dirfd: u64, pathname: GuestPtr, statbuf: GuestPtr, flags: u64) {

            let Some(at_flags) = carrick_abi::LinuxAtFlags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            // Only AT_SYMLINK_NOFOLLOW, AT_NO_AUTOMOUNT and AT_EMPTY_PATH are
            // valid; any other bit is EINVAL (fstatat01 case 4 passes flags=9999).
            if at_flags.bits() & !(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_NO_AUTOMOUNT | LINUX_AT_EMPTY_PATH) != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let pathname = pathname.0;
            let statbuf = statbuf.0;
            let memory = &mut *cx.memory;
            let path = read_guest_c_string(memory, pathname)?;
            match this.path_stat_record(cx.kernel, dirfd, &path, flags) {
                Ok(record) => Ok(write_x8664_stat_record(memory, statbuf, &record)),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }

        }

        fn statx(this, cx, dirfd: u64, pathname: GuestPtr, flags: u64, mask: u64, statxbuf: GuestPtr) {

            let pathname = pathname.0;
            let statxbuf = statxbuf.0;
            let memory = &mut *cx.memory;

            if false {
                let uninit_real = std::mem::MaybeUninit::<crate::fs_backend::RealStat>::uninit();
                let uninit_md = std::mem::MaybeUninit::<RootFsMetadata>::uninit();
                unsafe {
                    let _ = write_statx_real(memory, 0, "", &*uninit_real.as_ptr());
                    let _ = write_statx(memory, 0, &*uninit_md.as_ptr());
                }
                let _ = write_synthetic_statx(memory, 0, "", 0);
                let _ = write_synthetic_statx_mode(memory, 0, "", 0, 0);
            }

            if !linux_statx_flags_are_supported(flags) || mask & LINUX_STATX_RESERVED != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }

            let path = read_guest_c_string(memory, pathname)?;
            if path.is_empty() {
                if flags & LINUX_AT_EMPTY_PATH == 0 {
                    return Ok(DispatchOutcome::errno(LINUX_ENOENT));
                }
                return Ok(this.write_fd_statx(dirfd as i32, statxbuf, memory));
            }

            let at_flags = carrick_abi::LinuxAtFlags::from_bits_retain(flags);
            let lookup = match this.lookup_path(dirfd, &path, at_flags, LookupIntent::Statx { context: cx.kernel }) {
                Ok(lookup) => lookup,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let _ = lookup.fast_path_answered();
            let _ = lookup.resolved_path();
            match lookup.into_stat() {
                Ok(record) => Ok(write_statx_record(memory, statxbuf, &record)),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }

        }

        fn fstat(this, cx, fd: Fd, statbuf: GuestPtr) {

            let fd: Fd = fd;
            let statbuf = statbuf.0;
            Ok(this.write_fd_stat(fd.0, statbuf, &mut *cx.memory))

        }

    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_stream_file(
        host_fd: i32,
        pipe_id: u64,
        is_read_end: bool,
        write_kind: HostWriteKind,
    ) -> OpenFile {
        OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::HostPipe {
                base: OpenDescriptionBase::new(if is_read_end {
                    LINUX_O_RDONLY
                } else {
                    LINUX_O_WRONLY
                }),
                host_fd: HostFdRef::new(host_fd),
                is_read_end,
                pipe_id,
                pty: None,
                bidirectional: false,
                write_kind,
                stdio_stream: None,
            })),
            if is_read_end {
                LINUX_O_RDONLY
            } else {
                LINUX_O_WRONLY
            },
            0,
        )
    }

    #[test]
    fn host_stream_stats_distinguish_devices_and_preserve_pipe_identity() {
        let dispatcher = SyscallDispatcher::new();
        let mut pipe_fds = [-1; 2];
        // SAFETY: `pipe_fds` has space for both output descriptors.
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        // SAFETY: static NUL-terminated path; returned fd is owned below.
        let null_fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY) };
        assert!(null_fd >= 0);

        let pipe_identity = host_inode_pipe_id(pipe_fds[0]);
        let null_identity = host_inode_pipe_id(null_fd);
        assert_ne!(pipe_identity, 0);
        assert_ne!(null_identity, 0);
        {
            let file_table = dispatcher.captured_file_table();
            let mut files = file_table.write_open_files();
            files.insert(
                20,
                host_stream_file(pipe_fds[0], pipe_identity, true, HostWriteKind::PipeLike),
            );
            files.insert(
                21,
                host_stream_file(pipe_fds[1], pipe_identity, false, HostWriteKind::PipeLike),
            );
            files.insert(
                22,
                host_stream_file(null_fd, null_identity, false, HostWriteKind::RegularFile),
            );
        }

        let pipe_read = dispatcher.fd_stat_record(20).expect("pipe read stat");
        let pipe_write = dispatcher.fd_stat_record(21).expect("pipe write stat");
        let null = dispatcher.fd_stat_record(22).expect("null stat");
        assert_eq!(pipe_read.ino, pipe_write.ino);
        assert_ne!(pipe_read.ino, null.ino);
        assert_eq!(pipe_read.mode & LINUX_S_IFMT, LINUX_S_IFIFO);
        assert_eq!(null.mode & LINUX_S_IFMT, LINUX_S_IFCHR);

        let pipe_link = dispatcher
            .open_file(20)
            .and_then(|file| file.description.read()?.readlink_target())
            .expect("pipe readlink target");
        assert_eq!(pipe_link, format!("pipe:[{}]", pipe_read.ino));
    }
}
