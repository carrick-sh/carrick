//! Directory operations: `getdents64`, `mkdirat`, `mknodat`, `linkat`,
//! `symlinkat`, `renameat`, `renameat2`, `unlinkat`, `readlinkat`.
use super::*;
use std::path::Path;

struct RenameAtRequest {
    olddirfd: u64,
    oldpath: u64,
    newdirfd: u64,
    newpath: u64,
    flags: u64,
    target_tid: Option<crate::thread::ThreadId>,
}

impl SyscallDispatcher {
    /// Whether a raw `getdirentries64` stream off `trusted`'s fd IS the exact
    /// guest listing of `dir_path` — i.e. no other layer contributes a name to
    /// it and every `d_type` the stream reports is the guest-visible type.
    ///
    /// Both anchors qualify, under the proof their own layer already carries:
    ///
    /// - `MergedUpper`: the scratch tree is the merged truth (rootfs
    ///   materialized, deletions are real unlinks), so only a MARKER node (an
    ///   AF_UNIX socket or `mknod` device — a regular file whose guest type
    ///   lives in an xattr) can make the stream lie, which
    ///   `dir_has_overlay_interference` answers root-wide.
    /// - `ImmutableLower`: the anchor was minted only after
    ///   `fast_nofollow_absent(dir)` proved the sparse upper holds NOTHING at
    ///   this directory and has published no whiteout anywhere, so the upper
    ///   can contribute neither an addition nor a deletion below it and the
    ///   lower's own stream is the whole merged listing. The proof is bound to
    ///   the fork-shared structural generation stamped into the anchor: any
    ///   later create/unlink/rename/copy-up — in this process or a sibling —
    ///   retires it and the listing falls back to the layered merge. The lower
    ///   is itself a host backend, so it gets the SAME marker-node question as
    ///   the upper, asked of the lower's own root.
    ///
    /// `d_ino` needs no separate argument: a lower entry's guest `st_ino` IS
    /// its host inode in the layer cache (`RootFs::directory_entries` reports
    /// exactly that from its per-child `real_stat`), which is the number the
    /// stream already carries.
    fn trusted_dir_stream_is_exact(&self, trusted: &TrustedHostDir, dir_path: &str) -> bool {
        if trusted.is_merged_upper() {
            return !self
                .fs
                .rootfs_vfs
                .overlay
                .dir_has_overlay_interference(dir_path);
        }
        if !trusted.namespace_is_current_against(self.fs.rootfs_vfs.overlay.structural_generation())
        {
            return false;
        }
        self.fs
            .rootfs_vfs
            .rootfs
            .as_ref()
            .and_then(|rootfs| rootfs.immutable_backend())
            .is_some_and(|lower| !FsBackend::dir_has_overlay_interference(lower, dir_path))
    }

    /// List a directory for a guest read (`getdents64`, or an `lseek` that
    /// needs the entry count). A trusted dirfd whose layer provably owns the
    /// whole listing is STREAMED (one readdir batch — d_name/d_type/d_ino
    /// straight off the kernel, zero per-child stats, see
    /// [`Self::trusted_dir_stream_is_exact`]); everything else takes the exact
    /// layered merge by path. Runs on the first read of a description and
    /// again after an lseek-0 rewind.
    pub(super) fn list_directory_entries(
        &self,
        dir_path: &str,
        trusted: Option<&TrustedHostDir>,
    ) -> Vec<RootFsDirEntry> {
        let streamed = match trusted {
            Some(trusted) if self.trusted_dir_stream_is_exact(trusted, dir_path) => {
                crate::fs_backend::read_host_dir_entries(trusted.fd.raw(), dir_path)
            }
            _ => None,
        };
        let mut entries = match streamed {
            Some(list) => list,
            // Interference (marker nodes), a stream surprise (DT_UNKNOWN) or
            // an untrusted description: the layered path classifies each
            // child exactly. A directory deleted or renamed away since the
            // open reads as empty by its stale path — Linux would list the
            // inode's live contents; only the trusted stream matches that.
            None => crate::fs_backend::try_layered_stream_dirents(
                self.fs.rootfs_vfs.overlay.as_ref(),
                self.fs.rootfs_vfs.rootfs.as_ref(),
                dir_path,
            )
            .unwrap_or_else(|| {
                crate::overlay::layered_directory_entries(
                    self.fs.rootfs_vfs.overlay.as_ref(),
                    self.fs.rootfs_vfs.rootfs.as_ref(),
                    dir_path,
                )
                .unwrap_or_default()
            }),
        };
        self.inject_mount_dir_entries(dir_path, &mut entries);
        entries
    }

    /// Inject entries for mounts registered below `dir_path` so that injected
    /// mount points (such as `/data`) appear in parent directory readdir listings
    /// even when the underlying image has no such directory.
    pub(super) fn inject_mount_dir_entries(
        &self,
        dir_path: &str,
        entries: &mut Vec<RootFsDirEntry>,
    ) {
        let mount_children = self.fs.vfs_mounts.mount_children_of(dir_path);
        for child in mount_children {
            let child_kind = match child.kind {
                crate::vfs::EntryKind::Directory => RootFsEntryKind::Directory,
                crate::vfs::EntryKind::Symlink => RootFsEntryKind::Symlink,
                crate::vfs::EntryKind::Fifo => RootFsEntryKind::Fifo,
                crate::vfs::EntryKind::Socket => RootFsEntryKind::Socket,
                crate::vfs::EntryKind::CharDevice => RootFsEntryKind::CharDevice,
                crate::vfs::EntryKind::File => RootFsEntryKind::File,
            };
            if let Some(existing) = entries.iter_mut().find(|e| e.name == child.name) {
                existing.metadata.kind = child_kind;
            } else {
                let metadata = RootFsMetadata {
                    path: std::path::Path::new(dir_path).join(&child.name),
                    kind: child_kind,
                    mode: if child_kind == RootFsEntryKind::Directory {
                        0o755
                    } else {
                        0o644
                    },
                    size: 0,
                };
                entries.push(RootFsDirEntry {
                    name: child.name,
                    ino: 0,
                    metadata,
                });
            }
        }
    }

    /// Materialize an ANONYMOUS file fd (an `O_TMPFILE`/`memfd_create` inode that
    /// has no name in any directory) to `target` in the writable overlay. This
    /// is what `linkat(AT_FDCWD, "/proc/self/fd/<n>", AT_FDCWD, target,
    /// AT_SYMLINK_FOLLOW)` does on Linux: the magic `/proc/self/fd` symlink, when
    /// FOLLOWED, names the unnamed inode and gives it a directory entry, copying
    /// nothing — the inode is the SAME. carrick has no shared-inode primitive for
    /// the in-memory backing and the host anon inode is unlinked, so it
    /// materializes a fresh target from the fd's LIVE bytes + creation mode (the
    /// O_TMPFILE test only stats size + mode, never inode identity).
    ///
    /// Returns `None` if `fd` is not such an anonymous file (the caller falls
    /// through to ordinary hard-link handling), else the create result. The mode
    /// is the fd's stored creation mode (already `& ~umask` from open time), and
    /// the size is whatever the guest has written so far.
    fn materialize_anon_fd_to(&self, fd: i32, target: &str) -> Option<Result<(), LinuxErrno>> {
        let open_file = self.open_file(fd)?;
        let desc = open_file.description.read()?;
        let (bytes, mode) = match &*desc {
            // Real anonymous host inode (`--fs host` O_TMPFILE / memfd). The
            // metadata path is the synthetic "/__carrick_o_tmpfile" sentinel set
            // at open time — a name that exists in no namespace. Read its live
            // size + mode via fstat and its bytes via pread (the kernel owns the
            // offset; pread leaves it untouched).
            OpenDescription::HostFile {
                host_fd, metadata, ..
            } if is_anon_overlay_path(&metadata.path.to_string_lossy()) => {
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(host_fd.raw(), &mut st) } != 0 {
                    return Some(Err(LINUX_EBADF));
                }
                let size = st.st_size.max(0) as usize;
                let mut buf = vec![0u8; size];
                let mut read = 0usize;
                while read < size {
                    let n = unsafe {
                        libc::pread(
                            host_fd.raw(),
                            buf[read..].as_mut_ptr() as *mut libc::c_void,
                            size - read,
                            read as libc::off_t,
                        )
                    };
                    if n <= 0 {
                        break;
                    }
                    read = read.saturating_add(n as usize);
                }
                buf.truncate(read);
                // The GUEST creation mode is the one stamped on the description at
                // O_TMPFILE open time (`create_mode`), NOT the host inode's
                // fstat'd mode. macOS silently strips set-user-ID / set-group-ID
                // from a file an unprivileged process fchmods, so the host fstat
                // would report e.g. 01755 for a 07755 create — dropping the
                // setuid/setgid bits the guest asked for (open14/openat03 test03
                // links an O_TMPFILE created with 07777 and asserts the materialized
                // file keeps all 12 permission bits). Source the mode from the
                // stored metadata so set_mode below records the full guest mode in
                // the CARRICK_MODE_XATTR; only the SIZE/bytes come from the live fd.
                (buf, metadata.mode & 0o7777)
            }
            // In-memory O_TMPFILE / memfd fallback (`--fs memory`): the bytes and
            // creation mode live on the description itself.
            OpenDescription::File {
                path,
                contents,
                metadata,
                ..
            } if is_anon_overlay_path(path.as_str()) => {
                let len = match contents.len() {
                    Ok(l) => match usize::try_from(l) {
                        Ok(u) => u,
                        Err(_) => return Some(Err(linux_errno::EOVERFLOW)),
                    },
                    Err(errno) => return Some(Err(errno)),
                };
                let mut vec = vec![0u8; len];
                if let Err(errno) = contents.read_at(0, &mut vec) {
                    return Some(Err(errno));
                }
                (vec, metadata.mode & 0o7777)
            }
            _ => return None,
        };
        drop(desc);
        // Create the target from the captured bytes, then apply the creation
        // mode (set_file_contents creates with the host umask; set_mode forces
        // the O_TMPFILE create mode the test stats).
        if self.fs.rootfs_vfs.set_file_contents(target, bytes).is_err() {
            return Some(Err(LINUX_EROFS));
        }
        let _ = self.fs.rootfs_vfs.set_mode(target, mode);
        Some(Ok(()))
    }

    fn do_renameat<M: CurrentMmMemory>(
        &self,
        context: &crate::kernel::KernelContext,
        request: RenameAtRequest,
        memory: &M,
    ) -> Result<DispatchOutcome, DispatchError> {
        const RENAME_NOREPLACE: u64 = 1;
        const RENAME_EXCHANGE: u64 = 2;
        let RenameAtRequest {
            olddirfd,
            oldpath,
            newdirfd,
            newpath,
            flags,
            target_tid,
        } = request;
        let old = read_guest_c_string(memory, oldpath)?;
        let new_path = read_guest_c_string(memory, newpath)?;
        if old.is_empty() || new_path.is_empty() {
            return Ok(DispatchOutcome::errno(LINUX_ENOENT));
        }
        let resolved_old = self.resolve_at_path(olddirfd, &old)?;
        let resolved_new = self.resolve_at_path(newdirfd, &new_path)?;
        if self.is_synthetic_virtual_path(context, &resolved_old)
            || self.is_synthetic_virtual_path(context, &resolved_new)
        {
            return Ok(DispatchOutcome::errno(LINUX_EROFS));
        }
        // RENAME_EXCHANGE: atomically swap two EXISTING entries. Both must
        // exist (a missing side → ENOENT, renameat201 case 3); the swap lands
        // in the writable overlay backend, which preserves each entry's
        // mode/contents (renameat202). EXCHANGE that touches a VFS mount
        // (/dev/shm, bind mounts) is not supported by the overlay swap → EINVAL.
        if flags & RENAME_EXCHANGE != 0 {
            if self.fs.vfs_mounts.resolve(&resolved_old).is_some()
                || self.fs.vfs_mounts.resolve(&resolved_new).is_some()
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let old_exists = self.layered_metadata(&resolved_old).is_ok();
            let new_exists = self.layered_metadata(&resolved_new).is_ok();
            if !old_exists || !new_exists {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            // Capture dir-ness before the swap for inotify IN_ISDIR.
            let (old_is_dir, new_is_dir) = if self.fs.inotify_registry.is_empty() {
                (false, false)
            } else {
                (
                    self.inotify_path_kind(&resolved_old).unwrap_or(false),
                    self.inotify_path_kind(&resolved_new).unwrap_or(false),
                )
            };
            return match self
                .fs
                .rootfs_vfs
                .exchange_with_flags(&resolved_old, &resolved_new)
            {
                Ok(()) => {
                    if !self.fs.inotify_registry.is_empty() {
                        // A swap is two moves: each name now holds the other's
                        // object, so emit IN_MOVED_FROM/IN_MOVED_TO for both
                        // directions, cookie-tied per direction.
                        self.inotify_move(&resolved_old, &resolved_new, old_is_dir);
                        self.inotify_move(&resolved_new, &resolved_old, new_is_dir);
                    }
                    self.dnotify_child_for_tid(
                        context,
                        &resolved_old,
                        LinuxDnotifyMask::RENAME,
                        target_tid,
                    );
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            };
        }
        let no_replace = flags & RENAME_NOREPLACE != 0;
        // Renaming OVER an OVERRIDABLE single-file injection (/etc/services,
        // /etc/resolv.conf) DETACHES it: the read-only synthetic mount would
        // EROFS on the rename target. Record the override so the new path falls
        // through to the writable overlay (after this, `resolve(&resolved_new)`
        // returns None and the rename lands in the overlay below).
        if let Some(mnew) = self.fs.vfs_mounts.resolve(&resolved_new)
            && mnew.vfs.overridable()
        {
            self.fs.vfs_mounts.override_path(&resolved_new);
        }
        let mold = self.fs.vfs_mounts.resolve(&resolved_old);
        let mnew = self.fs.vfs_mounts.resolve(&resolved_new);
        match (mold, mnew) {
            (Some(mold), Some(mnew)) => {
                if mold.point != mnew.point {
                    return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EXDEV));
                }
                if no_replace && mnew.vfs.lookup(&mnew.full_path).is_ok() {
                    return Ok(DispatchOutcome::errno(LINUX_EEXIST));
                }
                return match mnew.vfs.rename(&mold.full_path, &mnew.full_path) {
                    Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
                    Err(errno) => Ok(DispatchOutcome::errno(errno)),
                };
            }
            (Some(_), None) | (None, Some(_)) => {
                return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EXDEV));
            }
            (None, None) => {}
        }
        // Capture the source kind before the move (for IN_ISDIR) only when
        // something is watching.
        let dnotify_rename_watched = !self.fs.dnotify_registry.lock().is_empty();
        let moved_is_dir = if self.fs.inotify_registry.is_empty() && !dnotify_rename_watched {
            false
        } else {
            self.inotify_path_kind(&resolved_old).unwrap_or(false)
        };
        match self
            .fs
            .rootfs_vfs
            .rename_with_flags(&resolved_old, &resolved_new, no_replace)
        {
            Ok(()) => {
                if !self.fs.inotify_registry.is_empty() {
                    // IN_MOVED_FROM (old name) + IN_MOVED_TO (new name), cookie-
                    // tied, to watches on the respective parent directories.
                    self.inotify_move(&resolved_old, &resolved_new, moved_is_dir);
                    // A watch ON the moved object follows it and also sees
                    // IN_MOVE_SELF (inotify02's directory self-rename). Emitted on
                    // the OLD path key, where the watch still lives, BEFORE the
                    // registry migrates the key to the new path.
                    self.inotify_self(&resolved_old, carrick_abi::LINUX_IN_MOVE_SELF);
                    self.fs
                        .inotify_registry
                        .rename_path(&resolved_old, &resolved_new);
                }
                if moved_is_dir {
                    self.dnotify_child_for_tid(
                        context,
                        &resolved_old,
                        LinuxDnotifyMask::RENAME,
                        target_tid,
                    );
                }
                // A process whose cwd IS the renamed directory (or sits under it)
                // must follow the move: Linux's cwd is an inode, but carrick tracks
                // it as a path string, so rewrite the prefix. Without this a later
                // relative path resolves against the stale cwd and returns ENOENT
                // (inotify02 renames its own cwd, then unlinks a child by relative
                // name). Same-process only; a cross-process ancestor rename does not
                // update another process's cwd string (its inode would, on Linux).
                let cwd = self.cwd();
                if cwd == resolved_old {
                    self.set_cwd(&resolved_new);
                } else if cwd.starts_with(&resolved_old)
                    && cwd.as_bytes().get(resolved_old.len()) == Some(&b'/')
                {
                    let rest = &cwd[resolved_old.len() + 1..];
                    self.set_cwd(&format!("{resolved_new}/{rest}"));
                }
                self.rename_open_paths(&resolved_old, &resolved_new);
                Ok(DispatchOutcome::Returned { value: 0 })
            }
            Err(errno) => Ok(DispatchOutcome::errno(errno)),
        }
    }

    define_syscall! {
        fn getdents64(this, cx, fd: Fd, dirp: GuestPtr, count: u64) {
            let fd: Fd = fd;
            let address = dirp.0;
            let length =
                usize::try_from(count).map_err(|_| DispatchError::LengthTooLarge(count))?;
            let memory = &mut *cx.memory;
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let Some(mut open) = open_file.description.write() else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let OpenDescription::Directory {
                listing,
                offset,
                path,
                trusted_host_dir,
                ..
            } = &mut *open
            else {
                return Ok(DispatchOutcome::errno(LINUX_ENOTDIR));
            };

            // The listing is taken LAZILY on the first read (Linux lists at
            // getdents time, and a walk anchor that never reads pays
            // nothing): streamed off a trusted host dirfd when nothing
            // interferes, the exact layered merge otherwise.
            let visible_self = proc_visible_self(cx.kernel);
            let is_self_fd = is_proc_self_fd_dir(path, visible_self);
            let is_self_fdinfo = is_proc_self_fdinfo_dir(path, visible_self);
            if (is_self_fd || is_self_fdinfo)
                && (*offset == 0 || matches!(listing, DirListing::Pending))
            {
                *listing = DirListing::Fixed(this.proc_self_fd_entries(path, is_self_fdinfo));
            } else if matches!(listing, DirListing::Pending) {
                *listing = DirListing::Loaded(
                    this.list_directory_entries(path, trusted_host_dir.as_ref()),
                );
            }
            let entries = match listing {
                DirListing::Loaded(entries) | DirListing::Fixed(entries) => entries,
                DirListing::Pending => unreachable!("listing materialized above"),
            };

            // Real Linux getdents64 always returns `.` (self) and `..` (parent)
            // first. Synthesize them on the READ path only — NOT in
            // layered_directory_entries, which also backs the rmdir/unlinkat
            // emptiness check (two synthetic dot entries there made every empty
            // dir look non-empty → ENOTEMPTY broke `rm -rf`). Idempotent: prepend
            // once if absent.
            if entries.first().map(|e| e.name.as_str()) != Some(".") {
                let parent = std::path::Path::new(path.as_str())
                    .parent()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "/".to_string());
                let dir_path = path.clone();
                let dot_entry = |name: &str, p: String| RootFsDirEntry {
                    name: name.to_string(),
                    metadata: RootFsMetadata {
                        path: std::path::PathBuf::from(p),
                        kind: RootFsEntryKind::Directory,
                        mode: 0o755,
                        size: 0,
                    },
                    // "."/".." are skipped by scandir; ino unused → hash fallback.
                    ino: 0,
                };
                entries.insert(0, dot_entry("..", parent));
                entries.insert(0, dot_entry(".", dir_path));
            }

            let mut out = Vec::new();
            while *offset < entries.len() {
                let record = dirent64_record(&entries[*offset], *offset + 1);
                if record.len() > length {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                if out.len() + record.len() > length {
                    break;
                }
                out.extend_from_slice(&record);
                *offset += 1;
            }

            memory.write_bytes(address, &out)?;

            Ok(DispatchOutcome::returned_len_or_errno(out.len()))
        }

        fn readlinkat(this, cx, dirfd: u64, pathname: GuestPtr, buf: GuestPtr, bufsiz: u64) {
            let pathname = pathname.0;
            let buffer = buf.0;
            let buffer_size =
                usize::try_from(bufsiz).map_err(|_| DispatchError::LengthTooLarge(bufsiz))?;
            if buffer_size == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }

            let path = read_guest_c_string(&*cx.memory, pathname)?;
            if path.len() > 1 && path.ends_with('/') {
                let resolved = this.resolve_at_path(dirfd, &path)?;
                let canonical = this
                    .canonicalize_following(&resolved)
                    .unwrap_or_else(|_| resolved.clone());
                return match this.layered_metadata(&canonical) {
                    Ok(md) => {
                        if md.kind == RootFsEntryKind::Directory {
                            Ok(DispatchOutcome::errno(LINUX_EINVAL))
                        } else {
                            Ok(DispatchOutcome::errno(LINUX_ENOTDIR))
                        }
                    }
                    Err(e) => Ok(DispatchOutcome::errno(e)),
                };
            }
            // An empty pathname with an O_PATH|O_NOFOLLOW dirfd naming a SYMLINK
            // reads that link — readlinkat implicitly treats "" as AT_EMPTY_PATH
            // for such an fd (readlinkat(2) since 2.6.39; readlinkat01 case 6).
            // Rewrite to the fd's recorded symlink path so the readlink below runs.
            let path = if path.is_empty() {
                let dfd = (dirfd as i32) as i64 as u64 as i32;
                match this.lookup_recorded_fd_open_path(dfd).filter(|p| {
                    this.fd_is_o_path(dfd)
                        && matches!(this.layered_lstat(p), Ok(md) if md.kind == RootFsEntryKind::Symlink)
                }) {
                    Some(p) => p,
                    // A plain empty readlink (AT_FDCWD / non-symlink fd) is ENOENT
                    // on modern Linux (readlink03), not the EINVAL a lookup raises.
                    None => return Ok(DispatchOutcome::errno(LINUX_ENOENT)),
                }
            } else {
                this.resolve_at_path(dirfd, &path)?
            };

            // A PEER's `/proc/<pid>/ns/<type>`: the context-free resolver in the
            // Vfs asks the host process table, which cannot see a Linux process
            // that is a thread of this carrier. Guarded on the path shape
            // because assembling the proc context is expensive.
            let peer_ns_target = (path.starts_with("/proc/") && path.contains("/ns/"))
                .then(|| {
                    crate::vfs::proc::proc_ns_link_target_with_context(
                        &path,
                        &this.synthetic_proc_context(cx.kernel),
                    )
                })
                .flatten();
            let visible_self = proc_visible_self(cx.kernel);
            let target = if let Some(t) = peer_ns_target {
                t
            } else if let Some(kind) = proc_self_magic_link(&path, visible_self) {
                match kind {
                    // /proc/self/exe is the REAL running binary. If the entrypoint
                    // was a symlink (e.g. /usr/bin/readlink -> /bin/busybox), resolve
                    // the chain like Docker/Linux do; a non-symlink path is returned
                    // unchanged, and a resolution failure falls back to the raw path.
                    "exe" => {
                        let exe = this.proc.lock().executable_path.clone();
                        this.canonicalize_following(&exe).unwrap_or(exe)
                    }
                    // /proc/self/cwd → the guest working dir; /proc/self/root → the
                    // guest root. Both come from the captured Kernel FsContext.
                    "cwd" => this.cwd(),
                    _ => "/".to_string(),
                }
            } else if let Some(t) = this.proc_self_fd_tty_link(&path) {
                // /proc/this/fd/{0,1,2} → /dev/pts/N when the guest's stdio is the
                // `carrick run -t` controlling pty. This is what glibc `ttyname(3)`
                // reads, so `tty(1)` and tty-name lookups resolve.
                t
            } else if let Some(t) = proc_self_fd_number(&path, visible_self).and_then(|n| {
                this.lookup_recorded_fd_open_path(n).or_else(|| {
                    this.open_file(n)
                        .and_then(|f| f.description.read().and_then(|g| g.open_path().map(str::to_owned)))
                })
            }) {
                // /proc/self/fd/N → the path fd N was opened at. Rosetta readlinks
                // its main-binary fd this way to recover the binary's path.
                t
            } else if let Some(t) = proc_self_fd_number(&path, visible_self).and_then(|n| {
                this.open_file(n).and_then(|f| {
                    if f.description
                        .concrete_backing::<crate::dispatch::ioring::IoUringBacking>()
                        .is_some()
                    {
                        Some("anon_inode:[io_uring]".to_string())
                    } else {
                        f.description.read().and_then(|g| g.readlink_target())
                    }
                })
            }) {
                // /proc/self/fd/N for an fd with NO backing path (pipe/socket/
                // eventfd/…) → the synthetic pipe:[ino]/socket:[ino]/anon_inode:[…]
                // target Linux shows, so fd-introspection and 'are we piped?'
                // checks see a real target instead of an empty string.
                t
            } else if let Some(m) = this.fs.vfs_mounts.resolve(&path) {
                match m.vfs.readlink(&m.full_path) {
                    Ok(p) => p.to_string_lossy().into_owned(),
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            } else if let Ok(t) = this.fs.rootfs_vfs.dentry_readlink(&path) {
                t
            } else if let Some(t) = this.fs.rootfs_vfs.overlay.read_link(&path) {
                // Symlink created in the writable backend (cap-std on --fs host).
                t
            } else {
                use crate::vfs::Vfs as _;
                match this.fs.rootfs_vfs.readlink(&path) {
                    Ok(p) => p.to_string_lossy().into_owned(),
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            };

            // `target` is in the VFS layer's reversible escape form; decode it
            // back to the opaque link-target BYTES so readlink hands the guest
            // exactly what was stored (an undecodable target round-trips).
            let decoded = crate::pathcodec::decode_to_bytes(&target);
            let written = decoded.len().min(buffer_size);
            cx.memory.write_bytes(buffer, &decoded[..written])?;
            Ok(DispatchOutcome::returned_len_or_errno(written))
        }

        fn mknodat(this, cx, dirfd: u64, pathname: GuestPtr, mode: u64, dev: u64) {
            let pathname = pathname.0;
            let mode = mode as u32;
            let path = read_guest_c_string(&*cx.memory, pathname)?;
            if path.is_empty() {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            let resolved = this.resolve_at_path(dirfd, &path)?;
            if this.is_synthetic_virtual_path(cx.kernel, &resolved) {
                return Ok(DispatchOutcome::errno(LINUX_EEXIST));
            }
            // Existence check must consult the layered view (overlay/disk
            // first, then rootfs) — a rootfs-direct lookup would miss a file
            // the guest already created in the overlay and wrongly report
            // EROFS instead of EEXIST. Mirrors the linkat EEXIST check.
            if this.layered_metadata(&resolved).is_ok() {
                return Ok(DispatchOutcome::errno(LINUX_EEXIST));
            }
            // mknod(2) does NOT create intermediate directories: a missing
            // parent is ENOENT (LTP mknod06). An intermediate path component
            // that is a non-directory already surfaced as ENOTDIR from
            // resolve_at_path above. Mirrors the open(O_CREAT) parent check.
            //
            // Follow a contained symlink-to-dir parent leaf exactly like Linux:
            // `mkfifo /link/f` where `/link -> /realdir` must land the node at
            // /realdir/f. We resolve the PARENT through canonicalize_following
            // (LINUX_ELOOP-bounded; the one-level leaf-of-parent case is what
            // the probe and LTP require) and rebuild the materialisation path
            // from the resolved parent + the final component. This (a) makes
            // the path_is_directory check see the followed directory instead of
            // misclassifying the symlink as a File → spurious ENOENT, and (b)
            // hands the backend a symlink-FREE path so its cap-std confinement
            // never has to follow an absolute in-rootfs symlink (which cap-std
            // refuses as a sandbox escape).
            let mut materialize_path = resolved.clone();
            if let Some(parent) = Path::new(&resolved).parent() {
                let parent_str = display_rootfs_path(parent);
                if !parent_str.is_empty() && parent_str != "/" {
                    let resolved_parent = this
                        .canonicalize_following(&parent_str)
                        .unwrap_or_else(|_| parent_str.clone());
                    if !this.path_is_directory(&resolved_parent) {
                        return Ok(DispatchOutcome::errno(LINUX_ENOENT));
                    }
                    if resolved_parent != parent_str
                        && let Some(name) = Path::new(&resolved).file_name()
                    {
                        materialize_path =
                            display_rootfs_path(&Path::new(&resolved_parent).join(name));
                    }
                }
            }
            // Linux mknod(2) type dispatch. A zero type field means S_IFREG.
            // An ambiguous/invalid type (e.g. S_IFMT, multiple type bits) is
            // EINVAL (LTP mknod09); a valid device/socket type carrick can't
            // back on the cap-std scratch is EPERM (the unprivileged-mknod
            // errno); FIFO and regular files are materialised below.
            let type_bits = mode & LINUX_S_IFMT;
            match type_bits {
                // FIFO: create a real named pipe on the host backend
                // (mkfifoat). Opened later as a non-blocking HostPipe so a
                // writer-less open can't wedge the dispatcher. The
                // MemoryBackend can't back a real pipe → Unsupported → EPERM.
                t if t == LINUX_S_IFIFO => {
                    // mknod(2) applies the umask to the permission bits (the
                    // suid/sgid/sticky bits are NOT masked).
                    let umask = this.cred_snapshot().umask & 0o777;
                    let fifo_mode = (mode & 0o7777) & !umask;
                    return Ok(
                        match this
                            .fs
                            .rootfs_vfs
                            .create_fifo(&materialize_path, fifo_mode)
                        {
                            Ok(()) => {
                                this.stamp_new_node_owner(&materialize_path, fifo_mode);
                                this.dnotify_child(cx.kernel, &materialize_path, LinuxDnotifyMask::CREATE);
                                DispatchOutcome::Returned { value: 0 }
                            }
                            Err(crate::fs_backend::BackendError::Unsupported) => {
                                DispatchOutcome::errno(LINUX_EPERM)
                            }
                            Err(_) => DispatchOutcome::errno(LINUX_EROFS),
                        },
                    );
                }
                // Character/block device nodes: macOS/cap-std can't mknod a real
                // device as a non-root process, so materialise a MARKER regular
                // file tagged with the device xattrs (full mode + raw dev_t,
                // fork-coherent on the scratch). The stat reconstruction reads
                // them back and reports S_IFCHR/S_IFBLK with the right st_rdev.
                // mknod(2) applies the umask to the permission bits only; the
                // type bits are preserved. The MemoryBackend has no host inode to
                // tag → Unsupported → EPERM (unprivileged-mknod errno).
                t if t == LINUX_S_IFCHR || t == LINUX_S_IFBLK => {
                    let umask = this.cred_snapshot().umask & 0o777;
                    let full_mode = t | ((mode & 0o7777) & !umask);
                    return Ok(
                        match this
                            .fs
                            .rootfs_vfs
                            .create_device(&materialize_path, full_mode, dev)
                        {
                            Ok(()) => {
                                this.stamp_new_node_owner(&materialize_path, full_mode);
                                this.dnotify_child(cx.kernel, &materialize_path, LinuxDnotifyMask::CREATE);
                                DispatchOutcome::Returned { value: 0 }
                            }
                            Err(crate::fs_backend::BackendError::Unsupported) => {
                                DispatchOutcome::errno(LINUX_EPERM)
                            }
                            Err(_) => DispatchOutcome::errno(LINUX_EROFS),
                        },
                    );
                }
                // AF_UNIX socket node via mknod is bind(2) territory (out of
                // scope here); report EPERM as before.
                // mknod(S_IFSOCK) creates a socket INODE (a filesystem node,
                // distinct from a bound AF_UNIX socket). Reuse the socket-node
                // marker the bind path uses — stat then reports it as S_IFSOCK
                // via RootFsEntryKind::Socket, so no device-override is needed.
                // (A later bind(2) to this path is EADDRINUSE, matching Linux.)
                t if t == LINUX_S_IFSOCK => {
                    let umask = this.cred_snapshot().umask & 0o777;
                    let sock_mode = (mode & 0o7777) & !umask;
                    return Ok(
                        match this
                            .fs
                            .rootfs_vfs
                            .create_socket(&materialize_path, sock_mode)
                        {
                            Ok(()) => {
                                this.stamp_new_node_owner(&materialize_path, sock_mode);
                                this.dnotify_child(cx.kernel, &materialize_path, LinuxDnotifyMask::CREATE);
                                DispatchOutcome::Returned { value: 0 }
                            }
                            Err(crate::fs_backend::BackendError::Unsupported) => {
                                DispatchOutcome::errno(LINUX_EPERM)
                            }
                            Err(_) => DispatchOutcome::errno(LINUX_EROFS),
                        },
                    );
                }
                // Regular file (0 or S_IFREG): materialised below.
                0 => {}
                t if t == LINUX_S_IFREG => {}
                // Anything else (S_IFMT, S_IFDIR, multiple type bits) is an
                // invalid mknod type → EINVAL.
                _ => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
            }
            // Create an empty regular file in the writable backend (cap-std).
            // MemoryBackend's create_file works in-memory too. After this the
            // path exists in the layered view.
            match this.fs.rootfs_vfs.create_file(&materialize_path) {
                Ok(()) => {
                    if mode & 0o7777 != 0 {
                        let _ = this
                            .fs
                            .rootfs_vfs
                            .set_mode(&materialize_path, mode & 0o7777);
                    }
                    this.stamp_new_node_owner(&materialize_path, mode & 0o7777);
                    this.dnotify_child(cx.kernel, &materialize_path, LinuxDnotifyMask::CREATE);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(crate::fs_backend::BackendError::Unsupported) => Ok(DispatchOutcome::errno(LINUX_EROFS)),
                Err(_) => Ok(DispatchOutcome::errno(LINUX_EROFS)),
            }
        }

        fn mkdirat(this, cx, dirfd: u64, pathname: GuestPtr, mode: u64) {
            let pathname = pathname.0;
            let path = read_guest_c_string(&*cx.memory, pathname)?;
            if path.is_empty() {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            let ends_with_dot = path == "."
                || path.ends_with("/.")
                || path.trim_end_matches('/').ends_with("/.")
                || path.trim_end_matches('/') == "."
                || path == ".."
                || path.ends_with("/..")
                || path.trim_end_matches('/').ends_with("/..")
                || path.trim_end_matches('/') == "..";
            let had_trailing_slash = path.len() > 1 && path.ends_with('/');
            let resolved = this.resolve_at_path(dirfd, &path)?;
            if ends_with_dot || had_trailing_slash {
                let followed = this
                    .canonicalize_following(&resolved)
                    .unwrap_or_else(|_| resolved.clone());
                match this.layered_metadata(&followed) {
                    Ok(md) => {
                        if md.kind == RootFsEntryKind::Directory {
                            if ends_with_dot {
                                return Ok(DispatchOutcome::errno(LINUX_EEXIST));
                            }
                        } else {
                            return Ok(DispatchOutcome::errno(LINUX_ENOTDIR));
                        }
                    }
                    Err(_) if ends_with_dot => return Ok(DispatchOutcome::errno(LINUX_ENOENT)),
                    _ => {}
                }
            }
            if this.is_synthetic_virtual_path(cx.kernel, &resolved) {
                return Ok(DispatchOutcome::errno(LINUX_EEXIST));
            }
            if let Some(m) = this.fs.vfs_mounts.resolve(&resolved) {
                let creds = this.cred_snapshot();
                let create_mode = (mode as u32 & 0o7777) & !(creds.umask & 0o777);
                return match m.vfs.mkdir(&m.full_path, create_mode) {
                    Ok(()) => {
                        let _ = m.vfs.chown(
                            &m.full_path,
                            Some(creds.euid),
                            Some(creds.egid),
                            false,
                        );
                        // inotify IN_CREATE|IN_ISDIR on the parent dir watch.
                        this.inotify_child(&resolved, carrick_abi::LINUX_IN_CREATE, true);
                        this.dnotify_child(cx.kernel, &resolved, LinuxDnotifyMask::CREATE);
                        Ok(DispatchOutcome::Returned { value: 0 })
                    }
                    Err(errno) => Ok(DispatchOutcome::errno(errno)),
                };
            }
            // DAC: creating a new entry needs write+search on the parent dir
            // (mkdir04). Only when the target doesn't already exist — an
            // existing target is EEXIST (returned by mkdir below), which the
            // kernel reports before the permission error.
            if !this.guest_dac_root_bypass()
                && this.layered_metadata(&resolved).is_err()
                && let Some(parent) = Path::new(&resolved).parent()
                && !this.guest_can_modify_dir(&display_rootfs_path(parent))
            {
                return Ok(DispatchOutcome::errno(LINUX_EACCES));
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
                    let mut create_mode = (mode as u32 & 0o7777) & !(creds.umask & 0o777);
                    let mut owner_gid = creds.egid;
                    // setgid-directory inheritance (LTP mkdir02/04): a new dir in
                    // a parent with S_ISGID inherits the parent's GID *and* gets
                    // S_ISGID itself (so a shared-group subtree propagates).
                    // Otherwise the new dir's group is the creator's egid.
                    let mut inherited_gid = false;
                    const S_ISGID: u32 = 0o2000;
                    if let Some(parent) = Path::new(&resolved).parent() {
                        let parent_str = display_rootfs_path(parent);
                        if let Ok(pmd) = this.layered_metadata(&parent_str)
                            && pmd.mode & S_ISGID != 0
                        {
                            create_mode |= S_ISGID;
                            if let Some((_, pgid)) =
                                this.fs.rootfs_vfs.overlay.get_owner(&parent_str)
                            {
                                owner_gid = pgid;
                                inherited_gid = true;
                            }
                        }
                    }
                    let _ = this.fs.rootfs_vfs.set_mode(&resolved, create_mode);
                    // Stamp the owner when it's non-root OR the gid was inherited
                    // from a setgid parent (so a root-created dir still records the
                    // inherited group).
                    if !creds.euid.is_root() || !owner_gid.is_root() || inherited_gid {
                        let _ = this
                            .fs
                            .rootfs_vfs
                            .set_owner(&resolved, Some(creds.euid), Some(owner_gid));
                    }
                    // inotify IN_CREATE|IN_ISDIR on the parent dir watch.
                    this.inotify_child(&resolved, carrick_abi::LINUX_IN_CREATE, true);
                    this.dnotify_child(cx.kernel, &resolved, LinuxDnotifyMask::CREATE);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }
        }

        fn linkat(this, cx, olddirfd: u64, oldpath: GuestPtr, newdirfd: u64, newpath: GuestPtr, flags: u64) {
            let oldpath = oldpath.0;
            let newpath = newpath.0;
            // linkat accepts AT_SYMLINK_FOLLOW + AT_EMPTY_PATH (NOT
            // AT_SYMLINK_NOFOLLOW — that is a *at-stat/chmod flag); reject any
            // other bit with EINVAL, before path faults. (audit M4; probe linkatflag)
            if flags & !(LINUX_AT_SYMLINK_FOLLOW | LINUX_AT_EMPTY_PATH) != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let old = read_guest_c_string(&*cx.memory, oldpath)?;
            let new_path = read_guest_c_string(&*cx.memory, newpath)?;
            if new_path.is_empty() {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            if old.is_empty() && flags & LINUX_AT_EMPTY_PATH == 0 {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            // O_TMPFILE / memfd materialization candidate. The source can name an
            // ANONYMOUS inode (an O_TMPFILE/memfd fd with no directory entry) two
            // ways:
            //   - linkat(AT_FDCWD, "/proc/self/fd/<n>", ..., AT_SYMLINK_FOLLOW)
            //     — the magic symlink FOLLOWED to the unnamed inode (open14,
            //     openat03). AT_SYMLINK_FOLLOW must be set, else linkat would
            //     hard-link the symlink itself.
            //   - linkat(fd, "", ..., AT_EMPTY_PATH) — link the fd's inode
            //     directly.
            // Resolved here BEFORE the ordinary source-existence check, because
            // the anon inode has no namespace path that check would find.
            let anon_fd_candidate = if old.is_empty() {
                Some(olddirfd as i32)
            } else if flags & LINUX_AT_SYMLINK_FOLLOW != 0 {
                proc_self_fd_number(&old, proc_visible_self(cx.kernel))
            } else {
                None
            };
            let resolved_old = if old.is_empty() {
                if !this.fd_is_valid(olddirfd as i32) {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                None
            } else {
                let resolved = this.resolve_at_path(olddirfd, &old)?;
                let exists =
                    this.is_synthetic_virtual_path(cx.kernel, &resolved)
                        || this.layered_metadata(&resolved).is_ok()
                        || this.fs.vfs_mounts.resolve(&resolved).is_some_and(|m| m.vfs.lookup(&m.full_path).is_ok())
                        // An anon fd's magic symlink has no layered metadata; its
                        // existence is the live fd, validated below in the
                        // materialize branch.
                        || anon_fd_candidate
                            .is_some_and(|n| this.fd_table_contains(n) || is_stdio_fd(n));
                if !exists {
                    return Ok(DispatchOutcome::errno(LINUX_ENOENT));
                }
                let resolved = if flags & LINUX_AT_SYMLINK_FOLLOW != 0
                    && anon_fd_candidate.is_none()
                {
                    this.canonicalize_following(&resolved)?
                } else {
                    resolved
                };
                Some(resolved)
            };
            let resolved_new = this.resolve_at_path(newdirfd, &new_path)?;
            if this.is_synthetic_virtual_path(cx.kernel, &resolved_new)
                || this.layered_metadata(&resolved_new).is_ok()
            {
                return Ok(DispatchOutcome::errno(LINUX_EEXIST));
            }
            // The new-path's parent directory must exist, be a directory, and be
            // writable by the caller — creating a hard link writes an entry into
            // it (link04: a missing parent component -> ENOENT, a non-directory
            // component -> ENOTDIR, an unwritable parent under a dropped euid ->
            // EACCES). VFS-mount targets own their own checks below.
            if this.fs.vfs_mounts.resolve(&resolved_new).is_none() {
                let new_parent = std::path::Path::new(&resolved_new)
                    .parent()
                    .map(|p| {
                        let s = p.to_string_lossy().into_owned();
                        if s.is_empty() { "/".to_string() } else { s }
                    })
                    .unwrap_or_else(|| "/".to_string());
                match this.layered_metadata(&new_parent) {
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_ENOENT)),
                    Ok(md) if md.kind != RootFsEntryKind::Directory => {
                        return Ok(DispatchOutcome::errno(LINUX_ENOTDIR));
                    }
                    Ok(_) => {}
                }
                if let Some(errno) = this.may_write(&new_parent) {
                    return Ok(DispatchOutcome::errno(errno));
                }
            }
            // Linux gives the unnamed inode a name in place (same inode); carrick
            // has no shared-inode primitive for the overlay, so it materializes a
            // fresh entry from the fd's live bytes + creation mode. The O_TMPFILE
            // tests only stat size + mode, so a content+mode copy is
            // observationally exact. `materialize_anon_fd_to` returns None when
            // the fd is NOT an anon file (a real /proc/self/fd/<n> to a named
            // file), so the ordinary hard-link path below still handles those.
            if let Some(n) = anon_fd_candidate
                && let Some(result) = this.materialize_anon_fd_to(n, &resolved_new)
            {
                return Ok(match result {
                    Ok(()) => {
                        this.dnotify_child(cx.kernel, &resolved_new, LinuxDnotifyMask::CREATE);
                        DispatchOutcome::Returned { value: 0 }
                    }
                    Err(errno) => DispatchOutcome::errno(errno),
                });
            }
            // Create a real hard link in the writable backend (cap-std
            // hard_link). dpkg link()s e.g. /var/lib/dpkg/status -> status-old.
            // AT_EMPTY_PATH (link by fd) isn't supported. MemoryBackend can't
            // hard-link an in-memory file, so it falls back to a content copy.
            let Some(src) = resolved_old else {
                return Ok(DispatchOutcome::errno(LINUX_EROFS));
            };
            // Hard-linking a DIRECTORY is forbidden: Linux's vfs_link returns
            // EPERM for S_ISDIR (only a privileged FS-specific path could, which
            // carrick never offers). Check before the overlay hard_link, which
            // would otherwise surface EROFS (linkat01 case 21 links ".").
            if matches!(
                this.layered_metadata(&src).map(|md| md.kind),
                Ok(RootFsEntryKind::Directory)
            ) {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            let msrc = this.fs.vfs_mounts.resolve(&src);
            let mnew = this.fs.vfs_mounts.resolve(&resolved_new);
            match (msrc, mnew) {
                (Some(msrc), Some(mnew)) => {
                    if msrc.point != mnew.point {
                        return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EXDEV));
                    }
                    return Ok(match mnew.vfs.link(&msrc.full_path, &mnew.full_path) {
                        Ok(()) => {
                            this.dnotify_child(cx.kernel, &resolved_new, LinuxDnotifyMask::CREATE);
                            DispatchOutcome::Returned { value: 0 }
                        }
                        Err(errno) => DispatchOutcome::errno(errno),
                    });
                }
                (Some(_), None) | (None, Some(_)) => {
                    return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EXDEV));
                }
                (None, None) => {
                    if this.is_synthetic_virtual_path(cx.kernel, &src) {
                        return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EXDEV));
                    }
                }
            }
            match this.fs.rootfs_vfs.link(&src, &resolved_new) {
                Ok(()) => {
                    this.dnotify_child(cx.kernel, &resolved_new, LinuxDnotifyMask::CREATE);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }
        }

        fn symlinkat(this, cx, target: GuestPtr, newdirfd: u64, linkpath: GuestPtr) {
            let target = target.0;
            let linkpath = linkpath.0;
            let target_path = read_guest_c_string(&*cx.memory, target)?;
            if target_path.is_empty() {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            let link = read_guest_c_string(&*cx.memory, linkpath)?;
            if link.is_empty() {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            let resolved_link = this.resolve_at_path(newdirfd, &link)?;
            if this.is_synthetic_virtual_path(cx.kernel, &resolved_link) {
                return Ok(DispatchOutcome::errno(LINUX_EEXIST));
            }
            // If the link path already exists (anywhere in the layered
            // view), report EEXIST. Otherwise the overlay can't create
            // symlinks today, so we return EROFS.
            if this.layered_metadata(&resolved_link).is_ok() {
                return Ok(DispatchOutcome::errno(LINUX_EEXIST));
            }
            if let Some(m) = this.fs.vfs_mounts.resolve(&resolved_link) {
                return match m.vfs.symlink(&target_path, &m.full_path) {
                    Ok(()) => {
                        this.dnotify_child(cx.kernel, &resolved_link, LinuxDnotifyMask::CREATE);
                        Ok(DispatchOutcome::Returned { value: 0 })
                    }
                    Err(errno) => Ok(DispatchOutcome::errno(errno)),
                };
            }
            // DAC: creating the symlink entry needs write+search on the parent
            // directory (symlink03 case 1 → EACCES). Root bypasses.
            if let Some(parent) = Path::new(&resolved_link).parent()
                && !this.guest_can_modify_dir(&display_rootfs_path(parent))
            {
                return Ok(DispatchOutcome::errno(LINUX_EACCES));
            }
            // Create a real symlink in the writable backend (cap-std). The
            // target is stored verbatim, matching symlinkat(2). MemoryBackend
            // returns Unsupported → EROFS.
            match this
                .fs
                .rootfs_vfs
                .symlink(&target_path, &resolved_link)
            {
                Ok(()) => {
                    this.dnotify_child(cx.kernel, &resolved_link, LinuxDnotifyMask::CREATE);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }
        }

        fn renameat(this, cx, olddirfd: u64, oldpath: GuestPtr, newdirfd: u64, newpath: GuestPtr) {
            this.do_renameat(
                cx.kernel,
                RenameAtRequest {
                    olddirfd,
                    oldpath: oldpath.0,
                    newdirfd,
                    newpath: newpath.0,
                    flags: 0,
                    target_tid: Some(cx.tid()),
                },
                &*cx.memory,
            )
        }

        fn renameat2(this, cx, olddirfd: u64, oldpath: GuestPtr, newdirfd: u64, newpath: GuestPtr, flags: u64) {
            let Some(rf) = LinuxRenameat2Flags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            if rf.contains(LinuxRenameat2Flags::EXCHANGE)
                && (rf.contains(LinuxRenameat2Flags::NOREPLACE)
                    || rf.contains(LinuxRenameat2Flags::WHITEOUT))
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if rf.contains(LinuxRenameat2Flags::WHITEOUT) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            this.do_renameat(
                cx.kernel,
                RenameAtRequest {
                    olddirfd,
                    oldpath: oldpath.0,
                    newdirfd,
                    newpath: newpath.0,
                    flags,
                    target_tid: Some(cx.tid()),
                },
                &*cx.memory,
            )
        }

        fn unlinkat(this, cx, dirfd: u64, pathname: GuestPtr, flags: u64) {
            let pathname = pathname.0;
            let Some(at_flags) = carrick_abi::LinuxAtFlags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            if at_flags.bits() & !LINUX_AT_REMOVEDIR != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let path = read_guest_c_string(&*cx.memory, pathname)?;
            if path.is_empty() {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            let remove_dir = at_flags.contains(carrick_abi::LinuxAtFlags::REMOVEDIR);
            let ends_with_dot = path == "."
                || path.ends_with("/.")
                || path.trim_end_matches('/').ends_with("/.")
                || path.trim_end_matches('/') == "."
                || path == ".."
                || path.ends_with("/..")
                || path.trim_end_matches('/').ends_with("/..")
                || path.trim_end_matches('/') == "..";
            let had_trailing_slash = path.len() > 1 && path.ends_with('/');
            let resolved = this.resolve_at_path(dirfd, &path)?;
            if ends_with_dot {
                let followed = this
                    .canonicalize_following(&resolved)
                    .unwrap_or_else(|_| resolved.clone());
                match this.layered_metadata(&followed) {
                    Ok(md) => {
                        if md.kind != RootFsEntryKind::Directory {
                            return Ok(DispatchOutcome::errno(LINUX_ENOTDIR));
                        } else if remove_dir {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        } else {
                            return Ok(DispatchOutcome::errno(LINUX_EISDIR));
                        }
                    }
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_ENOENT)),
                }
            }
            if had_trailing_slash {
                if let Ok(lmd) = this.layered_lstat(&resolved) {
                    if lmd.kind == RootFsEntryKind::Symlink {
                        return Ok(DispatchOutcome::errno(LINUX_ENOTDIR));
                    }
                }
                if let Ok(md) = this.layered_metadata(&resolved) {
                    if md.kind != RootFsEntryKind::Directory {
                        return Ok(DispatchOutcome::errno(LINUX_ENOTDIR));
                    } else if !remove_dir {
                        return Ok(DispatchOutcome::errno(LINUX_EISDIR));
                    }
                }
            }
            // Synthetic /proc /sys paths can't be unlinked.
            if this.is_synthetic_virtual_path(cx.kernel, &resolved) {
                return Ok(DispatchOutcome::errno(LINUX_EROFS));
            }
            use crate::vfs::Vfs as _;
            // DAC: removing an entry needs write+search on the parent dir
            // (unlink08: 0555 lacks write, 0666 lacks search — both → EACCES).
            // A sticky parent (S_ISVTX) additionally requires owning the entry
            // or the dir (rmdir03 case 2 → EPERM). Only when the target exists
            // (a missing one is ENOENT) and on the rootfs path (not the
            // carrick-internal bind-mount IPC paths).
            if !this.guest_dac_root_bypass()
                && this.fs.vfs_mounts.resolve(&resolved).is_none()
                && this.layered_metadata(&resolved).is_ok()
                && let Some(parent) = Path::new(&resolved).parent()
            {
                let parent_str = display_rootfs_path(parent);
                if !this.guest_can_modify_dir(&parent_str) {
                    return Ok(DispatchOutcome::errno(LINUX_EACCES));
                }
                if !this.guest_sticky_delete_ok(&parent_str, &resolved) {
                    return Ok(DispatchOutcome::errno(LINUX_EPERM));
                }
            }
            // Route through bind mounts (e.g. /dev/shm → host-tmp) so a file
            // CREATED via the openat mount path can also be unlinkat'd. The
            // open path resolves mounts first then falls through to rootfs;
            // unlinkat must mirror that or LTP's SAFE_UNLINK(shm_path) — which
            // creates the IPC region then immediately unlinks it (the mapping
            // outlives the name) — fails ENOENT and TBROKs setup_ipc.
            // An OVERRIDABLE single-file injection (/etc/services, /etc/resolv.conf)
            // is just a default the guest may replace: unlinking it must DETACH
            // the injection rather than EROFS from the read-only synthetic mount
            // (kaniko's image-unpack unlinks /etc/services to lay down the base
            // image's copy). Record the override so the path falls through to the
            // overlay everywhere thereafter; the injection isn't a real overlay
            // file, so "unlink" just means stop injecting. If the overlay DOES
            // happen to carry the path, also run the normal overlay delete.
            // Learn the target's inode identity BEFORE it goes away so the
            // removal also drops the inode record every other hard link of it
            // shares (`legacyfs`: unlink of the second name must lower the
            // first name's nlink). One `fstatat` on a cache miss.
            let _ = this.fs.rootfs_vfs.dentry_stat(&resolved, false);
            if let Some(m) = this.fs.vfs_mounts.resolve(&resolved)
                && m.vfs.overridable()
            {
                this.fs.vfs_mounts.override_path(&resolved);
                let overlay_result = if remove_dir {
                    this.fs.rootfs_vfs.rmdir(&resolved)
                } else {
                    this.fs.rootfs_vfs.unlink(&resolved)
                };
                // A missing overlay file is expected (the injection had no real
                // backing) — that's still a successful detach. Only a non-ENOENT
                // error from a real overlay file should surface.
                return match overlay_result {
                    Ok(()) | Err(LINUX_ENOENT) => Ok(DispatchOutcome::Returned { value: 0 }),
                    Err(errno) => Ok(DispatchOutcome::errno(errno)),
                };
            }
            // Capture the target kind and (for a file) its pre-delete link count
            // BEFORE the delete, only when something is watching (the lookups are
            // otherwise wasted work). The link count distinguishes "a link was
            // removed but the inode survives" (IN_ATTRIB only) from "the last link
            // is gone, the file is removed" (IN_ATTRIB → IN_DELETE_SELF →
            // IN_IGNORED) — see inotify04 and inotify(7).
            let watching = !this.fs.inotify_registry.is_empty();
            let unlinked_is_dir = if watching {
                this.inotify_path_kind(&resolved).unwrap_or(remove_dir)
            } else {
                false
            };
            // nlink only matters for the file (non-dir) self-watch sequence.
            let nlink_before = if watching && !unlinked_is_dir {
                this.path_stat_record(cx.kernel, dirfd, &path, 0)
                    .map(|r| r.nlink)
                    .unwrap_or(1)
            } else {
                0
            };
            let result = if let Some(m) = this.fs.vfs_mounts.resolve(&resolved) {
                if remove_dir { m.vfs.rmdir(&m.full_path) } else { m.vfs.unlink(&m.full_path) }
            } else if remove_dir {
                this.fs.rootfs_vfs.rmdir(&resolved)
            } else {
                this.fs.rootfs_vfs.unlink(&resolved)
            };
            match result {
                Ok(()) => {
                    // inotify: IN_DELETE (name) to a watch on the parent dir.
                    this.inotify_child(
                        &resolved,
                        carrick_abi::LINUX_IN_DELETE,
                        unlinked_is_dir,
                    );
                    this.dnotify_child(cx.kernel, &resolved, LinuxDnotifyMask::DELETE);
                    // To a watch ON the entry itself:
                    // - A directory (rmdir) has no link-count subtlety:
                    //   IN_DELETE_SELF → IN_IGNORED.
                    // - A file whose link count just dropped to 0 (the last link):
                    //   IN_ATTRIB (link count changed) → IN_DELETE_SELF → IN_IGNORED.
                    // - A file with surviving hardlinks (link count was > 1): the
                    //   inode lives on, so only IN_ATTRIB — no self-delete/ignore.
                    if unlinked_is_dir {
                        this.inotify_self(&resolved, carrick_abi::LINUX_IN_DELETE_SELF);
                        this.inotify_self(&resolved, carrick_abi::LINUX_IN_IGNORED);
                        this.fs.inotify_registry.unregister_path(&resolved);
                    } else {
                        // The unlinked name changes the inode's link count → IN_ATTRIB.
                        this.inotify_self(&resolved, carrick_abi::LINUX_IN_ATTRIB);
                        if nlink_before <= 1 {
                            // Last link gone: the watched object is destroyed.
                            this.inotify_self(&resolved, carrick_abi::LINUX_IN_DELETE_SELF);
                            this.inotify_self(&resolved, carrick_abi::LINUX_IN_IGNORED);
                            this.fs.inotify_registry.unregister_path(&resolved);
                        }
                    }
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }
        }
    }
}
