//! Mount table manipulation, working directory tracking, and chroot.

use super::*;

impl SyscallDispatcher {
    /// Join bind sources through the registry owned by this carrier.
    pub fn set_bind_cache_cohorts(
        &mut self,
        cohorts: std::sync::Arc<carrick_vfs::fs_resolve_cache::BindCacheCohorts>,
    ) {
        self.fs.bind_cache_cohorts = cohorts;
        let cohorts = std::sync::Arc::clone(&self.fs.bind_cache_cohorts);
        self.fs.vfs_mounts_mut().set_bind_cache_cohorts(&cohorts);
        self.fs.resolve_cache.clear();
    }
    pub fn register_mount(
        &mut self,
        point: impl Into<std::path::PathBuf>,
        mut vfs: Box<dyn carrick_vfs::Vfs>,
    ) {
        if let Some(source) = vfs.bind_source()
            && let Ok(coherence) = self.fs.bind_cache_cohorts.admit(source)
        {
            vfs.set_cache_coherence(coherence);
        }
        crate::el1_inotify::invalidate_name_cache_all();
        self.fs.vfs_mounts_mut().mount(point, vfs);
        self.fs.resolve_cache.clear();
    }
}

impl<'a> FsView<'a> {
    /// The directory `chdir(path)` makes the cwd, as the cwd spells it: the
    /// one lookup the host task's `chdir` and a ring task's chdir crossing
    /// share. Follows a trailing directory symlink through the full layered
    /// VFS (so a link into another mount resolves, and a freshly created
    /// directory is visible), requires a directory (ENOTDIR) and search
    /// permission on it (EACCES), and reports the resolved target's
    /// canonical path, which `getcwd` then reports, as Linux does.
    pub(in crate::dispatch) fn chdir_target(&self, path: &str) -> Result<String, LinuxErrno> {
        let path = self.resolve_at_path(LINUX_AT_FDCWD, path)?;
        let resolved = self.canonicalize_following(&path)?;
        let metadata = self.layered_metadata(&resolved)?;
        if metadata.kind != RootFsEntryKind::Directory {
            return Err(LINUX_ENOTDIR);
        }
        let target = display_rootfs_path(&metadata.path);
        self.check_directory_search_access(&target)?;
        Ok(target)
    }
}

impl<'a> FsView<'a> {
    define_syscall! {
        fn getcwd(this, cx, address: GuestPtr, size: u64) {
            let address = address.0;
            let size =
                usize::try_from(size).map_err(|_| DispatchError::LengthTooLarge(size))?;
            // One rule for the host task and a ring task: the global cwd,
            // except a cwd above a chroot (`task_fs::visible_cwd`).
            let fs_context = this.captured_fs_context();
            let cwd = match carrick_personality_linux::task_fs::visible_cwd(
                fs_context.cwd().as_bytes(),
                fs_context.chroot_root().as_deref().map(str::as_bytes),
            ) {
                Ok(visible) => String::from_utf8(visible).map_err(|_| DispatchError::Errno(LINUX_EINVAL))?,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            // The cwd is stored in the VFS layer's reversible escape form;
            // decode to the opaque path BYTES so getcwd is byte-exact for a
            // cwd that contains undecodable (non-UTF-8) components.
            let mut bytes = carrick_vfs::pathcodec::decode_to_bytes(&cwd);
            bytes.push(0);
            if bytes.len() > size {
                return Ok(DispatchOutcome::errno(LINUX_ERANGE));
            }
            // Linux getcwd(2) returns the LENGTH of the buffer filled (including
            // the terminating NUL), not the buffer address. glibc tolerates a
            // positive non-length, but tools that use the return value as a
            // length (and the kernel ABI) require the real count.
            Ok(Self::copyout_bytes(
                cx.kernel,
                &mut *cx.memory,
                address,
                &bytes,
                DispatchOutcome::returned_len_or_errno(bytes.len()),
            ))
        }

        fn chdir(this, cx, pathname: GuestPtr) {
            let pathname = pathname.0;
            let path = read_guest_c_string(&*cx.memory, pathname)?;
            let target = match this.chdir_target(&path) {
                Ok(target) => target,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            this.captured_fs_context().set_cwd(target);
            crate::el1_inotify::bump_cwd_generation();
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn chroot(this, cx, pathname: GuestPtr) {
            let path = read_guest_c_string(&*cx.memory, pathname.0)?;
            // Resolve the path FIRST — the kernel does the lookup before the
            // capability check, so an over-long path is ENAMETOOLONG and a
            // missing/non-dir target is ENOENT/ENOTDIR even for an unprivileged
            // caller (chroot03 expects ENAMETOOLONG, not EPERM). resolve_at_path
            // already enforces the length limits.
            let path = this.resolve_at_path(LINUX_AT_FDCWD, &path)?;
            let resolved = this.canonicalize_following(&path)?;
            let metadata = this.layered_metadata(&resolved)?;
            if metadata.kind != RootFsEntryKind::Directory {
                return Ok(DispatchOutcome::errno(LINUX_ENOTDIR));
            }
            let new_root = display_rootfs_path(&metadata.path);
            if let Err(errno) = this.check_directory_search_access(&new_root) {
                return Ok(DispatchOutcome::errno(errno));
            }
            // chroot(2) requires CAP_SYS_CHROOT. carrick models the capability
            // set as "effective uid 0"; a guest that has dropped to a non-root
            // euid no longer holds it (chroot01 expects EPERM).
            if !this.cred_snapshot().euid.is_root() {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            // The request is valid and we accept it. Full per-process root
            // enforcement inside resolve_at_path (so the guest's "/" maps under
            // the new root) is a tracked follow-up — chroot02 only needs the call
            // to succeed; chroot04 (EACCES from a no-search-permission component)
            // awaits that plus the DAC search-permission check. We DO record the
            // new root so getcwd can report a cwd left outside it as ENOENT
            // (realpath01 / CVE-2018-1000001).
            this.captured_fs_context().set_chroot_root(Some(new_root));
            crate::el1_inotify::bump_cwd_generation();
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn fchdir(this, cx, fd: Fd) {
            let fd: Fd = fd;
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let Some(open) = crate::kernel::FileDescription::inspect(&open_file.description) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            Ok(match &*open {
                OpenDescription::Closed { .. } => DispatchOutcome::errno(LINUX_EBADF),
                OpenDescription::Directory { metadata, .. } => {
                    let dir_path = display_rootfs_path(&metadata.path);
                    // fchdir(2) requires search (execute) permission on the
                    // directory the fd refers to. The fd may have been opened
                    // O_RDONLY (needing only read) and the directory later
                    // chmod'd to drop its search bit — so re-stat to observe the
                    // CURRENT mode/owner rather than the value captured at open
                    // time. A non-root euid lacking X on the directory gets
                    // EACCES (fchdir03); root (euid 0) bypasses via
                    // CAP_DAC_OVERRIDE.
                    let creds = this.cred_snapshot();
                    if !creds.euid.is_root()
                        && let Some(real) =
                            this.fs.rootfs_vfs.overlay.real_stat(&dir_path, true)
                        && crate::dispatch::dac_check(
                            creds.euid,
                            creds.egid,
                            real.uid,
                            real.gid,
                            real.mode,
                            true,
                            LINUX_X_OK,
                        )
                        .is_err()
                    {
                        return Ok(DispatchOutcome::errno(LINUX_EACCES));
                    }
                    this.captured_fs_context().set_cwd(dir_path);
                    crate::el1_inotify::bump_cwd_generation();
                    DispatchOutcome::Returned { value: 0 }
                }
                OpenDescription::File { .. }
                | OpenDescription::InMemoryFile { .. }
                | OpenDescription::HostFile { .. }
                | OpenDescription::SyntheticFile { .. }
                | OpenDescription::ProcExecutable { .. }
                | OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. }
                | OpenDescription::Fanotify { .. }
                | OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::InMemorySocket { .. }
                | OpenDescription::SignalFd { .. }
                | OpenDescription::PerfEvent { .. }
                | OpenDescription::FsContext { .. }
                | OpenDescription::Mqueue { .. }
                | OpenDescription::BpfMap { .. }
                | OpenDescription::BpfProg { .. }
                | OpenDescription::SyntheticDevice { .. }
                | OpenDescription::VirtualConsole { .. }
                | OpenDescription::Netlink { .. }
                | OpenDescription::Packet { .. } => DispatchOutcome::errno(LINUX_ENOTDIR),
            })
        }
    }
}
