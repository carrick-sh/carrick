//! Mount table manipulation, working directory tracking, and chroot.

use super::*;

impl SyscallDispatcher {
    pub fn register_mount(
        &mut self,
        point: impl Into<std::path::PathBuf>,
        vfs: Box<dyn crate::vfs::Vfs>,
    ) {
        self.fs.vfs_mounts_mut().mount(point, vfs);
    }

    define_syscall! {
        fn getcwd(this, cx, address: GuestPtr, size: u64) {
            let address = address.0;
            let size =
                usize::try_from(size).map_err(|_| DispatchError::LengthTooLarge(size))?;
            // carrick stores the GLOBAL cwd and does NOT re-root path
            // resolution, so getcwd(2) reports that global path verbatim in
            // almost every case — including a cwd set by a post-chroot chdir
            // (`chroot("/x"); chdir("/etc"); getcwd()` → "/etc", matching
            // Linux). The ONE exception is the CVE-2018-1000001 shape realpath01
            // exercises: the guest chroots into a SUBDIRECTORY of its cwd
            // without chdir'ing in, leaving the cwd ABOVE the new root. Such a
            // cwd is unreachable from the root, so getcwd returns ENOENT. A
            // chroot("/") is a no-op and never triggers this.
            let fs_context = this.captured_fs_context();
            let cwd = fs_context.cwd();
            let cwd = match fs_context.chroot_root().as_deref() {
                Some(root) if root != "/" => {
                    if cwd == root {
                        // The guest chdir'd into the new root itself.
                        "/".to_owned()
                    } else if let Some(rel) = cwd.strip_prefix(&format!("{root}/")) {
                        // cwd lies inside the root subtree.
                        format!("/{rel}")
                    } else if cwd == "/" || root.starts_with(&format!("{cwd}/")) {
                        // cwd is a strict ANCESTOR of the new root: it is above
                        // the root and unreachable (realpath01 / CVE-2018-1000001).
                        return Ok(DispatchOutcome::errno(LINUX_ENOENT));
                    } else {
                        // Neither inside nor above the root: report the global
                        // cwd verbatim (carrick does not re-root).
                        cwd
                    }
                }
                // No chroot, or the chroot("/") no-op.
                _ => cwd,
            };
            // The cwd is stored in the VFS layer's reversible escape form;
            // decode to the opaque path BYTES so getcwd is byte-exact for a
            // cwd that contains undecodable (non-UTF-8) components.
            let mut bytes = crate::pathcodec::decode_to_bytes(&cwd);
            bytes.push(0);
            if bytes.len() > size {
                return Ok(DispatchOutcome::errno(LINUX_ERANGE));
            }
            cx.memory.write_bytes(address, &bytes)?;
            // Linux getcwd(2) returns the LENGTH of the buffer filled (including
            // the terminating NUL), not the buffer address. glibc tolerates a
            // positive non-length, but tools that use the return value as a
            // length (and the kernel ABI) require the real count.
            Ok(DispatchOutcome::returned_len_or_errno(bytes.len()))
        }

        fn chdir(this, cx, pathname: GuestPtr) {
            let pathname = pathname.0;
            let path = read_guest_c_string(&*cx.memory, pathname)?;
            let path = this.resolve_at_path(LINUX_AT_FDCWD, &path)?;
            // Follow a trailing directory symlink the way Linux chdir(2) does,
            // THROUGH the full VFS — so a symlink whose target lands in a
            // different mount (e.g. a /tmp scratch link → /run bind mount)
            // resolves instead of returning ENOTDIR (the per-backend real_stat
            // only follows within one backend). getcwd then reports the resolved
            // target's canonical path, matching the kernel. Uses the LAYERED
            // lookup so a freshly mkdir'd dir is visible (dpkg-deb chdir).
            let resolved = this.canonicalize_following(&path)?;
            let metadata = this.layered_metadata(&resolved)?;
            if metadata.kind != RootFsEntryKind::Directory {
                return Ok(DispatchOutcome::errno(LINUX_ENOTDIR));
            }
            this.captured_fs_context()
                .set_cwd(display_rootfs_path(&metadata.path));
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
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn fchdir(this, cx, fd: Fd) {
            let fd: Fd = fd;
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let Some(open) = open_file.description.read() else {
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
                    DispatchOutcome::Returned { value: 0 }
                }
                OpenDescription::File { .. }
                | OpenDescription::InMemoryFile { .. }
                | OpenDescription::HostFile { .. }
                | OpenDescription::SyntheticFile { .. }
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
                | OpenDescription::Netlink { .. } => DispatchOutcome::errno(LINUX_ENOTDIR),
            })
        }
    }
}
