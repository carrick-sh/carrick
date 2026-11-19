//! Extended-attribute (xattr) syscall helpers: `setxattr`/`getxattr`/
//! `listxattr` (path, lpath and f-variants share these via `XattrTarget`),
//! backed by the overlay's xattr store. Split out of `dispatch/fs.rs` (WS-F3)
//! as `impl SyscallDispatcher` methods; `self.…` resolution is type-based so
//! the move is transparent to callers.
use super::*;
use crate::linux_abi::LinuxErrno;

impl<'a> FsView<'a> {
    /// Resolve the first argument of an xattr syscall to the rootfs path it
    /// names: a path string (path/lpath variants) or the path of the file an
    /// fd refers to (f-variant). Returns `Err(errno)` on a bad path or an fd
    /// that has no backing host file (e.g. the in-memory backend).
    fn xattr_target_path(
        &self,
        memory: &impl CurrentMmMemory,
        target: XattrTarget,
    ) -> Result<String, LinuxErrno> {
        match target {
            XattrTarget::Path {
                path: path_ptr,
                follow,
            } => {
                let path = read_guest_c_string(memory, path_ptr.0)?;
                self.resolve_xattr_path(&path, follow)
            }
            XattrTarget::Fd(fd) => {
                let open_file = self.open_file(fd.0).ok_or(LINUX_EBADF)?;
                Self::description_xattr_path(&open_file.description)
            }
        }
    }

    pub(in crate::dispatch) fn resolve_xattr_path(
        &self,
        path: &str,
        follow: bool,
    ) -> Result<String, LinuxErrno> {
        if path.is_empty() {
            return Err(LINUX_ENOENT);
        }
        let resolved = self.resolve_at_path(LINUX_AT_FDCWD, path)?;
        // Resolve existence before operating on the attribute namespace.
        let exists = if follow {
            self.layered_metadata(&resolved)
        } else {
            self.layered_lstat(&resolved)
        };
        if exists.is_err() {
            return Err(LINUX_ENOENT);
        }
        Ok(resolved)
    }

    pub(in crate::dispatch) fn description_xattr_path(
        description: &crate::kernel::FileDescription,
    ) -> Result<String, LinuxErrno> {
        description
            .inspect_kind(|open| match open {
                OpenDescription::File { path, .. } | OpenDescription::Directory { path, .. } => {
                    Ok(path.clone())
                }
                OpenDescription::HostFile { metadata, .. } => metadata
                    .path
                    .to_str()
                    .map(str::to_owned)
                    .ok_or(LINUX_ENOTSUP),
                _ => Err(LINUX_ENOTSUP),
            })
            .unwrap_or(Err(LINUX_ENOTSUP))
    }

    pub(super) fn setxattr(
        &self,
        memory: &mut impl CurrentMmMemory,
        target: XattrTarget,
        name_ptr: GuestPtr,
        value_ptr: GuestPtr,
        size: u64,
        flags: u64,
    ) -> Result<DispatchOutcome, DispatchError> {
        // setxattr(path/fd, name, value, size, flags)
        let follow = target.follow();
        let resolved = self.xattr_target_path(memory, target)?;
        let name = read_guest_c_string(memory, name_ptr.0)?;
        self.set_xattr_bytes(&resolved, &name, flags, follow, || {
            memory
                .read_bytes(value_ptr.0, size as usize)
                .map_err(|_| LINUX_EFAULT)
        })
    }

    pub(in crate::dispatch) fn set_xattr_bytes<T: AsRef<[u8]>>(
        &self,
        resolved: &str,
        name: &str,
        flags: u64,
        follow: bool,
        read_value: impl FnOnce() -> Result<T, LinuxErrno>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let flags = i32::try_from(flags).map_err(|_| LINUX_EINVAL)?;
        let valid_flags =
            crate::linux_abi::LINUX_XATTR_CREATE | crate::linux_abi::LINUX_XATTR_REPLACE;
        if flags & !valid_flags != 0 || flags == valid_flags {
            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
        }
        // Linux restricts the `user.*` namespace to regular files and
        // directories: setxattr(user.*) on a FIFO, char/block device, or socket
        // is EPERM (setxattr02). The path variant follows symlinks, so a symlink
        // resolves to its target's type (case 02 -> the regular file -> EEXIST,
        // not EPERM). Device markers carry their S_IFCHR/S_IFBLK type bits in the
        // stored mode; a plain regular file reports `File` with no device bits.
        // Skipped when the backend can't report a type (e.g. `--fs memory`).
        if name.starts_with("user.") {
            let regular_or_dir = if let Some(mount) = self.fs.vfs_mounts.resolve(resolved) {
                mount.vfs.lookup(&mount.full_path).ok().map(|metadata| {
                    matches!(
                        metadata.kind,
                        carrick_vfs::EntryKind::File | carrick_vfs::EntryKind::Directory
                    )
                })
            } else {
                let stat = self
                    .fs
                    .rootfs_vfs
                    .dentry_stat(resolved, follow)
                    .ok()
                    .or_else(|| self.fs.rootfs_vfs.overlay.real_stat(resolved, follow));
                stat.map(|real| {
                    let type_bits = real.mode & LINUX_S_IFMT;
                    matches!(real.kind, RootFsEntryKind::Directory)
                        || (matches!(real.kind, RootFsEntryKind::File)
                            && type_bits != LINUX_S_IFCHR
                            && type_bits != LINUX_S_IFBLK)
                })
            };
            if regular_or_dir == Some(false) {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
        }
        let value = read_value()?;
        // VFS mounts do not yet expose an xattr operation. Do not fall through
        // to the rootfs overlay: the mounted path is absent there, which
        // misleadingly returned ENODATA ("attribute missing") for setxattr.
        // EOPNOTSUPP is Linux's filesystem-does-not-support-this-namespace
        // result and lets tools such as GNU install skip optional metadata while
        // still applying the requested mode through fchmod.
        if let Some(mount) = self.fs.vfs_mounts.resolve(resolved) {
            return Ok(DispatchOutcome::errno(
                mount.vfs.setxattr_unsupported_errno(),
            ));
        }
        self.fs
            .rootfs_vfs
            .set_xattr(resolved, name, value.as_ref(), flags, follow)?;
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn getxattr(
        &self,
        context: &crate::kernel::KernelContext,
        memory: &mut impl CurrentMmMemory,
        target: XattrTarget,
        name_ptr: GuestPtr,
        value_ptr: GuestPtr,
        size: u64,
    ) -> Result<DispatchOutcome, DispatchError> {
        // getxattr(path/fd, name, value, size)
        let buf_addr = value_ptr.0;
        let size = size as usize;
        if size > 0
            && let Some(outcome) = self.resume_copyout_bytes(
                context,
                memory,
                super::SuspendedCopyoutKind::GetXattr { size },
                buf_addr,
            )
        {
            return Ok(outcome);
        }
        let follow = target.follow();
        let resolved = self.xattr_target_path(memory, target)?;
        let name = read_guest_c_string(memory, name_ptr.0)?;
        let value = self.get_xattr_bytes(&resolved, &name, follow)?;
        // size == 0 is the "tell me how big" probe: return the length without
        // copying anything.
        if size == 0 {
            return Ok(DispatchOutcome::returned_len_or_errno(value.len()));
        }
        if value.len() > size {
            return Ok(DispatchOutcome::errno(LINUX_ERANGE));
        }
        Ok(self.copyout_bytes_with_kind(
            context,
            memory,
            super::SuspendedCopyoutKind::GetXattr { size },
            buf_addr,
            &value,
        ))
    }

    pub(super) fn listxattr(
        &self,
        context: &crate::kernel::KernelContext,
        memory: &mut impl CurrentMmMemory,
        target: XattrTarget,
        list_ptr: GuestPtr,
        size: u64,
    ) -> Result<DispatchOutcome, DispatchError> {
        // listxattr(path/fd, list, size)
        let buf_addr = list_ptr.0;
        let size = size as usize;
        if size > 0
            && let Some(outcome) = self.resume_copyout_bytes(
                context,
                memory,
                super::SuspendedCopyoutKind::ListXattr { size },
                buf_addr,
            )
        {
            return Ok(outcome);
        }
        let follow = target.follow();
        let resolved = self.xattr_target_path(memory, target)?;
        let list = self.list_xattr_bytes(&resolved, follow)?;
        if size == 0 {
            return Ok(DispatchOutcome::returned_len_or_errno(list.len()));
        }
        if list.len() > size {
            return Ok(DispatchOutcome::errno(LINUX_ERANGE));
        }
        Ok(self.copyout_bytes_with_kind(
            context,
            memory,
            super::SuspendedCopyoutKind::ListXattr { size },
            buf_addr,
            &list,
        ))
    }

    pub(in crate::dispatch) fn get_xattr_bytes(
        &self,
        resolved: &str,
        name: &str,
        follow: bool,
    ) -> Result<Vec<u8>, LinuxErrno> {
        self.fs.rootfs_vfs.get_xattr(resolved, name, follow)
    }

    pub(in crate::dispatch) fn list_xattr_bytes(
        &self,
        resolved: &str,
        follow: bool,
    ) -> Result<Vec<u8>, LinuxErrno> {
        let names = self.fs.rootfs_vfs.list_xattr(resolved, follow)?;
        // Assemble the NUL-separated, NUL-terminated name list Linux returns.
        let mut list = Vec::new();
        for n in &names {
            list.extend_from_slice(n.as_bytes());
            list.push(0);
        }
        Ok(list)
    }

    pub(super) fn removexattr(
        &self,
        memory: &mut impl CurrentMmMemory,
        target: XattrTarget,
        name_ptr: GuestPtr,
    ) -> Result<DispatchOutcome, DispatchError> {
        // removexattr(path/fd, name)
        let follow = target.follow();
        let resolved = self.xattr_target_path(memory, target)?;
        // Path existence (missing -> ENOENT, distinct from ENODATA for an
        // absent attribute on a file that DOES exist; removexattr02 checks
        // both) is now enforced centrally in xattr_target_path.
        let name = read_guest_c_string(memory, name_ptr.0)?;
        self.fs.rootfs_vfs.remove_xattr(&resolved, &name, follow)?;
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    define_syscall! {
        fn sys_setxattr_path(this, cx, path: GuestPtr, name: GuestPtr, value: GuestPtr, size: u64, flags: u64) {
            this.setxattr(cx.memory, XattrTarget::Path { path, follow: true }, name, value, size, flags)
        }

        fn sys_lsetxattr_path(this, cx, path: GuestPtr, name: GuestPtr, value: GuestPtr, size: u64, flags: u64) {
            this.setxattr(cx.memory, XattrTarget::Path { path, follow: false }, name, value, size, flags)
        }

        fn sys_setxattr_fd(this, cx, fd: Fd, name: GuestPtr, value: GuestPtr, size: u64, flags: u64) {
            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            this.setxattr(cx.memory, XattrTarget::Fd(fd), name, value, size, flags)
        }

        fn sys_getxattr_path(this, cx, path: GuestPtr, name: GuestPtr, value: GuestPtr, size: u64) {
            this.getxattr(cx.kernel, cx.memory, XattrTarget::Path { path, follow: true }, name, value, size)
        }

        fn sys_lgetxattr_path(this, cx, path: GuestPtr, name: GuestPtr, value: GuestPtr, size: u64) {
            this.getxattr(cx.kernel, cx.memory, XattrTarget::Path { path, follow: false }, name, value, size)
        }

        fn sys_getxattr_fd(this, cx, fd: Fd, name: GuestPtr, value: GuestPtr, size: u64) {
            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            this.getxattr(cx.kernel, cx.memory, XattrTarget::Fd(fd), name, value, size)
        }

        fn sys_listxattr_path(this, cx, path: GuestPtr, list: GuestPtr, size: u64) {
            this.listxattr(cx.kernel, cx.memory, XattrTarget::Path { path, follow: true }, list, size)
        }

        fn sys_llistxattr_path(this, cx, path: GuestPtr, list: GuestPtr, size: u64) {
            this.listxattr(cx.kernel, cx.memory, XattrTarget::Path { path, follow: false }, list, size)
        }

        fn sys_listxattr_fd(this, cx, fd: Fd, list: GuestPtr, size: u64) {
            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            this.listxattr(cx.kernel, cx.memory, XattrTarget::Fd(fd), list, size)
        }

        fn sys_removexattr_path(this, cx, path: GuestPtr, name: GuestPtr) {
            this.removexattr(cx.memory, XattrTarget::Path { path, follow: true }, name)
        }

        fn sys_lremovexattr_path(this, cx, path: GuestPtr, name: GuestPtr) {
            this.removexattr(cx.memory, XattrTarget::Path { path, follow: false }, name)
        }

        fn sys_removexattr_fd(this, cx, fd: Fd, name: GuestPtr) {
            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            this.removexattr(cx.memory, XattrTarget::Fd(fd), name)
        }
    }
}

impl XattrTarget {
    fn follow(self) -> bool {
        match self {
            Self::Path { follow, .. } => follow,
            Self::Fd(_) => true,
        }
    }
}
