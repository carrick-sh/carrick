//! Extended-attribute (xattr) syscall helpers: `setxattr`/`getxattr`/
//! `listxattr` (path, lpath and f-variants share these via `XattrTarget`),
//! backed by the overlay's xattr store. Split out of `dispatch/fs.rs` (WS-F3)
//! as `impl SyscallDispatcher` methods; `self.…` resolution is type-based so
//! the move is transparent to callers.
use super::*;

impl SyscallDispatcher {
    pub(super) fn xattr_unsupported(&self) -> DispatchOutcome {
        DispatchOutcome::errno(LINUX_ENOTSUP)
    }

    /// Resolve the first argument of an xattr syscall to the rootfs path it
    /// names: a path string (path/lpath variants) or the path of the file an
    /// fd refers to (f-variant). Returns `Err(errno)` on a bad path or an fd
    /// that has no backing host file (e.g. the in-memory backend).
    fn xattr_target_path(
        &self,
        memory: &impl GuestMemory,
        target: XattrTarget,
    ) -> Result<String, i32> {
        match target {
            XattrTarget::Path(path_ptr) => {
                let path = read_guest_c_string(memory, path_ptr.0)?;
                if path.is_empty() {
                    return Err(LINUX_ENOENT);
                }
                self.resolve_at_path(LINUX_AT_FDCWD, &path)
            }
            XattrTarget::Fd(fd) => {
                let open_file = self.open_file(fd.0).ok_or(LINUX_EBADF)?;
                let open = open_file.description.read();
                match &*open {
                    OpenDescription::File { path, .. }
                    | OpenDescription::Directory { path, .. } => Ok(path.clone()),
                    // HostFile caches no path; xattr on a raw host fd that has
                    // no recoverable rootfs path is unsupported. The probe and
                    // the common case use the path variants.
                    _ => Err(LINUX_ENOTSUP),
                }
            }
        }
    }

    pub(super) fn setxattr(
        &self,
        memory: &mut impl GuestMemory,
        target: XattrTarget,
        name_ptr: GuestPtr,
        value_ptr: GuestPtr,
        size: u64,
        flags: u64,
    ) -> Result<DispatchOutcome, DispatchError> {
        // setxattr(path/fd, name, value, size, flags)
        let resolved = match self.xattr_target_path(memory, target) {
            Ok(p) => p,
            Err(errno) => return Ok(errno.into()),
        };
        let name = match read_guest_c_string(memory, name_ptr.0) {
            Ok(name) => name,
            Err(errno) => return Ok(errno.into()),
        };
        let size = size as usize;
        let flags = flags as i32;
        let value = match memory.read_bytes(value_ptr.0, size) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Ok(LINUX_EFAULT.into());
            }
        };
        match self
            .fs
            .rootfs_vfs
            .overlay
            .set_xattr(&resolved, &name, &value, flags)
        {
            Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
            Err(errno) => Ok(errno.into()),
        }
    }

    pub(super) fn getxattr(
        &self,
        memory: &mut impl GuestMemory,
        target: XattrTarget,
        name_ptr: GuestPtr,
        value_ptr: GuestPtr,
        size: u64,
    ) -> Result<DispatchOutcome, DispatchError> {
        // getxattr(path/fd, name, value, size)
        let resolved = match self.xattr_target_path(memory, target) {
            Ok(p) => p,
            Err(errno) => return Ok(errno.into()),
        };
        let name = match read_guest_c_string(memory, name_ptr.0) {
            Ok(name) => name,
            Err(errno) => return Ok(errno.into()),
        };
        let buf_addr = value_ptr.0;
        let size = size as usize;
        let value = match self.fs.rootfs_vfs.overlay.get_xattr(&resolved, &name) {
            Ok(value) => value,
            Err(errno) => return Ok(errno.into()),
        };
        // size == 0 is the "tell me how big" probe: return the length without
        // copying anything.
        if size == 0 {
            return Ok(DispatchOutcome::Returned {
                value: value.len() as i64,
            });
        }
        if value.len() > size {
            return Ok(LINUX_ERANGE.into());
        }
        if memory.write_bytes(buf_addr, &value).is_err() {
            return Ok(LINUX_EFAULT.into());
        }
        Ok(DispatchOutcome::Returned {
            value: value.len() as i64,
        })
    }

    pub(super) fn listxattr(
        &self,
        memory: &mut impl GuestMemory,
        target: XattrTarget,
        list_ptr: GuestPtr,
        size: u64,
    ) -> Result<DispatchOutcome, DispatchError> {
        // listxattr(path/fd, list, size)
        let resolved = match self.xattr_target_path(memory, target) {
            Ok(p) => p,
            Err(errno) => return Ok(errno.into()),
        };
        let buf_addr = list_ptr.0;
        let size = size as usize;
        let names = match self.fs.rootfs_vfs.overlay.list_xattr(&resolved) {
            Ok(names) => names,
            Err(errno) => return Ok(errno.into()),
        };
        // Assemble the NUL-separated, NUL-terminated name list Linux returns.
        let mut list = Vec::new();
        for n in &names {
            list.extend_from_slice(n.as_bytes());
            list.push(0);
        }
        if size == 0 {
            return Ok(DispatchOutcome::Returned {
                value: list.len() as i64,
            });
        }
        if list.len() > size {
            return Ok(LINUX_ERANGE.into());
        }
        if memory.write_bytes(buf_addr, &list).is_err() {
            return Ok(LINUX_EFAULT.into());
        }
        Ok(DispatchOutcome::Returned {
            value: list.len() as i64,
        })
    }
}
