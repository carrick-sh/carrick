//! Extended-attribute (xattr) syscall helpers: `setxattr`/`getxattr`/
//! `listxattr` (path, lpath and f-variants share these via `XattrTarget`),
//! backed by the overlay's xattr store. Split out of `dispatch/fs.rs` (WS-F3)
//! as `impl SyscallDispatcher` methods; `self.…` resolution is type-based so
//! the move is transparent to callers.
use super::*;

impl SyscallDispatcher {
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
                let resolved = self.resolve_at_path(LINUX_AT_FDCWD, &path)?;
                // Linux resolves the path FIRST for every *xattr syscall: a path
                // that does not exist is ENOENT, before any attr/namespace check
                // (oracle: debian:stable arm64 set/get/list/remove on a missing
                // path all -> errno 2). Without this the request falls through to
                // the backend, which reports ENOTSUP (in-memory) / ENODATA (host).
                if self.layered_metadata(&resolved).is_err() {
                    return Err(LINUX_ENOENT);
                }
                Ok(resolved)
            }
            XattrTarget::Fd(fd) => {
                let open_file = self.open_file(fd.0).ok_or(LINUX_EBADF)?;
                let open = open_file.description.read();
                match &*open {
                    OpenDescription::File { path, .. }
                    | OpenDescription::Directory { path, .. } => Ok(path.clone()),
                    // A disk-backed HostFile (the `--fs host` common case, e.g.
                    // tempfile.mkstemp's fd) carries its guest rootfs path in
                    // metadata; recover it so f-variant xattr syscalls work
                    // (CPython's xattr-support probe does os.setxattr(fd, ...)).
                    OpenDescription::HostFile { metadata, .. } => metadata
                        .path
                        .to_str()
                        .map(str::to_owned)
                        .ok_or(LINUX_ENOTSUP),
                    // Pipes/sockets/etc. have no backing file → unsupported.
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
        let resolved = self.xattr_target_path(memory, target)?;
        let name = read_guest_c_string(memory, name_ptr.0)?;
        let size = size as usize;
        let flags = flags as i32;
        let value = memory
            .read_bytes(value_ptr.0, size)
            .map_err(|_| DispatchError::Errno(LINUX_EFAULT))?;
        self.fs
            .rootfs_vfs
            .overlay
            .set_xattr(&resolved, &name, &value, flags)?;
        Ok(DispatchOutcome::Returned { value: 0 })
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
        let resolved = self.xattr_target_path(memory, target)?;
        let name = read_guest_c_string(memory, name_ptr.0)?;
        let buf_addr = value_ptr.0;
        let size = size as usize;
        let value = self.fs.rootfs_vfs.overlay.get_xattr(&resolved, &name)?;
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
        memory
            .write_bytes(buf_addr, &value)
            .map_err(|_| DispatchError::Errno(LINUX_EFAULT))?;
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
        let resolved = self.xattr_target_path(memory, target)?;
        let buf_addr = list_ptr.0;
        let size = size as usize;
        let names = self.fs.rootfs_vfs.overlay.list_xattr(&resolved)?;
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
        memory
            .write_bytes(buf_addr, &list)
            .map_err(|_| DispatchError::Errno(LINUX_EFAULT))?;
        Ok(DispatchOutcome::Returned {
            value: list.len() as i64,
        })
    }

    pub(super) fn removexattr(
        &self,
        memory: &mut impl GuestMemory,
        target: XattrTarget,
        name_ptr: GuestPtr,
    ) -> Result<DispatchOutcome, DispatchError> {
        // removexattr(path/fd, name)
        let resolved = self.xattr_target_path(memory, target)?;
        // Path existence (missing -> ENOENT, distinct from ENODATA for an
        // absent attribute on a file that DOES exist; removexattr02 checks
        // both) is now enforced centrally in xattr_target_path.
        let name = read_guest_c_string(memory, name_ptr.0)?;
        self.fs.rootfs_vfs.overlay.remove_xattr(&resolved, &name)?;
        Ok(DispatchOutcome::Returned { value: 0 })
    }
}
