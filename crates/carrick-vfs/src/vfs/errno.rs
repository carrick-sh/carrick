//! Host-errno adaptation for the VFS.
//!
//! Two pieces the filesystem layer needs to turn a failure into a Linux errno,
//! placed below the dispatcher so `vfs/rootfs.rs` and the `fs_backend` host
//! backend do not reach upward into the dispatcher for them:
//!
//! * [`HostSyscallResult`] (with its `Err` type [`HostSyscallError`]) captures
//!   the host libc's `errno` at the moment a raw host call returned a negative
//!   value and translates it into the Linux errno domain.
//! * [`rootfs_errno`] maps a [`RootFsError`] from the in-memory OCI rootfs onto
//!   the Linux errno the guest observes.

use carrick_abi::{LINUX_E2BIG, LINUX_EINVAL, LINUX_ENOENT, LinuxErrno};

use crate::rootfs::RootFsError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostSyscallError {
    /// The HOST errno as read from the host libc — NOT a Linux errno.
    raw_errno: i32,
    linux_errno: LinuxErrno,
}

impl HostSyscallError {
    pub fn last() -> Self {
        let raw_errno = carrick_portable::errno();

        Self {
            raw_errno,
            linux_errno: crate::host_to_linux_errno(raw_errno),
        }
    }

    #[cfg(all(any(test, feature = "test-support"), target_os = "macos"))]
    pub fn raw_errno(self) -> i32 {
        self.raw_errno
    }

    pub fn linux_errno(self) -> LinuxErrno {
        self.linux_errno
    }
}

pub trait HostSyscallResult: Sized {
    fn host_syscall_result(self) -> Result<Self, HostSyscallError>;

    fn host_syscall_errno(self) -> Result<Self, LinuxErrno> {
        self.host_syscall_result()
            .map_err(HostSyscallError::linux_errno)
    }
}

impl HostSyscallResult for i32 {
    fn host_syscall_result(self) -> Result<Self, HostSyscallError> {
        if self < 0 {
            Err(HostSyscallError::last())
        } else {
            Ok(self)
        }
    }
}

impl HostSyscallResult for isize {
    fn host_syscall_result(self) -> Result<Self, HostSyscallError> {
        if self < 0 {
            Err(HostSyscallError::last())
        } else {
            Ok(self)
        }
    }
}

impl HostSyscallResult for i64 {
    fn host_syscall_result(self) -> Result<Self, HostSyscallError> {
        if self < 0 {
            Err(HostSyscallError::last())
        } else {
            Ok(self)
        }
    }
}

pub fn rootfs_errno(error: RootFsError) -> LinuxErrno {
    match error {
        RootFsError::NotFound(_) => LINUX_ENOENT,
        RootFsError::UnsafePath(_) | RootFsError::Utf8(_) | RootFsError::TooManySymlinks(_) => {
            LINUX_EINVAL
        }
        RootFsError::DirectoryTooLarge(_) => LINUX_E2BIG,
        RootFsError::Io(_) => LINUX_EINVAL,
    }
}
