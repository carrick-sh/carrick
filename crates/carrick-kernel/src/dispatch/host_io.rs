//! Injectable external host operations. Implementations must not access guest
//! memory. Dispatch with an authenticated host-wait context releases MM
//! admission and CPU ownership first; off-executor callers run inline.

use carrick_abi::LinuxErrno;
use carrick_vfs::errno::HostSyscallResult;
use std::os::fd::{AsRawFd, BorrowedFd};

/// Host filesystem durability operations, shared across guest fork. This
/// replaces the actual host call rather than observing a test-only event.
pub trait HostIo: Send + Sync {
    fn sync(&self);
    fn flush(&self, fd: BorrowedFd<'_>) -> Result<(), LinuxErrno>;
}

#[derive(Debug, Default)]
pub struct SystemHostIo;

impl HostIo for SystemHostIo {
    fn sync(&self) {
        unsafe {
            libc::sync();
        }
    }

    fn flush(&self, fd: BorrowedFd<'_>) -> Result<(), LinuxErrno> {
        unsafe { libc::fsync(fd.as_raw_fd()) }.host_syscall_errno()?;
        #[cfg(target_os = "macos")]
        if std::env::var_os("CARRICK_STRICT_DURABILITY").is_some_and(|value| value != "0") {
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_FULLFSYNC) }.host_syscall_errno()?;
        }
        Ok(())
    }
}
