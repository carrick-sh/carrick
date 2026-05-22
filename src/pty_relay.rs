//! Interactive pty bridge for `carrick run -t`. carrick allocates a host
//! pty, hands the slave to the guest as fds 0/1/2, and relays bytes between
//! the user's real terminal and the master while the guest runs.

use std::ffi::CString;
use std::io;

/// A freshly-allocated host pty (master + already-opened slave).
pub struct PtyPair {
    pub master_fd: i32,
    pub slave_fd: i32,
}

impl PtyPair {
    /// Allocate via posix_openpt + open the slave. Reuses Phase A's
    /// `open_master` (posix_openpt/grantpt/unlockpt/ptsname).
    pub fn allocate() -> io::Result<Self> {
        let (master_fd, slave_name) = crate::vfs::devpts::open_master(false)
            .map_err(io::Error::from_raw_os_error)?;
        let cname = CString::new(slave_name)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: cname is a valid NUL-terminated slave device path.
        let slave_fd = unsafe { libc::open(cname.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
        if slave_fd < 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(master_fd) };
            return Err(e);
        }
        Ok(Self { master_fd, slave_fd })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_opens_master_and_tty_slave() {
        let pty = PtyPair::allocate().expect("allocate pty");
        assert!(pty.master_fd >= 0);
        assert!(pty.slave_fd >= 0);
        assert_eq!(unsafe { libc::isatty(pty.slave_fd) }, 1);
        assert_ne!(pty.master_fd, pty.slave_fd);
        unsafe { libc::close(pty.master_fd); libc::close(pty.slave_fd); }
    }
}
