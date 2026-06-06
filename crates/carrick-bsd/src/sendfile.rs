//! macOS/FreeBSD Sendfile trait implementation.

use carrick_hal::error::OsError;
use carrick_hal::sendfile::Sendfile;
use std::os::fd::RawFd;

pub struct BsdSendfile;

impl Sendfile for BsdSendfile {
    fn file_to_socket(
        &self,
        file: RawFd,
        sock: RawFd,
        offset: i64,
        count: usize,
    ) -> Result<usize, OsError> {
        #[cfg(target_os = "macos")]
        {
            let mut len: libc::off_t = count as libc::off_t;
            let rc = unsafe {
                libc::sendfile(
                    file,
                    sock,
                    offset as libc::off_t,
                    &mut len,
                    std::ptr::null_mut(),
                    0,
                )
            };
            let sent = len.max(0) as usize;
            if rc < 0 && sent == 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                return Err(OsError::from_raw(errno));
            }
            Ok(sent)
        }

        #[cfg(target_os = "freebsd")]
        {
            let mut sbytes: libc::off_t = 0;
            let rc = unsafe {
                libc::sendfile(
                    file,
                    sock,
                    offset as libc::off_t,
                    count,
                    std::ptr::null_mut(),
                    &mut sbytes,
                    0,
                )
            };
            let sent = sbytes.max(0) as usize;
            if rc < 0 && sent == 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                return Err(OsError::from_raw(errno));
            }
            Ok(sent)
        }
    }
}
