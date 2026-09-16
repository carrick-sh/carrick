//! Typed constructors for guest return values at the syscall boundary.
//!
//! Syscall handlers return [`DispatchOutcome::Returned { value }`]. Bare casts
//! (`value: n as i64`) can silently truncate or overflow negative, causing
//! positive counts or pointers above `i64::MAX` to be misread as Linux errnos.
//! These constructors enforce checked domain conversions.

use carrick_abi::{LINUX_EINVAL, LINUX_EOVERFLOW, LinuxErrno};

use super::{DispatchOutcome, Fd, GuestPtr};

impl DispatchOutcome {
    /// Return a length or byte count (e.g. from `read`, `write`, buffer size).
    ///
    /// Fails with `LINUX_EOVERFLOW` if the length exceeds `i64::MAX`.
    #[inline]
    pub fn returned_len(len: usize) -> Result<Self, LinuxErrno> {
        let value = i64::try_from(len).map_err(|_| LINUX_EOVERFLOW)?;
        Ok(Self::Returned { value })
    }

    /// Return an infallible `DispatchOutcome` from a length, converting an
    /// overflow error to `LINUX_EOVERFLOW`. Useful in functions returning
    /// `DispatchOutcome` directly rather than `Result<DispatchOutcome, _>`.
    #[inline]
    pub fn returned_len_or_errno(len: usize) -> Self {
        match Self::returned_len(len) {
            Ok(outcome) => outcome,
            Err(errno) => Self::errno(errno),
        }
    }

    /// Return a 64-bit unsigned value (e.g. an address, timestamp, or large counter).
    ///
    /// Fails with `LINUX_EOVERFLOW` if the value exceeds `i64::MAX`.
    #[inline]
    pub fn returned_u64(val: u64) -> Result<Self, LinuxErrno> {
        let value = i64::try_from(val).map_err(|_| LINUX_EOVERFLOW)?;
        Ok(Self::Returned { value })
    }

    /// Return an infallible `DispatchOutcome` from a `u64`, converting an
    /// overflow error to `LINUX_EOVERFLOW`. Useful in functions returning
    /// `DispatchOutcome` directly rather than `Result<DispatchOutcome, _>`.
    #[inline]
    pub fn returned_u64_or_errno(val: u64) -> Self {
        match Self::returned_u64(val) {
            Ok(outcome) => outcome,
            Err(errno) => Self::errno(errno),
        }
    }

    /// Return a typed guest pointer address.
    ///
    /// Fails with `LINUX_EOVERFLOW` if the pointer value exceeds `i64::MAX`.
    #[inline]
    pub fn returned_ptr(ptr: GuestPtr) -> Result<Self, LinuxErrno> {
        Self::returned_u64(ptr.0)
    }

    /// Return a 32-bit signed integer (widens infallibly to `i64`).
    #[inline]
    pub fn returned_i32(val: i32) -> Self {
        Self::Returned { value: val as i64 }
    }

    /// Return a 32-bit unsigned integer (widens infallibly to `i64`).
    #[inline]
    pub fn returned_u32(val: u32) -> Self {
        Self::Returned { value: val as i64 }
    }

    /// Return a 16-bit unsigned integer (widens infallibly to `i64`).
    #[inline]
    pub fn returned_u16(val: u16) -> Self {
        Self::Returned { value: val as i64 }
    }

    /// Return a typed guest file descriptor (widens infallibly to `i64`).
    #[inline]
    pub fn returned_fd(fd: Fd) -> Self {
        Self::Returned { value: fd.0 as i64 }
    }

    /// Return a raw 64-bit word preserving all bits without range checking.
    /// Used specifically by `ptrace(PEEKTEXT/PEEKDATA)` where the return register
    /// carries arbitrary guest memory words, including words with bit 63 set.
    #[inline]
    pub fn returned_raw_u64(val: u64) -> Self {
        Self::Returned { value: val as i64 }
    }

    /// Return a file offset (e.g. from `lseek`).
    ///
    /// Fails with `LINUX_EINVAL` if the offset is negative.
    #[inline]
    pub fn returned_offset(off: i64) -> Result<Self, LinuxErrno> {
        if off < 0 {
            return Err(LINUX_EINVAL);
        }
        Ok(Self::Returned { value: off })
    }

    /// Return an infallible `DispatchOutcome` from a file offset, converting a
    /// negative offset to `LINUX_EINVAL`. Useful in functions returning
    /// `DispatchOutcome` directly rather than `Result<DispatchOutcome, _>`.
    #[inline]
    pub fn returned_offset_or_errno(off: i64) -> Self {
        match Self::returned_offset(off) {
            Ok(outcome) => outcome,
            Err(errno) => Self::errno(errno),
        }
    }

    /// Return a signed length or byte count (e.g. from `libc::readv`, `libc::pread`, `libc::pwrite`).
    ///
    /// Fails with `LINUX_EINVAL` if negative, or `LINUX_EOVERFLOW` if it exceeds `i64::MAX`.
    #[inline]
    pub fn returned_isize(val: isize) -> Result<Self, LinuxErrno> {
        if val < 0 {
            return Err(LINUX_EINVAL);
        }
        let value = i64::try_from(val).map_err(|_| LINUX_EOVERFLOW)?;
        Ok(Self::Returned { value })
    }

    /// Return an infallible `DispatchOutcome` from an `isize`, converting an error
    /// (negative -> `LINUX_EINVAL`, overflow -> `LINUX_EOVERFLOW`) to errno.
    #[inline]
    pub fn returned_isize_or_errno(val: isize) -> Self {
        match Self::returned_isize(val) {
            Ok(outcome) => outcome,
            Err(errno) => Self::errno(errno),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returned_len_overflow_and_success() {
        assert_eq!(
            DispatchOutcome::returned_len(usize::MAX),
            Err(LINUX_EOVERFLOW)
        );
        assert_eq!(
            DispatchOutcome::returned_len(7),
            Ok(DispatchOutcome::Returned { value: 7 })
        );
    }

    #[test]
    fn returned_len_or_errno_fallback() {
        assert_eq!(
            DispatchOutcome::returned_len_or_errno(usize::MAX),
            DispatchOutcome::Errno {
                errno: LINUX_EOVERFLOW
            }
        );
        assert_eq!(
            DispatchOutcome::returned_len_or_errno(12),
            DispatchOutcome::Returned { value: 12 }
        );
    }

    #[test]
    fn returned_u64_overflow_and_success() {
        assert_eq!(
            DispatchOutcome::returned_u64(u64::MAX),
            Err(LINUX_EOVERFLOW)
        );
        assert_eq!(
            DispatchOutcome::returned_u64(i64::MAX as u64 + 1),
            Err(LINUX_EOVERFLOW)
        );
        assert_eq!(
            DispatchOutcome::returned_u64(42),
            Ok(DispatchOutcome::Returned { value: 42 })
        );
    }

    #[test]
    fn returned_u64_or_errno_test() {
        assert_eq!(
            DispatchOutcome::returned_u64_or_errno(u64::MAX),
            DispatchOutcome::Errno {
                errno: LINUX_EOVERFLOW,
            }
        );
        assert_eq!(
            DispatchOutcome::returned_u64_or_errno(42),
            DispatchOutcome::Returned { value: 42 }
        );
    }

    #[test]
    fn returned_ptr_overflow_and_success() {
        assert_eq!(
            DispatchOutcome::returned_ptr(GuestPtr(u64::MAX)),
            Err(LINUX_EOVERFLOW)
        );
        assert_eq!(
            DispatchOutcome::returned_ptr(GuestPtr(0x4000)),
            Ok(DispatchOutcome::Returned { value: 0x4000 })
        );
    }

    #[test]
    fn returned_i32_widening() {
        assert_eq!(
            DispatchOutcome::returned_i32(-1),
            DispatchOutcome::Returned { value: -1 }
        );
        assert_eq!(
            DispatchOutcome::returned_i32(100),
            DispatchOutcome::Returned { value: 100 }
        );
    }

    #[test]
    fn returned_u32_widening() {
        assert_eq!(
            DispatchOutcome::returned_u32(u32::MAX),
            DispatchOutcome::Returned {
                value: u32::MAX as i64
            }
        );
    }

    #[test]
    fn returned_u16_widening() {
        assert_eq!(
            DispatchOutcome::returned_u16(u16::MAX),
            DispatchOutcome::Returned {
                value: u16::MAX as i64
            }
        );
    }

    #[test]
    fn returned_fd_conversion() {
        assert_eq!(
            DispatchOutcome::returned_fd(Fd(3)),
            DispatchOutcome::Returned { value: 3 }
        );
        assert_eq!(
            DispatchOutcome::returned_fd(Fd(-1)),
            DispatchOutcome::Returned { value: -1 }
        );
    }

    #[test]
    fn returned_raw_u64_preserves_high_bit() {
        assert_eq!(
            DispatchOutcome::returned_raw_u64(0x8000_0000_0000_0000),
            DispatchOutcome::Returned {
                value: -9223372036854775808
            }
        );
    }

    #[test]
    fn returned_offset_validation() {
        assert_eq!(DispatchOutcome::returned_offset(-1), Err(LINUX_EINVAL));
        assert_eq!(
            DispatchOutcome::returned_offset(1024),
            Ok(DispatchOutcome::Returned { value: 1024 })
        );
        assert_eq!(
            DispatchOutcome::returned_offset_or_errno(-5),
            DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            }
        );
        assert_eq!(
            DispatchOutcome::returned_offset_or_errno(0),
            DispatchOutcome::Returned { value: 0 }
        );
    }

    #[test]
    fn returned_isize_validation() {
        assert_eq!(DispatchOutcome::returned_isize(-1), Err(LINUX_EINVAL));
        assert_eq!(
            DispatchOutcome::returned_isize(42),
            Ok(DispatchOutcome::Returned { value: 42 })
        );
        assert_eq!(
            DispatchOutcome::returned_isize_or_errno(-1),
            DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            }
        );
        assert_eq!(
            DispatchOutcome::returned_isize_or_errno(100),
            DispatchOutcome::Returned { value: 100 }
        );
    }
}
