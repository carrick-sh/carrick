//! On a Linux host the host errno space already IS the Linux errno space, so
//! the `carrick-hal` `host_to_linux_errno` hook is the identity function here
//! (contrast the macOS/FreeBSD `bsd_to_linux_errno` table in carrick-host-bsd).
//! It still returns the typed [`LinuxErrno`]: the translation hook is the
//! host→Linux domain boundary even when the mapping is 1:1.
use carrick_abi::LinuxErrno;

#[inline]
#[must_use]
pub fn host_to_linux_errno(errno: i32) -> LinuxErrno {
    LinuxErrno::new(errno)
}
