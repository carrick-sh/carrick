//! On a Linux host the host errno space already IS the Linux errno space, so
//! the `carrick-hal` `host_to_linux_errno` hook is the identity function here
//! (contrast the macOS/FreeBSD `bsd_to_linux_errno` table in carrick-bsd).
#[inline]
#[must_use]
pub fn host_to_linux_errno(errno: i32) -> i32 {
    errno
}
