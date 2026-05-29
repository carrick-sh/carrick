//! fcntl file leases (F_SETLEASE/F_GETLEASE). macOS has no lease primitive, so
//! carrick records the lease type on the open-file description:
//!   - O_RDONLY fd: F_SETLEASE F_RDLCK → 0; F_GETLEASE → F_RDLCK; F_SETLEASE
//!     F_UNLCK → 0; F_GETLEASE → F_UNLCK (the fcntl23-26 round-trip).
//!   - F_SETLEASE with a bad type → EINVAL.
//!   - F_SETLEASE F_RDLCK on a write-capable (O_RDWR) fd → EAGAIN, because the
//!     fd is itself a conflicting writer (the fcntl27 shape).
//!
//! (Cross-PROCESS F_WRLCK open-conflict EAGAIN — fcntl32 — needs an inode-wide
//! opener count and is not asserted here.) Deterministic booleans, diffed
//! line-exact carrick-vs-Linux.

use conformance_probes::errno;
use std::ffi::CString;

const F_SETLEASE: i32 = 1024;
const F_GETLEASE: i32 = 1025;
const F_RDLCK: i32 = 0;
const F_UNLCK: i32 = 2;

fn main() {
    unsafe {
        let path = CString::new("/tmp/lease_probe").unwrap();
        let cfd = libc::open(
            path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        if cfd >= 0 {
            libc::close(cfd);
        }

        // O_RDONLY: read-lease round-trip.
        let rfd = libc::open(path.as_ptr(), libc::O_RDONLY, 0);
        println!(
            "setlease_rdlck_ok={}",
            libc::fcntl(rfd, F_SETLEASE, F_RDLCK) == 0
        );
        println!("getlease_is_rdlck={}", libc::fcntl(rfd, F_GETLEASE) == F_RDLCK);
        println!(
            "setlease_unlck_ok={}",
            libc::fcntl(rfd, F_SETLEASE, F_UNLCK) == 0
        );
        println!("getlease_is_unlck={}", libc::fcntl(rfd, F_GETLEASE) == F_UNLCK);
        let bad = libc::fcntl(rfd, F_SETLEASE, 99);
        println!(
            "setlease_bad_type_einval={}",
            bad == -1 && errno() == libc::EINVAL
        );
        if rfd >= 0 {
            libc::close(rfd);
        }

        // O_RDWR fd is itself a writer → a read lease conflicts → EAGAIN.
        let wfd = libc::open(path.as_ptr(), libc::O_RDWR, 0);
        let rc = libc::fcntl(wfd, F_SETLEASE, F_RDLCK);
        println!(
            "setlease_rdlck_on_rdwr_eagain={}",
            rc == -1 && errno() == libc::EAGAIN
        );
        if wfd >= 0 {
            libc::close(wfd);
        }
    }
}
