//! `fcntl(F_GETFL)` reports only file STATUS flags (audit M8): creation-only
//! flags (O_CREAT/O_EXCL/O_TRUNC/O_DIRECTORY/…) are consumed by open() and must
//! NOT be reported back. carrick previously echoed the raw open flags, leaking
//! the creation bits (also into /proc/self/fdinfo). O_NONBLOCK is a status flag
//! and must remain.
//!
//! Invariants encoded (carrick must match Linux line-for-line):
//!   - F_GETFL after open(O_CREAT|O_TRUNC|O_RDWR|O_NONBLOCK) has neither O_CREAT
//!     nor O_TRUNC set.
//!   - The access mode (O_RDWR) and O_NONBLOCK ARE reported.

use conformance_probes::report;
use std::ffi::CString;

fn main() {
    unsafe {
        let path = CString::new("/tmp/carrick-fgetfl-probe").unwrap();
        let fd = libc::open(
            path.as_ptr(),
            libc::O_CREAT | libc::O_TRUNC | libc::O_RDWR | libc::O_NONBLOCK,
            0o644,
        );
        report!(open_ok = fd >= 0);

        let flags = libc::fcntl(fd, libc::F_GETFL);
        report!(no_o_creat = flags & libc::O_CREAT == 0);
        report!(no_o_trunc = flags & libc::O_TRUNC == 0);
        report!(accmode_is_rdwr = flags & libc::O_ACCMODE == libc::O_RDWR);
        report!(keeps_o_nonblock = flags & libc::O_NONBLOCK == libc::O_NONBLOCK);

        libc::close(fd);
        libc::unlink(path.as_ptr());
    }
}
