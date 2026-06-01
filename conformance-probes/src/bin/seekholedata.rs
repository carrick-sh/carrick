//! lseek(SEEK_DATA)/lseek(SEEK_HOLE) on a sparse file must work — CPython
//! test_posix.test_fs_holes relies on them. macOS supports both but SWAPS the
//! constants (Linux SEEK_DATA=3/SEEK_HOLE=4; macOS SEEK_DATA=4/SEEK_HOLE=3), and
//! carrick's lseek rejected any whence outside SET/CUR/END (EINVAL → OSError →
//! the test skipped). carrick now translates them to the macOS values.
//!
//!  * seek_data_ok: lseek(fd, 0, SEEK_DATA) succeeds (>= 0), not EINVAL.
//!  * seek_hole_ok: lseek(fd, 0, SEEK_HOLE) succeeds (>= 0).

use conformance_probes::report;
const LINUX_SEEK_DATA: i32 = 3;
const LINUX_SEEK_HOLE: i32 = 4;
fn main() {
    unsafe {
        let path = b"cr_sparse\0".as_ptr() as *const libc::c_char;
        libc::unlink(path);
        let fd = libc::open(path, libc::O_CREAT | libc::O_RDWR, 0o644);
        if fd < 0 {
            report!(seek_data_ok = false, seek_hole_ok = false);
            return;
        }
        // 4 KiB of data, then a trailing hole out to 64 KiB.
        let data = [b'x'; 4096];
        libc::write(fd, data.as_ptr() as *const libc::c_void, data.len());
        libc::ftruncate(fd, 65536);
        let d = libc::lseek(fd, 0, LINUX_SEEK_DATA);
        let h = libc::lseek(fd, 0, LINUX_SEEK_HOLE);
        report!(seek_data_ok = (d >= 0), seek_hole_ok = (h >= 0));
        libc::close(fd);
        libc::unlink(path);
    }
}
