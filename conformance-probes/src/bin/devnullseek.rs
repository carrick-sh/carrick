//! `/dev/null` (and the other seekable char devices) must support `lseek` —
//! Linux returns 0 (never ESPIPE). CPython opens `io.open(os.devnull, "r+")`
//! whose BufferedRandom requires a seekable stream; if lseek fails it raises
//! `io.UnsupportedOperation: File or stream is not seekable`, which broke
//! test_subprocess.test_*_single_inout_fd (they pass /dev/null r+ as two of
//! stdin/stdout/stderr).
//!
//! Carrick backed /dev/null with a host fd presented as a HostPipe (a stream),
//! so lseek returned ESPIPE → non-seekable.
//!
//!  * devnull_lseek_cur0: lseek(/dev/null, 0, SEEK_CUR) succeeds (>= 0).
//!  * devnull_lseek_set:  lseek(/dev/null, 0, SEEK_SET) succeeds (>= 0).

use conformance_probes::report;

fn main() {
    unsafe {
        let fd = libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, libc::O_RDWR);
        if fd < 0 {
            report!(devnull_lseek_cur0 = false, devnull_lseek_set = false);
            return;
        }
        let cur = libc::lseek(fd, 0, libc::SEEK_CUR);
        let set = libc::lseek(fd, 0, libc::SEEK_SET);
        report!(
            devnull_lseek_cur0 = (cur >= 0),
            devnull_lseek_set = (set >= 0)
        );
        libc::close(fd);
    }
}
