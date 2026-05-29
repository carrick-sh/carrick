//! Positional/vector read errno on special fds:
//!   - pread on a pipe (non-seekable) → ESPIPE.
//!   - pread on a directory → EISDIR.
//!   - readv on a directory → EISDIR.
//!   - pread on a regular file still succeeds (no false positive).
//! carrick previously returned EINVAL for the pipe/dir cases. Stands in for LTP
//! pread02 and the directory case of readv02. Deterministic booleans, diffed
//! line-exact carrick-vs-Linux.

use conformance_probes::errno;
use std::ffi::CString;

fn main() {
    unsafe {
        let mut buf = [0u8; 16];

        // pread on a pipe read-end → ESPIPE.
        let mut fds = [0i32; 2];
        if libc::pipe(fds.as_mut_ptr()) == 0 {
            let rc = libc::pread(fds[0], buf.as_mut_ptr() as *mut _, 16, 0);
            println!(
                "pread_pipe_espipe={}",
                rc == -1 && errno() == libc::ESPIPE
            );
            libc::close(fds[0]);
            libc::close(fds[1]);
        }

        // pread / readv on a directory → EISDIR.
        let d = CString::new("/tmp").unwrap();
        let dfd = libc::open(d.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY, 0);
        let rc = libc::pread(dfd, buf.as_mut_ptr() as *mut _, 16, 0);
        println!("pread_dir_eisdir={}", rc == -1 && errno() == libc::EISDIR);
        let iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: 16,
        };
        let rc = libc::readv(dfd, &iov, 1);
        println!("readv_dir_eisdir={}", rc == -1 && errno() == libc::EISDIR);
        if dfd >= 0 {
            libc::close(dfd);
        }

        // pread on a regular file still works.
        let f = CString::new("/tmp/pread_probe").unwrap();
        let wf = libc::open(f.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644);
        if wf >= 0 {
            libc::write(wf, b"hello".as_ptr() as *const _, 5);
        }
        let rc = libc::pread(wf, buf.as_mut_ptr() as *mut _, 5, 0);
        println!("pread_regular_ok={}", rc == 5);
        if wf >= 0 {
            libc::close(wf);
        }
    }
}
