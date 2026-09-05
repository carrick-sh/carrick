//! `splice(2)` / `vmsplice(2)` out of an EMPTY pipe.
//!
//! An empty pipe is not a zero-byte transfer. With a writer alive a blocking
//! splice must wait for bytes and a `SPLICE_F_NONBLOCK` one must fail with
//! EAGAIN; only with no writer left is the answer 0. carrick returned 0 as
//! soon as the reader outran the writer, so LTP splice02's copy loop ended
//! early under load (file 76800 of 1048576 bytes).
//!
//! Invariants (booleans / small integers, deterministic):
//!
//!   * blocking splice(pipe -> file) with a child that writes 4096 bytes
//!     after 300 ms returns 4096 (it waited), and the file holds the bytes;
//!   * the next splice after the writer exited returns 0 (EOF);
//!   * splice with SPLICE_F_NONBLOCK on an empty pipe whose write end is
//!     still open fails with EAGAIN;
//!   * vmsplice(read end, SPLICE_F_NONBLOCK) on that empty pipe is EAGAIN too.

use conformance_probes::report;
use std::ffi::CString;

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

fn main() {
    unsafe {
        let mut pfd = [0i32; 2];
        assert_eq!(libc::pipe(pfd.as_mut_ptr()), 0);
        let child = libc::fork();
        if child == 0 {
            libc::close(pfd[0]);
            libc::usleep(300_000);
            let payload = vec![0x5au8; 4096];
            let mut off = 0usize;
            while off < payload.len() {
                let w = libc::write(pfd[1], payload.as_ptr().add(off).cast(), payload.len() - off);
                if w <= 0 {
                    libc::_exit(2);
                }
                off += w as usize;
            }
            libc::_exit(0);
        }
        libc::close(pfd[1]);
        let path = CString::new("/tmp/splicepipeempty.out").unwrap();
        let out = libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644);
        let first = libc::splice(pfd[0], std::ptr::null_mut(), out, std::ptr::null_mut(), 65536, 0);
        let mut status = 0i32;
        libc::waitpid(child, &mut status, 0);
        let after_eof = libc::splice(pfd[0], std::ptr::null_mut(), out, std::ptr::null_mut(), 65536, 0);
        let mut check = vec![0u8; 4096];
        let got = libc::pread(out, check.as_mut_ptr().cast(), 4096, 0);
        let file_ok = got == 4096 && check.iter().all(|&b| b == 0x5a);

        let mut qfd = [0i32; 2];
        assert_eq!(libc::pipe(qfd.as_mut_ptr()), 0);
        let nb = libc::splice(qfd[0], std::ptr::null_mut(), out, std::ptr::null_mut(), 4096, libc::SPLICE_F_NONBLOCK);
        let nb_errno = errno();
        let mut buf = vec![0u8; 4096];
        let iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: 4096 };
        let vm = libc::vmsplice(qfd[0], &iov, 1, libc::SPLICE_F_NONBLOCK);
        let vm_errno = errno();

        report!(
            blocking_splice_waited_for_writer = first == 4096,
            file_holds_spliced_bytes = file_ok,
            splice_after_last_writer_is_eof = after_eof == 0,
            nonblock_splice_empty_pipe_eagain = nb == -1 && nb_errno == libc::EAGAIN,
            nonblock_vmsplice_empty_pipe_eagain = vm == -1 && vm_errno == libc::EAGAIN,
        );
    }
}
