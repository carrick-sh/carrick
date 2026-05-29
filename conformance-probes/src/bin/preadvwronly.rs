//! preadv(2) fd access-mode validation (LTP preadv02 "not open for reading"
//! case): preadv reads the fd, so a write-only (O_WRONLY) descriptor → EBADF,
//! while a readable fd returns the bytes. carrick read the fd regardless of its
//! access mode. Deterministic, line-exact carrick-vs-Linux.

use conformance_probes::errno;

fn main() {
    unsafe {
        libc::mkdir(b"/tmp\0".as_ptr() as *const _, 0o777);
        let path = b"/tmp/preadv_f\0".as_ptr() as *const libc::c_char;
        // create + seed 4 bytes.
        let seed = libc::open(path, libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644);
        let data = b"abcd";
        libc::write(seed, data.as_ptr() as *const _, 4);
        libc::close(seed);

        let mut buf = [0u8; 4];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: 4,
        };

        // O_WRONLY fd → preadv EBADF (not open for reading).
        let wr = libc::open(path, libc::O_WRONLY);
        let r1 = libc::preadv(wr, &iov, 1, 0);
        println!("preadv_wronly_ebadf={}", r1 == -1 && errno() == libc::EBADF);
        libc::close(wr);

        // O_RDONLY fd → preadv reads the 4 seeded bytes.
        let rd = libc::open(path, libc::O_RDONLY);
        let r2 = libc::preadv(rd, &iov, 1, 0);
        println!("preadv_rdonly_reads4={}", r2 == 4 && &buf == data);
        libc::close(rd);

        let _ = &mut iov;
        let _ = errno;
    }
}
