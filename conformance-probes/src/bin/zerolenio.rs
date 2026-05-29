//! A zero-length transfer never accesses the user buffer: `write`/`pwrite`
//! with count=0 (even a NULL buffer) returns 0, and a `{NULL, 0}` iovec
//! segment in `pwritev` is a permitted no-op — NOT EFAULT. carrick previously
//! validated the buffer regardless of length, faulting on `read_bytes(NULL,0)`.
//! Stands in for LTP pwrite03 / pwritev01 / pwritev201. Deterministic booleans.

use conformance_probes::errno;

fn main() {
    unsafe {
        libc::mkdir(b"/tmp\0".as_ptr() as *const _, 0o777);
        let path = b"/tmp/zlio\0".as_ptr() as *const libc::c_char;
        let fd = libc::open(path, libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644);
        println!("open_ok={}", fd >= 0);

        // pwrite(fd, NULL, 0) → 0, never EFAULT (LTP pwrite03).
        let r1 = libc::pwrite(fd, std::ptr::null(), 0, 0);
        println!("pwrite_null_zero_returns_0={}", r1 == 0);

        // write(fd, NULL, 0) → 0.
        let r2 = libc::write(fd, std::ptr::null(), 0);
        println!("write_null_zero_returns_0={}", r2 == 0);

        // pwritev([{buf,4}, {NULL,0}], 2) → 4 (the zero-length NULL segment is a
        // permitted no-op, LTP pwritev01/pwritev201).
        let data = b"abcd";
        let iov = [
            libc::iovec {
                iov_base: data.as_ptr() as *mut _,
                iov_len: 4,
            },
            libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            },
        ];
        let r3 = libc::pwritev(fd, iov.as_ptr(), 2, 0);
        println!("pwritev_with_null_seg_returns_4={}", r3 == 4);

        // The 4 bytes actually landed.
        let mut rb = [0u8; 4];
        let n = libc::pread(fd, rb.as_mut_ptr() as *mut _, 4, 0);
        println!("readback_ok={}", n == 4 && &rb == b"abcd");

        let _ = errno;
        libc::close(fd);
        libc::unlink(path);
    }
}
