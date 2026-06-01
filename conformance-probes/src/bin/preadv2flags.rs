//! preadv2(2)/pwritev2(2) (aarch64 syscalls 286/287) are positional vectored
//! I/O plus a RWF_* flags arg. CPython os.preadv(fd, buf, off, RWF_HIPRI) issues
//! preadv2; carrick left 286/287 unregistered → ENOSYS, and glibc maps
//! (ENOSYS + nonzero flags) to ENOTSUP, so test_posix.test_preadv_flags SKIPPED
//! ("RWF_HIPRI is not supported") while Linux RAN it. RWF_HIPRI is a pure
//! high-priority hint; preadv2 with it must read exactly like preadv.
//!
//!  * preadv2_ret_10:   preadv2(off=3, RWF_HIPRI) over [5,3,2] returns 10
//!  * preadv2_content_ok: the three buffers are "t1tt2","t3t","5t"

use conformance_probes::report;

const RWF_HIPRI: u64 = 0x0000_0001;
const SYS_PREADV2: libc::c_long = 286;

fn main() {
    unsafe {
        let path = b"/tmp/preadv2probe\0";
        let fd = libc::open(
            path.as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        );
        if fd < 0 {
            report!(preadv2_ret_10 = false, preadv2_content_ok = false);
            return;
        }
        let data = b"test1tt2t3t5t6t6t8";
        libc::write(fd, data.as_ptr() as *const libc::c_void, data.len());

        let mut b0 = [0u8; 5];
        let mut b1 = [0u8; 3];
        let mut b2 = [0u8; 2];
        let iov = [
            libc::iovec {
                iov_base: b0.as_mut_ptr() as *mut libc::c_void,
                iov_len: 5,
            },
            libc::iovec {
                iov_base: b1.as_mut_ptr() as *mut libc::c_void,
                iov_len: 3,
            },
            libc::iovec {
                iov_base: b2.as_mut_ptr() as *mut libc::c_void,
                iov_len: 2,
            },
        ];
        // aarch64 preadv2(fd, iov, iovcnt, pos_lo, pos_hi, flags); offset 3.
        let ret = libc::syscall(SYS_PREADV2, fd, iov.as_ptr(), 3, 3, 0, RWF_HIPRI);

        let content_ok = &b0 == b"t1tt2" && &b1 == b"t3t" && &b2 == b"5t";
        report!(
            preadv2_ret_10 = (ret == 10),
            preadv2_content_ok = content_ok
        );
        libc::close(fd);
        libc::unlink(path.as_ptr() as *const libc::c_char);
    }
}
