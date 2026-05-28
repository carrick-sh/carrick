//! `writev`/`readv` iovec-validation edges. Linux validates the iov array at
//! syscall entry (rw_copy_check_uvector) and treats a zero-length iovec as a
//! no-op regardless of its base. carrick previously read each iovec
//! unconditionally, so a {NULL, 0} entry EFAULTed and an oversized iov_len
//! EFAULTed instead of EINVAL (LTP writev01 / readv02). Stands in for those.
//!
//! Invariants:
//!   1. **zero-length iovec is skipped**: writev([{buf,N},{NULL,0}]) writes N
//!      and succeeds (the {NULL,0} entry is a no-op, not EFAULT).
//!   2. **oversized iov_len → EINVAL**: writev with an iov_len > SSIZE_MAX
//!      returns -1/EINVAL (not EFAULT).
//!   3. **genuinely bad pointer → EFAULT** (negative control): writev with a
//!      non-zero base + non-zero len pointing at an unmapped page is -1/EFAULT
//!      — the fix skips empty iovecs, it does NOT blanket-suppress EFAULT.

use conformance_probes::{errno, report};

#[repr(C)]
#[derive(Clone, Copy)]
struct Iovec {
    base: u64,
    len: u64,
}

unsafe fn writev(fd: i32, iov: &[Iovec]) -> i64 {
    libc::syscall(libc::SYS_writev, fd, iov.as_ptr(), iov.len() as i64)
}

fn main() {
    unsafe {
        libc::mkdir(b"/tmp\0".as_ptr() as *const libc::c_char, 0o777);
        let path = b"/tmp/carrick_iovecedge\0";
        let fd = libc::open(
            path.as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        );
        if fd < 0 {
            report!(setup = false);
            return;
        }

        // (1) {buf, 8} then {NULL, 0} → writes 8, succeeds.
        let buf = b"abcdefgh";
        let iov = [
            Iovec { base: buf.as_ptr() as u64, len: 8 },
            Iovec { base: 0, len: 0 },
        ];
        let rc = writev(fd, &iov);
        report!(
            zero_len_iovec_skipped_rc_is_8 = rc == 8,
        );

        // (2) oversized iov_len (> SSIZE_MAX) → -1/EINVAL.
        let iov = [Iovec {
            base: buf.as_ptr() as u64,
            len: (i64::MAX as u64) + 1,
        }];
        let rc = writev(fd, &iov);
        let er = if rc < 0 { errno() } else { 0 };
        report!(
            oversized_iovlen_rc_neg_one = rc == -1,
            oversized_iovlen_errno_einval = er == libc::EINVAL,
        );

        // (3) genuinely bad pointer (non-zero base, non-zero len, unmapped) →
        //     -1/EFAULT. Negative control: the zero-skip must not swallow this.
        let iov = [Iovec { base: 0x10, len: 64 }];
        let rc = writev(fd, &iov);
        let er = if rc < 0 { errno() } else { 0 };
        report!(
            bad_ptr_rc_neg_one = rc == -1,
            bad_ptr_errno_efault = er == libc::EFAULT,
        );

        libc::close(fd);
        libc::unlink(path.as_ptr() as *const libc::c_char);
    }
}
