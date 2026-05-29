//! sync_file_range(fd, offset, nbytes, flags) error validation (LTP
//! sync_file_range01): bad fd → EBADF, a pipe → ESPIPE, negative offset/nbytes
//! → EINVAL, unknown flags → EINVAL, a valid regular-file call → 0. carrick was
//! ENOSYS. Raw syscall (aarch64 nr 84: fd, offset, nbytes, flags). Deterministic
//! booleans, line-exact vs Linux.

use conformance_probes::errno;

fn main() {
    unsafe {
        libc::mkdir(b"/tmp\0".as_ptr() as *const _, 0o777);
        let fd = libc::open(
            b"/tmp/sfr\0".as_ptr() as *const _,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        let mut pf = [0i32; 2];
        libc::pipe(pf.as_mut_ptr());

        // bad fd → EBADF
        let r1 = libc::syscall(libc::SYS_sync_file_range, -1i64, 0i64, 1i64, 2i64);
        println!("sfr_badfd_ebadf={}", r1 == -1 && errno() == libc::EBADF);

        // pipe (no page-cache range) → ESPIPE
        let r2 = libc::syscall(libc::SYS_sync_file_range, pf[0] as i64, 0i64, 1i64, 2i64);
        println!("sfr_pipe_espipe={}", r2 == -1 && errno() == libc::ESPIPE);

        // negative offset → EINVAL
        let r3 = libc::syscall(libc::SYS_sync_file_range, fd as i64, -1i64, 1i64, 1i64);
        println!("sfr_neg_offset_einval={}", r3 == -1 && errno() == libc::EINVAL);

        // negative nbytes → EINVAL
        let r4 = libc::syscall(libc::SYS_sync_file_range, fd as i64, 0i64, -1i64, 2i64);
        println!("sfr_neg_nbytes_einval={}", r4 == -1 && errno() == libc::EINVAL);

        // unknown flag bit → EINVAL
        let r5 = libc::syscall(libc::SYS_sync_file_range, fd as i64, 0i64, 1i64, 8i64);
        println!("sfr_bad_flags_einval={}", r5 == -1 && errno() == libc::EINVAL);

        // valid regular-file call → 0
        let r6 = libc::syscall(libc::SYS_sync_file_range, fd as i64, 0i64, 1i64, 2i64);
        println!("sfr_valid_ok={}", r6 == 0);

        let _ = errno;
        libc::close(fd);
        libc::close(pf[0]);
        libc::close(pf[1]);
        libc::unlink(b"/tmp/sfr\0".as_ptr() as *const _);
    }
}
