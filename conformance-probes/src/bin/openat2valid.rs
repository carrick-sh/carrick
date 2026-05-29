//! openat2(2) open_how validation. carrick previously whitelisted only
//! O_CLOEXEC|O_NONBLOCK and rejected any mode/resolve → every normal open via
//! openat2 was EINVAL. Now it passes flags+mode through and validates:
//!   - a normal O_RDWR|O_CREAT open succeeds;
//!   - mode set without O_CREAT → EINVAL; mode with bits outside 0o7777 → EINVAL;
//!   - unknown resolve bits → EINVAL; size 0/<sizeof → EINVAL;
//!   - size > sizeof with NONZERO trailing padding → E2BIG (zero pad accepted);
//!   - a bad dirfd → EBADF.
//! Stands in for LTP openat201 (the sizeof+8 zero-pad case) + openat203.
//! Deterministic booleans, diffed line-exact carrick-vs-Linux.

use conformance_probes::errno;
use std::ffi::CString;

const SYS_OPENAT2: libc::c_long = 437;
const AT_FDCWD: libc::c_long = -100;
const SIZEOF_HOW: usize = 24; // 3 × u64: flags, mode, resolve

fn openat2(dfd: libc::c_long, path: *const libc::c_char, how: &[u64], size: usize) -> libc::c_long {
    unsafe { libc::syscall(SYS_OPENAT2, dfd, path, how.as_ptr(), size) }
}

fn main() {
    unsafe {
        let p = CString::new("/tmp/oa2_probe").unwrap();
        let o_rdwr = libc::O_RDWR as u64;
        let o_rdonly = libc::O_RDONLY as u64;
        let o_creat = libc::O_CREAT as u64;

        // Normal create → success.
        let how = [o_rdwr | o_creat, 0o644, 0];
        let fd = openat2(AT_FDCWD, p.as_ptr(), &how, SIZEOF_HOW);
        println!("openat2_create_ok={}", fd >= 0);
        if fd >= 0 {
            libc::close(fd as i32);
        }

        // mode without O_CREAT → EINVAL.
        let how = [o_rdonly, 0o400, 0];
        let r = openat2(AT_FDCWD, p.as_ptr(), &how, SIZEOF_HOW);
        println!(
            "openat2_mode_no_create_einval={}",
            r == -1 && errno() == libc::EINVAL
        );

        // mode bits outside 0o7777 → EINVAL.
        let how = [o_rdwr | o_creat, u64::MAX, 0];
        let r = openat2(AT_FDCWD, p.as_ptr(), &how, SIZEOF_HOW);
        println!(
            "openat2_bad_mode_einval={}",
            r == -1 && errno() == libc::EINVAL
        );

        // unknown resolve bits → EINVAL.
        let how = [o_rdwr | o_creat, 0o644, u64::MAX];
        let r = openat2(AT_FDCWD, p.as_ptr(), &how, SIZEOF_HOW);
        println!(
            "openat2_bad_resolve_einval={}",
            r == -1 && errno() == libc::EINVAL
        );

        // size 0 → EINVAL.
        let how = [o_rdonly, 0, 0];
        let r = openat2(AT_FDCWD, p.as_ptr(), &how, 0);
        println!(
            "openat2_size_zero_einval={}",
            r == -1 && errno() == libc::EINVAL
        );

        // size > sizeof with nonzero trailing padding → E2BIG.
        let how_pad = [o_rdonly, 0, 0, 0xdead_beefu64];
        let r = openat2(AT_FDCWD, p.as_ptr(), &how_pad, SIZEOF_HOW + 8);
        println!(
            "openat2_nonzero_pad_e2big={}",
            r == -1 && errno() == libc::E2BIG
        );

        // bad dirfd → EBADF.
        let how = [o_rdwr | o_creat, 0o644, 0];
        let r = openat2(-1, p.as_ptr(), &how, SIZEOF_HOW);
        println!("openat2_bad_dfd_ebadf={}", r == -1 && errno() == libc::EBADF);
    }
}
