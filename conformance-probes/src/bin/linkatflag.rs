//! linkat(2) AT_* flag-validation invariant.
//!
//! linkat accepts EXACTLY two flags: AT_SYMLINK_FOLLOW (0x400, dereference the
//! old path if it is a symlink) and AT_EMPTY_PATH (0x1000, link by fd). It does
//! NOT accept AT_SYMLINK_NOFOLLOW (0x100) — that bit is meaningless for linkat,
//! whose DEFAULT (flags == 0) is already no-follow. Any unknown bit is EINVAL.
//!
//! carrick validates linkat against the WRONG mask
//! (dispatch/fs.rs:4850 `flags & !(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH)`)
//! because carrick-abi never defines LINUX_AT_SYMLINK_FOLLOW (0x400). The bug is
//! visible at the syscall boundary, independent of whether the link is created:
//!   - AT_SYMLINK_FOLLOW (0x400) is a legal flag, so Linux ACCEPTS it; carrick
//!     treats 0x400 as an unknown bit and rejects with EINVAL.
//!   - AT_SYMLINK_NOFOLLOW (0x100) is NOT legal for linkat, so Linux rejects
//!     with EINVAL; carrick ACCEPTS it.
//!
//! This probe reports only the linkat RETURN status (0 / errno) for four flag
//! values plus the baseline default-link rc. It deliberately does NOT assert
//! whether AT_SYMLINK_FOLLOW dereferenced the symlink (link-vs-target content):
//! that deref branch is a separate, larger implementation concern; the flag
//! VALIDATION is the bounded finding under test.
//!
//! Deterministic: every reported value is a fixed bool / token. No fds, sizes,
//! inodes, pids or paths leak into the diff.

use conformance_probes::{errno, report};
use std::ffi::CString;

const SYS_LINKAT: libc::c_long = 37; // aarch64 linkat
const AT_FDCWD: libc::c_int = -100;
const AT_SYMLINK_FOLLOW: libc::c_int = 0x400;
const AT_SYMLINK_NOFOLLOW: libc::c_int = 0x100;
const BOGUS_HIGH_BIT: libc::c_int = 0x0400_0000; // not any defined AT_* flag

/// Raw linkat with AT_FDCWD on both ends. Returns the linkat rc (0) or, on
/// failure, the negated errno so a single token captures both the success
/// path and the failure path deterministically.
unsafe fn linkat(oldpath: &CStr2, newpath: &CStr2, flags: libc::c_int) -> i64 {
    let rc = libc::syscall(
        SYS_LINKAT,
        AT_FDCWD,
        oldpath.ptr(),
        AT_FDCWD,
        newpath.ptr(),
        flags,
    );
    if rc < 0 {
        -(errno() as i64)
    } else {
        0
    }
}

/// Tiny owned C string wrapper so the call sites stay terse.
struct CStr2(CString);
impl CStr2 {
    fn new(s: &str) -> Self {
        CStr2(CString::new(s).unwrap())
    }
    fn ptr(&self) -> *const libc::c_char {
        self.0.as_ptr()
    }
}

/// Create a fresh regular file at `path` (unlinking any prior copy). Returns
/// whether setup succeeded.
unsafe fn make_regfile(path: &CStr2) -> bool {
    libc::unlink(path.ptr());
    let fd = libc::open(
        path.ptr(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
        0o644,
    );
    if fd < 0 {
        return false;
    }
    let d = b"x";
    libc::write(fd, d.as_ptr() as *const libc::c_void, 1);
    libc::close(fd);
    true
}

fn main() {
    unsafe {
        // run-elf's rootfs may lack /tmp.
        libc::mkdir(b"/tmp\0".as_ptr() as *const libc::c_char, 0o777);

        let target = CStr2::new("/tmp/linkatflag_target");
        let sym = CStr2::new("/tmp/linkatflag_sym");

        // /tmp/linkatflag_target : a real regular file.
        let setup_target = make_regfile(&target);
        // /tmp/linkatflag_sym -> /tmp/linkatflag_target : a symlink TO it.
        libc::unlink(sym.ptr());
        let setup_sym =
            libc::symlinkat(target.ptr(), AT_FDCWD, sym.ptr()) == 0;

        report!(
            setup_target_ok = setup_target,
            setup_sym_ok = setup_sym,
        );

        // (1) AT_SYMLINK_FOLLOW on the symlink. Linux: legal flag -> rc 0.
        //     carrick (bug): 0x400 is an unknown bit -> EINVAL(-22).
        {
            let l = CStr2::new("/tmp/linkatflag_l_follow");
            libc::unlink(l.ptr());
            let rc = linkat(&sym, &l, AT_SYMLINK_FOLLOW);
            report!(follow_rc_zero = rc == 0);
            libc::unlink(l.ptr());
        }

        // (2) Bogus high bit. Linux + carrick (after fix): EINVAL(-22).
        {
            let l = CStr2::new("/tmp/linkatflag_l_bogus");
            libc::unlink(l.ptr());
            let rc = linkat(&target, &l, BOGUS_HIGH_BIT);
            report!(bogus_einval = rc == -(libc::EINVAL as i64));
            libc::unlink(l.ptr());
        }

        // (3) flags == 0 (default no-follow) hard-linking the REGULAR file.
        //     Linux: rc 0. This is the baseline the bug doesn't touch but a
        //     too-aggressive fix could break.
        {
            let l = CStr2::new("/tmp/linkatflag_l_default");
            libc::unlink(l.ptr());
            let rc = linkat(&target, &l, 0);
            report!(default_link_rc_zero = rc == 0);
            libc::unlink(l.ptr());
        }

        // (4) AT_SYMLINK_NOFOLLOW (0x100). NOT a valid linkat flag.
        //     Linux: EINVAL(-22). carrick (bug): accepted -> rc 0.
        {
            let l = CStr2::new("/tmp/linkatflag_l_nofollow");
            libc::unlink(l.ptr());
            let rc = linkat(&target, &l, AT_SYMLINK_NOFOLLOW);
            report!(nofollow_einval = rc == -(libc::EINVAL as i64));
            libc::unlink(l.ptr());
        }
    }
}