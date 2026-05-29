//! chmod/fchmodat setgid handling + fchmodat2 flag validation:
//!   - An unprivileged process that OWNS a file but whose effective gid differs
//!     from the file's group cannot set S_ISGID: chmod succeeds but the kernel
//!     strips the setgid bit (chmod05/fchmod05).
//!   - fchmodat2 (syscall 452) validates its flags arg: AT_SYMLINK_NOFOLLOW is
//!     accepted, an unknown flag bit → EINVAL (fchmodat2_02). (Plain fchmodat,
//!     nr 53, ignores the flags register — apt relies on that — so it is not
//!     asserted here.)
//!
//! The probe starts as root (the carrick guest's default uid), so it can chown
//! the file to a non-root owner/group and drop privilege before the chmod.
//! Deterministic booleans, diffed line-exact carrick-vs-Linux.

use conformance_probes::errno;
use std::ffi::CString;

const SYS_FCHMODAT2: libc::c_long = 452;
const AT_FDCWD: libc::c_long = -100;
const AT_SYMLINK_NOFOLLOW: libc::c_long = 0x100;

fn main() {
    unsafe {
        // (1) setgid-clear: own the file, but egid != file's group, non-root.
        let dir = CString::new("/tmp/sgid_probe").unwrap();
        libc::mkdir(dir.as_ptr(), 0o755);
        // Owner uid 1000, group 2000.
        libc::chown(dir.as_ptr(), 1000, 2000);
        // Drop privilege: egid 3000 (NOT the file's gid 2000), euid 1000 (the
        // owner). Order matters — set gids while still root.
        let _ = libc::setresgid(3000, 3000, 3000);
        let _ = libc::setresuid(1000, 1000, 1000);
        let rc = libc::chmod(dir.as_ptr(), (libc::S_ISGID | 0o777) as libc::mode_t);
        let mut st: libc::stat = core::mem::zeroed();
        let st_ok = libc::stat(dir.as_ptr(), &mut st) == 0;
        println!("setgid_chmod_ok={}", rc == 0);
        println!(
            "setgid_cleared_for_nonmember={}",
            st_ok && (st.st_mode as u32 & libc::S_ISGID as u32) == 0
        );

        // (2) fchmodat2 (syscall 452) rejects an unknown flag bit with EINVAL
        //     (raw syscall — exercises carrick's dispatch, not the libc wrapper).
        //     The AT_SYMLINK_NOFOLLOW *success* path is fs-dependent on Linux
        //     (EOPNOTSUPP on some), so only the EINVAL edge is asserted here; the
        //     valid-flag path is covered by LTP fchmodat2_02.
        let _ = AT_SYMLINK_NOFOLLOW;
        let bad_flag = libc::syscall(
            SYS_FCHMODAT2,
            AT_FDCWD,
            dir.as_ptr(),
            0o755 as libc::c_long,
            0x4000 as libc::c_long,
        );
        println!(
            "fchmodat2_bad_flag_einval={}",
            bad_flag == -1 && errno() == libc::EINVAL
        );
    }
}
