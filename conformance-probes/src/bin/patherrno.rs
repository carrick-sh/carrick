//! Path-resolution errno synthesis: ENAMETOOLONG (component > NAME_MAX / path
//! > PATH_MAX) and ENOTDIR (a non-directory used as an intermediate path
//! component). carrick lacked both — a too-long path wrongly SUCCEEDED, and
//! traversing through a regular file returned ENOENT. Stands in for the
//! ENAMETOOLONG/ENOTDIR subtests across LTP lstat02/stat03/truncate03/open13/
//! mkdir02/readlink03/chdir04/statfs03/… (the shared resolver gap).
//!
//! (ELOOP — too many symlink hops — is a separate resolver change and is not
//! asserted here yet.)
//!
//! Invariants:
//!   1. stat() of a path with a > 255-byte component → -1/ENAMETOOLONG.
//!   2. stat() of "/etc/hostname/foo" (intermediate is a regular file) →
//!      -1/ENOTDIR.
//!   3. mkdir() with a too-long final component → -1/ENAMETOOLONG.
//!   4. a normal stat still succeeds (no false positive).

use conformance_probes::{errno, report};

unsafe fn stat_path(p: &[u8]) -> i64 {
    let mut st: libc::stat = core::mem::zeroed();
    libc::syscall(libc::SYS_newfstatat, libc::AT_FDCWD, p.as_ptr(), &mut st, 0)
}

fn main() {
    unsafe {
        // (1) ENAMETOOLONG: a 300-char component.
        let mut long = Vec::new();
        long.push(b'/');
        long.extend(std::iter::repeat(b'a').take(300));
        long.push(0);
        let rc = stat_path(&long);
        let er = if rc < 0 { errno() } else { 0 };
        report!(
            toolong_rc_neg_one = rc == -1,
            toolong_errno_enametoolong = er == libc::ENAMETOOLONG,
        );

        // (2) ENOTDIR: traverse through a regular file. /etc/hostname is a file
        //     on the ubuntu image used by the harness.
        let rc = stat_path(b"/etc/hostname/foo\0");
        let er = if rc < 0 { errno() } else { 0 };
        report!(
            notdir_rc_neg_one = rc == -1,
            notdir_errno_enotdir = er == libc::ENOTDIR,
        );

        // (3) mkdir with a too-long final component → ENAMETOOLONG.
        let mut md = Vec::new();
        md.extend_from_slice(b"/tmp/");
        md.extend(std::iter::repeat(b'b').take(300));
        md.push(0);
        let rc = libc::syscall(libc::SYS_mkdirat, libc::AT_FDCWD, md.as_ptr(), 0o755);
        let er = if rc < 0 { errno() } else { 0 };
        report!(
            mkdir_toolong_rc_neg_one = rc == -1,
            mkdir_toolong_errno = er == libc::ENAMETOOLONG,
        );

        // (4) a valid path still stats fine (no false positive).
        let ok = stat_path(b"/etc/hostname\0");
        report!(valid_stat_ok = ok == 0);
    }
}
