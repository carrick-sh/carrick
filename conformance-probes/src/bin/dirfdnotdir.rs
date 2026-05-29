//! *at dirfd validation (LTP statx03): a relative path resolved against a
//! dirfd that is a VALID but non-directory fd (e.g. stdout fd 1) → ENOTDIR;
//! a genuinely-invalid dirfd → EBADF. carrick returned EBADF for a valid
//! stdio dirfd because stdio fds aren't in its open-file table. Exercised via
//! fstatat (same resolve_at_path path the fix touches). Deterministic,
//! line-exact carrick-vs-Linux.

use conformance_probes::errno;

fn main() {
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        let rel = b"some_rel_name\0".as_ptr() as *const libc::c_char;

        // fd 1 (stdout) is a valid non-directory fd → ENOTDIR.
        let r1 = libc::fstatat(1, rel, &mut st, 0);
        println!(
            "fstatat_nondir_dirfd_enotdir={}",
            r1 == -1 && errno() == libc::ENOTDIR
        );

        // a genuinely-invalid fd → EBADF.
        let r2 = libc::fstatat(-1, rel, &mut st, 0);
        println!("fstatat_badfd_ebadf={}", r2 == -1 && errno() == libc::EBADF);

        let _ = errno;
    }
}
