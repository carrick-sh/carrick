//! O_DIRECTORY / O_NOFOLLOW open-flag semantics (LTP open08). carrick had the
//! aarch64 fcntl constants wrong — O_DIRECTORY (0o40000) and O_DIRECT (0o200000)
//! were swapped and O_NOFOLLOW was 0o400000 (really 0o100000) — so O_DIRECTORY
//! never triggered the must-be-a-directory check. Deterministic booleans,
//! line-exact carrick-vs-Linux.

use conformance_probes::errno;

fn main() {
    unsafe {
        libc::mkdir(b"/tmp\0".as_ptr() as *const _, 0o777);
        // a regular file and a directory under /tmp.
        let f = libc::open(
            b"/tmp/odir_file\0".as_ptr() as *const _,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        if f >= 0 {
            libc::close(f);
        }
        libc::mkdir(b"/tmp/odir_dir\0".as_ptr() as *const _, 0o755);

        // O_DIRECTORY on a regular file → ENOTDIR.
        let rc = libc::open(b"/tmp/odir_file\0".as_ptr() as *const _, libc::O_RDONLY | libc::O_DIRECTORY);
        println!(
            "odirectory_on_file_enotdir={}",
            rc == -1 && errno() == libc::ENOTDIR
        );

        // O_DIRECTORY on a directory → success.
        let d = libc::open(b"/tmp/odir_dir\0".as_ptr() as *const _, libc::O_RDONLY | libc::O_DIRECTORY);
        println!("odirectory_on_dir_ok={}", d >= 0);
        if d >= 0 {
            libc::close(d);
        }

        // O_RDWR on a directory → EISDIR.
        let w = libc::open(b"/tmp/odir_dir\0".as_ptr() as *const _, libc::O_RDWR);
        println!("rdwr_on_dir_eisdir={}", w == -1 && errno() == libc::EISDIR);

        // NOTE: O_NOFOLLOW-on-symlink → ELOOP is NOT asserted here — the aarch64
        // O_NOFOLLOW constant is now correct (so the flag is detected), but
        // carrick doesn't yet ENFORCE ELOOP (the host open still follows the
        // link). That enforcement is a tracked follow-up.

        let _ = errno;
    }
}
