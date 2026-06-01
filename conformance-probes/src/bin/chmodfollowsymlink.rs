//! chmod(2) (and fchmodat without AT_SYMLINK_NOFOLLOW) FOLLOWS a final symlink:
//! it changes the TARGET's mode, not the link's. CPython
//! test_posix.test_chmod_dir_symlink relies on this (chmod a symlink-to-dir →
//! the dir's mode changes). carrick's chmod_at stopped at the link (resolve_at_path
//! doesn't follow the final component), so the target was never chmod'd.
//!
//!  * chmod_followed_symlink: chmod(link→dir, 0o500); stat(dir).mode & 0o777 == 0o500.

use conformance_probes::report;

fn main() {
    unsafe {
        let tgt = b"/tmp/cr_chmtgt\0".as_ptr() as *const libc::c_char;
        let link = b"/tmp/cr_chmlink\0".as_ptr() as *const libc::c_char;
        libc::rmdir(tgt);
        libc::unlink(link);
        libc::mkdir(tgt, 0o755);
        libc::symlink(tgt, link);

        let rc = libc::chmod(link, 0o500);

        let mut st: libc::stat = std::mem::zeroed();
        libc::stat(tgt, &mut st);
        let target_mode = st.st_mode & 0o777;

        report!(chmod_followed_symlink = (rc == 0 && target_mode == 0o500));

        libc::chmod(tgt, 0o755);
        libc::unlink(link);
        libc::rmdir(tgt);
    }
}
