//! lchown(2) records the SYMLINK's own owner (not its target's). carrick stores
//! guest owners in xattrs (not root on macOS); for a symlink the xattr must live
//! on the LINK (macOS path-based setxattr/getxattr with XATTR_NOFOLLOW, since
//! cap-std can't open a symlink). It previously followed the link → lstat showed
//! 0 (CPython test_posix.test_lchown: 0 != 2147483648). Uses CWD-relative paths
//! so they route to the rootfs backend, like the test's TESTFN.
//!
//!  * link_owner_set:   lchown(link, U, G); lstat(link).{uid,gid} == {U,G}.
//!  * target_untouched: stat(target).uid stays 0.
use conformance_probes::report;
fn main() {
    unsafe {
        let tgt = b"cr_lco_t\0".as_ptr() as *const libc::c_char;
        let link = b"cr_lco_l\0".as_ptr() as *const libc::c_char;
        libc::unlink(tgt); libc::unlink(link);
        libc::close(libc::open(tgt, libc::O_CREAT | libc::O_WRONLY, 0o644));
        libc::symlink(tgt, link);
        let rc = libc::lchown(link, 4242, 4243);
        let mut ls: libc::stat = std::mem::zeroed();
        libc::lstat(link, &mut ls);
        let mut ts: libc::stat = std::mem::zeroed();
        libc::stat(tgt, &mut ts);
        report!(
            link_owner_set = (rc == 0 && ls.st_uid == 4242 && ls.st_gid == 4243),
            target_untouched = (ts.st_uid == 0)
        );
        libc::unlink(link); libc::unlink(tgt);
    }
}
