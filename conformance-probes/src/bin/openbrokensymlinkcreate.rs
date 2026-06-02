//! `open(broken_symlink, O_CREAT|O_WRONLY)` must FOLLOW the dangling link and
//! CREATE its target — not return ENOENT. Linux open(2): a trailing symlink is
//! followed; O_CREAT (without O_EXCL) creates the missing target, and the link
//! then resolves to it. carrick's broken-symlink-follow fix (a plain open of a
//! dangling link is ENOENT, for fwalk) over-applied to the O_CREAT case, so
//! zipfile/tarfile extraction that overwrites a broken symlink as a file failed
//! with FileNotFoundError (CPython test_zipfile
//! test_overwrite_broken_file_symlink_as_file).
//!
//! INVARIANT: a dangling symlink opened O_CREAT|O_WRONLY succeeds, writes, and
//! materialises the target file (the link stays, now non-broken).

use conformance_probes::report;

fn main() {
    unsafe {
        let dir = c"/tmp/obsl";
        libc::mkdir(dir.as_ptr(), 0o755);
        let link = c"/tmp/obsl/link";
        let target = c"/tmp/obsl/target";
        libc::unlink(link.as_ptr());
        libc::unlink(target.as_ptr());

        // A broken symlink: link -> target, target does not exist.
        let symlink_ok = libc::symlink(c"target".as_ptr(), link.as_ptr()) == 0;

        // open the dangling link O_CREAT|O_WRONLY|O_TRUNC — follows + creates target.
        let fd = libc::open(
            link.as_ptr(),
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
            0o644,
        );
        let opened = fd >= 0;
        let mut wrote = false;
        let mut target_created = false;
        let mut link_still_link = false;
        if opened {
            wrote = libc::write(fd, c"hi".as_ptr().cast(), 2) == 2;
            libc::close(fd);
            // The link's TARGET now exists (the link was followed + created it)...
            let mut st: libc::stat = core::mem::zeroed();
            target_created = libc::stat(target.as_ptr(), &mut st) == 0;
            // ...and the link itself is still a symlink (we created the target,
            // did not replace the link with a regular file).
            let mut lst: libc::stat = core::mem::zeroed();
            link_still_link = libc::lstat(link.as_ptr(), &mut lst) == 0
                && (lst.st_mode & libc::S_IFMT) == libc::S_IFLNK;
        }

        report!(
            symlink_created = symlink_ok,
            open_create_through_broken_symlink = opened,
            wrote_through_link = wrote,
            target_materialised = target_created,
            link_unchanged = link_still_link,
        );
    }
}
