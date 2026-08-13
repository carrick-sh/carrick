//! Directory-rename coherence for carrick's kernel directory cache.
//!
//! carrick resolves a guest path by holding an open host dirfd per directory
//! and issuing ONE `*at` call against it, instead of re-resolving every
//! component on every call. A dirfd names an INODE, not a path, so renaming
//! the directory makes a cached entry silently follow it — and identity
//! revalidation cannot notice, because the inode, ctime and size are all
//! unchanged at the new location.
//!
//! The sharp case is rename-then-recreate: move `d` to `moved`, then make a
//! FRESH EMPTY `d`. A stale cache would resolve `d` to the moved inode and
//! report the old child as still present, which no correct kernel does. The
//! earlier assertions are the ordinary shape of the same bug.
//!
//! Every observation is a boolean about presence or errno, so the output is
//! line-exact on any machine.

use conformance_probes::{errno, report};

unsafe fn stat_ok(p: &[u8]) -> bool {
    let mut st: libc::stat = core::mem::zeroed();
    libc::syscall(libc::SYS_newfstatat, libc::AT_FDCWD, p.as_ptr(), &mut st, 0) == 0
}

unsafe fn stat_enoent(p: &[u8]) -> bool {
    let mut st: libc::stat = core::mem::zeroed();
    let rc = libc::syscall(libc::SYS_newfstatat, libc::AT_FDCWD, p.as_ptr(), &mut st, 0);
    rc == -1 && errno() == libc::ENOENT
}

unsafe fn read_byte(p: &[u8]) -> Option<u8> {
    let fd = libc::open(p.as_ptr() as *const libc::c_char, libc::O_RDONLY);
    if fd < 0 {
        return None;
    }
    let mut buf = [0u8; 1];
    let n = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 1);
    libc::close(fd);
    if n == 1 { Some(buf[0]) } else { None }
}

fn main() {
    unsafe {
        // Fresh tree, independent of whatever a previous probe left behind.
        libc::unlink(b"/tmp/drc_d/leaf\0".as_ptr() as *const libc::c_char);
        libc::unlink(b"/tmp/drc_moved/leaf\0".as_ptr() as *const libc::c_char);
        libc::rmdir(b"/tmp/drc_d\0".as_ptr() as *const libc::c_char);
        libc::rmdir(b"/tmp/drc_moved\0".as_ptr() as *const libc::c_char);
        let made = libc::mkdir(b"/tmp/drc_d\0".as_ptr() as *const libc::c_char, 0o755) == 0;

        let fd = libc::open(
            b"/tmp/drc_d/leaf\0".as_ptr() as *const libc::c_char,
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
            0o644,
        );
        let seeded = fd >= 0 && {
            let wrote = libc::write(fd, b"A".as_ptr() as *const libc::c_void, 1) == 1;
            libc::close(fd);
            wrote
        };

        // WARM the resolution of `/tmp/drc_d` before the rename. Without this
        // the probe would pass trivially on an implementation that never
        // cached anything.
        let warm_before_rename = stat_ok(b"/tmp/drc_d/leaf\0");

        let renamed = libc::rename(
            b"/tmp/drc_d\0".as_ptr() as *const libc::c_char,
            b"/tmp/drc_moved\0".as_ptr() as *const libc::c_char,
        ) == 0;

        // The ordinary shape: the old path is gone, the new one works, and the
        // bytes moved with the inode.
        let old_path_gone = stat_enoent(b"/tmp/drc_d/leaf\0");
        let new_path_present = stat_ok(b"/tmp/drc_moved/leaf\0");
        let content_followed = read_byte(b"/tmp/drc_moved/leaf\0") == Some(b'A');
        let old_open_enoent = {
            let fd = libc::open(b"/tmp/drc_d/leaf\0".as_ptr() as *const libc::c_char, 0);
            let bad = fd < 0 && errno() == libc::ENOENT;
            if fd >= 0 {
                libc::close(fd);
            }
            bad
        };

        // The sharp case: a FRESH EMPTY directory at the old name. A stale
        // dirfd would resolve `drc_d` to the moved inode and report `leaf`.
        let recreated = libc::mkdir(b"/tmp/drc_d\0".as_ptr() as *const libc::c_char, 0o755) == 0;
        let recreated_dir_is_empty = stat_enoent(b"/tmp/drc_d/leaf\0");
        let recreated_dir_itself_exists = stat_ok(b"/tmp/drc_d\0");

        report!(
            made_dir = made,
            seeded_leaf = seeded,
            warm_before_rename = warm_before_rename,
            renamed = renamed,
            old_path_gone = old_path_gone,
            new_path_present = new_path_present,
            content_followed = content_followed,
            old_open_enoent = old_open_enoent,
            recreated = recreated,
            recreated_dir_is_empty = recreated_dir_is_empty,
            recreated_dir_itself_exists = recreated_dir_itself_exists
        );
    }
}
