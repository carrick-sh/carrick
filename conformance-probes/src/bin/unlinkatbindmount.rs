//! `unlinkat(AT_FDCWD, "/dev/shm/<f>", 0)` must remove a file created via the
//! same bind-mounted path. carrick mounts `/dev/shm` as a host-backed BindVfs
//! (commit 01571cb), but until 063ccf4 the unlink/unlinkat dispatcher went
//! straight to `rootfs_vfs` and bypassed `vfs_mounts.resolve` — so a file
//! created through the bind mount could never be removed through the same
//! guest path. LTP's `tst_test setup_ipc` creates `/dev/shm/ltp_<…>` with
//! `O_CREAT|O_EXCL` and `SAFE_UNLINK`s the name immediately (the mapping
//! survives); a busted unlink path TBROKs the entire `tst_checkpoint`-using
//! signals suite.
//!
//! Invariants encoded:
//!   1. `mkdir(/dev/shm)` already exists (carrick BindVfs / Linux tmpfs).
//!   2. `open(/dev/shm/probe_unlink, O_CREAT|O_EXCL|O_RDWR, 0600)` succeeds.
//!   3. `access(F_OK)` on the new path returns 0.
//!   4. `unlinkat(AT_FDCWD, path, 0)` returns 0.
//!   5. `access(F_OK)` afterwards returns -1 with errno=ENOENT.
//!   6. As a stronger guard, repeat the same sequence with `unlink` (the
//!      libc wrapper, which on glibc-aarch64 calls SYS_unlinkat with flag=0).
//!      Both spellings must route through the BindVfs.
//!
//! Deterministic output: one bool per invariant, plus the post-unlink errno.

use conformance_probes::{errno, report};

const AT_FDCWD: libc::c_int = -100;

unsafe fn sys_unlinkat(dirfd: libc::c_int, path: *const libc::c_char, flags: libc::c_int) -> i64 {
    libc::syscall(libc::SYS_unlinkat, dirfd, path, flags)
}

fn main() {
    unsafe {
        // /dev/shm should already exist on both Linux (tmpfs) and carrick
        // (BindVfs). EEXIST is a clean PASS for "exists".
        let mk = libc::mkdir(b"/dev/shm\0".as_ptr() as *const libc::c_char, 0o1777);
        let mk_errno = if mk == 0 { 0 } else { errno() };
        let shm_exists = mk == 0 || mk_errno == libc::EEXIST;
        report!(shm_dir_exists = shm_exists);

        // --- Path 1: unlinkat(AT_FDCWD, …) -----------------------------------
        let path1 = b"/dev/shm/carrick_probe_unlinkat\0";
        // Best-effort pre-clean in case a previous run left it behind.
        let _ = sys_unlinkat(AT_FDCWD, path1.as_ptr() as *const libc::c_char, 0);

        let fd = libc::open(
            path1.as_ptr() as *const libc::c_char,
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
            0o600,
        );
        let open_ok = fd >= 0;
        report!(unlinkat_open_ok = open_ok);
        if !open_ok {
            // Print stable false lines so the diff stays line-aligned.
            report!(
                unlinkat_pre_exists = false,
                unlinkat_returned_zero = false,
                unlinkat_post_exists = true,
                unlinkat_post_errno_enoent = false,
                unlink_open_ok = false,
                unlink_returned_zero = false,
                unlink_post_errno_enoent = false,
            );
            return;
        }
        libc::close(fd);

        let pre_access = libc::access(path1.as_ptr() as *const libc::c_char, libc::F_OK);
        report!(unlinkat_pre_exists = pre_access == 0);

        let rc = sys_unlinkat(AT_FDCWD, path1.as_ptr() as *const libc::c_char, 0);
        report!(unlinkat_returned_zero = rc == 0);

        let post_access = libc::access(path1.as_ptr() as *const libc::c_char, libc::F_OK);
        let post_errno = if post_access < 0 { errno() } else { 0 };
        report!(
            unlinkat_post_exists = post_access == 0,
            unlinkat_post_errno_enoent = post_errno == libc::ENOENT,
        );

        // --- Path 2: libc::unlink (glibc -> SYS_unlinkat flag=0) -------------
        let path2 = b"/dev/shm/carrick_probe_unlink\0";
        let _ = libc::unlink(path2.as_ptr() as *const libc::c_char);
        let fd2 = libc::open(
            path2.as_ptr() as *const libc::c_char,
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
            0o600,
        );
        let open2_ok = fd2 >= 0;
        report!(unlink_open_ok = open2_ok);
        if !open2_ok {
            report!(
                unlink_returned_zero = false,
                unlink_post_errno_enoent = false,
            );
            return;
        }
        libc::close(fd2);
        let rc2 = libc::unlink(path2.as_ptr() as *const libc::c_char);
        report!(unlink_returned_zero = rc2 == 0);
        let post2 = libc::access(path2.as_ptr() as *const libc::c_char, libc::F_OK);
        let post2_errno = if post2 < 0 { errno() } else { 0 };
        report!(unlink_post_errno_enoent = post2_errno == libc::ENOENT);
    }
}
