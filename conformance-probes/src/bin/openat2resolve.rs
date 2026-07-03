//! openat2(2) RESOLVE_* path-walk restrictions.
//!
//! `openat2valid` owns open_how size/flag validation. This probe owns the
//! path-resolution bits: unflagged opens still succeed, while NO_SYMLINKS,
//! BENEATH, NO_XDEV, NO_MAGICLINKS, and IN_ROOT apply Linux's containment
//! failures at walk time.

use conformance_probes::errno;
use std::ffi::CString;

const SYS_OPENAT2: libc::c_long = 437;
const AT_FDCWD: libc::c_long = -100;
const SIZEOF_HOW: usize = 24;

const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_IN_ROOT: u64 = 0x10;

fn openat2(dfd: libc::c_long, path: &str, flags: u64, mode: u64, resolve: u64) -> libc::c_long {
    let path = CString::new(path).unwrap();
    let how = [flags, mode, resolve];
    unsafe { libc::syscall(SYS_OPENAT2, dfd, path.as_ptr(), how.as_ptr(), SIZEOF_HOW) }
}

fn main() {
    unsafe {
        let root = "/tmp/openat2resolve";
        let root_dir = c(root);
        let nested = c("/tmp/openat2resolve/root/dir");
        let target = c("/tmp/openat2resolve/target");
        let outside = c("/tmp/openat2resolve/root/outside");
        let link = c("/tmp/openat2resolve/link");
        libc::mkdir(c("/tmp").as_ptr(), 0o777);
        libc::mkdir(root_dir.as_ptr(), 0o777);
        libc::mkdir(c("/tmp/openat2resolve/root").as_ptr(), 0o777);
        libc::mkdir(nested.as_ptr(), 0o777);

        seed_file(&target);
        seed_file(&outside);
        libc::unlink(link.as_ptr());
        libc::symlink(c("target").as_ptr(), link.as_ptr());

        let fd = openat2(
            AT_FDCWD,
            "/tmp/openat2resolve/link",
            libc::O_RDONLY as u64,
            0,
            0,
        );
        println!("plain_symlink_open_ok={}", fd >= 0);
        if fd >= 0 {
            libc::close(fd as i32);
        }

        let fd = openat2(
            AT_FDCWD,
            "/tmp/openat2resolve/link",
            libc::O_RDONLY as u64,
            0,
            RESOLVE_NO_SYMLINKS,
        );
        println!(
            "no_symlinks_rejects_symlink_eloop={}",
            fd == -1 && errno() == libc::ELOOP
        );

        let dirfd = libc::open(nested.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
        let dirfd_open_ok = dirfd >= 0;
        println!("dirfd_open_ok={dirfd_open_ok}");

        let fd = openat2(
            dirfd as libc::c_long,
            "../outside",
            libc::O_RDONLY as u64,
            0,
            0,
        );
        println!("plain_dotdot_escape_ok={}", fd >= 0);
        if fd >= 0 {
            libc::close(fd as i32);
        }

        let fd = openat2(
            dirfd as libc::c_long,
            "../outside",
            libc::O_RDONLY as u64,
            0,
            RESOLVE_BENEATH,
        );
        println!(
            "beneath_rejects_dotdot_escape_exdev={}",
            fd == -1 && errno() == libc::EXDEV
        );
        if dirfd >= 0 {
            libc::close(dirfd);
        }

        let fd = openat2(
            AT_FDCWD,
            "/proc/self/status",
            libc::O_RDONLY as u64,
            0,
            RESOLVE_NO_XDEV,
        );
        println!(
            "no_xdev_rejects_proc_exdev={}",
            fd == -1 && errno() == libc::EXDEV
        );

        let target_fd = libc::open(target.as_ptr(), libc::O_RDONLY);
        let proc_fd_path = format!("/proc/self/fd/{target_fd}");
        let fd = openat2(
            AT_FDCWD,
            &proc_fd_path,
            libc::O_RDONLY as u64,
            0,
            RESOLVE_NO_MAGICLINKS,
        );
        println!(
            "no_magiclinks_rejects_proc_fd_eloop={}",
            fd == -1 && errno() == libc::ELOOP
        );
        if target_fd >= 0 {
            libc::close(target_fd);
        }

        let rootfd = libc::open(c("/tmp/openat2resolve/root").as_ptr(), libc::O_RDONLY);
        let fd = openat2(
            rootfd as libc::c_long,
            "/outside",
            libc::O_RDONLY as u64,
            0,
            RESOLVE_IN_ROOT,
        );
        println!("in_root_absolute_scoped_open_ok={}", fd >= 0);
        if fd >= 0 {
            libc::close(fd as i32);
        }
        if rootfd >= 0 {
            libc::close(rootfd);
        }
    }
}

fn seed_file(path: &CString) {
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC,
            0o644,
        )
    };
    if fd >= 0 {
        let byte = [b'x'];
        unsafe {
            libc::write(fd, byte.as_ptr() as *const libc::c_void, 1);
            libc::close(fd);
        }
    }
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}
