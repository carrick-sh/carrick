//! fexecve(fd, argv, env) executes an already-open file descriptor. glibc/musl
//! implement it via execveat(fd, "", argv, env, AT_EMPTY_PATH). CPython's
//! os.execve(fd, ...) / test_posix.test_fexecve relies on it. carrick had no
//! execveat handler at all → ENOSYS ("Function not implemented").
//!
//!  * fexecve_runs: fexecve of an open fd on this probe re-enters a marker
//!    child mode and exits 0.
//!  * fexecve_rootfs_binary_after_chdir: open an ordinary IMAGE-LAYER binary
//!    (`/bin/sh`), then fexecve it from a child whose cwd is NOT `/`. fexecve
//!    names an INODE, so the caller's cwd is irrelevant on Linux. carrick
//!    instead recovers the fd's open path and re-resolves it, and the
//!    immutable-lower open lane recorded that path in its rootfs-RELATIVE form
//!    — so the exec silently became `cwd + path` and ENOENTed everywhere except
//!    cwd `/`. That is exactly CPython test_posix.test_fexecve, which chdirs to
//!    the executable's directory before exec'ing. `/proc/self/exe` does NOT
//!    cover this: /proc paths are excluded from that lane and keep an absolute
//!    recorded path, so the first assertion passed throughout.

use conformance_probes::report;

/// fork a child that optionally `chdir`s, then fexecve's `fd` with `argv`.
/// True iff the child exited 0.
fn fexecve_child_exits_zero(
    fd: i32,
    chdir_to: Option<&std::ffi::CStr>,
    argv: &[*const libc::c_char],
) -> bool {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            if let Some(dir) = chdir_to {
                if libc::chdir(dir.as_ptr()) != 0 {
                    libc::_exit(98);
                }
            }
            let envp = [std::ptr::null::<libc::c_char>()];
            libc::fexecve(fd, argv.as_ptr(), envp.as_ptr());
            // Only reached if fexecve failed.
            libc::_exit(99);
        }
        let mut status = 0i32;
        libc::waitpid(pid, &mut status, 0);
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--fexec-child") {
        return;
    }

    unsafe {
        let self_path = c"/proc/self/exe";
        let self_fd = libc::open(self_path.as_ptr(), libc::O_RDONLY);
        if self_fd < 0 {
            report!(fexecve_runs = false);
        } else {
            let argv = [
                self_path.as_ptr(),
                b"--fexec-child\0".as_ptr() as *const libc::c_char,
                std::ptr::null(),
            ];
            report!(fexecve_runs = fexecve_child_exits_zero(self_fd, None, &argv));
            libc::close(self_fd);
        }

        let sh = c"/bin/sh";
        let sh_fd = libc::open(sh.as_ptr(), libc::O_RDONLY);
        if sh_fd < 0 {
            report!(fexecve_rootfs_binary_after_chdir = false);
            return;
        }
        let argv = [
            sh.as_ptr(),
            b"-c\0".as_ptr() as *const libc::c_char,
            b"exit 0\0".as_ptr() as *const libc::c_char,
            std::ptr::null(),
        ];
        report!(
            fexecve_rootfs_binary_after_chdir =
                fexecve_child_exits_zero(sh_fd, Some(c"/tmp"), &argv)
        );
        libc::close(sh_fd);
    }
}
