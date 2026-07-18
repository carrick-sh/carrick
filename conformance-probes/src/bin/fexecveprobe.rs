//! fexecve(fd, argv, env) executes an already-open file descriptor. glibc/musl
//! implement it via execveat(fd, "", argv, env, AT_EMPTY_PATH). CPython's
//! os.execve(fd, ...) / test_posix.test_fexecve relies on it. carrick had no
//! execveat handler at all → ENOSYS ("Function not implemented").
//!
//!  * fexecve_runs: fexecve of an open fd on this probe re-enters a marker
//!    child mode and exits 0.

use conformance_probes::report;

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--fexec-child") {
        return;
    }

    unsafe {
        let path = std::ffi::CString::new(std::env::args().next().unwrap_or_default()).unwrap();
        let fd = libc::open(path.as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            report!(fexecve_runs = false);
            return;
        }
        let pid = libc::fork();
        if pid == 0 {
            let argv = [
                path.as_ptr(),
                b"--fexec-child\0".as_ptr() as *const libc::c_char,
                std::ptr::null(),
            ];
            let envp = [std::ptr::null::<libc::c_char>()];
            libc::fexecve(fd, argv.as_ptr(), envp.as_ptr());
            // Only reached if fexecve failed.
            libc::_exit(99);
        }
        let mut status = 0i32;
        libc::waitpid(pid, &mut status, 0);
        let ran = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        report!(fexecve_runs = ran);
        libc::close(fd);
    }
}
