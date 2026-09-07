//! Invariant: a failed child execve must not leak file descriptors, and
//! both /proc/self/fd and /proc/<pid>/fd must be valid directories whose
//! listings match before and after the failed child execution.
//!
//! Invariants encoded:
//!   * fd_listing_equal=1
//!   * count=3 (stdin, stdout, stderr)

use conformance_probes::report;

unsafe fn list_fds(path: *const libc::c_char) -> Option<Vec<i32>> {
    let dir = libc::opendir(path);
    if dir.is_null() {
        return None;
    }
    let dir_fd = libc::dirfd(dir);
    let mut fds = Vec::new();
    loop {
        let entry = libc::readdir(dir);
        if entry.is_null() {
            break;
        }
        let name = std::ffi::CStr::from_ptr((*entry).d_name.as_ptr());
        if let Ok(s) = name.to_str() {
            if let Ok(fd) = s.parse::<i32>() {
                if fd != dir_fd {
                    fds.push(fd);
                }
            }
        }
    }
    libc::closedir(dir);
    fds.sort();
    Some(fds)
}

fn main() {
    unsafe {
        let pid = libc::getpid();
        let pid_fd_path = std::ffi::CString::new(format!("/proc/{pid}/fd")).unwrap();
        let self_fd_path = std::ffi::CStr::from_bytes_with_nul_unchecked(b"/proc/self/fd\0");

        let before_pid = list_fds(pid_fd_path.as_ptr());
        let before_self = list_fds(self_fd_path.as_ptr());

        let child = libc::fork();
        if child == 0 {
            let path = b"/nonexistent_exec_path_for_probe\0".as_ptr().cast();
            let argv = [path, core::ptr::null()];
            let envp = [core::ptr::null()];
            libc::execve(path, argv.as_ptr(), envp.as_ptr());
            libc::_exit(127);
        }
        let mut status = 0;
        libc::waitpid(child, &mut status, 0);

        let after_pid = list_fds(pid_fd_path.as_ptr());
        let after_self = list_fds(self_fd_path.as_ptr());

        let ok = before_pid.is_some()
            && after_pid.is_some()
            && before_self.is_some()
            && after_self.is_some()
            && before_pid == after_pid
            && before_self == after_self
            && before_pid == before_self;

        let fd_listing_equal = if ok { 1 } else { 0 };
        let count = after_self.as_ref().map(|v| v.len()).unwrap_or(0);

        report!(fd_listing_equal = fd_listing_equal, count = count);
    }
}
