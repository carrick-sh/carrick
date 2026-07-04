//! Reducer for LTP ioctl_loop setup: the Docker oracle exposes loop-device
//! support through /proc/config.gz.

use std::ffi::CString;

use conformance_probes::report;

fn main() {
    let shell = CString::new("/bin/sh").unwrap();
    let arg0 = CString::new("sh").unwrap();
    let arg1 = CString::new("-c").unwrap();
    let script =
        CString::new("gzip -dc /proc/config.gz 2>/dev/null | grep -qx CONFIG_BLK_DEV_LOOP=y")
            .unwrap();

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        report!(fork_ok = false);
        return;
    }
    if pid == 0 {
        unsafe {
            libc::execl(
                shell.as_ptr(),
                arg0.as_ptr(),
                arg1.as_ptr(),
                script.as_ptr(),
                core::ptr::null::<libc::c_char>(),
            );
            libc::_exit(127);
        }
    }

    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    let exited = waited == pid && libc::WIFEXITED(status);
    let code = if exited { libc::WEXITSTATUS(status) } else { -1 };
    report!(
        fork_ok = true,
        proc_config_loop_enabled = exited && code == 0,
    );
}
