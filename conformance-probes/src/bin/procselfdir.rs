//! `/proc/self` must resolve as a directory the guest can open/stat/scandir —
//! not just as a prefix for sub-path file reads. Tools do `ls /proc/self`,
//! `os.listdir('/proc/self')`, `stat /proc/self`, and `for fd in
//! /proc/self/fd/*`; carrick resolved /proc/self/<file> reads but returned
//! ENOENT for the bare /proc/self directory (proc_pid_dir_host_pid only
//! accepted a numeric pid).
//!
//!  * self_opendir:    open("/proc/self", O_DIRECTORY) succeeds.
//!  * self_accessible: access("/proc/self", F_OK) succeeds.
//!  * self_subpath:    open("/proc/self/status", O_RDONLY) succeeds (sanity).

use conformance_probes::report;

fn main() {
    unsafe {
        let dirfd = libc::open(
            b"/proc/self\0".as_ptr() as *const libc::c_char,
            libc::O_DIRECTORY | libc::O_RDONLY,
        );
        let self_opendir = dirfd >= 0;
        if dirfd >= 0 {
            libc::close(dirfd);
        }
        let self_accessible =
            libc::access(b"/proc/self\0".as_ptr() as *const libc::c_char, libc::F_OK) == 0;
        let sub = libc::open(
            b"/proc/self/status\0".as_ptr() as *const libc::c_char,
            libc::O_RDONLY,
        );
        let self_subpath = sub >= 0;
        if sub >= 0 {
            libc::close(sub);
        }
        report!(
            self_opendir = self_opendir,
            self_accessible = self_accessible,
            self_subpath = self_subpath
        );
    }
}
