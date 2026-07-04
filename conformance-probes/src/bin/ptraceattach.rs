//! `PTRACE_ATTACH` denial errno.
//!
//! LTP `ptrace02` expects Linux to reject `PTRACE_ATTACH` with `EPERM`, not
//! report the ptrace request as absent.

use conformance_probes::{errno, report};

unsafe fn wait_child(pid: i32) -> i32 {
    let mut status = 0;
    loop {
        let rc = libc::waitpid(pid, &mut status, 0);
        if rc == pid {
            return libc::WEXITSTATUS(status);
        }
        if rc == -1 && errno() == libc::EINTR {
            continue;
        }
        return 99;
    }
}

fn main() {
    unsafe {
        let parent = libc::getpid();
        let dumpable_rc = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        let pid = libc::fork();
        if pid == 0 {
            let rc = libc::ptrace(
                libc::PTRACE_ATTACH,
                parent,
                core::ptr::null_mut::<libc::c_void>(),
                0,
            );
            libc::_exit((rc == -1 && errno() == libc::EPERM) as i32 ^ 1);
        }
        let child_status = if pid > 0 { wait_child(pid) } else { 99 };
        report!(attach_nondumpable_eperm = dumpable_rc == 0 && child_status == 0);
    }
}
