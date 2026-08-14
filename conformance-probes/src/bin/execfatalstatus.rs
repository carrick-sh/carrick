//! Observe the terminal shape of a child whose successful `execve` is forced
//! to fail inside Carrick after sibling teardown.
//!
//! Without runtime failure injection this is an ordinary fork/exec/wait probe
//! and matches Docker line-for-line. For the HVPatch failure receipt, set
//! `CARRICK_HVPATCH_EXEC_INVENTORY_FAILURE=<point>@/bin/true`; the child must be
//! reported as killed by SIGSEGV, never as a normal exit 127. The target suffix
//! lets the outer shell start this probe normally before injection fires.

use conformance_probes::report;

fn main() {
    unsafe {
        let child = libc::fork();
        if child == 0 {
            let path = c"/bin/true";
            let argv = [path.as_ptr(), std::ptr::null()];
            let envp = [std::ptr::null()];
            libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(126);
        }
        if child < 0 {
            report!(fork_ok = false);
            return;
        }

        let mut status = 0;
        let reaped = libc::waitpid(child, &mut status, 0) == child;
        report!(
            reaped = reaped,
            child_exited = libc::WIFEXITED(status),
            child_exit_status = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                -1
            },
            child_signaled = libc::WIFSIGNALED(status),
            child_signal = if libc::WIFSIGNALED(status) {
                libc::WTERMSIG(status)
            } else {
                0
            },
        );
    }
}
