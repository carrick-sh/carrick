//! Prove that an ordinary guest `_exit(127)` remains a normal wait status.
//!
//! This is the control for fatal post-exec failures, which Carrick must expose
//! as WIFSIGNALED/SIGSEGV rather than collapsing into the same numeric 127.

use conformance_probes::report;

fn main() {
    unsafe {
        let child = libc::fork();
        if child == 0 {
            libc::_exit(127);
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
