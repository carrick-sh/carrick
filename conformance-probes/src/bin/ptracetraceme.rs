//! Minimal `ptrace(PTRACE_TRACEME)` stop/continue ownership.
//!
//! Stands in for the first failure mode in LTP `ptrace05` / `ptrace06`.
//!
//! Invariants encoded:
//!   * A child can request tracing with `PTRACE_TRACEME`.
//!   * The parent observes the child's signal stop through `waitpid(WUNTRACED)`.
//!   * `PTRACE_CONT` resumes the stopped child, which can then exit normally.
//!
//! Deterministic output only: booleans and stable signal/exit-status values.

use conformance_probes::{errno, report};

const WAIT_ITERS: usize = 200;

unsafe fn ptrace_traceme() -> bool {
    libc::ptrace(
        libc::PTRACE_TRACEME,
        0,
        core::ptr::null_mut::<libc::c_void>(),
        0,
    ) == 0
}

unsafe fn ptrace_cont(pid: i32) -> bool {
    libc::ptrace(
        libc::PTRACE_CONT,
        pid,
        core::ptr::null_mut::<libc::c_void>(),
        0,
    ) == 0
}

unsafe fn wait_changed(pid: i32, options: i32) -> (i32, i32) {
    let mut status = 0;
    for _ in 0..WAIT_ITERS {
        let rc = libc::waitpid(pid, &mut status, options | libc::WNOHANG);
        if rc != 0 {
            return (rc, status);
        }
        libc::usleep(10_000);
    }
    (0, 0)
}

fn main() {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            if !ptrace_traceme() {
                libc::_exit(70);
            }
            libc::raise(libc::SIGSTOP);
            libc::_exit(42);
        }
        if pid < 0 {
            report!(fork_ok = false);
            return;
        }

        let (stop_rc, stop_status) = wait_changed(pid, libc::WUNTRACED);
        let stopped = stop_rc == pid && libc::WIFSTOPPED(stop_status);
        let stop_sig = if stopped {
            libc::WSTOPSIG(stop_status)
        } else {
            0
        };
        let exited_before_stop = stop_rc == pid && libc::WIFEXITED(stop_status);
        let early_exit_status = if exited_before_stop {
            libc::WEXITSTATUS(stop_status)
        } else {
            0
        };

        let cont_ok = stopped && ptrace_cont(pid);
        let cont_errno = if stopped && !cont_ok { errno() } else { 0 };

        let (final_rc, final_status) = if cont_ok {
            wait_changed(pid, 0)
        } else {
            libc::kill(pid, libc::SIGKILL);
            wait_changed(pid, 0)
        };

        report!(
            fork_ok = true,
            traceme_stop_reaped = stop_rc == pid,
            traceme_stopped = stopped,
            traceme_stopsig = stop_sig,
            traceme_stopsig_is_sigstop = stop_sig == libc::SIGSTOP,
            traceme_exited_before_stop = exited_before_stop,
            traceme_early_exit_status = early_exit_status,
            ptrace_cont_ok = cont_ok,
            ptrace_cont_errno = cont_errno,
            ptrace_cont_errno_zero = cont_errno == 0,
            final_reaped = final_rc == pid,
            final_exited = libc::WIFEXITED(final_status),
            final_exit_status_is_42 = libc::WIFEXITED(final_status)
                && libc::WEXITSTATUS(final_status) == 42,
        );
    }
}
