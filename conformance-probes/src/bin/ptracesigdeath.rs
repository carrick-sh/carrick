//! Ptrace signal-delivery and death ownership.
//!
//! Stands in for the next `ptrace05` failure set after `ptracetraceme`:
//!   * a traced child that sends itself `SIGKILL` dies by `SIGKILL`;
//!   * a traced child that sends itself an otherwise default-ignored signal
//!     still reports a ptrace signal-delivery stop.
//!
//! Deterministic output only: booleans and stable signal/status values.

use conformance_probes::{errno, report};

const WAIT_ITERS: usize = 200;

#[derive(Copy, Clone)]
struct WaitStatus {
    rc: i32,
    status: i32,
}

unsafe fn ptrace_traceme() -> bool {
    libc::ptrace(
        libc::PTRACE_TRACEME,
        0,
        core::ptr::null_mut::<libc::c_void>(),
        0,
    ) == 0
}

unsafe fn ptrace_cont(pid: i32, signal: i32) -> bool {
    libc::ptrace(
        libc::PTRACE_CONT,
        pid,
        core::ptr::null_mut::<libc::c_void>(),
        signal,
    ) == 0
}

unsafe fn wait_changed(pid: i32, options: i32) -> WaitStatus {
    let mut status = 0;
    for _ in 0..WAIT_ITERS {
        let rc = libc::waitpid(pid, &mut status, options | libc::WNOHANG);
        if rc != 0 {
            return WaitStatus { rc, status };
        }
        libc::usleep(10_000);
    }
    WaitStatus { rc: 0, status: 0 }
}

unsafe fn spawn_traced_self_signal(signal: i32, exit_code: i32) -> i32 {
    let pid = libc::fork();
    if pid == 0 {
        if !ptrace_traceme() {
            libc::_exit(70);
        }
        if libc::kill(libc::getpid(), signal) != 0 {
            libc::_exit(71);
        }
        libc::_exit(exit_code);
    }
    pid
}

unsafe fn cleanup_stopped_child(pid: i32, signal: i32) {
    let _ = ptrace_cont(pid, signal);
    let _ = wait_changed(pid, 0);
    let _ = libc::kill(pid, libc::SIGKILL);
    let _ = wait_changed(pid, 0);
}

fn main() {
    unsafe {
        let sigkill_pid = spawn_traced_self_signal(libc::SIGKILL, 72);
        if sigkill_pid < 0 {
            report!(sigkill_fork_ok = false);
            return;
        }
        let sigkill = wait_changed(sigkill_pid, 0);
        let sigkill_reaped = sigkill.rc == sigkill_pid;
        let sigkill_signaled = sigkill_reaped && libc::WIFSIGNALED(sigkill.status);
        let sigkill_stopped = sigkill_reaped && libc::WIFSTOPPED(sigkill.status);
        let sigkill_termsig = if sigkill_signaled {
            libc::WTERMSIG(sigkill.status)
        } else {
            0
        };
        let sigkill_stopsig = if sigkill_stopped {
            libc::WSTOPSIG(sigkill.status)
        } else {
            0
        };
        if sigkill_stopped {
            cleanup_stopped_child(sigkill_pid, libc::SIGKILL);
        }

        let sigchld_pid = spawn_traced_self_signal(libc::SIGCHLD, 73);
        if sigchld_pid < 0 {
            report!(sigkill_fork_ok = true, sigchld_fork_ok = false);
            return;
        }
        let sigchld = wait_changed(sigchld_pid, 0);
        let sigchld_reaped = sigchld.rc == sigchld_pid;
        let sigchld_stopped = sigchld_reaped && libc::WIFSTOPPED(sigchld.status);
        let sigchld_exited = sigchld_reaped && libc::WIFEXITED(sigchld.status);
        let sigchld_stopsig = if sigchld_stopped {
            libc::WSTOPSIG(sigchld.status)
        } else {
            0
        };
        let sigchld_exit_status = if sigchld_exited {
            libc::WEXITSTATUS(sigchld.status)
        } else {
            0
        };
        let sigchld_cont_ok = sigchld_stopped && ptrace_cont(sigchld_pid, 0);
        let sigchld_cont_errno = if sigchld_stopped && !sigchld_cont_ok {
            errno()
        } else {
            0
        };
        let sigchld_final = if sigchld_cont_ok {
            wait_changed(sigchld_pid, 0)
        } else {
            cleanup_stopped_child(sigchld_pid, libc::SIGKILL);
            WaitStatus { rc: 0, status: 0 }
        };

        report!(
            sigkill_fork_ok = true,
            sigkill_reaped = sigkill_reaped,
            sigkill_signaled = sigkill_signaled,
            sigkill_termsig = sigkill_termsig,
            sigkill_termsig_is_sigkill = sigkill_termsig == libc::SIGKILL,
            sigkill_stopped = sigkill_stopped,
            sigkill_stopsig = sigkill_stopsig,
            sigchld_fork_ok = true,
            sigchld_reaped = sigchld_reaped,
            sigchld_stopped = sigchld_stopped,
            sigchld_stopsig = sigchld_stopsig,
            sigchld_stopsig_is_sigchld = sigchld_stopsig == libc::SIGCHLD,
            sigchld_exited_instead = sigchld_exited,
            sigchld_exit_status = sigchld_exit_status,
            sigchld_cont_ok = sigchld_cont_ok,
            sigchld_cont_errno = sigchld_cont_errno,
            sigchld_final_reaped = sigchld_final.rc == sigchld_pid,
            sigchld_final_exited = libc::WIFEXITED(sigchld_final.status),
            sigchld_final_exit_status_is_73 = libc::WIFEXITED(sigchld_final.status)
                && libc::WEXITSTATUS(sigchld_final.status) == 73,
        );
    }
}
