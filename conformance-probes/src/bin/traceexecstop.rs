//! Ptrace exec-stop ownership.
//!
//! Stands in for the `ptrace06` setup blocker: after a child calls
//! `PTRACE_TRACEME` and successfully execs, Linux makes the parent observe a
//! ptrace stop before the new program runs. Carrick must not wait through the
//! exec'd child to normal exit.
//!
//! Deterministic output only: booleans and stable signal/exit-status values.

use conformance_probes::{errno, report};
use std::env;
use std::ffi::CString;

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

unsafe fn spawn_traced_exec(path: &CString) -> i32 {
    let pid = libc::fork();
    if pid == 0 {
        if !ptrace_traceme() {
            libc::_exit(70);
        }
        let child = CString::new("child").unwrap();
        let argv = [path.as_ptr(), child.as_ptr(), core::ptr::null()];
        let envp = [core::ptr::null()];
        libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
        libc::_exit(71);
    }
    pid
}

unsafe fn cleanup(pid: i32) {
    let _ = ptrace_cont(pid, libc::SIGKILL);
    let _ = wait_changed(pid, 0);
    let _ = libc::kill(pid, libc::SIGKILL);
    let _ = wait_changed(pid, 0);
}

fn child_stage() -> ! {
    std::process::exit(77);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("child") {
        child_stage();
    }

    let path = CString::new(args.first().map(String::as_str).unwrap_or("/tmp/p")).unwrap();

    unsafe {
        let pid = spawn_traced_exec(&path);
        if pid < 0 {
            report!(fork_ok = false);
            return;
        }

        let first = wait_changed(pid, 0);
        let reaped_first = first.rc == pid;
        let stopped = reaped_first && libc::WIFSTOPPED(first.status);
        let stopsig = if stopped {
            libc::WSTOPSIG(first.status)
        } else {
            0
        };
        let exited_instead = reaped_first && libc::WIFEXITED(first.status);
        let early_exit_status = if exited_instead {
            libc::WEXITSTATUS(first.status)
        } else {
            0
        };

        let cont_ok = stopped && ptrace_cont(pid, 0);
        let cont_errno = if stopped && !cont_ok { errno() } else { 0 };
        let final_wait = if cont_ok {
            wait_changed(pid, 0)
        } else {
            cleanup(pid);
            WaitStatus { rc: 0, status: 0 }
        };

        report!(
            fork_ok = true,
            exec_stop_reaped = reaped_first,
            exec_stopped = stopped,
            exec_stopsig = stopsig,
            exec_stopsig_is_sigtrap = stopsig == libc::SIGTRAP,
            exec_exited_instead = exited_instead,
            exec_early_exit_status = early_exit_status,
            ptrace_cont_ok = cont_ok,
            ptrace_cont_errno = cont_errno,
            final_reaped = final_wait.rc == pid,
            final_exited = libc::WIFEXITED(final_wait.status),
            final_exit_status_is_77 = libc::WIFEXITED(final_wait.status)
                && libc::WEXITSTATUS(final_wait.status) == 77,
        );
    }
}
