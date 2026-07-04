//! PTRACE_ATTACH to namespace init, as exercised by LTP `ptrace11`.

use conformance_probes::{errno, report};

unsafe fn ptrace_attach(pid: i32) -> i32 {
    libc::ptrace(
        libc::PTRACE_ATTACH,
        pid,
        core::ptr::null_mut::<libc::c_void>(),
        0,
    ) as i32
}

unsafe fn ptrace_detach(pid: i32) -> i32 {
    libc::ptrace(
        libc::PTRACE_DETACH,
        pid,
        core::ptr::null_mut::<libc::c_void>(),
        0,
    ) as i32
}

fn main() {
    unsafe {
        let attach = ptrace_attach(1);
        let attach_errno = if attach == 0 { 0 } else { errno() };

        let mut status = 0;
        let waited = if attach == 0 {
            libc::waitpid(1, &mut status, 0)
        } else {
            -1
        };
        let wait_errno = if waited >= 0 { 0 } else { errno() };
        let stopped = waited == 1 && libc::WIFSTOPPED(status);
        let stopsig = if stopped { libc::WSTOPSIG(status) } else { 0 };

        let detach = if waited == 1 { ptrace_detach(1) } else { -1 };
        let detach_errno = if detach == 0 { 0 } else { errno() };

        let mut leftover_status = 0;
        let leftover = libc::waitpid(-1, &mut leftover_status, libc::WNOHANG);
        let leftover_errno = if leftover >= 0 { 0 } else { errno() };

        report!(
            attach_ok = attach == 0,
            attach_errno = attach_errno,
            wait_reaped_init = waited == 1,
            wait_errno = wait_errno,
            wait_stopped = stopped,
            wait_stopsig_is_sigstop = stopsig == libc::SIGSTOP,
            detach_ok = detach == 0,
            detach_errno = detach_errno,
            no_leftover_children = leftover == -1 && leftover_errno == libc::ECHILD,
        );
    }
}
