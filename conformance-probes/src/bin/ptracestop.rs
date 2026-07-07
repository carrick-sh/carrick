//! `PTRACE_TRACEME` makes `raise(SIGSTOP)` visible to plain `waitpid(..., 0)`.
//!
//! LTP ptrace06 relies on this setup sequence before exercising invalid ptrace
//! requests. A traced child stopped by `raise(SIGSTOP)` is waitable even when
//! the parent did not ask for ordinary job-control stops with WUNTRACED.

use conformance_probes::{errno, report};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

const WAIT_ITERS: usize = 200;
const ALARM_SECONDS: libc::c_uint = 2;

static TRACE_PID: AtomicI32 = AtomicI32::new(0);
static ALARM_FIRED: AtomicBool = AtomicBool::new(false);

extern "C" fn alarm_handler(_sig: libc::c_int) {
    ALARM_FIRED.store(true, Ordering::Relaxed);
    let pid = TRACE_PID.load(Ordering::Relaxed);
    if pid > 0 {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
}

unsafe fn install_alarm_handler() {
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    action.sa_sigaction = alarm_handler as *const () as usize;
    action.sa_flags = 0;
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGALRM, &action, core::ptr::null_mut());
    }
}

unsafe fn wait_changed(pid: i32, options: i32) -> (i32, i32, i32) {
    let mut status = 0;
    for _ in 0..WAIT_ITERS {
        let rc = unsafe { libc::waitpid(pid, &mut status, options | libc::WNOHANG) };
        if rc != 0 {
            return (rc, status, if rc < 0 { errno() } else { 0 });
        }
        unsafe { libc::usleep(10_000) };
    }
    (0, 0, 0)
}

unsafe fn blocking_wait(pid: i32) -> (i32, i32, i32) {
    let mut status = 0;
    TRACE_PID.store(pid, Ordering::Relaxed);
    ALARM_FIRED.store(false, Ordering::Relaxed);
    unsafe {
        libc::alarm(ALARM_SECONDS);
    }
    let rc = loop {
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc < 0 && errno() == libc::EINTR && !ALARM_FIRED.load(Ordering::Relaxed) {
            continue;
        }
        break rc;
    };
    unsafe {
        libc::alarm(0);
    }
    (rc, status, if rc < 0 { errno() } else { 0 })
}

unsafe fn ptrace_cont(pid: i32) -> (bool, i32) {
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_CONT,
            pid,
            core::ptr::null_mut::<libc::c_void>(),
            0,
        )
    };
    (rc == 0, if rc == 0 { 0 } else { errno() })
}

fn main() {
    unsafe {
        install_alarm_handler();
        let pid = libc::fork();
        if pid == 0 {
            let rc = libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                core::ptr::null_mut::<libc::c_void>(),
                0,
            );
            if rc != 0 {
                libc::_exit(70);
            }
            libc::raise(libc::SIGSTOP);
            libc::_exit(0);
        }
        if pid < 0 {
            report!(fork_ok = false);
            return;
        }

        let (wait_rc, wait_status, wait_errno) = blocking_wait(pid);
        let stopped = wait_rc == pid && libc::WIFSTOPPED(wait_status);
        let stopsig = if stopped {
            libc::WSTOPSIG(wait_status)
        } else {
            0
        };
        let (cont_ok, cont_errno) = if stopped {
            ptrace_cont(pid)
        } else {
            (false, 0)
        };
        let (exit_rc, exit_status, exit_errno) = if cont_ok {
            wait_changed(pid, 0)
        } else {
            let _ = libc::kill(pid, libc::SIGKILL);
            wait_changed(pid, libc::WUNTRACED)
        };

        report!(
            fork_ok = true,
            blocking_wait_reaped_stop = wait_rc == pid,
            blocking_wait_alarm_fired = ALARM_FIRED.load(Ordering::Relaxed),
            blocking_wait_errno = wait_errno,
            blocking_wait_errno_zero = wait_errno == 0,
            blocking_wait_stopped = stopped,
            blocking_wait_stopsig = stopsig,
            blocking_wait_stopsig_is_sigstop = stopsig == libc::SIGSTOP,
            cont_ok = cont_ok,
            cont_errno = cont_errno,
            cont_errno_zero = cont_errno == 0,
            exit_reaped = exit_rc == pid,
            exit_errno = exit_errno,
            exit_errno_zero = exit_errno == 0,
            exit_exited = libc::WIFEXITED(exit_status),
            exit_status_zero = libc::WIFEXITED(exit_status) && libc::WEXITSTATUS(exit_status) == 0,
        );
    }
}
