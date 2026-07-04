//! `PTRACE_KILL` / `PTRACE_CONT` over repeated traced children.
//!
//! Stands in for LTP `ptrace01`: each child calls `PTRACE_TRACEME`, raises a
//! traced `SIGUSR2` stop for its parent, then the parent either kills the
//! stopped tracee with `PTRACE_KILL` or resumes it with `PTRACE_CONT`. The
//! sequence is run with and without an installed child handler so stale
//! ptrace/stop state between children is visible.

use conformance_probes::{errno, report};
use std::sync::atomic::{AtomicBool, Ordering};

static TIMED_OUT: AtomicBool = AtomicBool::new(false);

extern "C" fn on_usr2(_: libc::c_int) {}
extern "C" fn on_alarm(_: libc::c_int) {
    TIMED_OUT.store(true, Ordering::Relaxed);
}

#[derive(Clone, Copy)]
struct WaitStatus {
    rc: i32,
    status: i32,
    err: i32,
}

#[derive(Clone, Copy)]
struct CaseResult {
    fork_ok: bool,
    stopped: bool,
    stop_sig: i32,
    ptrace_ok: bool,
    ptrace_errno: i32,
    final_reaped: bool,
    final_signaled: bool,
    final_termsig: i32,
    final_exited: bool,
    final_exit_status: i32,
    final_errno: i32,
    cleanup_no_child: bool,
    cleanup_rc: i32,
    cleanup_errno: i32,
}

unsafe fn install_handler() {
    let mut sa: libc::sigaction = core::mem::zeroed();
    sa.sa_sigaction = on_usr2 as *const () as usize;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(libc::SIGUSR2, &sa, core::ptr::null_mut());
}

unsafe fn install_alarm_handler() {
    let mut sa: libc::sigaction = core::mem::zeroed();
    sa.sa_sigaction = on_alarm as *const () as usize;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(libc::SIGALRM, &sa, core::ptr::null_mut());
}

unsafe fn arm_alarm_ms(ms: i64) {
    let it = libc::itimerval {
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: libc::timeval {
            tv_sec: ms / 1000,
            tv_usec: (ms % 1000) * 1000,
        },
    };
    libc::setitimer(libc::ITIMER_REAL, &it, core::ptr::null_mut());
}

unsafe fn disarm_alarm() {
    let zero: libc::itimerval = core::mem::zeroed();
    libc::setitimer(libc::ITIMER_REAL, &zero, core::ptr::null_mut());
}

unsafe fn ignore_usr2() {
    let mut sa: libc::sigaction = core::mem::zeroed();
    sa.sa_sigaction = libc::SIG_IGN;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(libc::SIGUSR2, &sa, core::ptr::null_mut());
}

unsafe fn ptrace_traceme() -> bool {
    libc::ptrace(
        libc::PTRACE_TRACEME,
        0,
        core::ptr::null_mut::<libc::c_void>(),
        0,
    ) == 0
}

unsafe fn ptrace_kill(pid: i32) -> bool {
    libc::ptrace(
        libc::PTRACE_KILL,
        pid,
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

unsafe fn wait_changed(pid: i32, options: i32) -> WaitStatus {
    let mut status = 0;
    TIMED_OUT.store(false, Ordering::Relaxed);
    arm_alarm_ms(2_000);
    loop {
        let rc = libc::waitpid(pid, &mut status, options);
        disarm_alarm();
        if rc == pid {
            return WaitStatus { rc, status, err: 0 };
        }
        if rc < 0 {
            let err = errno();
            if err == libc::EINTR && !TIMED_OUT.load(Ordering::Relaxed) {
                arm_alarm_ms(2_000);
                continue;
            }
            return WaitStatus { rc, status, err };
        }
        return WaitStatus { rc, status, err: 0 };
    }
}

unsafe fn cleanup_wait() -> (i32, i32) {
    let mut cleanup_status = 0;
    *libc::__errno_location() = libc::ENOTTY;
    TIMED_OUT.store(false, Ordering::Relaxed);
    arm_alarm_ms(2_000);
    let cleanup_rc = libc::waitpid(-1, &mut cleanup_status, 0);
    disarm_alarm();
    (cleanup_rc, errno())
}

unsafe fn run_case(kill: bool, handler: bool) -> CaseResult {
    let pid = libc::fork();
    if pid == 0 {
        if handler {
            install_handler();
        } else {
            ignore_usr2();
        }
        if !ptrace_traceme() {
            libc::_exit(70);
        }
        libc::kill(libc::getpid(), libc::SIGUSR2);
        libc::_exit(1);
    }
    if pid < 0 {
        return CaseResult {
            fork_ok: false,
            stopped: false,
            stop_sig: 0,
            ptrace_ok: false,
            ptrace_errno: 0,
            final_reaped: false,
            final_signaled: false,
            final_termsig: 0,
            final_exited: false,
            final_exit_status: 0,
            final_errno: 0,
            cleanup_no_child: false,
            cleanup_rc: 0,
            cleanup_errno: 0,
        };
    }

    let stop = wait_changed(pid, 0);
    let stopped = stop.rc == pid && libc::WIFSTOPPED(stop.status);
    let stop_sig = if stopped { libc::WSTOPSIG(stop.status) } else { 0 };
    let ptrace_ok = stopped && if kill { ptrace_kill(pid) } else { ptrace_cont(pid) };
    let ptrace_errno = if stopped && !ptrace_ok { errno() } else { 0 };
    let final_wait = if ptrace_ok {
        wait_changed(pid, 0)
    } else {
        libc::kill(pid, libc::SIGKILL);
        wait_changed(pid, 0)
    };
    let (cleanup_rc, cleanup_errno) = cleanup_wait();
    CaseResult {
        fork_ok: true,
        stopped,
        stop_sig,
        ptrace_ok,
        ptrace_errno,
        final_reaped: final_wait.rc == pid,
        final_signaled: final_wait.rc == pid && libc::WIFSIGNALED(final_wait.status),
        final_termsig: if final_wait.rc == pid && libc::WIFSIGNALED(final_wait.status) {
            libc::WTERMSIG(final_wait.status)
        } else {
            0
        },
        final_exited: final_wait.rc == pid && libc::WIFEXITED(final_wait.status),
        final_exit_status: if final_wait.rc == pid && libc::WIFEXITED(final_wait.status) {
            libc::WEXITSTATUS(final_wait.status)
        } else {
            0
        },
        final_errno: final_wait.err,
        cleanup_no_child: cleanup_rc == -1 && cleanup_errno == libc::ECHILD,
        cleanup_rc,
        cleanup_errno,
    }
}

fn main() {
    unsafe {
        install_alarm_handler();
        let kill_plain = run_case(true, false);
        let kill_handler = run_case(true, true);
        let cont_plain = run_case(false, false);
        let cont_handler = run_case(false, true);

        report!(
            kill_plain_ok = kill_plain.fork_ok
                && kill_plain.stopped
                && kill_plain.stop_sig == libc::SIGUSR2
                && kill_plain.ptrace_ok
                && kill_plain.final_reaped
                && kill_plain.final_signaled
                && kill_plain.final_termsig == libc::SIGKILL,
            kill_plain_ptrace_errno = kill_plain.ptrace_errno,
            kill_plain_final_errno = kill_plain.final_errno,
            kill_plain_cleanup_no_child = kill_plain.cleanup_no_child,
            kill_plain_cleanup_rc = kill_plain.cleanup_rc,
            kill_plain_cleanup_errno = kill_plain.cleanup_errno,
            kill_handler_ok = kill_handler.fork_ok
                && kill_handler.stopped
                && kill_handler.stop_sig == libc::SIGUSR2
                && kill_handler.ptrace_ok
                && kill_handler.final_reaped
                && kill_handler.final_signaled
                && kill_handler.final_termsig == libc::SIGKILL,
            kill_handler_ptrace_errno = kill_handler.ptrace_errno,
            kill_handler_final_errno = kill_handler.final_errno,
            kill_handler_cleanup_no_child = kill_handler.cleanup_no_child,
            kill_handler_cleanup_rc = kill_handler.cleanup_rc,
            kill_handler_cleanup_errno = kill_handler.cleanup_errno,
            cont_plain_ok = cont_plain.fork_ok
                && cont_plain.stopped
                && cont_plain.stop_sig == libc::SIGUSR2
                && cont_plain.ptrace_ok
                && cont_plain.final_reaped
                && cont_plain.final_exited
                && cont_plain.final_exit_status == 1,
            cont_plain_ptrace_errno = cont_plain.ptrace_errno,
            cont_plain_final_errno = cont_plain.final_errno,
            cont_plain_cleanup_no_child = cont_plain.cleanup_no_child,
            cont_plain_cleanup_rc = cont_plain.cleanup_rc,
            cont_plain_cleanup_errno = cont_plain.cleanup_errno,
            cont_handler_ok = cont_handler.fork_ok
                && cont_handler.stopped
                && cont_handler.stop_sig == libc::SIGUSR2
                && cont_handler.ptrace_ok
                && cont_handler.final_reaped
                && cont_handler.final_exited
                && cont_handler.final_exit_status == 1,
            cont_handler_ptrace_errno = cont_handler.ptrace_errno,
            cont_handler_final_errno = cont_handler.final_errno,
            cont_handler_cleanup_no_child = cont_handler.cleanup_no_child,
            cont_handler_cleanup_rc = cont_handler.cleanup_rc,
            cont_handler_cleanup_errno = cont_handler.cleanup_errno,
        );
    }
}
