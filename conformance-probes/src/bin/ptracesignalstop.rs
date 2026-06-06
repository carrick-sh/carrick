//! Ptrace signal-delivery stop ownership for nonfatal self-signals.
//!
//! Stands in for the remaining `ptrace05.c:149` failures after
//! `ptracesigdeath`: a traced child that sends itself a non-`SIGKILL` signal
//! must become waitable as a ptrace signal-delivery stop. For ordinary standard
//! signals whose numbers can be represented by Darwin, also check the
//! translated stop signal. For Linux `SIGCONT` and real-time signals, LTP only
//! requires `WIFSTOPPED`; the runtime uses a stop carrier because Darwin cannot
//! faithfully report those as ptrace delivery-stop wait statuses.
//!
//! Deterministic output only: booleans and stable signal/status values.

use conformance_probes::{errno, report};

const WAIT_ITERS: usize = 200;
const LINUX_SIGRTMIN: i32 = 34;
const LINUX_SIGRTMAX: i32 = 64;

#[derive(Copy, Clone)]
struct WaitStatus {
    rc: i32,
    status: i32,
    errno: i32,
}

#[derive(Copy, Clone)]
struct Case {
    signal: i32,
    exit_code: i32,
}

#[derive(Copy, Clone)]
struct CaseResult {
    fork_ok: bool,
    reaped_stop: bool,
    stopped: bool,
    stopsig: i32,
    exited_instead: bool,
    exit_status: i32,
    cont_ok: bool,
    cont_errno: i32,
    final_reaped: bool,
    final_exited: bool,
    final_exit_matches: bool,
}

#[derive(Copy, Clone)]
struct BlockingCaseResult {
    fork_ok: bool,
    reaped_stop: bool,
    stopped: bool,
    stopsig: i32,
    wait_errno: i32,
    cont_ok: bool,
    final_reaped: bool,
    final_exited: bool,
    final_exit_matches: bool,
}

extern "C" fn on_alarm(_sig: libc::c_int) {}

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
            let err = if rc < 0 { errno() } else { 0 };
            return WaitStatus {
                rc,
                status,
                errno: err,
            };
        }
        libc::usleep(10_000);
    }
    WaitStatus {
        rc: 0,
        status: 0,
        errno: 0,
    }
}

unsafe fn wait_blocking_with_alarm(pid: i32) -> WaitStatus {
    let mut sa: libc::sigaction = core::mem::zeroed();
    sa.sa_sigaction = on_alarm as usize;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(libc::SIGALRM, &sa, core::ptr::null_mut());

    let mut status = 0;
    libc::alarm(2);
    let rc = libc::waitpid(pid, &mut status, 0);
    let err = if rc < 0 { errno() } else { 0 };
    libc::alarm(0);
    WaitStatus {
        rc,
        status,
        errno: err,
    }
}

unsafe fn spawn_traced_self_signal(case: Case) -> i32 {
    let pid = libc::fork();
    if pid == 0 {
        if !ptrace_traceme() {
            libc::_exit(70);
        }
        if libc::kill(libc::getpid(), case.signal) != 0 {
            libc::_exit(71);
        }
        libc::_exit(case.exit_code);
    }
    pid
}

unsafe fn spawn_delayed_traced_self_signal(case: Case, delay_us: u32) -> i32 {
    let pid = libc::fork();
    if pid == 0 {
        libc::usleep(delay_us);
        if !ptrace_traceme() {
            libc::_exit(70);
        }
        if libc::kill(libc::getpid(), case.signal) != 0 {
            libc::_exit(71);
        }
        libc::_exit(case.exit_code);
    }
    pid
}

unsafe fn cleanup(pid: i32) {
    let _ = ptrace_cont(pid, libc::SIGKILL);
    let _ = wait_changed(pid, 0);
    let _ = libc::kill(pid, libc::SIGKILL);
    let _ = wait_changed(pid, 0);
}

unsafe fn run_case(case: Case) -> CaseResult {
    let pid = spawn_traced_self_signal(case);
    if pid < 0 {
        return CaseResult {
            fork_ok: false,
            reaped_stop: false,
            stopped: false,
            stopsig: 0,
            exited_instead: false,
            exit_status: 0,
            cont_ok: false,
            cont_errno: 0,
            final_reaped: false,
            final_exited: false,
            final_exit_matches: false,
        };
    }

    let first = wait_changed(pid, 0);
    let reaped_stop = first.rc == pid;
    let stopped = reaped_stop && libc::WIFSTOPPED(first.status);
    let exited_instead = reaped_stop && libc::WIFEXITED(first.status);
    let stopsig = if stopped {
        libc::WSTOPSIG(first.status)
    } else {
        0
    };
    let exit_status = if exited_instead {
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
        WaitStatus {
            rc: 0,
            status: 0,
            errno: 0,
        }
    };

    CaseResult {
        fork_ok: true,
        reaped_stop,
        stopped,
        stopsig,
        exited_instead,
        exit_status,
        cont_ok,
        cont_errno,
        final_reaped: final_wait.rc == pid,
        final_exited: libc::WIFEXITED(final_wait.status),
        final_exit_matches: libc::WIFEXITED(final_wait.status)
            && libc::WEXITSTATUS(final_wait.status) == case.exit_code,
    }
}

unsafe fn run_blocking_case(case: Case) -> BlockingCaseResult {
    run_blocking_spawn(spawn_traced_self_signal(case), case)
}

unsafe fn run_delayed_blocking_case(case: Case, delay_us: u32) -> BlockingCaseResult {
    run_blocking_spawn(spawn_delayed_traced_self_signal(case, delay_us), case)
}

unsafe fn run_blocking_spawn(pid: i32, case: Case) -> BlockingCaseResult {
    if pid < 0 {
        return BlockingCaseResult {
            fork_ok: false,
            reaped_stop: false,
            stopped: false,
            stopsig: 0,
            wait_errno: 0,
            cont_ok: false,
            final_reaped: false,
            final_exited: false,
            final_exit_matches: false,
        };
    }

    let first = wait_blocking_with_alarm(pid);
    let reaped_stop = first.rc == pid;
    let stopped = reaped_stop && libc::WIFSTOPPED(first.status);
    let stopsig = if stopped {
        libc::WSTOPSIG(first.status)
    } else {
        0
    };
    let cont_ok = stopped && ptrace_cont(pid, 0);
    let final_wait = if cont_ok {
        wait_changed(pid, 0)
    } else {
        cleanup(pid);
        WaitStatus {
            rc: 0,
            status: 0,
            errno: 0,
        }
    };

    BlockingCaseResult {
        fork_ok: true,
        reaped_stop,
        stopped,
        stopsig,
        wait_errno: first.errno,
        cont_ok,
        final_reaped: final_wait.rc == pid,
        final_exited: libc::WIFEXITED(final_wait.status),
        final_exit_matches: libc::WIFEXITED(final_wait.status)
            && libc::WEXITSTATUS(final_wait.status) == case.exit_code,
    }
}

fn main() {
    unsafe {
        let sigterm = run_case(Case {
            signal: libc::SIGTERM,
            exit_code: 72,
        });
        let sigstop = run_case(Case {
            signal: libc::SIGSTOP,
            exit_code: 73,
        });
        let sigcont = run_case(Case {
            signal: libc::SIGCONT,
            exit_code: 76,
        });
        let sigrtmin = run_case(Case {
            signal: LINUX_SIGRTMIN,
            exit_code: 74,
        });
        let sigrtmax = run_case(Case {
            signal: LINUX_SIGRTMAX,
            exit_code: 75,
        });
        let blocking_sigterm = run_blocking_case(Case {
            signal: libc::SIGTERM,
            exit_code: 77,
        });
        let blocking_sighup = run_blocking_case(Case {
            signal: libc::SIGHUP,
            exit_code: 78,
        });
        let delayed_blocking_sighup = run_delayed_blocking_case(
            Case {
                signal: libc::SIGHUP,
                exit_code: 79,
            },
            200_000,
        );

        report!(
            sigterm_fork_ok = sigterm.fork_ok,
            sigterm_reaped_stop = sigterm.reaped_stop,
            sigterm_stopped = sigterm.stopped,
            sigterm_stopsig = sigterm.stopsig,
            sigterm_stopsig_is_sigterm = sigterm.stopsig == libc::SIGTERM,
            sigterm_exited_instead = sigterm.exited_instead,
            sigterm_exit_status = sigterm.exit_status,
            sigterm_cont_ok = sigterm.cont_ok,
            sigterm_cont_errno = sigterm.cont_errno,
            sigterm_final_reaped = sigterm.final_reaped,
            sigterm_final_exited = sigterm.final_exited,
            sigterm_final_exit_matches = sigterm.final_exit_matches,
            blocking_sigterm_fork_ok = blocking_sigterm.fork_ok,
            blocking_sigterm_reaped_stop = blocking_sigterm.reaped_stop,
            blocking_sigterm_stopped = blocking_sigterm.stopped,
            blocking_sigterm_stopsig = blocking_sigterm.stopsig,
            blocking_sigterm_stopsig_is_sigterm =
                blocking_sigterm.stopsig == libc::SIGTERM,
            blocking_sigterm_wait_errno = blocking_sigterm.wait_errno,
            blocking_sigterm_wait_eintr = blocking_sigterm.wait_errno == libc::EINTR,
            blocking_sigterm_cont_ok = blocking_sigterm.cont_ok,
            blocking_sigterm_final_reaped = blocking_sigterm.final_reaped,
            blocking_sigterm_final_exited = blocking_sigterm.final_exited,
            blocking_sigterm_final_exit_matches = blocking_sigterm.final_exit_matches,
            blocking_sighup_fork_ok = blocking_sighup.fork_ok,
            blocking_sighup_reaped_stop = blocking_sighup.reaped_stop,
            blocking_sighup_stopped = blocking_sighup.stopped,
            blocking_sighup_stopsig = blocking_sighup.stopsig,
            blocking_sighup_stopsig_is_sighup = blocking_sighup.stopsig == libc::SIGHUP,
            blocking_sighup_wait_errno = blocking_sighup.wait_errno,
            blocking_sighup_wait_eintr = blocking_sighup.wait_errno == libc::EINTR,
            blocking_sighup_cont_ok = blocking_sighup.cont_ok,
            blocking_sighup_final_reaped = blocking_sighup.final_reaped,
            blocking_sighup_final_exited = blocking_sighup.final_exited,
            blocking_sighup_final_exit_matches = blocking_sighup.final_exit_matches,
            delayed_blocking_sighup_fork_ok = delayed_blocking_sighup.fork_ok,
            delayed_blocking_sighup_reaped_stop = delayed_blocking_sighup.reaped_stop,
            delayed_blocking_sighup_stopped = delayed_blocking_sighup.stopped,
            delayed_blocking_sighup_stopsig = delayed_blocking_sighup.stopsig,
            delayed_blocking_sighup_stopsig_is_sighup =
                delayed_blocking_sighup.stopsig == libc::SIGHUP,
            delayed_blocking_sighup_wait_errno = delayed_blocking_sighup.wait_errno,
            delayed_blocking_sighup_wait_eintr =
                delayed_blocking_sighup.wait_errno == libc::EINTR,
            delayed_blocking_sighup_cont_ok = delayed_blocking_sighup.cont_ok,
            delayed_blocking_sighup_final_reaped = delayed_blocking_sighup.final_reaped,
            delayed_blocking_sighup_final_exited = delayed_blocking_sighup.final_exited,
            delayed_blocking_sighup_final_exit_matches =
                delayed_blocking_sighup.final_exit_matches,
            sigstop_fork_ok = sigstop.fork_ok,
            sigstop_reaped_stop = sigstop.reaped_stop,
            sigstop_stopped = sigstop.stopped,
            sigstop_stopsig = sigstop.stopsig,
            sigstop_stopsig_is_sigstop = sigstop.stopsig == libc::SIGSTOP,
            sigstop_exited_instead = sigstop.exited_instead,
            sigstop_exit_status = sigstop.exit_status,
            sigstop_cont_ok = sigstop.cont_ok,
            sigstop_cont_errno = sigstop.cont_errno,
            sigstop_final_reaped = sigstop.final_reaped,
            sigstop_final_exited = sigstop.final_exited,
            sigstop_final_exit_matches = sigstop.final_exit_matches,
            sigcont_fork_ok = sigcont.fork_ok,
            sigcont_reaped_stop = sigcont.reaped_stop,
            sigcont_stopped = sigcont.stopped,
            sigcont_exited_instead = sigcont.exited_instead,
            sigcont_exit_status = sigcont.exit_status,
            sigcont_cont_ok = sigcont.cont_ok,
            sigcont_cont_errno = sigcont.cont_errno,
            sigcont_final_reaped = sigcont.final_reaped,
            sigcont_final_exited = sigcont.final_exited,
            sigcont_final_exit_matches = sigcont.final_exit_matches,
            sigrtmin_fork_ok = sigrtmin.fork_ok,
            sigrtmin_reaped_stop = sigrtmin.reaped_stop,
            sigrtmin_stopped = sigrtmin.stopped,
            sigrtmin_exited_instead = sigrtmin.exited_instead,
            sigrtmin_exit_status = sigrtmin.exit_status,
            sigrtmin_cont_ok = sigrtmin.cont_ok,
            sigrtmin_cont_errno = sigrtmin.cont_errno,
            sigrtmin_final_reaped = sigrtmin.final_reaped,
            sigrtmin_final_exited = sigrtmin.final_exited,
            sigrtmin_final_exit_matches = sigrtmin.final_exit_matches,
            sigrtmax_fork_ok = sigrtmax.fork_ok,
            sigrtmax_reaped_stop = sigrtmax.reaped_stop,
            sigrtmax_stopped = sigrtmax.stopped,
            sigrtmax_exited_instead = sigrtmax.exited_instead,
            sigrtmax_exit_status = sigrtmax.exit_status,
            sigrtmax_cont_ok = sigrtmax.cont_ok,
            sigrtmax_cont_errno = sigrtmax.cont_errno,
            sigrtmax_final_reaped = sigrtmax.final_reaped,
            sigrtmax_final_exited = sigrtmax.final_exited,
            sigrtmax_final_exit_matches = sigrtmax.final_exit_matches,
        );
    }
}
