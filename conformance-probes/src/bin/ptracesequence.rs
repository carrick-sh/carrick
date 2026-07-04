//! LTP `ptrace05` signal sequence.
//!
//! The isolated signal-stop probes pass, while LTP sweeps signal 0, then all
//! non-reserved signals in order. Keep the same ordering so state leaked from
//! one traced child to the next is observable.

use conformance_probes::report;

const WAIT_ITERS: usize = 200;

#[derive(Clone, Copy)]
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

unsafe fn wait_changed(pid: i32) -> WaitStatus {
    let mut status = 0;
    for _ in 0..WAIT_ITERS {
        let rc = libc::waitpid(pid, &mut status, libc::WNOHANG);
        if rc != 0 {
            return WaitStatus { rc, status };
        }
        libc::usleep(10_000);
    }
    WaitStatus { rc: 0, status: 0 }
}

unsafe fn spawn_self_signal(signal: i32, exit_code: i32) -> i32 {
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

unsafe fn signal_case(signal: i32) -> bool {
    let pid = spawn_self_signal(signal, 0);
    let first = wait_changed(pid);
    let first_stopped = first.rc == pid && libc::WIFSTOPPED(first.status);
    let first_stopsig = if first_stopped {
        libc::WSTOPSIG(first.status)
    } else {
        0
    };
    let first_exited = first.rc == pid && libc::WIFEXITED(first.status);
    let first_signaled = first.rc == pid && libc::WIFSIGNALED(first.status);
    if signal == 0 {
        return first_exited;
    }
    if signal == libc::SIGKILL {
        return first_signaled && libc::WTERMSIG(first.status) == libc::SIGKILL;
    }
    if !first_stopped || first_stopsig != signal {
        if first.rc == pid && !libc::WIFEXITED(first.status) && !libc::WIFSIGNALED(first.status) {
            let _ = libc::kill(pid, libc::SIGKILL);
            let _ = wait_changed(pid);
        }
        return false;
    }
    if !ptrace_cont(pid, 0) {
        let _ = libc::kill(pid, libc::SIGKILL);
        let _ = wait_changed(pid);
        return false;
    }
    let final_wait = wait_changed(pid);
    let final_reaped = final_wait.rc == pid;
    final_reaped && libc::WIFEXITED(final_wait.status)
}

fn main() {
    unsafe {
        let mut all_ok = true;
        let mut first_bad = 0;
        for signal in (0..=31).chain(34..=64) {
            if !signal_case(signal) {
                all_ok = false;
                first_bad = signal;
                break;
            }
        }

        report!(
            ptrace05_signal_sweep_ok = all_ok,
            first_bad_signal = first_bad,
        );
    }
}
