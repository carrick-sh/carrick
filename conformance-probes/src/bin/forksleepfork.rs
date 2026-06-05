//! Multithreaded-fork-with-a-sleeping-sibling conformance probe.
//!
//! A process with a sibling thread blocked in `nanosleep` forks. On Linux the
//! fork just succeeds (the sleeping thread is irrelevant to the child, which
//! has only the forking thread). carrick must quiesce sibling vCPUs before a
//! multithreaded fork — but a sibling stuck in a *synchronous host nanosleep*
//! inside the dispatcher never reaches the run-loop top to park, so the fork
//! quiesce spun forever (deadlock). The fix routes nanosleep through the run
//! loop's waiter (DispatchOutcome::WaitOnSleep) so it parks for the quiesce.
//!
//! Deterministic: prints booleans only. With the bug, carrick HANGS here (the
//! harness records a TIMEOUT → DIFF); with the fix it prints the same lines as
//! Docker. A SIGALRM watchdog converts a residual hang into `false` output
//! rather than an indefinite wedge.

use std::ffi::c_void;

extern "C" fn sleeper(_: *mut c_void) -> *mut c_void {
    // A long sleep: blocked for the whole test unless the process exits. This is
    // exactly the shape of a runtime watchdog / a `time.sleep()` worker that is
    // alive when another thread forks.
    let ts = libc::timespec {
        tv_sec: 3600,
        tv_nsec: 0,
    };
    unsafe {
        libc::nanosleep(&ts, std::ptr::null_mut());
    }
    std::ptr::null_mut()
}

fn main() {
    use std::io::Write;
    // Watchdog: if the fork wedges (the second, HVF-VM-rebuild deadlock that
    // remains after the WaitOnSleep fix), SIGALRM terminates the probe so it
    // DIFFs deterministically (carrick: just `thread_created=true`; Docker:
    // all four lines) instead of hanging the harness for a full deadline.
    let alarm_secs = std::env::var("FORKSLEEPFORK_ALARM_SECS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(8);
    unsafe { libc::alarm(alarm_secs) };

    // Spawn the sleeping sibling thread.
    // pthread_t is a pointer on musl, an integer on glibc — `zeroed` is valid
    // for both as the out-param init that pthread_create overwrites.
    let mut tid: libc::pthread_t = unsafe { std::mem::zeroed() };
    let rc =
        unsafe { libc::pthread_create(&mut tid, std::ptr::null(), sleeper, std::ptr::null_mut()) };
    if rc != 0 {
        println!("thread_created=false");
        return;
    }
    println!("thread_created=true");
    let _ = std::io::stdout().flush(); // emit before the fork can wedge
    // Let the sibling actually enter nanosleep before we fork.
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 200_000_000,
    };
    unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };

    // Fork while the sibling sleeps — the operation that deadlocked.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // Child: a fresh process with only this thread. Exit promptly with a
        // recognisable code; the parent verifies it was reaped correctly.
        unsafe { libc::_exit(7) };
    }
    println!("forked={}", pid > 0);

    let mut status: libc::c_int = 0;
    let w = unsafe { libc::waitpid(pid, &mut status, 0) };
    let exited = libc::WIFEXITED(status);
    let code = libc::WEXITSTATUS(status);
    println!("child_reaped={}", w == pid);
    println!("child_exit_code_7={}", exited && code == 7);
}
