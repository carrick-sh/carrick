//! Cross-process kill + BLOCKING reap of a death-by-signal child.
//!
//! The minimal reducer for the kill+reap deadlock the KVM lane surfaced
//! (`signalexit`/`waitexitstorm` HANG 124): a parent forks a child that blocks
//! in `pause()`, sends it a terminating signal, then BLOCKS in `wait4(pid, 0)`
//! (options == 0, no WNOHANG) to reap it. The blocking reap must return the
//! child's pid with `WIFSIGNALED` set to the killing signal — it must NOT hang.
//!
//! Two halves, both load-bearing:
//!   * `SIGTERM` — a catchable default-terminate signal. carrick delivers it via
//!     a host `kill`, the child wakes from `pause()`, takes the default action,
//!     and dies *by* the signal (`forked_child_die_by_signal` raises it). The
//!     parent's `wait4` park (WaitOnProcExit) must wake and reap promptly.
//!   * `SIGKILL` — an UNCATCHABLE signal. The host kernel terminates the child
//!     carrick process directly, asynchronously, bypassing all of carrick's
//!     orchestration. A carrick guest process is MULTI-THREADED (vCPU + signal
//!     pump + waiters), so the thread-group leader's zombie is not reapable
//!     until every thread has torn down. The parent's WaitOnProcExit must block
//!     on the real exit (not busy-churn re-dispatching `wait4(WNOHANG)`) and
//!     reap once the teardown completes.
//!
//! Repeated a handful of times so a per-iteration lost-wake / reap-churn race
//! has chances to bite, while staying well inside the case deadline on a healthy
//! runtime. Deterministic booleans; every child is reaped, so a correct runtime
//! never hangs.

use conformance_probes::report;

/// Fork a child that blocks in `pause()`, kill it with `sig`, then BLOCK in
/// `wait4(pid, 0)` to reap it. Returns `(reaped_ok, wifsignaled_matches)`.
unsafe fn fork_kill_blocking_reap(sig: i32) -> (bool, bool) {
    let pid = libc::fork();
    if pid < 0 {
        return (false, false);
    }
    if pid == 0 {
        // Child: install no handler; block until the signal ends us.
        loop {
            libc::pause();
        }
    }
    // Parent: let the child reach pause(), then signal + blocking reap.
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 20_000_000,
    };
    libc::nanosleep(&ts, std::ptr::null_mut());
    libc::kill(pid, sig);
    let mut st = 0i32;
    // Blocking wait4 (options == 0): this is the path that parks in
    // WaitOnProcExit and the one that deadlocked.
    let r = loop {
        let r = libc::wait4(pid, &mut st, 0, std::ptr::null_mut());
        if r == -1 && *libc::__errno_location() == libc::EINTR {
            continue;
        }
        break r;
    };
    (r == pid, libc::WIFSIGNALED(st) && libc::WTERMSIG(st) == sig)
}

fn main() {
    unsafe {
        const ROUNDS: i32 = 8;
        let mut term_reaped = true;
        let mut term_signalled = true;
        let mut kill_reaped = true;
        let mut kill_signalled = true;
        for _ in 0..ROUNDS {
            let (tr, ts) = fork_kill_blocking_reap(libc::SIGTERM);
            term_reaped &= tr;
            term_signalled &= ts;
            let (kr, ks) = fork_kill_blocking_reap(libc::SIGKILL);
            kill_reaped &= kr;
            kill_signalled &= ks;
        }
        report!(
            sigterm_reaped = term_reaped,
            sigterm_wifsignaled = term_signalled,
            sigkill_reaped = kill_reaped,
            sigkill_wifsignaled = kill_signalled,
        );
    }
}
