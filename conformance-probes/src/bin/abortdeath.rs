//! Default-disposition death-by-signal + abort(): a fatal signal whose
//! disposition is SIG_DFL terminates the receiving process and the parent's
//! wait4 reports `WIFSIGNALED && WTERMSIG == sig`. We can't observe our own
//! termination from inside the probe, so each invariant is encoded in a forked
//! child whose parent reaps it and reports booleans about the resulting status.
//!
//! Stands in for LTP `kill05`, `kill07`, `abort01`.
//!
//! Invariants encoded:
//!   * `kill(getpid(), SIGTERM)` with the default disposition (no handler, no
//!     SIG_IGN, not blocked) terminates the child by signal. Parent observes
//!     `WIFSIGNALED && WTERMSIG == SIGTERM`. (kill05)
//!   * Same for SIGKILL — the always-fatal signal. (kill07)
//!   * `abort()` resets SIGABRT to SIG_DFL and raises it, so the child dies
//!     by SIGABRT regardless of any installed handler. (abort01)
//!   * Sanity / negative case: a child that calls `_exit(0)` is `WIFEXITED`
//!     with status 0 and is NOT `WIFSIGNALED`.
//!
//! No timing, no PIDs, no addresses in stdout — every line is a boolean.

use conformance_probes::{install_dfl, install_handler, reap, report};

extern "C" fn never_called(_: i32) {
    // abort01: even if the test installed a SIGABRT handler, abort() must
    // reset the disposition to SIG_DFL before re-raising, so this handler
    // must NOT keep the child alive.
}

/// Fork a child that runs `body` and is reaped by the parent. Returns
/// `(wifsignaled, wtermsig_matches_expected, wifexited, wexitstatus)` — the
/// caller picks which booleans to report.
unsafe fn fork_run_and_reap(
    expected_sig: i32,
    body: extern "C" fn(),
) -> (bool, bool, bool, i32) {
    let pid = libc::fork();
    if pid == 0 {
        body();
        // body() must not return; if it does, force a non-signal exit so the
        // parent's WIFSIGNALED check is unambiguously false.
        libc::_exit(0);
    }
    let (_, status) = reap(pid);
    let signaled = libc::WIFSIGNALED(status);
    let term_matches = signaled && libc::WTERMSIG(status) == expected_sig;
    let exited = libc::WIFEXITED(status);
    let exit_status = if exited { libc::WEXITSTATUS(status) } else { -1 };
    (signaled, term_matches, exited, exit_status)
}

extern "C" fn body_sigterm() {
    unsafe {
        // Belt-and-braces: SIGTERM's default disposition IS terminate, but
        // reset just in case the test runner inherited something. SIGTERM
        // must NOT be blocked either.
        let _ = install_dfl(libc::SIGTERM);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::kill(libc::getpid(), libc::SIGTERM);
        // SIGTERM is synchronous on Linux when unblocked; we should never
        // reach here. Fall through to _exit(0) so the parent sees a
        // clearly-wrong result if delivery silently dropped the signal.
    }
}

extern "C" fn body_sigkill() {
    unsafe {
        // SIGKILL cannot be caught, blocked, or ignored, so no setup needed.
        libc::kill(libc::getpid(), libc::SIGKILL);
    }
}

extern "C" fn body_abort() {
    unsafe {
        // Install a handler that, on Linux, abort() must reset to SIG_DFL
        // before re-raising. If the runtime forgets the reset the handler
        // would swallow the abort and the child would exit cleanly instead
        // of dying by SIGABRT.
        let _ = install_handler(libc::SIGABRT, never_called, 0);
        libc::abort();
    }
}

extern "C" fn body_clean_exit() {
    unsafe {
        libc::_exit(0);
    }
}

fn main() {
    unsafe {
        let (sigterm_signaled, sigterm_matches, _, _) =
            fork_run_and_reap(libc::SIGTERM, body_sigterm);
        report!(
            sigterm_kills_child = sigterm_signaled,
            sigterm_wtermsig_matches = sigterm_matches,
        );

        let (sigkill_signaled, sigkill_matches, _, _) =
            fork_run_and_reap(libc::SIGKILL, body_sigkill);
        report!(
            sigkill_kills_child = sigkill_signaled,
            sigkill_wtermsig_matches = sigkill_matches,
        );

        let (abort_signaled, abort_matches, _, _) =
            fork_run_and_reap(libc::SIGABRT, body_abort);
        report!(
            abort_sigabrts_child = abort_signaled,
            abort_wtermsig_matches = abort_matches,
        );

        let (clean_signaled, _, clean_exited, clean_status) =
            fork_run_and_reap(0, body_clean_exit);
        report!(
            clean_exit_no_signal = !clean_signaled,
            clean_exit_wifexited = clean_exited,
            clean_exit_status_zero = clean_status == 0,
        );
    }
}
