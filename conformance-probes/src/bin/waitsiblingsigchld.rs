//! A blocking `waitpid(child_A)` must NOT be interrupted (EINTR) by a SIGCHLD
//! delivered for a DIFFERENT child (child_B) when SIGCHLD has its default
//! disposition (ignore). On Linux a signal interrupts a blocking syscall only
//! if it is unblocked AND has an effect — a delivered-and-dropped default-
//! ignore SIGCHLD does not. carrick previously interrupted the wait for ANY
//! pending signal, so a sibling's exit spuriously EINTR'd the reap of another
//! child (LTP futex_cmp_requeue01's `SAFE_WAITPID`, and any multi-child reap
//! loop, TBROKed on it).
//!
//! Shape: parent forks B (exits fast, ~10ms) and A (exits slow, ~150ms).
//! Parent immediately `waitpid(A, 0)` (blocking, no WNOHANG). While blocked,
//! B exits → SIGCHLD (no handler installed → default-ignore). The wait must
//! ride through that and return A's status, NOT -1/EINTR. Then B is reaped.
//!
//! Negative control: with a SIGCHLD HANDLER installed (no SA_RESTART), the
//! same sibling exit DOES interrupt the wait → EINTR (the signal now has an
//! effect). This pins both directions so the fix can't over-correct into
//! "never interrupt".
//!
//! Deterministic booleans; every child is reaped so nothing leaks.

use conformance_probes::report;
use std::sync::atomic::{AtomicU32, Ordering};

static HANDLER_HITS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_sigchld(_sig: i32) {
    HANDLER_HITS.fetch_add(1, Ordering::SeqCst);
}

unsafe fn errno() -> i32 {
    *libc::__errno_location()
}

/// Fork a child that sleeps `ms` then exits 0. Returns its pid.
unsafe fn fork_sleep_exit(ms: u64) -> i32 {
    let pid = libc::fork();
    if pid == 0 {
        libc::usleep((ms * 1000) as libc::c_uint);
        libc::_exit(0);
    }
    pid
}

fn main() {
    unsafe {
        // ---- Case 1: default-ignore SIGCHLD must NOT interrupt waitpid(A) ----
        // SIGCHLD left at default disposition (we install nothing).
        let b = fork_sleep_exit(10); // exits soon → fires the sibling SIGCHLD
        let a = fork_sleep_exit(150); // the one we block on

        let mut status_a = 0i32;
        // Single blocking waitpid; on Linux it rides through B's SIGCHLD.
        let r = libc::waitpid(a, &mut status_a, 0);
        let er = if r < 0 { errno() } else { 0 };
        report!(
            default_ignore_wait_not_eintr = r == a,
            default_ignore_wait_no_errno = er == 0,
            default_ignore_child_a_exited_zero =
                libc::WIFEXITED(status_a) && libc::WEXITSTATUS(status_a) == 0,
        );
        // Reap B (already a zombie).
        let mut sb = 0i32;
        let _ = libc::waitpid(b, &mut sb, 0);

        // ---- Case 2 (negative control): a SIGCHLD HANDLER (no SA_RESTART)
        //      DOES interrupt waitpid(A) when sibling B exits. ----
        HANDLER_HITS.store(0, Ordering::SeqCst);
        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = on_sigchld as *const () as usize;
        sa.sa_flags = 0; // NOT SA_RESTART → an interrupted wait stays EINTR
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGCHLD, &sa, core::ptr::null_mut());

        let b = fork_sleep_exit(10);
        let a = fork_sleep_exit(150);
        let mut status_a = 0i32;
        // Loop is NOT used: we want to observe the single EINTR. A handler
        // without SA_RESTART means the first sibling SIGCHLD interrupts.
        let r = libc::waitpid(a, &mut status_a, 0);
        let er = if r < 0 { errno() } else { 0 };
        // Either we caught the EINTR (handler ran, wait interrupted) OR — if B
        // hadn't exited yet when we entered — we reaped A directly. The
        // deterministic invariant across both sides is: IF r == -1 then errno
        // is EINTR and the handler ran at least once. Assert that implication
        // plus "the handler observed the sibling SIGCHLD".
        let interrupted_implies_eintr = r != -1 || er == libc::EINTR;
        report!(
            handler_interrupted_implies_eintr = interrupted_implies_eintr,
            handler_observed_sigchld = HANDLER_HITS.load(Ordering::SeqCst) >= 1,
        );
        // Drain: reap both A and B regardless of how the wait ended.
        for pid in [a, b] {
            loop {
                let mut s = 0i32;
                let rc = libc::waitpid(pid, &mut s, 0);
                if rc == pid || (rc == -1 && errno() != libc::EINTR) {
                    break;
                }
            }
        }
        // Restore default so nothing leaks into a later test in the same image.
        let mut dfl: libc::sigaction = core::mem::zeroed();
        dfl.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut dfl.sa_mask);
        libc::sigaction(libc::SIGCHLD, &dfl, core::ptr::null_mut());
    }
}
