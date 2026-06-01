//! A signal set to SIG_IGN must be DROPPED even when delivered CROSS-PROCESS
//! (a sibling/child `kill(other_pid, sig)`), not just process-directed. The
//! host process must not terminate.
//!
//! CPython's signalinterproctester.py (PosixTests.test_interprocess_signal)
//! sets SIGUSR2 -> SIG_IGN, then a child subprocess sends SIGHUP, SIGUSR1
//! (both handled) and SIGUSR2 to the parent. The parent died with return code
//! -12 (killed by SIGUSR2): cross-process delivery of a SIG_IGN signal
//! terminated the process instead of dropping it — carrick never set the HOST
//! disposition for the ignored signal, so the real macOS default action
//! (terminate) fired when a sibling host process delivered it.
//!
//!  * parent_ignored_cross_process_sigusr2: with SIGUSR2 set to SIG_IGN, a
//!    forked child's kill(getppid(), SIGUSR2) does NOT terminate the parent;
//!    the parent runs past the delivery and reports success.

use conformance_probes::report;
use std::time::Duration;

fn main() {
    unsafe {
        // Ignore SIGUSR2 in the parent.
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_IGN;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        if libc::sigaction(libc::SIGUSR2, &sa, std::ptr::null_mut()) != 0 {
            report!(setup_ok = false);
            return;
        }

        let parent = libc::getpid();
        let pid = libc::fork();
        if pid == 0 {
            // Child: send SIGUSR2 to the parent (cross-process), then exit.
            // A brief pause lets the parent reach its wait below first.
            std::thread::sleep(Duration::from_millis(100));
            libc::kill(parent, libc::SIGUSR2);
            libc::_exit(0);
        }

        // Parent: wait long enough to receive the child's SIGUSR2. If delivery
        // honors SIG_IGN the parent survives; if it terminates, the process is
        // killed here and emits no verdict (a DIFF vs Linux).
        std::thread::sleep(Duration::from_millis(400));
        let mut status = 0i32;
        libc::waitpid(pid, &mut status, 0);

        report!(parent_ignored_cross_process_sigusr2 = true);
    }
}
