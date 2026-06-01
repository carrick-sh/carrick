//! A process-directed signal (`kill(getpid(), sig)`) that EVERY thread blocks
//! must be consumable by whichever thread is parked in `sigwait`/
//! `sigtimedwait` selecting it — NOT pinned to the SENDER thread.
//!
//! This mirrors CPython's `test_signal.PendingSignalsTests.test_sigwait_thread`:
//! the whole process blocks SIGUSR1, the MAIN thread parks in sigtimedwait
//! waiting for it, and a SIBLING ("killer") thread sends it process-directed.
//!
//! Carrick's `raise_process_directed` held an all-threads-blocked
//! process-directed signal pending on the CALLER's tid (the killer). sigwait's
//! dequeue is strictly per-tid, so the main thread (a different tid) never
//! found it and looped until its own timeout — an indefinite hang in the real
//! test (sigwait has no timeout). A process-directed signal belongs to the
//! SHARED process pending set, dequeued by whichever thread sigwaits it.
//!
//!  * woke_with_sigusr1: with SIGUSR1 blocked in every thread, the main thread
//!    parked in sigtimedwait([SIGUSR1]) returns SIGUSR1 after a sibling thread
//!    sends kill(getpid(), SIGUSR1) — it is not stranded on the sender's tid.

use conformance_probes::report;
use std::thread;
use std::time::Duration;

fn main() {
    unsafe {
        // Block SIGUSR1 process-wide BEFORE spawning, so the killer thread
        // inherits the block too — every thread blocks SIGUSR1.
        let mut block: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut block);
        libc::sigaddset(&mut block, libc::SIGUSR1);
        libc::pthread_sigmask(libc::SIG_BLOCK, &block, std::ptr::null_mut());

        // Sibling "killer" thread: wait until the main thread is parked in
        // sigtimedwait, then send the signal PROCESS-directed.
        let killer = thread::spawn(|| {
            thread::sleep(Duration::from_millis(200));
            libc::kill(libc::getpid(), libc::SIGUSR1);
        });

        // Main thread waits for SIGUSR1. A 5s timeout bounds the probe so it
        // always emits a verdict: on Linux sigtimedwait returns SIGUSR1
        // promptly; a stranded signal would instead time out (rv < 0).
        let mut wait_set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut wait_set);
        libc::sigaddset(&mut wait_set, libc::SIGUSR1);
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let ts = libc::timespec {
            tv_sec: 5,
            tv_nsec: 0,
        };
        let rv = libc::sigtimedwait(&wait_set, &mut info, &ts);

        report!(woke_with_sigusr1 = (rv == libc::SIGUSR1));

        let _ = killer.join();
        std::process::exit(0);
    }
}
