//! pidnsinitsig: pid-1 signal defaults (pid_namespaces(7)). The namespace init
//! does not get the default action for a signal it has no handler for — a
//! SIGTERM from within the namespace to pid 1 with no installed handler is
//! dropped, so the init survives. This probe runs AS a child of the init and
//! sends SIGTERM to pid 1; if the init died the whole container would be torn
//! down and this probe would never report. So observing our own continued
//! execution + a successful kill(1, SIGTERM) is the signal that pid-1 ignored
//! the default-action SIGTERM. Then we verify a normal signal to a normal
//! member (ourselves, with a handler) is delivered, as a control.
//!
//! Deterministic booleans. (carrick models this in the kill/raise path; Linux
//! enforces it in the kernel.)
use conformance_probes::{report, errno};
use std::sync::atomic::{AtomicBool, Ordering};
static GOT: AtomicBool = AtomicBool::new(false);
extern "C" fn on_term(_: i32) { GOT.store(true, Ordering::SeqCst); }
fn main() {
    unsafe {
        // (1) Send SIGTERM to pid 1 (the init) with no handler installed there.
        //     Linux drops it (init has no default action in its own ns); the
        //     call itself returns 0 (permitted). The init must NOT die — if it
        //     did, this process is SIGKILLed during teardown and reports nothing.
        let rc = libc::kill(1, libc::SIGTERM);
        let kill_errno = if rc < 0 { errno() } else { 0 };
        // Give any (erroneous) teardown a moment to manifest; if the init died
        // we'd be killed here and produce no output.
        let ts = libc::timespec { tv_sec: 0, tv_nsec: 200_000_000 };
        libc::nanosleep(&ts, core::ptr::null_mut());

        // (2) Control: a member WITH a handler receives its own signal.
        conformance_probes::install_handler(libc::SIGUSR1, on_term, 0);
        libc::kill(libc::getpid(), libc::SIGUSR1);
        libc::nanosleep(&ts, core::ptr::null_mut());

        report!(
            kill_init_term_ok = rc == 0,
            kill_init_term_errno = kill_errno,
            survived_after_signalling_init = true,
            self_handler_fired = GOT.load(Ordering::SeqCst),
        );
    }
}
