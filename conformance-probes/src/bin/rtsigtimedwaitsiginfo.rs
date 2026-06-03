//! `rt_sigtimedwait` fills the FULL siginfo from a queued payload (audit M9):
//! a successful wait must report si_code/si_pid (and si_value) from the
//! `sigqueue`'d signal, not just si_signo. carrick previously wrote only
//! si_signo, leaving the rest uninitialized. Flagged oracle-sensitive in
//! docs/archive/asymmetric-behavior-audit.md (siginfo_t field offsets) — this probe is
//! what validates the layout against the Docker linux/arm64 oracle.
//!
//! Invariants encoded (carrick must match Linux line-for-line):
//!   - sigtimedwait returns the waited signal number (SIGUSR1).
//!   - si_signo == SIGUSR1, si_code == SI_QUEUE.
//!   - si_pid is the sender (our own pid, since we sigqueue to ourselves).

use conformance_probes::report;

fn main() {
    unsafe {
        // Block SIGUSR1 and queue it to ourselves with a payload.
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR1);
        libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());

        let value = libc::sigval {
            sival_ptr: 0x1234 as *mut libc::c_void,
        };
        let q = libc::sigqueue(libc::getpid(), libc::SIGUSR1, value);
        report!(sigqueue_ok = q == 0);

        // Dequeue synchronously; the signal is already pending so this returns
        // immediately (NULL timeout = block, but it's deliverable now).
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let rc = libc::sigtimedwait(&set, &mut info, std::ptr::null());
        report!(sigtimedwait_returns_sigusr1 = rc == libc::SIGUSR1);
        report!(si_signo_is_sigusr1 = info.si_signo == libc::SIGUSR1);
        report!(si_code_is_si_queue = info.si_code == libc::SI_QUEUE);
        report!(si_pid_is_self = info.si_pid() == libc::getpid());
    }
}
