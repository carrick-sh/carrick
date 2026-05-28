//! `WCOREDUMP(status)` reports the 0x80 bit on the wait status of a child that
//! died by a core-dumping signal. macOS's default `RLIMIT_CORE = 0` means the
//! host's wait status never has the bit set; carrick synthesizes it for the
//! Linux core-dumping signal set (SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGBUS,
//! SIGFPE, SIGSEGV, SIGXCPU, SIGXFSZ, SIGSYS) in `translate_wait_status` so
//! that Linux apps (glibc abort(), LTP, etc.) see the bit they expect.
//! Commit 0b55501 added the synthesis; this probe gates it.
//!
//! Output shape per case: bool(WIFSIGNALED) && bool(WCOREDUMP). The probe
//! sets `RLIMIT_CORE` to `RLIM_INFINITY` so a real Linux container (Docker)
//! also has its dump-attempt path enabled; both sides should then report the
//! bit. A non-core-dumping signal (SIGTERM, SIGKILL) is the negative case —
//! its WCOREDUMP must be FALSE on both sides.

use conformance_probes::report;

unsafe fn enable_core_dumps() {
    let lim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    libc::setrlimit(libc::RLIMIT_CORE, &lim);
    // PR_SET_DUMPABLE = 4. Some hardened environments demote the dumpable
    // flag after setuid/exec; we force it ON so the kernel will actually
    // attempt the dump (and set the bit).
    libc::prctl(4 /* PR_SET_DUMPABLE */, 1, 0, 0, 0);
}

/// Fork a child that immediately raises `sig` against itself, then reap.
/// Returns (signalled, coredumped).
unsafe fn fork_and_die_by(sig: i32) -> (bool, bool) {
    let pid = libc::fork();
    if pid == 0 {
        // Child: set default disposition for the signal so it actually kills
        // us (e.g. a parent's SIGQUIT handler must not leak into the child
        // for this test). Then raise.
        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(sig, &sa, core::ptr::null_mut());
        // Also unblock the signal in case the parent had it masked.
        let mut set: libc::sigset_t = core::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, sig);
        libc::sigprocmask(libc::SIG_UNBLOCK, &set, core::ptr::null_mut());
        libc::raise(sig);
        // raise() of a fatal default-disposition signal must not return.
        libc::_exit(99);
    }
    let mut status = 0i32;
    loop {
        let r = libc::wait4(pid, &mut status, 0, core::ptr::null_mut());
        if r == -1 && *libc::__errno_location() == libc::EINTR {
            continue;
        }
        break;
    }
    (libc::WIFSIGNALED(status), libc::WCOREDUMP(status))
}

fn main() {
    unsafe {
        enable_core_dumps();

        // Core-dumping signals: WCOREDUMP must be TRUE.
        let (sigabrt_term, sigabrt_core) = fork_and_die_by(libc::SIGABRT);
        let (sigsegv_term, sigsegv_core) = fork_and_die_by(libc::SIGSEGV);
        let (sigquit_term, sigquit_core) = fork_and_die_by(libc::SIGQUIT);

        // Non-core-dumping signals: WCOREDUMP must be FALSE. SIGTERM and
        // SIGKILL terminate the process but are NOT in the core-dumping set;
        // a synthesized 0x80 bit here would be a false positive.
        let (sigterm_term, sigterm_core) = fork_and_die_by(libc::SIGTERM);
        let (sigkill_term, sigkill_core) = fork_and_die_by(libc::SIGKILL);

        report!(
            sigabrt_wifsignaled = sigabrt_term,
            sigabrt_wcoredump_set = sigabrt_core,
            sigsegv_wifsignaled = sigsegv_term,
            sigsegv_wcoredump_set = sigsegv_core,
            sigquit_wifsignaled = sigquit_term,
            sigquit_wcoredump_set = sigquit_core,
            sigterm_wifsignaled = sigterm_term,
            sigterm_wcoredump_set = sigterm_core,
            sigkill_wifsignaled = sigkill_term,
            sigkill_wcoredump_set = sigkill_core,
        );
    }
}
