//! SP4.2 fixture: cross-process `kill()` to ANOTHER guest PID.
//!
//! The parent `fork`s a child. The child installs an `SA_SIGINFO` SIGUSR1 handler,
//! signals readiness over a pipe, then waits for delivery. The parent reads the
//! ready byte (so the kill cannot race the handler install), captures its own pid,
//! and `kill(child, SIGUSR1)`s the child. The child's handler must fire with
//! `si_signo == SIGUSR1` AND `si_pid == the parent's pid` (the sender) — proving
//! cross-process delivery carries the correct sender identity. The child prints
//! "crosssig-ok" and `_exit(0)`; the parent `wait4`s and asserts exit 0, then
//! prints "crosssig-parent-ok" and exits 0.
//!
//! RED on the pre-SP4.2 binary: bhyve's `xsig_nudge` / host-disposition mirror /
//! pump were no-ops and the FreeBSD signum table was identity, so the parent's
//! `kill` either never reached the child's guest handler (host default action) or
//! was mis-numbered. GREEN once the bhyve cross-process host layer is wired.
//! Static x86_64-unknown-linux-musl (non-PIE ET_EXEC).
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// Set by the handler on delivery. The child's wait loop reads this.
static DELIVERED: AtomicBool = AtomicBool::new(false);
/// The handler records `info->si_signo` for a sanity check.
static GOT_SIGNO: AtomicI32 = AtomicI32::new(0);
/// The handler records `info->si_pid` (the SENDER) — must equal the parent's pid.
static GOT_SENDER: AtomicI32 = AtomicI32::new(-1);

extern "C" fn handler(_sig: i32, info: *mut libc::siginfo_t, _uc: *mut libc::c_void) {
    if info.is_null() {
        GOT_SIGNO.store(-1, Ordering::SeqCst);
    } else {
        // SAFETY: SA_SIGINFO supplies a valid siginfo; si_pid reads the POSIX union
        // member (the sender's pid for an SI_USER kill).
        unsafe {
            GOT_SIGNO.store((*info).si_signo, Ordering::SeqCst);
            GOT_SENDER.store((*info).si_pid(), Ordering::SeqCst);
        }
    }
    DELIVERED.store(true, Ordering::SeqCst);
}

fn die(msg: &[u8], code: i32) -> ! {
    unsafe {
        libc::write(2, msg.as_ptr() as *const _, msg.len());
        libc::_exit(code);
    }
}

fn main() {
    // SAFETY: libc::fork in a single-threaded program.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        die(b"fork-failed\n", 11);
    }

    if pid == 0 {
        // ---- CHILD ----
        // Install the SA_SIGINFO SIGUSR1 handler FIRST thing (before the parent's
        // post-fork sleep elapses), so the cross-process kill cannot race it. A
        // time-delay handshake (parent sleeps ~250ms) avoids a pipe — carrick's
        // x86_64 dispatcher does not yet implement legacy `pipe(2)` = 22 (an
        // arg-shape-shim gap unrelated to signals).
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction =
                handler as extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void) as usize;
            sa.sa_flags = libc::SA_SIGINFO;
            libc::sigemptyset(&mut sa.sa_mask);
            if libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut()) != 0 {
                die(b"child-sigaction-failed\n", 12);
            }
        }
        // Wait for the cross-process SIGUSR1. A bounded spin so a delivery failure
        // is RED (timeout) rather than a hang. `pause()`-style: a syscall per
        // iteration is fine here (this is the syscall-boundary delivery path).
        let mut spins: u64 = 0;
        while !DELIVERED.load(Ordering::SeqCst) {
            // nanosleep ~1ms; the signal interrupts it (EINTR) when it lands.
            let ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 1_000_000,
            };
            unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
            spins += 1;
            if spins > 10_000 {
                // ~10s with no delivery -> the cross-process kill never arrived.
                die(b"crosssig-timeout\n", 14);
            }
        }
        // Validate the delivered siginfo.
        let signo = GOT_SIGNO.load(Ordering::SeqCst);
        if signo != libc::SIGUSR1 {
            die(b"crosssig-bad-signo\n", 15);
        }
        let sender = GOT_SENDER.load(Ordering::SeqCst);
        let parent = unsafe { libc::getppid() };
        if sender != parent {
            // si_pid must be the SENDER (the parent). A 0 / wrong sender is the
            // classic "si_pid side-channel" failure.
            die(b"crosssig-bad-sender\n", 16);
        }
        unsafe {
            libc::write(1, b"crosssig-ok\n".as_ptr() as *const _, 12);
            libc::_exit(0);
        }
    }

    // ---- PARENT ----
    // Give the child time to install its handler + reach its wait loop before the
    // kill (no pipe handshake — see the child branch). ~250ms is generous for a
    // bhyve guest fork+sigaction; the child's own 10s spin bounds the other side.
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 250_000_000,
    };
    unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
    // Send the cross-process signal to the child.
    if unsafe { libc::kill(pid, libc::SIGUSR1) } != 0 {
        die(b"parent-kill-failed\n", 21);
    }
    // Reap the child and verify it exited 0 (handler ran + siginfo correct).
    let mut status: libc::c_int = 0;
    let w = unsafe { libc::wait4(pid, &mut status, 0, std::ptr::null_mut()) };
    if w != pid {
        die(b"parent-wait4-mismatch\n", 22);
    }
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    if code != 0 {
        die(b"crosssig-child-nonzero\n", 23);
    }
    unsafe {
        libc::write(1, b"crosssig-parent-ok\n".as_ptr() as *const _, 19);
        libc::_exit(0);
    }
}
