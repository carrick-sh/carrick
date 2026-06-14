//! SP4.2 fixture: cross-process `kill()` of SIGUSR2 to another guest PID.
//!
//! A second host-kill cross-process proof, distinct from `bhyve-crosssig`
//! (SIGUSR1): SIGUSR2 is Linux 12 -> FreeBSD 31, so it exercises a DIFFERENT entry
//! of the FreeBSD linux<->host signum table than SIGUSR1 (Linux 10 -> FreeBSD 30),
//! catching a one-off signum mistranslation that a single-signal test would miss.
//!
//! The parent forks a child; the child installs an `SA_SIGINFO` SIGUSR2 handler
//! and waits; the parent (after a ~250ms delay so the install cannot race the
//! kill) `kill(child, SIGUSR2)`s it. The child handler must fire with
//! `si_signo == SIGUSR2` AND `si_pid == the parent's pid` -> "crossusr2-ok";
//! the parent then wait4s the child to exit 0 and prints "crossusr2-parent-ok".
//!
//! RED on the pre-SP4.2 binary: bhyve's host-disposition mirror / pump were no-ops
//! and the signum table was identity (host SIGUSR2 = 12 = FreeBSD SIGSYS), so the
//! parent's kill either mis-numbered or never reached the child's guest handler.
//! Static x86_64-unknown-linux-musl (non-PIE ET_EXEC).
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

static DELIVERED: AtomicBool = AtomicBool::new(false);
static GOT_SIGNO: AtomicI32 = AtomicI32::new(0);
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
        // ---- CHILD ---- install the SIGUSR2 handler FIRST (time-delay handshake).
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction =
                handler as extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void) as usize;
            sa.sa_flags = libc::SA_SIGINFO;
            libc::sigemptyset(&mut sa.sa_mask);
            if libc::sigaction(libc::SIGUSR2, &sa, std::ptr::null_mut()) != 0 {
                die(b"child-sigaction-failed\n", 12);
            }
        }
        let mut spins: u64 = 0;
        while !DELIVERED.load(Ordering::SeqCst) {
            let ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 1_000_000,
            };
            unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
            spins += 1;
            if spins > 10_000 {
                die(b"crossusr2-timeout\n", 14);
            }
        }
        let signo = GOT_SIGNO.load(Ordering::SeqCst);
        if signo != libc::SIGUSR2 {
            die(b"crossusr2-bad-signo\n", 15);
        }
        let sender = GOT_SENDER.load(Ordering::SeqCst);
        let parent = unsafe { libc::getppid() };
        if sender != parent {
            die(b"crossusr2-bad-sender\n", 16);
        }
        unsafe {
            libc::write(1, b"crossusr2-ok\n".as_ptr() as *const _, 13);
            libc::_exit(0);
        }
    }

    // ---- PARENT ---- let the child install its handler + reach its wait loop.
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 250_000_000,
    };
    unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
    if unsafe { libc::kill(pid, libc::SIGUSR2) } != 0 {
        die(b"parent-kill-failed\n", 21);
    }
    let mut status: libc::c_int = 0;
    let w = unsafe { libc::wait4(pid, &mut status, 0, std::ptr::null_mut()) };
    if w != pid {
        die(b"crossusr2-wait4-mismatch\n", 22);
    }
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    if code != 0 {
        die(b"crossusr2-child-nonzero\n", 23);
    }
    unsafe {
        libc::write(1, b"crossusr2-parent-ok\n".as_ptr() as *const _, 20);
        libc::_exit(0);
    }
}
