//! SP4.2 fixture: child exit -> async SIGCHLD -> guest handler waitpid(WNOHANG).
//!
//! The parent installs an SA_SIGINFO SIGCHLD handler, forks a child that exits
//! 7, and does NOT block in wait4 first. The SIGCHLD handler must run with a
//! Linux-shaped siginfo and must be able to reap the child with waitpid(WNOHANG).
//! That pins the backend contract: the host-side reaper may observe the exit,
//! but it must use WNOWAIT and leave the zombie for guest waitpid.

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

const CLD_EXITED: i32 = 1;

static DELIVERED: AtomicBool = AtomicBool::new(false);
static CHILD_PID: AtomicI32 = AtomicI32::new(-1);
static GOT_SIGNO: AtomicI32 = AtomicI32::new(0);
static GOT_CODE: AtomicI32 = AtomicI32::new(0);
static GOT_PID: AtomicI32 = AtomicI32::new(0);
static REAPED_PID: AtomicI32 = AtomicI32::new(0);
static REAPED_STATUS: AtomicI32 = AtomicI32::new(0);

extern "C" fn sigchld_handler(sig: i32, info: *mut libc::siginfo_t, _uc: *mut libc::c_void) {
    GOT_SIGNO.store(sig, Ordering::SeqCst);
    if !info.is_null() {
        // SAFETY: SA_SIGINFO supplies a valid siginfo pointer.
        unsafe {
            GOT_CODE.store((*info).si_code, Ordering::SeqCst);
            GOT_PID.store((*info).si_pid(), Ordering::SeqCst);
        }
    }

    let child = CHILD_PID.load(Ordering::SeqCst);
    if child > 0 {
        let mut status: libc::c_int = 0;
        // SAFETY: raw waitpid on the known child pid; WNOHANG keeps the handler
        // bounded if delivery races child readiness.
        let reaped = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        REAPED_PID.store(reaped, Ordering::SeqCst);
        REAPED_STATUS.store(status, Ordering::SeqCst);
    }
    DELIVERED.store(true, Ordering::SeqCst);
}

fn die(msg: &[u8], code: i32) -> ! {
    unsafe {
        libc::write(2, msg.as_ptr().cast(), msg.len());
        libc::_exit(code);
    }
}

fn main() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction =
            sigchld_handler as extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void) as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        if libc::sigaction(libc::SIGCHLD, &sa, std::ptr::null_mut()) != 0 {
            die(b"sigaction-failed\n", 2);
        }
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        die(b"fork-failed\n", 3);
    }
    if pid == 0 {
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 50_000_000,
        };
        unsafe {
            libc::nanosleep(&ts, std::ptr::null_mut());
            libc::_exit(7);
        }
    }

    CHILD_PID.store(pid, Ordering::SeqCst);

    let mut spins: u64 = 0;
    while !DELIVERED.load(Ordering::SeqCst) {
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        };
        unsafe {
            libc::nanosleep(&ts, std::ptr::null_mut());
        }
        spins += 1;
        if spins > 10_000 {
            die(b"sigchld-timeout\n", 4);
        }
    }

    if GOT_SIGNO.load(Ordering::SeqCst) != libc::SIGCHLD {
        die(b"sigchld-bad-signo\n", 5);
    }
    if GOT_CODE.load(Ordering::SeqCst) != CLD_EXITED {
        die(b"sigchld-bad-code\n", 6);
    }
    if GOT_PID.load(Ordering::SeqCst) != pid {
        die(b"sigchld-bad-pid\n", 8);
    }
    if REAPED_PID.load(Ordering::SeqCst) != pid {
        die(b"sigchld-not-reaped\n", 9);
    }
    let status = REAPED_STATUS.load(Ordering::SeqCst);
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 7 {
        die(b"sigchld-bad-status\n", 10);
    }

    unsafe {
        libc::write(1, b"sigchld-ok\n".as_ptr().cast(), 11);
        libc::_exit(0);
    }
}
