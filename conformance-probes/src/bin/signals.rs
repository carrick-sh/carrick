//! Signal-handling probe. Exercises rt_sigprocmask/rt_sigaction/sigaltstack/
//! sigpending/kill/rt_sigtimedwait syscalls and prints one labelled line per
//! observation. The conformance harness runs this identical static binary
//! under carrick and real Linux and diffs line by line — a divergent line
//! names the exact failing syscall.
//!
//! Deterministic only: no timestamps, pids, or addresses. All observations are
//! booleans, counts, signal numbers, or errnos. Single-threaded; all signals
//! are blocked or handled before being raised so the process is never killed.

use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};

static HANDLER_RAN: AtomicBool = AtomicBool::new(false);

extern "C" fn handler(_sig: libc::c_int) {
    HANDLER_RAN.store(true, Ordering::SeqCst);
}

fn main() {
    // rt_sigprocmask: block SIGUSR1 (SIG_BLOCK), read mask back (SIG_SETMASK
    // with NULL set, oldset out), report membership; then unblock and report
    // absence.
    {
        let mut set: libc::sigset_t = unsafe { MaybeUninit::zeroed().assume_init() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGUSR1);
        }
        let rc = unsafe {
            libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut())
        };
        if rc != 0 {
            println!("sigprocmask_block=ERR:{}", errno());
        } else {
            // Read the current mask: pass NULL set, capture oldset.
            let mut cur: libc::sigset_t = unsafe { MaybeUninit::zeroed().assume_init() };
            let rrc = unsafe {
                libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut cur)
            };
            if rrc != 0 {
                println!("sigprocmask_read=ERR:{}", errno());
            } else {
                let member = unsafe { libc::sigismember(&cur, libc::SIGUSR1) };
                println!("sigprocmask_usr1_blocked={}", member == 1);
            }
        }

        // Unblock SIGUSR1 and confirm it is absent from the mask.
        let mut set2: libc::sigset_t = unsafe { MaybeUninit::zeroed().assume_init() };
        unsafe {
            libc::sigemptyset(&mut set2);
            libc::sigaddset(&mut set2, libc::SIGUSR1);
        }
        let urc = unsafe {
            libc::sigprocmask(libc::SIG_UNBLOCK, &set2, std::ptr::null_mut())
        };
        if urc != 0 {
            println!("sigprocmask_unblock=ERR:{}", errno());
        } else {
            let mut cur: libc::sigset_t = unsafe { MaybeUninit::zeroed().assume_init() };
            unsafe {
                libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut cur);
            }
            let member = unsafe { libc::sigismember(&cur, libc::SIGUSR1) };
            println!("sigprocmask_usr1_absent={}", member == 0);
        }
    }

    // rt_sigaction: install a handler for SIGUSR1 that sets a flag, raise it,
    // report whether the handler ran; then restore SIG_DFL and report rc.
    {
        let mut act: libc::sigaction = unsafe { MaybeUninit::zeroed().assume_init() };
        act.sa_sigaction = handler as *const () as usize;
        unsafe { libc::sigemptyset(&mut act.sa_mask) };
        act.sa_flags = 0;
        let rc = unsafe {
            libc::sigaction(libc::SIGUSR1, &act, std::ptr::null_mut())
        };
        if rc != 0 {
            println!("sigaction_install=ERR:{}", errno());
        } else {
            HANDLER_RAN.store(false, Ordering::SeqCst);
            unsafe { libc::raise(libc::SIGUSR1) };
            println!("sigaction_handler_ran={}", HANDLER_RAN.load(Ordering::SeqCst));
        }

        // Restore default disposition.
        let mut dfl: libc::sigaction = unsafe { MaybeUninit::zeroed().assume_init() };
        dfl.sa_sigaction = libc::SIG_DFL;
        unsafe { libc::sigemptyset(&mut dfl.sa_mask) };
        dfl.sa_flags = 0;
        let drc = unsafe {
            libc::sigaction(libc::SIGUSR1, &dfl, std::ptr::null_mut())
        };
        println!("sigaction_restore_rc={}", drc);
    }

    // rt_sigaction with SIG_IGN for SIGUSR2: raise it, confirm the process
    // survives (the ignored signal is discarded).
    {
        let mut ign: libc::sigaction = unsafe { MaybeUninit::zeroed().assume_init() };
        ign.sa_sigaction = libc::SIG_IGN;
        unsafe { libc::sigemptyset(&mut ign.sa_mask) };
        ign.sa_flags = 0;
        let rc = unsafe {
            libc::sigaction(libc::SIGUSR2, &ign, std::ptr::null_mut())
        };
        if rc != 0 {
            println!("sigaction_ign_usr2=ERR:{}", errno());
        } else {
            unsafe { libc::raise(libc::SIGUSR2) };
            // Reaching here means the ignored signal did not terminate us.
            println!("sigign_usr2_survived={}", true);
        }
        // Restore default for SIGUSR2 to keep later state clean.
        let mut dfl: libc::sigaction = unsafe { MaybeUninit::zeroed().assume_init() };
        dfl.sa_sigaction = libc::SIG_DFL;
        unsafe { libc::sigemptyset(&mut dfl.sa_mask) };
        unsafe { libc::sigaction(libc::SIGUSR2, &dfl, std::ptr::null_mut()) };
    }

    // sigaltstack: set an alternate signal stack, read it back, confirm the
    // reported ss_size matches what we set.
    {
        const ALT_SIZE: usize = libc::SIGSTKSZ;
        let mut stack_mem = vec![0u8; ALT_SIZE];
        let ss = libc::stack_t {
            ss_sp: stack_mem.as_mut_ptr() as *mut libc::c_void,
            ss_flags: 0,
            ss_size: ALT_SIZE,
        };
        let rc = unsafe { libc::sigaltstack(&ss, std::ptr::null_mut()) };
        if rc != 0 {
            println!("sigaltstack_set=ERR:{}", errno());
        } else {
            let mut got: libc::stack_t = unsafe { MaybeUninit::zeroed().assume_init() };
            let grc = unsafe { libc::sigaltstack(std::ptr::null(), &mut got) };
            if grc != 0 {
                println!("sigaltstack_get=ERR:{}", errno());
            } else {
                println!("sigaltstack_size_match={}", got.ss_size == ALT_SIZE);
                println!("sigaltstack_rc={}", grc);
            }
        }
        // Disable the alternate stack so the backing Vec can be freed safely.
        let disable = libc::stack_t {
            ss_sp: std::ptr::null_mut(),
            ss_flags: libc::SS_DISABLE,
            ss_size: 0,
        };
        unsafe { libc::sigaltstack(&disable, std::ptr::null_mut()) };
    }

    // sigpending: block SIGUSR1, raise it (so it stays pending), query
    // sigpending, report membership; then unblock to deliver/discard it.
    {
        let mut set: libc::sigset_t = unsafe { MaybeUninit::zeroed().assume_init() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGUSR1);
        }
        // Ensure SIGUSR1 is at default disposition so an unintended delivery
        // would be visible, but it stays blocked while we test pending.
        let mut dfl: libc::sigaction = unsafe { MaybeUninit::zeroed().assume_init() };
        dfl.sa_sigaction = libc::SIG_IGN;
        unsafe { libc::sigemptyset(&mut dfl.sa_mask) };
        unsafe { libc::sigaction(libc::SIGUSR1, &dfl, std::ptr::null_mut()) };

        let brc = unsafe {
            libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut())
        };
        if brc != 0 {
            println!("sigpending=ERR:{}", errno());
        } else {
            unsafe { libc::raise(libc::SIGUSR1) };
            let mut pend: libc::sigset_t = unsafe { MaybeUninit::zeroed().assume_init() };
            let prc = unsafe { libc::sigpending(&mut pend) };
            if prc != 0 {
                println!("sigpending=ERR:{}", errno());
            } else {
                let member = unsafe { libc::sigismember(&pend, libc::SIGUSR1) };
                println!("sigpending_usr1={}", member == 1);
            }
            // Unblock to deliver (SIG_IGN discards it harmlessly).
            unsafe {
                libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
            }
        }
    }

    // kill(getpid(), 0): existence check; rc 0 means the process exists.
    {
        let rc = unsafe { libc::kill(libc::getpid(), 0) };
        println!("kill_self_sig0_rc={}", rc);
    }

    // rt_sigtimedwait: block SIGUSR1, raise it, wait with a short timeout, and
    // report the returned signal number (should be SIGUSR1).
    {
        let mut set: libc::sigset_t = unsafe { MaybeUninit::zeroed().assume_init() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGUSR1);
        }
        let brc = unsafe {
            libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut())
        };
        if brc != 0 {
            println!("sigtimedwait=ERR:{}", errno());
        } else {
            unsafe { libc::raise(libc::SIGUSR1) };
            let mut info: libc::siginfo_t = unsafe { MaybeUninit::zeroed().assume_init() };
            let ts = libc::timespec {
                tv_sec: 1,
                tv_nsec: 0,
            };
            let signo = unsafe { libc::sigtimedwait(&set, &mut info, &ts) };
            if signo < 0 {
                println!("sigtimedwait=ERR:{}", errno());
            } else {
                println!("sigtimedwait_signo={}", signo);
            }
            unsafe {
                libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
            }
        }
    }
}

/// Current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}
