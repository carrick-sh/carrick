//! waitrestart: when a signal interrupts a BLOCKING `wait4`, does carrick match
//! Linux's restart semantics? This is the framework-level blocker behind nearly
//! the whole LTP sweep: LTP's `tst_test` parent reaps its test child with
//! `SAFE_WAITPID(pid, &st, 0)`, and the test processes install SA_RESTART
//! handlers (SIGALRM/SIGUSR1 heartbeat+timeout). A signal landing during that
//! reap must RESTART the wait on Linux, not surface EINTR.
//!
//! Three deterministic scenarios (booleans only — byte-identical across two
//! correct runs; every wait is bounded by a child that exits, so a broken path
//! prints `false` instead of hanging):
//!   A  SA_RESTART handler fires mid-wait  -> wait restarts, reaps child (no EINTR)
//!   B  non-SA_RESTART handler fires mid-wait -> wait returns -1/EINTR (both agree)
//!   C  awaited child's own exit (with a non-SA_RESTART SIGCHLD handler installed)
//!      -> wait returns the child, never a spurious EINTR

use std::sync::atomic::{AtomicU32, Ordering};

static ALRM: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_alrm(_: i32) {
    ALRM.fetch_add(1, Ordering::SeqCst);
}
extern "C" fn on_chld(_: i32) {}

unsafe fn install(sig: i32, h: extern "C" fn(i32), flags: i32) {
    let mut sa: libc::sigaction = std::mem::zeroed();
    sa.sa_sigaction = h as usize;
    sa.sa_flags = flags;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(sig, &sa, std::ptr::null_mut());
}

unsafe fn arm_alarm_ms(ms: i64) {
    let it = libc::itimerval {
        it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
        it_value: libc::timeval {
            tv_sec: ms / 1000,
            tv_usec: (ms % 1000) * 1000,
        },
    };
    libc::setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut());
}

unsafe fn disarm_alarm() {
    let it: libc::itimerval = std::mem::zeroed();
    libc::setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut());
}

unsafe fn sleep_ms(ms: i64) {
    let ts = libc::timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * 1_000_000,
    };
    libc::nanosleep(&ts, std::ptr::null_mut());
}

/// Bounded blocking reap (loops past EINTR) so a scenario leaves no zombie.
unsafe fn reap(pid: i32) {
    loop {
        let mut st = 0i32;
        let r = libc::wait4(pid, &mut st, 0, std::ptr::null_mut());
        if r == -1 && *libc::__errno_location() == libc::EINTR {
            continue;
        }
        break;
    }
}

fn main() {
    unsafe {
        // A: SA_RESTART handler interrupts a blocking wait4. The child sleeps
        // 800ms; the alarm fires at 200ms while the parent is parked in wait4.
        // Linux restarts the wait (SA_RESTART), reaps the child, returns pid.
        install(libc::SIGALRM, on_alrm, libc::SA_RESTART);
        ALRM.store(0, Ordering::SeqCst);
        let a = {
            let pid = libc::fork();
            if pid == 0 {
                sleep_ms(800);
                libc::_exit(0);
            }
            arm_alarm_ms(200);
            let mut st = 0i32;
            let r = libc::wait4(pid, &mut st, 0, std::ptr::null_mut());
            disarm_alarm();
            let ok = r == pid && ALRM.load(Ordering::SeqCst) >= 1;
            if r != pid {
                reap(pid);
            }
            ok
        };
        println!("A_restart_reaps_child={a}");

        // B: NON-SA_RESTART handler interrupts a blocking wait4 -> EINTR. Both
        // Linux and carrick must agree (this is the case carrick already gets
        // right); it pins that the fix doesn't over-restart.
        install(libc::SIGALRM, on_alrm, 0);
        ALRM.store(0, Ordering::SeqCst);
        let b = {
            let pid = libc::fork();
            if pid == 0 {
                sleep_ms(800);
                libc::_exit(0);
            }
            arm_alarm_ms(200);
            let mut st = 0i32;
            let r = libc::wait4(pid, &mut st, 0, std::ptr::null_mut());
            let e = *libc::__errno_location();
            disarm_alarm();
            let got_eintr = r == -1 && e == libc::EINTR;
            reap(pid);
            got_eintr
        };
        println!("B_norestart_eintr={b}");

        // C: the awaited child's OWN exit must not spuriously EINTR, even with a
        // non-SA_RESTART SIGCHLD handler installed. Child exits at 200ms while
        // the parent is parked; Linux returns the child.
        install(libc::SIGCHLD, on_chld, 0);
        let c = {
            let pid = libc::fork();
            if pid == 0 {
                sleep_ms(200);
                libc::_exit(0);
            }
            let mut st = 0i32;
            let r = libc::wait4(pid, &mut st, 0, std::ptr::null_mut());
            if r != pid {
                reap(pid);
            }
            r == pid
        };
        println!("C_child_exit_no_eintr={c}");
    }
}
