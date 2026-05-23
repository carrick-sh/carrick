//! Interval-timer probe. Exercises setitimer/getitimer delivery of
//! SIGALRM/SIGVTALRM/SIGPROF on expiry — including the case that bit carrick:
//! a guest BUSY-WAITING (no syscalls) for the signal, and the same inside a
//! forked child. The conformance harness runs this identical static binary
//! under carrick and real Linux and diffs line by line.
//!
//! Deterministic only: NEVER print times/counts/durations. Print only
//! relationships and booleans (e.g. "delivered=true") so output is
//! byte-identical across two correct runs. A broken delivery path turns a
//! `true` into `false` (the spin gives up after a generous wall-clock bound)
//! rather than hanging the harness.

use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static COUNT: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_timer(_sig: i32) {
    COUNT.fetch_add(1, Ordering::SeqCst);
}

fn install_handler(sig: i32) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_timer as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

fn arm(which: i32, usec: i64) -> i32 {
    let it = libc::itimerval {
        it_interval: libc::timeval { tv_sec: 0, tv_usec: usec },
        it_value: libc::timeval { tv_sec: 0, tv_usec: usec },
    };
    unsafe { libc::setitimer(which, &it, std::ptr::null_mut()) }
}

fn disarm(which: i32) {
    let zero = libc::itimerval {
        it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
        it_value: libc::timeval { tv_sec: 0, tv_usec: 0 },
    };
    unsafe {
        libc::setitimer(which, &zero, std::ptr::null_mut());
    }
}

/// Busy-wait (no blocking syscalls in the hot path) until `target` signals have
/// been delivered or a generous wall-clock bound elapses. Returns whether the
/// target was reached. The bound keeps a broken delivery path from hanging.
fn busy_wait_for(target: u32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if COUNT.load(Ordering::SeqCst) >= target {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::hint::spin_loop();
    }
}

fn main() {
    // ITIMER_REAL → SIGALRM, delivered to a busy-waiting process. This is the
    // exact shape of LTP setitimer01: arm a short repeating timer, then spin
    // until several have fired. Requires the signal to preempt the spin.
    install_handler(libc::SIGALRM);
    COUNT.store(0, Ordering::SeqCst);
    let rc = arm(libc::ITIMER_REAL, 2000);
    let real_ok = busy_wait_for(3);
    disarm(libc::ITIMER_REAL);
    println!("itimer_real_arm_rc={rc} busywait_delivered={real_ok}");

    // getitimer readback: a freshly-armed long timer reports a non-zero
    // remaining value and the configured interval; after disarming it reads
    // back zero. (Booleans only — never the raw remaining time.)
    {
        let it = libc::itimerval {
            it_interval: libc::timeval { tv_sec: 7, tv_usec: 0 },
            it_value: libc::timeval { tv_sec: 7, tv_usec: 0 },
        };
        unsafe { libc::setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut()) };
        let mut got = MaybeUninit::<libc::itimerval>::uninit();
        let grc = unsafe { libc::getitimer(libc::ITIMER_REAL, got.as_mut_ptr()) };
        let got = unsafe { got.assume_init() };
        let armed_value_positive = got.it_value.tv_sec > 0 || got.it_value.tv_usec > 0;
        let interval_kept = got.it_interval.tv_sec == 7;
        disarm(libc::ITIMER_REAL);
        let mut z = MaybeUninit::<libc::itimerval>::uninit();
        unsafe { libc::getitimer(libc::ITIMER_REAL, z.as_mut_ptr()) };
        let z = unsafe { z.assume_init() };
        let disarmed_zero = z.it_value.tv_sec == 0 && z.it_value.tv_usec == 0;
        println!(
            "getitimer rc={grc} armed_positive={armed_value_positive} interval_kept={interval_kept} disarmed_zero={disarmed_zero}"
        );
    }

    // ITIMER_VIRTUAL/PROF → SIGVTALRM/SIGPROF, delivered while burning CPU in a
    // spin (carrick approximates these with a wall-clock timer; the spin keeps
    // the CPU busy so both real Linux and carrick fire).
    for (name, which, sig) in [
        ("virtual", libc::ITIMER_VIRTUAL, libc::SIGVTALRM),
        ("prof", libc::ITIMER_PROF, libc::SIGPROF),
    ] {
        install_handler(sig);
        COUNT.store(0, Ordering::SeqCst);
        let rc = arm(which, 2000);
        let ok = busy_wait_for(2);
        disarm(which);
        println!("itimer_{name}_arm_rc={rc} busywait_delivered={ok}");
    }

    // The forking case: a child arms ITIMER_REAL and busy-waits for the signal,
    // then exits 0. The parent reaps it and reports whether it exited cleanly —
    // delivery must work in the forked child (its own signal pump).
    install_handler(libc::SIGALRM);
    let child_ok = unsafe {
        let pid = libc::fork();
        if pid == 0 {
            COUNT.store(0, Ordering::SeqCst);
            arm(libc::ITIMER_REAL, 2000);
            let ok = busy_wait_for(3);
            libc::_exit(if ok { 0 } else { 1 });
        }
        let mut status = 0i32;
        libc::waitpid(pid, &mut status, 0);
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    };
    println!("itimer_fork_child_delivered={child_ok}");
}
