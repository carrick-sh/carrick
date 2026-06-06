//! ITIMER_PROF CPU-time semantics. A profiler timer must tick while the process
//! consumes CPU, and must not tick while the process is idle in a blocking
//! sleep. The existing `itimer` probe owns the busy-delivery side; this probe
//! owns the missing idle side behind Go runtime/pprof's CPU sample magnitude
//! check: wall-clock timer delivery overcounts idle time.

use std::sync::atomic::{AtomicU32, Ordering};
static PROF_TICKS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_prof(_sig: i32) {
    PROF_TICKS.fetch_add(1, Ordering::SeqCst);
}

fn install_prof_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_prof as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGPROF, &sa, std::ptr::null_mut());
    }
}

fn arm_prof(usec: i64) -> i32 {
    let it = libc::itimerval {
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: usec,
        },
        it_value: libc::timeval {
            tv_sec: 0,
            tv_usec: usec,
        },
    };
    unsafe { libc::setitimer(libc::ITIMER_PROF, &it, std::ptr::null_mut()) }
}

fn disarm_prof() {
    let zero = libc::itimerval {
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
    };
    unsafe {
        libc::setitimer(libc::ITIMER_PROF, &zero, std::ptr::null_mut());
    }
}

fn ignore_prof() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_IGN;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGPROF, &sa, std::ptr::null_mut());
    }
}

fn main() {
    install_prof_handler();

    PROF_TICKS.store(0, Ordering::SeqCst);
    let idle_arm_rc = arm_prof(20_000);
    let req = libc::timespec {
        tv_sec: 0,
        tv_nsec: 250_000_000,
    };
    let mut rem = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::nanosleep(&req, &mut rem);
    }
    disarm_prof();
    ignore_prof();
    let idle_ticks = PROF_TICKS.load(Ordering::SeqCst);

    println!("prof_idle_arm_rc_zero={}", idle_arm_rc == 0);
    println!("prof_idle_no_ticks={}", idle_ticks == 0);
}
