//! Pending-signal delivery on unblock, end-to-end through the real
//! rt_sigprocmask/kill/handler syscall path (the lib test covers the
//! dispatcher's queue/coalesce logic; this covers the guest-visible syscall
//! behaviour). Linux: while a signal is blocked, repeated sends of a STANDARD
//! signal COALESCE (N sends -> 1 delivery on unblock), while a REAL-TIME signal
//! QUEUES (N sends -> N deliveries). carrick has no host RT signals, so it must
//! emulate the queue; this pins that it matches Linux. Deterministic counts.

use std::sync::atomic::{AtomicU32, Ordering};

static STD: AtomicU32 = AtomicU32::new(0);
static RT: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_std(_: i32) {
    STD.fetch_add(1, Ordering::SeqCst);
}
extern "C" fn on_rt(_: i32) {
    RT.fetch_add(1, Ordering::SeqCst);
}

unsafe fn install(sig: i32, h: extern "C" fn(i32)) {
    let mut sa: libc::sigaction = std::mem::zeroed();
    sa.sa_sigaction = h as usize;
    sa.sa_flags = 0;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(sig, &sa, std::ptr::null_mut());
}

unsafe fn set_blocked(sig: i32, block: bool) {
    let mut set: libc::sigset_t = std::mem::zeroed();
    libc::sigemptyset(&mut set);
    libc::sigaddset(&mut set, sig);
    let how = if block { libc::SIG_BLOCK } else { libc::SIG_UNBLOCK };
    libc::sigprocmask(how, &set, std::ptr::null_mut());
}

fn main() {
    unsafe {
        let std_sig = libc::SIGUSR1;
        let rt_sig = libc::SIGRTMIN(); // first real-time signal (musl)
        install(std_sig, on_std);
        install(rt_sig, on_rt);

        // Block both, then send each 3x while blocked (they accumulate).
        set_blocked(std_sig, true);
        set_blocked(rt_sig, true);
        for _ in 0..3 {
            libc::raise(std_sig);
            libc::raise(rt_sig);
        }

        // Unblock: the kernel delivers all pending-unblocked signals before
        // sigprocmask returns — standard coalesced to one, RT all three.
        set_blocked(std_sig, false);
        set_blocked(rt_sig, false);

        println!("standard_coalesced_to_one={}", STD.load(Ordering::SeqCst) == 1);
        println!("realtime_queued_all_three={}", RT.load(Ordering::SeqCst) == 3);
    }
}
