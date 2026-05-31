//! Regression: an indefinite `epoll_pwait` must stay reachable after its
//! instance kqueue drains a stale in-memory wake.
//!
//! Reproduces the Node `worker_threads` teardown hang. A libuv loop thread's
//! `epoll_pwait(timeout=-1)` drained a redundant in-memory wake (Carrick fires
//! one on every eventfd 0->nonzero transition, even for a host-backed eventfd),
//! was wrongly classified "all events filtered out", and parked on the signal
//! pipe only — off its epoll kqueue — so the later cross-thread eventfd write
//! that should wake it was lost forever. The thread never exited, the main
//! thread's `pthread_join` of it hung, and the guest never reached `exit_group`.
//!
//!   * `woke_via_eventfd`: a cross-thread eventfd write wakes a blocked
//!     `epoll_pwait(timeout=-1)` promptly, even after a prior write+read primed
//!     (and left pending) an in-memory wake on the epoll instance.
//!
//! A watchdog thread raises SIGUSR1 after 3s, so a regressed (stranded) wait
//! returns via the signal instead of hanging the harness; the probe then prints
//! `false`. On Linux the eventfd write always wakes the wait → `true`.

use std::thread;
use std::time::{Duration, Instant};

const EPOLLIN: u32 = 0x001;

extern "C" fn noop_handler(_sig: libc::c_int) {}

fn main() {
    unsafe { run() }
}

unsafe fn run() {
    // SIGUSR1 handler with no SA_RESTART, so the watchdog can break a stranded
    // (signal-pipe-only) wait with EINTR instead of hanging.
    let mut sa: libc::sigaction = std::mem::zeroed();
    sa.sa_sigaction = noop_handler as usize;
    libc::sigemptyset(&mut sa.sa_mask);
    sa.sa_flags = 0;
    libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());

    let efd = libc::eventfd(0, 0);
    let epfd = libc::epoll_create1(0);
    if efd < 0 || epfd < 0 {
        println!("woke_via_eventfd=false");
        return;
    }
    let mut ev = libc::epoll_event {
        events: EPOLLIN,
        u64: efd as u64,
    };
    libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, efd, &mut ev);

    // Prime a pending in-memory wake on the epoll instance, then clear the
    // eventfd's own readiness: the 0->nonzero write fires the in-memory wake
    // (which the instance kqueue latches), and the read drains the eventfd
    // counter so the fd itself is NOT ready when we block below. No epoll_wait
    // runs in between, so that latched in-memory wake is still pending and gets
    // consumed by the blocking epoll_pwait's pre-wait drain.
    let one: u64 = 1;
    libc::write(efd, &one as *const u64 as *const libc::c_void, 8);
    let mut drain: u64 = 0;
    libc::read(efd, &mut drain as *mut u64 as *mut libc::c_void, 8);

    let pid = libc::getpid();
    let main_tid = libc::syscall(libc::SYS_gettid) as i32;

    // Writer: from another thread, make the eventfd ready after the main thread
    // has reached epoll_pwait.
    let writer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(150));
        let one: u64 = 1;
        unsafe { libc::write(efd, &one as *const u64 as *const libc::c_void, 8) };
    });

    // Watchdog: if the wait is stranded (regression), break it after 3s so the
    // harness never hangs. Thread-directed at the main thread.
    let watchdog = thread::spawn(move || {
        thread::sleep(Duration::from_millis(3000));
        unsafe {
            libc::syscall(libc::SYS_tgkill, pid, main_tid, libc::SIGUSR1);
        }
    });

    let mut out = [libc::epoll_event { events: 0, u64: 0 }; 1];
    let started = Instant::now();
    let ret = libc::epoll_pwait(epfd, out.as_mut_ptr(), 1, -1, std::ptr::null());
    let elapsed = started.elapsed();

    // Woke promptly via the eventfd readiness (not the 3s watchdog signal).
    let woke_via_eventfd =
        ret == 1 && (out[0].events & EPOLLIN) != 0 && elapsed < Duration::from_millis(1500);

    let _ = writer.join();
    let _ = watchdog.join();
    libc::close(epfd);
    libc::close(efd);

    println!("woke_via_eventfd={woke_via_eventfd}");
}
