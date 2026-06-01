//! A process-directed signal — `kill(getpid(), sig)` — must be delivered to
//! SOME thread that does not block `sig`, honoring the PER-THREAD signal mask.
//! When the calling thread blocks the signal but a sibling thread leaves it
//! unblocked, Linux runs the handler on the sibling.
//!
//! Carrick delivered a self/process-directed `kill` unconditionally to the
//! CALLING thread (raise_self(ctx_tid)); when that thread had the signal
//! blocked it was merely marked pending there and never routed to the
//! unblocked sibling — so the handler never ran. libuv's signal_multiple_loops
//! relies on exactly this (the main thread blocks all signals, then
//! kill(getpid,SIGUSR1) must run libuv's handler on a worker thread, which
//! fans the wake out to every loop). The result was an indefinite hang.
//!
//!  * delivered_to_unblocked_thread: with SIGUSR1 blocked in the main thread
//!    and unblocked in a worker thread, kill(getpid(),SIGUSR1) causes the
//!    handler to run (the worker observes the handler's pipe write) within the
//!    watchdog window.

use conformance_probes::report;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static PIPE_W: AtomicI32 = AtomicI32::new(-1);
static DELIVERED: AtomicBool = AtomicBool::new(false);

extern "C" fn handler(_sig: libc::c_int) {
    // async-signal-safe: a single raw write to the self-pipe.
    let w = PIPE_W.load(Ordering::Relaxed);
    if w >= 0 {
        let c: u8 = b'x';
        unsafe {
            libc::write(w, &c as *const u8 as *const libc::c_void, 1);
        }
    }
}

fn main() {
    unsafe {
        let mut fds = [0i32; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            report!(setup_ok = false);
            return;
        }
        PIPE_W.store(fds[1], Ordering::Relaxed);
        let read_fd = fds[0];

        // Process-wide handler for SIGUSR1 (no SA_RESTART; EINTR is fine).
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        if libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut()) != 0 {
            report!(setup_ok = false);
            return;
        }

        // Worker spawned BEFORE main blocks SIGUSR1, so it inherits an UNBLOCKED
        // SIGUSR1. It blocks in read() until the handler (which must run on
        // THIS thread, the only unblocked one) writes the self-pipe byte.
        let worker = thread::spawn(move || {
            let mut buf = [0u8; 1];
            loop {
                let n = libc::read(read_fd, buf.as_mut_ptr() as *mut libc::c_void, 1);
                if n == 1 {
                    DELIVERED.store(true, Ordering::Release);
                    return;
                }
                if n < 0 {
                    let e = *libc::__errno_location();
                    if e == libc::EINTR {
                        continue; // handler ran here; retry the read
                    }
                    return;
                }
                return; // EOF/unexpected
            }
        });

        // Let the worker reach its blocking read().
        thread::sleep(Duration::from_millis(120));

        // Block SIGUSR1 in the MAIN (calling) thread only.
        let mut block: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut block);
        libc::sigaddset(&mut block, libc::SIGUSR1);
        libc::pthread_sigmask(libc::SIG_BLOCK, &block, std::ptr::null_mut());

        // Process-directed: must be delivered to the unblocked worker, not the
        // blocked main thread.
        libc::kill(libc::getpid(), libc::SIGUSR1);

        // Watchdog so the probe always terminates with a verdict (never hangs).
        let deadline = Instant::now() + Duration::from_secs(3);
        while !DELIVERED.load(Ordering::Acquire) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }

        report!(delivered_to_unblocked_thread = DELIVERED.load(Ordering::Acquire));

        // The worker may still be parked in read() if delivery failed; don't
        // join (that would hang). Exiting the process reaps it.
        let _ = &worker;
        std::process::exit(0);
    }
}
