//! Two DISTINCT process-directed signals delivered back-to-back must BOTH
//! reach a handler, even when they route to the same thread. `kill(getpid(),
//! SIGUSR1)` then `kill(getpid(), SIGUSR2)` with both blocked in the calling
//! thread and unblocked in one worker thread: Linux holds both pending for the
//! worker and runs both handlers.
//!
//! Carrick's per-tid pending slot held only ONE signum per thread (last write
//! wins), so routing two distinct process-directed signals to the same worker
//! coalesced them — the first (SIGUSR1) was overwritten by the second
//! (SIGUSR2) before delivery and its handler never ran. This is the residual
//! race that hung libuv's signal_multiple_loops: the threads waiting on the
//! dropped signal never woke. (Confirmed via carrick trace: two
//! signal-publish for one tid, one signal-deliver.)
//!
//!  * both_signals_delivered_every_round: over many rounds of the two-kill
//!    sequence, BOTH handlers ran every time (no coalescing loss). The single
//!    worker forces both signals onto one tid, the exact coalescing condition.

use conformance_probes::report;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static GOT1: AtomicBool = AtomicBool::new(false);
static GOT2: AtomicBool = AtomicBool::new(false);
static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn h1(_s: libc::c_int) {
    GOT1.store(true, Ordering::Release);
}
extern "C" fn h2(_s: libc::c_int) {
    GOT2.store(true, Ordering::Release);
}

fn install(sig: libc::c_int, h: extern "C" fn(libc::c_int)) -> bool {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = h as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0; // no SA_RESTART: EINTR is fine, the worker re-loops
        libc::sigaction(sig, &sa, std::ptr::null_mut()) == 0
    }
}

fn main() {
    unsafe {
        if !install(libc::SIGUSR1, h1) || !install(libc::SIGUSR2, h2) {
            report!(setup_ok = false);
            return;
        }

        // ONE worker, spawned before main blocks the signals, so it inherits an
        // UNBLOCKED SIGUSR1+SIGUSR2. Both process-directed signals therefore
        // route to this single tid — the coalescing condition. It stays
        // interruptible in a short nanosleep loop so handlers fire on it.
        let worker = thread::spawn(|| {
            while !STOP.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(1));
            }
        });
        thread::sleep(Duration::from_millis(120));

        // Block both in the main (calling) thread only.
        let mut block: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut block);
        libc::sigaddset(&mut block, libc::SIGUSR1);
        libc::sigaddset(&mut block, libc::SIGUSR2);
        libc::pthread_sigmask(libc::SIG_BLOCK, &block, std::ptr::null_mut());

        const ROUNDS: usize = 100;
        let mut fails = 0usize;
        for _ in 0..ROUNDS {
            GOT1.store(false, Ordering::Release);
            GOT2.store(false, Ordering::Release);
            // Back-to-back: both land before the worker can consume the first,
            // so both target the same per-tid pending slot.
            libc::kill(libc::getpid(), libc::SIGUSR1);
            libc::kill(libc::getpid(), libc::SIGUSR2);
            let deadline = Instant::now() + Duration::from_millis(60);
            while !(GOT1.load(Ordering::Acquire) && GOT2.load(Ordering::Acquire))
                && Instant::now() < deadline
            {
                thread::sleep(Duration::from_millis(1));
            }
            if !(GOT1.load(Ordering::Acquire) && GOT2.load(Ordering::Acquire)) {
                fails += 1;
            }
            // small gap so a late delivery can't bleed into the next round
            thread::sleep(Duration::from_millis(2));
        }
        // stderr (not compared) — the magnitude isn't portable, only the invariant
        eprintln!("rounds={ROUNDS} fails={fails}");

        report!(both_signals_delivered_every_round = fails == 0);

        STOP.store(true, Ordering::Release);
        let _ = worker.join();
    }
}
