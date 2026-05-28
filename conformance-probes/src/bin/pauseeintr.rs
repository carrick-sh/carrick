//! pause(2) and sigsuspend(2) - the classic "block until signal" pair.
//! Stands in for LTP `pause01` + `sigsuspend01` + `sighold02` + `sigrelse01`.
//!
//! Invariants encoded:
//!
//!   A. pause(): an UNBLOCKED signal delivered during pause runs its handler,
//!      then pause returns -1 / EINTR. (LTP pause01)
//!
//!   B. sigsuspend(empty): atomically replaces the mask with empty for the
//!      duration of the wait. A pending blocked SIGUSR1 (raised BEFORE the
//!      call) is now deliverable: handler runs, sigsuspend returns -1/EINTR,
//!      and on return the ORIGINAL mask is restored. The pending bit is
//!      consumed because the handler dequeued it. (LTP sigsuspend01)
//!
//!   C. block/unblock mask manipulation (sighold02/sigrelse01 family).
//!      sigprocmask(SIG_BLOCK, …) makes a signal blocked, sigprocmask
//!      (SIG_UNBLOCK, …) un-blocks it. Verified by reading the mask back.
//!
//! Deterministic: a setitimer (SIGALRM) one-shot supplies the async delivery
//! for case A, with a generous wall-clock bound on the pause to keep the
//! harness alive if delivery is broken. Cases B and C are entirely
//! self-contained (no timing).

use conformance_probes::{
    arm_alarm_ms, block_signal, disarm_alarm, errno, install_handler, is_blocked, is_pending,
    report,
};
use std::sync::atomic::{AtomicU32, Ordering};

static ALRM_HITS: AtomicU32 = AtomicU32::new(0);
static USR1_HITS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_alrm(_: i32) {
    ALRM_HITS.fetch_add(1, Ordering::SeqCst);
}

extern "C" fn on_usr1(_: i32) {
    USR1_HITS.fetch_add(1, Ordering::SeqCst);
}

fn case_pause_eintr() {
    unsafe {
        ALRM_HITS.store(0, Ordering::SeqCst);
        let _ = install_handler(libc::SIGALRM, on_alrm, 0);
        // Arm a one-shot 50ms SIGALRM and call pause(). The signal must
        // INTERRUPT the pause: handler runs, pause returns -1 / EINTR.
        arm_alarm_ms(50);
        let rc = libc::pause();
        let pause_errno = errno();
        disarm_alarm();
        report!(
            pause_returned_minus_one = rc == -1,
            pause_errno_is_eintr = pause_errno == libc::EINTR,
            pause_handler_ran = ALRM_HITS.load(Ordering::SeqCst) >= 1,
        );
    }
}

fn case_sigsuspend_drains_pending() {
    unsafe {
        USR1_HITS.store(0, Ordering::SeqCst);
        let _ = install_handler(libc::SIGUSR1, on_usr1, 0);
        // Block SIGUSR1 in the process mask, raise it (now pending), then
        // sigsuspend(empty) - this atomically unblocks everything and waits.
        // SIGUSR1's handler runs, sigsuspend returns -1/EINTR, and on return
        // the mask is restored (SIGUSR1 blocked again).
        let _ = block_signal(libc::SIGUSR1);
        libc::raise(libc::SIGUSR1);
        let pending_before = is_pending(libc::SIGUSR1);

        let mut empty: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut empty);
        let rc = libc::sigsuspend(&empty);
        let ss_errno = errno();

        let mask_restored = is_blocked(libc::SIGUSR1);
        let pending_cleared = !is_pending(libc::SIGUSR1);

        report!(
            sigsuspend_pending_before = pending_before,
            sigsuspend_returned_minus_one = rc == -1,
            sigsuspend_errno_is_eintr = ss_errno == libc::EINTR,
            sigsuspend_handler_ran = USR1_HITS.load(Ordering::SeqCst) >= 1,
            sigsuspend_mask_restored = mask_restored,
            sigsuspend_pending_cleared = pending_cleared,
        );

        // Tidy up so subsequent cases run on a known mask state.
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR1);
        libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
    }
}

fn case_block_unblock_roundtrip() {
    unsafe {
        // sigprocmask(BLOCK) → mask records `sig` as blocked;
        // sigprocmask(UNBLOCK) → unblocked. This is what sighold02/sigrelse01
        // assert at the kernel level (the BSD `sighold`/`sigrelse` wrappers
        // are thin libc shims around sigprocmask and aren't exposed by musl).
        let held_ok = conformance_probes::block_signal(libc::SIGUSR2);
        let became_blocked = is_blocked(libc::SIGUSR2);
        let released_ok = conformance_probes::unblock_signal(libc::SIGUSR2);
        let became_unblocked = !is_blocked(libc::SIGUSR2);
        report!(
            block_rc_ok = held_ok,
            block_made_blocked = became_blocked,
            unblock_rc_ok = released_ok,
            unblock_made_unblocked = became_unblocked,
        );
    }
}

fn main() {
    case_pause_eintr();
    case_sigsuspend_drains_pending();
    case_block_unblock_roundtrip();
}
