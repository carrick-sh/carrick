//! select / pselect timeout & wakeup semantics. Stands in for LTP `select01`,
//! `select02`, `select03`, and `pselect02`.
//!
//! Invariants encoded (booleans only — no timestamps, fds, durations):
//!
//!   1. `select(0, NULL, NULL, NULL, {0, 10_000})` (no fds, 10 ms timeout)
//!      returns 0 and is bounded — the wait completes well under 1 s of wall
//!      clock. (select01 — the bare-timeout wait path.)
//!
//!   2. `select` with a ready pipe in `readfds` returns 1 with the pipe's fd
//!      bit set; the timeout was not exhausted (data was immediately
//!      available). (select02 — fd-ready path.)
//!
//!   3. `select` with a non-ready pipe and a short timeout returns 0 after
//!      the timeout elapses; no fds become readable. (select03 — fd-not-ready
//!      path.)
//!
//!   4. `pselect(0, NULL, NULL, NULL, {0, 10ms}, NULL)` with a NULL sigmask
//!      mirrors invariant 1: returns 0 within the wall-clock bound. The NULL
//!      sigmask leaves the caller's mask unchanged. (pselect02 — basic.)
//!
//!   5. `pselect` with the sigmask BLOCKING SIGALRM: a one-shot alarm fires
//!      mid-wait but stays pending while pselect blocks, so the wait times
//!      out → rc 0. After return the original mask is restored and the
//!      blocked signal is still pending.
//!
//!   6. `pselect` with a NULL sigmask, an installed SIGALRM handler, and an
//!      alarm armed mid-wait: the signal interrupts the wait → rc -1,
//!      errno == EINTR, the handler ran.
//!
//! Deterministic: every wait has a wall-clock bound under 1 second so a
//! broken delivery path turns a `true` into `false` rather than hanging the
//! harness.

use conformance_probes::{
    arm_alarm_ms, block_signal, disarm_alarm, errno, install_handler, is_blocked, is_pending,
    pipe2, report, unblock_signal,
};
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicU32, Ordering};

static ALRM_HITS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_alrm(_: i32) {
    ALRM_HITS.fetch_add(1, Ordering::SeqCst);
}

/// Wall-clock elapsed time between two CLOCK_MONOTONIC reads, in milliseconds.
fn elapsed_ms_since(start: &libc::timespec) -> i64 {
    let mut now: libc::timespec = unsafe { MaybeUninit::zeroed().assume_init() };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now);
    }
    let sec = (now.tv_sec - start.tv_sec) as i64;
    let nsec = (now.tv_nsec - start.tv_nsec) as i64;
    sec * 1000 + nsec / 1_000_000
}

fn now_monotonic() -> libc::timespec {
    let mut ts: libc::timespec = unsafe { MaybeUninit::zeroed().assume_init() };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    ts
}

fn case_select_bare_timeout() {
    unsafe {
        let mut tv = libc::timeval { tv_sec: 0, tv_usec: 10_000 };
        let start = now_monotonic();
        let rc = libc::select(
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut tv,
        );
        let bounded = elapsed_ms_since(&start) < 1_000;
        report!(
            select_bare_timeout_rc_zero = rc == 0,
            select_bare_timeout_bounded = bounded,
        );
    }
}

fn case_select_pipe_ready() {
    unsafe {
        let (rd, wr) = pipe2();
        let msg = [b'r'];
        libc::write(wr, msg.as_ptr() as *const libc::c_void, 1);

        let mut set: libc::fd_set = MaybeUninit::zeroed().assume_init();
        libc::FD_ZERO(&mut set);
        libc::FD_SET(rd, &mut set);
        let mut tv = libc::timeval { tv_sec: 0, tv_usec: 10_000 };
        let start = now_monotonic();
        let rc = libc::select(
            rd + 1,
            &mut set,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut tv,
        );
        let isset = libc::FD_ISSET(rd, &set);
        let bounded = elapsed_ms_since(&start) < 1_000;
        report!(
            select_ready_rc_one = rc == 1,
            select_ready_pipe_bit_set = isset,
            select_ready_bounded = bounded,
        );
        libc::close(rd);
        libc::close(wr);
    }
}

fn case_select_pipe_not_ready() {
    unsafe {
        let (rd, wr) = pipe2();
        // Nothing written → not ready.

        let mut set: libc::fd_set = MaybeUninit::zeroed().assume_init();
        libc::FD_ZERO(&mut set);
        libc::FD_SET(rd, &mut set);
        let mut tv = libc::timeval { tv_sec: 0, tv_usec: 10_000 };
        let start = now_monotonic();
        let rc = libc::select(
            rd + 1,
            &mut set,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut tv,
        );
        let isset = libc::FD_ISSET(rd, &set);
        let bounded = elapsed_ms_since(&start) < 1_000;
        report!(
            select_notready_rc_zero = rc == 0,
            select_notready_pipe_bit_clear = !isset,
            select_notready_bounded = bounded,
        );
        libc::close(rd);
        libc::close(wr);
    }
}

fn case_pselect_bare_timeout() {
    unsafe {
        let ts = libc::timespec { tv_sec: 0, tv_nsec: 10_000_000 };
        let start = now_monotonic();
        let rc = libc::pselect(
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &ts,
            std::ptr::null(),
        );
        let bounded = elapsed_ms_since(&start) < 1_000;
        report!(
            pselect_bare_timeout_rc_zero = rc == 0,
            pselect_bare_timeout_bounded = bounded,
        );
    }
}

fn case_pselect_blocked_signal_stays_pending() {
    unsafe {
        ALRM_HITS.store(0, Ordering::SeqCst);
        let _ = install_handler(libc::SIGALRM, on_alrm, 0);

        // Caller's mask must NOT have SIGALRM blocked entering the call —
        // we want to observe that pselect's temp mask is what's in force.
        let _ = unblock_signal(libc::SIGALRM);

        // Build a mask that blocks SIGALRM during the pselect wait.
        let mut mask: libc::sigset_t = MaybeUninit::zeroed().assume_init();
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGALRM);

        // One-shot alarm fires while pselect is blocked; the temp mask
        // blocks it, so the signal stays pending and pselect times out
        // (rc 0). Note: by the time control returns to user space the
        // original mask is restored AND any pending blocked signal has
        // been delivered, so we cannot directly observe "handler did not
        // run during the wait" from user code — only the rc/timeout
        // shape and the post-return mask + delivered-or-pending state.
        arm_alarm_ms(5);
        let ts = libc::timespec { tv_sec: 0, tv_nsec: 50_000_000 };
        let start = now_monotonic();
        let rc = libc::pselect(
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &ts,
            &mask,
        );
        let bounded = elapsed_ms_since(&start) < 1_000;

        // After return the original mask is restored (SIGALRM NOT blocked
        // again) and the pending signal has been (or will imminently be)
        // delivered. Sample the mask, then re-block to capture pending +
        // handler-ran in a stable window.
        let mask_restored = !is_blocked(libc::SIGALRM);
        let _ = block_signal(libc::SIGALRM);
        let delivered_after =
            is_pending(libc::SIGALRM) || ALRM_HITS.load(Ordering::SeqCst) >= 1;
        // Drain.
        let _ = unblock_signal(libc::SIGALRM);
        disarm_alarm();

        report!(
            pselect_blocked_alarm_rc_zero = rc == 0,
            pselect_blocked_alarm_bounded = bounded,
            pselect_blocked_alarm_mask_restored = mask_restored,
            pselect_blocked_alarm_delivered_after = delivered_after,
        );
    }
}

fn case_pselect_unblocked_signal_interrupts() {
    unsafe {
        ALRM_HITS.store(0, Ordering::SeqCst);
        let _ = install_handler(libc::SIGALRM, on_alrm, 0);
        let _ = unblock_signal(libc::SIGALRM);

        arm_alarm_ms(5);
        // 500 ms upper bound — but with the alarm wired and unblocked the
        // wait should EINTR in ~5 ms; the 500 ms is just the safety bound.
        let ts = libc::timespec { tv_sec: 0, tv_nsec: 500_000_000 };
        let start = now_monotonic();
        let rc = libc::pselect(
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &ts,
            std::ptr::null(),
        );
        let ps_errno = errno();
        let bounded = elapsed_ms_since(&start) < 1_000;
        disarm_alarm();

        report!(
            pselect_unblocked_alarm_rc_minus_one = rc == -1,
            pselect_unblocked_alarm_errno_eintr = ps_errno == libc::EINTR,
            pselect_unblocked_alarm_handler_ran = ALRM_HITS.load(Ordering::SeqCst) >= 1,
            pselect_unblocked_alarm_bounded = bounded,
        );
    }
}

fn main() {
    case_select_bare_timeout();
    case_select_pipe_ready();
    case_select_pipe_not_ready();
    case_pselect_bare_timeout();
    case_pselect_blocked_signal_stays_pending();
    case_pselect_unblocked_signal_interrupts();
}
