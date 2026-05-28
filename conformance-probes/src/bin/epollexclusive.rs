//! epoll edge-trigger, EPOLLEXCLUSIVE, EPOLLONESHOT, and epoll_pwait sigmask
//! semantics beyond what `epollpwait` / `pollevent` already own.
//!
//! Stands in for LTP `epoll_ctl05` (EPOLLEXCLUSIVE), `epoll_wait05/06/07`
//! (edge/oneshot event semantics), `epoll_pwait01/02/05` (sigmask + alarm
//! interaction).
//!
//! Invariants encoded (booleans only — never timestamps, fd numbers, or
//! event counts):
//!
//!   * `epoll_create1(EPOLL_CLOEXEC)` returns a positive fd.
//!   * `epoll_ctl(ADD, fd, EPOLLIN|EPOLLEXCLUSIVE)` is accepted by the
//!     kernel. (epoll_ctl05)
//!   * Adding the SAME fd twice (no MOD in between) returns -1/EEXIST.
//!   * `epoll_ctl(ADD, fd, events=0)` is accepted — the kernel records the
//!     registration; the fd never fires until MOD adds an event mask.
//!   * EPOLLET (edge-triggered): one write → one event. A second wait
//!     without an intervening write sees 0 events (the same edge has
//!     already fired). Draining and writing again yields a fresh event.
//!     (epoll_wait05/06)
//!   * EPOLLONESHOT: after the first fire the fd is disarmed; only an
//!     EPOLL_CTL_MOD re-arm wakes the next wait. (epoll_wait07)
//!   * `epoll_pwait(sigmask blocking SIGALRM)` + an itimer that fires
//!     mid-wait → wait completes normally (rc 0 if no fds ready), NO
//!     EINTR; with a NULL sigmask the same alarm interrupts → -1/EINTR.
//!     (epoll_pwait01/02)
//!
//! Every wait is bounded to <= 100 ms so a broken delivery path turns a
//! `true` into a `false` instead of hanging the harness.

use conformance_probes::{
    arm_alarm_ms, block_signal, disarm_alarm, errno, install_handler, pipe2, report,
    unblock_signal,
};
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicU32, Ordering};

static ALRM_HITS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_alrm(_: i32) {
    ALRM_HITS.fetch_add(1, Ordering::SeqCst);
}

/// Helper: build an `epoll_event` with the requested events mask, naming the
/// fd in the user-data slot for symmetry (we don't compare it back).
fn ev(mask: u32, fd: i32) -> libc::epoll_event {
    libc::epoll_event { events: mask, u64: fd as u64 }
}

fn case_create_and_exclusive_add() {
    unsafe {
        let epfd = libc::epoll_create1(libc::EPOLL_CLOEXEC);
        let created_ok = epfd > 0;
        let (rd, wr) = pipe2();
        let mut e = ev(libc::EPOLLIN as u32 | libc::EPOLLEXCLUSIVE as u32, rd);
        let add_rc = libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, rd, &mut e);
        report!(
            epoll_create1_cloexec_positive = created_ok,
            epoll_ctl_add_exclusive_rc_zero = add_rc == 0,
        );
        libc::close(rd);
        libc::close(wr);
        libc::close(epfd);
    }
}

fn case_double_add_eexist() {
    unsafe {
        let epfd = libc::epoll_create1(libc::EPOLL_CLOEXEC);
        let (rd, wr) = pipe2();
        let mut e = ev(libc::EPOLLIN as u32, rd);
        let add1 = libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, rd, &mut e);
        let add2 = libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, rd, &mut e);
        let er = errno();
        report!(
            epoll_ctl_first_add_rc_zero = add1 == 0,
            epoll_ctl_second_add_rc_minus_one = add2 == -1,
            epoll_ctl_second_add_errno_eexist = er == libc::EEXIST,
        );
        libc::close(rd);
        libc::close(wr);
        libc::close(epfd);
    }
}

fn case_add_zero_events_then_mod() {
    unsafe {
        let epfd = libc::epoll_create1(libc::EPOLL_CLOEXEC);
        let (rd, wr) = pipe2();
        // Add with NO event flags. Kernel must accept; fd never fires.
        let mut e = ev(0, rd);
        let add_rc = libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, rd, &mut e);

        // Make it readable; wait briefly — the fd is registered but with no
        // events, so it must NOT fire.
        libc::write(wr, b"x".as_ptr() as *const libc::c_void, 1);
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
        let wait_pre = libc::epoll_wait(epfd, out.as_mut_ptr(), 4, 50);

        // Now MOD to add EPOLLIN; the next wait must see the fd.
        let mut e2 = ev(libc::EPOLLIN as u32, rd);
        let mod_rc = libc::epoll_ctl(epfd, libc::EPOLL_CTL_MOD, rd, &mut e2);
        let wait_post = libc::epoll_wait(epfd, out.as_mut_ptr(), 4, 50);

        report!(
            epoll_ctl_add_zero_events_rc_zero = add_rc == 0,
            epoll_zero_events_no_fire = wait_pre == 0,
            epoll_ctl_mod_rc_zero = mod_rc == 0,
            epoll_after_mod_fires = wait_post == 1,
        );
        libc::close(rd);
        libc::close(wr);
        libc::close(epfd);
    }
}

fn case_edge_trigger() {
    unsafe {
        let epfd = libc::epoll_create1(libc::EPOLL_CLOEXEC);
        let (rd, wr) = pipe2();
        let mut e = ev(libc::EPOLLIN as u32 | libc::EPOLLET as u32, rd);
        let add_rc = libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, rd, &mut e);

        // First write → one edge → one event.
        libc::write(wr, b"a".as_ptr() as *const libc::c_void, 1);
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
        let w1 = libc::epoll_wait(epfd, out.as_mut_ptr(), 4, 50);

        // Same wait again with NO intervening write: the same edge has
        // already been delivered → 0.
        let w2 = libc::epoll_wait(epfd, out.as_mut_ptr(), 4, 50);

        // Drain everything, then write once → fresh edge → one event.
        let mut buf = [0u8; 16];
        let _ = libc::read(rd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
        libc::write(wr, b"c".as_ptr() as *const libc::c_void, 1);
        let w3 = libc::epoll_wait(epfd, out.as_mut_ptr(), 4, 50);

        report!(
            epoll_et_add_rc_zero = add_rc == 0,
            epoll_et_first_write_fires = w1 == 1,
            epoll_et_no_repoll_no_event = w2 == 0,
            epoll_et_after_drain_new_write_fires = w3 == 1,
        );
        libc::close(rd);
        libc::close(wr);
        libc::close(epfd);
    }
}

fn case_oneshot() {
    unsafe {
        let epfd = libc::epoll_create1(libc::EPOLL_CLOEXEC);
        let (rd, wr) = pipe2();
        let mut e = ev(libc::EPOLLIN as u32 | libc::EPOLLONESHOT as u32, rd);
        let add_rc = libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, rd, &mut e);

        libc::write(wr, b"a".as_ptr() as *const libc::c_void, 1);
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
        let w1 = libc::epoll_wait(epfd, out.as_mut_ptr(), 4, 50);

        // After the oneshot fire the fd is DISARMED — even though more data
        // could be made available, another wait must NOT see it without a
        // MOD re-arm.
        libc::write(wr, b"b".as_ptr() as *const libc::c_void, 1);
        let w2 = libc::epoll_wait(epfd, out.as_mut_ptr(), 4, 50);

        // Re-arm via MOD; the next wait sees the (still-readable) fd again.
        let mut e2 = ev(libc::EPOLLIN as u32 | libc::EPOLLONESHOT as u32, rd);
        let mod_rc = libc::epoll_ctl(epfd, libc::EPOLL_CTL_MOD, rd, &mut e2);
        let w3 = libc::epoll_wait(epfd, out.as_mut_ptr(), 4, 50);

        report!(
            epoll_oneshot_add_rc_zero = add_rc == 0,
            epoll_oneshot_first_fires = w1 == 1,
            epoll_oneshot_disarmed_after_fire = w2 == 0,
            epoll_oneshot_mod_rearm_rc_zero = mod_rc == 0,
            epoll_oneshot_rearm_fires = w3 == 1,
        );
        libc::close(rd);
        libc::close(wr);
        libc::close(epfd);
    }
}

fn case_pwait_sigmask_blocks_alarm() {
    unsafe {
        ALRM_HITS.store(0, Ordering::SeqCst);
        let _ = install_handler(libc::SIGALRM, on_alrm, 0);
        let _ = unblock_signal(libc::SIGALRM);

        // sigmask that blocks SIGALRM during epoll_pwait.
        let mut mask: libc::sigset_t = MaybeUninit::zeroed().assume_init();
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGALRM);

        let epfd = libc::epoll_create1(libc::EPOLL_CLOEXEC);
        // No fds added — epoll_pwait will block waiting for either a
        // signal-delivery or the timeout.
        arm_alarm_ms(5);
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
        let rc = libc::epoll_pwait(epfd, out.as_mut_ptr(), 4, 50, &mask);

        // SIGALRM was blocked through the wait, so it should NOT EINTR.
        // rc == 0 (timeout) is the deterministic result.
        let pwait_returned_zero = rc == 0;

        // After return the original mask is restored. Drain any pending
        // alarm so the next case starts clean.
        let _ = block_signal(libc::SIGALRM);
        let _ = unblock_signal(libc::SIGALRM);
        disarm_alarm();
        libc::close(epfd);

        report!(epoll_pwait_blocked_alarm_rc_zero = pwait_returned_zero);
    }
}

fn case_pwait_null_sigmask_alarm_eintrs() {
    unsafe {
        ALRM_HITS.store(0, Ordering::SeqCst);
        let _ = install_handler(libc::SIGALRM, on_alrm, 0);
        let _ = unblock_signal(libc::SIGALRM);

        let epfd = libc::epoll_create1(libc::EPOLL_CLOEXEC);
        arm_alarm_ms(5);
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
        // NULL sigmask: alarm is unblocked → handler runs → wait EINTRs.
        let rc = libc::epoll_pwait(epfd, out.as_mut_ptr(), 4, 100, std::ptr::null());
        let er = errno();
        let handler_ran = ALRM_HITS.load(Ordering::SeqCst) >= 1;
        disarm_alarm();
        libc::close(epfd);

        report!(
            epoll_pwait_null_mask_rc_minus_one = rc == -1,
            epoll_pwait_null_mask_errno_eintr = er == libc::EINTR,
            epoll_pwait_null_mask_handler_ran = handler_ran,
        );
    }
}

fn main() {
    case_create_and_exclusive_add();
    case_double_add_eexist();
    case_add_zero_events_then_mod();
    case_edge_trigger();
    case_oneshot();
    case_pwait_sigmask_blocks_alarm();
    case_pwait_null_sigmask_alarm_eintrs();
}
