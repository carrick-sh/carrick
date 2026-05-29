//! SO_RCVTIMEO must BOUND a blocking recv: a recv on an empty socket whose
//! receive timeout is set returns -1/EAGAIN after the timeout elapses — it does
//! NOT block forever. carrick stores nothing for SO_RCVTIMEO and never threads a
//! timeout into the `blocking_io`->`WaitOnFds{timeout:None}` wait (dispatch/net.rs
//! 188-215), so a blocking-mode recv on an empty socket blocks indefinitely (the
//! audit "so-timeo" finding).
//!
//! Determinism + no-hang: every blocking recv is fenced by a one-shot SIGALRM
//! WATCHDOG installed with NO SA_RESTART (flags=0), so it interrupts a blocked
//! recv with EINTR instead of silently resuming it. On Linux the 100 ms
//! SO_RCVTIMEO fires first -> recv returns -1/EAGAIN and the 2 s watchdog never
//! fires. On buggy carrick the recv blocks forever, the watchdog interrupts it
//! -> recv returns -1/EINTR. The boolean shape diverges (errno EAGAIN vs EINTR;
//! watchdog_fired false vs true) AND the probe always terminates well under the
//! harness CASE_DEADLINE.
//!
//! Output is booleans only (no times/pids/addresses/sizes), one report! line per
//! observation, diffed line-for-line against the Docker linux/arm64 oracle.

use conformance_probes::{arm_alarm_ms, disarm_alarm, errno, install_handler, report};
use std::sync::atomic::{AtomicU32, Ordering};

static ALRM_HITS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_alrm(_: i32) {
    ALRM_HITS.fetch_add(1, Ordering::SeqCst);
}

/// Set SO_RCVTIMEO to {sec, usec} on `fd`. Returns whether the call succeeded.
/// On aarch64 the libc crate's SO_RCVTIMEO == SO_RCVTIMEO_OLD == 20 and
/// `struct timeval` is two i64 (16 bytes) — matching carrick's LINUX_SO_RCVTIMEO.
unsafe fn set_rcvtimeo(fd: i32, sec: i64, usec: i64) -> bool {
    let tv = libc::timeval {
        tv_sec: sec as libc::time_t,
        tv_usec: usec as libc::suseconds_t,
    };
    libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_RCVTIMEO,
        &tv as *const _ as *const libc::c_void,
        std::mem::size_of::<libc::timeval>() as libc::socklen_t,
    ) == 0
}

fn main() {
    unsafe {
        // Non-restarting SIGALRM watchdog (flags=0): it EINTRs a blocked recv
        // rather than silently resuming it.
        let _ = install_handler(libc::SIGALRM, on_alrm, 0);

        // A connected, EMPTY socket pair backed by a real host socketpair
        // (carrick installs both ends as OpenDescription::HostSocket). The `rd`
        // end never has data, so a blocking recv on it would block until
        // SO_RCVTIMEO (or, if ignored, forever — caught by the watchdog).
        let mut sv = [0i32; 2];
        let pair_ok =
            libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) == 0;
        if !pair_ok {
            report!(setup_socketpair_ok = false);
            return;
        }
        let (rd, wr) = (sv[0], sv[1]);

        // Baseline: a per-call non-blocking recv (MSG_DONTWAIT) on the empty
        // socket returns -1/EAGAIN immediately. Proves the socket is empty and
        // the EAGAIN errno path works on both runtimes (always MATCHES).
        let mut b = [0u8; 4];
        let nb = libc::recv(
            rd,
            b.as_mut_ptr() as *mut libc::c_void,
            b.len(),
            libc::MSG_DONTWAIT,
        );
        let nb_e = errno();
        report!(
            setup_socketpair_ok = true,
            dontwait_rc_minus_one = nb == -1,
            dontwait_errno_eagain = nb_e == libc::EAGAIN || nb_e == libc::EWOULDBLOCK,
        );

        // SO_RCVTIMEO = 100 ms, then a BLOCKING recv on the empty socket. Watch-
        // dog at 2 s. Linux: recv returns -1/EAGAIN at ~100 ms, watchdog never
        // fires. Buggy carrick: recv blocks forever -> watchdog EINTRs it.
        let set_ok = set_rcvtimeo(rd, 0, 100_000);
        ALRM_HITS.store(0, Ordering::SeqCst);
        arm_alarm_ms(2000);
        let n = libc::recv(rd, b.as_mut_ptr() as *mut libc::c_void, b.len(), 0);
        let rc_e = errno();
        disarm_alarm();
        let watchdog_fired = ALRM_HITS.load(Ordering::SeqCst) >= 1;

        report!(
            rcvtimeo_set_ok = set_ok,
            // Linux: recv timed out -> -1.
            rcvtimeo_recv_rc_minus_one = n == -1,
            // Linux: EAGAIN/EWOULDBLOCK (timeout). Buggy carrick: EINTR (watchdog).
            rcvtimeo_recv_errno_eagain = rc_e == libc::EAGAIN || rc_e == libc::EWOULDBLOCK,
            // Linux: SO_RCVTIMEO returned first, so the watchdog never fired.
            // Buggy carrick: the watchdog had to break a forever-block.
            rcvtimeo_watchdog_quiet = !watchdog_fired,
        );

        // Sanity: with data already waiting, a blocking recv (timeout set)
        // returns the bytes immediately — the timeout is not consumed. Same on
        // both runtimes (MATCHES); guards against a fix that turns EVERY recv
        // into a timeout.
        let msg = b"ok";
        libc::send(wr, msg.as_ptr() as *const libc::c_void, msg.len(), 0);
        ALRM_HITS.store(0, Ordering::SeqCst);
        arm_alarm_ms(2000);
        let n2 = libc::recv(rd, b.as_mut_ptr() as *mut libc::c_void, b.len(), 0);
        disarm_alarm();
        report!(
            ready_recv_n_two = n2 == 2,
            ready_recv_bytes_ok = n2 == 2 && &b[..2] == b"ok",
        );

        libc::close(rd);
        libc::close(wr);
    }
}