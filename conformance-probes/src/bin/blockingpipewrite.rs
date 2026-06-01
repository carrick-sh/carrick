//! A blocking `write(2)` to a pipe must BLOCK until all bytes are written, or
//! return the partial count if a signal interrupts it after partial progress
//! (EINTR only if zero bytes were written). Linux never returns a short count
//! on a blocking pipe absent a signal.
//!
//! CPython test_io.test_interrupted_write_unbuffered arms `alarm(1)` then does
//! one unbuffered `write()` of a >capacity buffer to a pipe. On Linux the write
//! fills the pipe, BLOCKS waiting for room, and ~1s later SIGALRM interrupts it
//! and it returns the partial count; CPython's IO layer then runs the pending
//! handler (which raises). Carrick force-set the host pipe O_NONBLOCK and, for a
//! >PIPE_BUF write, returned the first partial count IMMEDIATELY — so the write
//! never blocked, the alarm never interrupted it, and the test's exception never
//! fired.
//!
//! This probe fills a blocking pipe (no reader) with a >capacity write under
//! alarm(1). The deterministic differentiator is whether the write BLOCKED until
//! the signal (~1s) rather than returning instantly.
//!
//!  * write_returned_partial:    0 < ret < len  (a short count, both before+after)
//!  * write_blocked_until_signal: the write took >= 500ms, i.e. it blocked until
//!                                SIGALRM fired rather than returning immediately.

use conformance_probes::report;
use std::sync::atomic::{AtomicBool, Ordering};

static ALARM_FIRED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_alarm(_sig: libc::c_int) {
    ALARM_FIRED.store(true, Ordering::SeqCst);
}

fn monotonic_ms() -> i64 {
    let mut ts: libc::timespec = unsafe { core::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as i64) * 1000 + (ts.tv_nsec as i64) / 1_000_000
}

fn main() {
    unsafe {
        // SIGALRM handler with SA_RESTART cleared so it interrupts the write.
        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = on_alarm as usize;
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGALRM, &sa, core::ptr::null_mut());

        let mut fds = [0i32; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            report!(
                write_returned_partial = false,
                write_blocked_until_signal = false
            );
            return;
        }
        // Both ends stay open (an open read end => no SIGPIPE); we never read,
        // so once the pipe fills the write must block waiting for room.
        let len: usize = 256 * 1024; // > any pipe capacity (16K..64K)
        let buf = vec![0u8; len];

        let t0 = monotonic_ms();
        libc::alarm(1);
        let ret = libc::write(fds[1], buf.as_ptr() as *const libc::c_void, len);
        let elapsed = monotonic_ms() - t0;
        libc::alarm(0);

        report!(
            write_returned_partial = (ret > 0 && (ret as usize) < len),
            write_blocked_until_signal = (elapsed >= 500)
        );
        let _ = ALARM_FIRED.load(Ordering::SeqCst);
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
}
