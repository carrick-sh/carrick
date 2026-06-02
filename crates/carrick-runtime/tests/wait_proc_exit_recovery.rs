//! Regression: the apt-get-install fork-storm hang.
//!
//! When an internal fd is closed out from under a thread blocked in
//! `wait_proc_exit` (the fork-storm relocates kqueue/pipe fds across the shared
//! 16384+ pool), `kevent` returns EBADF. The old code did `Err(_) => continue`,
//! busy-spinning at 100% CPU forever so the guest's `wait4` never completed →
//! apt hung. The waiter must instead notice the kqueue is unusable and fall back
//! to a bounded, interruptible `waitid` poll that still observes the child exit.
//!
//! This is its OWN test binary (separate process) on purpose: `wait_proc_exit`
//! consults process-global signal/quiesce state, so running it alongside the
//! HVF/fork tests in the `integration` binary makes it flaky for reasons
//! unrelated to the fix.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(target_os = "macos")]
#[test]
fn wait_proc_exit_recovers_when_kqueue_fd_closed_mid_wait() {
    use std::sync::mpsc;
    use std::time::Duration;

    use carrick_runtime::io_wait::{ThreadWaiter, WaitResult};

    // A child that exits shortly: a correct waiter observes the exit and returns
    // Ready (the caller then re-dispatches waitid to reap).
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed");
    if child == 0 {
        unsafe {
            libc::usleep(200_000);
            libc::_exit(0);
        }
    }

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut waiter = ThreadWaiter::new(unsafe { libc::getpid() });
        // Simulate the fork-storm race: the per-thread kqueue fd is closed out
        // from under us, so the next kevent returns EBADF.
        waiter.debug_close_kqueue();
        // The old busy-spin would never return here; the fix falls back to a
        // bounded waitid poll and returns Ready once the child exits.
        let r = waiter.wait_proc_exit(child, 0);
        let _ = tx.send(r);
    });

    let outcome = rx.recv_timeout(Duration::from_secs(5));
    // Reap the child regardless of outcome so we don't leak a zombie.
    let mut status = 0i32;
    unsafe { libc::waitpid(child, &mut status, 0) };

    match outcome {
        Ok(WaitResult::Ready) => {}
        Ok(other) => panic!("expected Ready after kqueue EBADF, got {other:?}"),
        Err(_) => panic!(
            "wait_proc_exit busy-spun on a closed (EBADF) kqueue and never returned \
             — this is the apt-get-install fork-storm hang"
        ),
    }
}
