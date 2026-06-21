//! ppoll(2) temp-sigmask UNBLOCK semantics (POSIX replace, not union).
//!
//! A signal that is BLOCKED in the thread's persistent mask but UNBLOCKED by
//! ppoll's temporary sigmask must be able to interrupt the ppoll wait — ppoll
//! REPLACES the thread mask with `sigmask` for the duration of the call. The
//! companion to `maskfork`: maskfork proved a blocked+pending signal must NOT
//! interrupt a plain `read(2)`; this proves the SAME signal MUST interrupt a
//! ppoll whose temp mask unblocks it. A predicate that unions the persistent
//! mask into the wait mask passes maskfork but fails here (it leaves the signal
//! blocked even though ppoll unblocked it), so it pins the over-block regression.
//!
//! Deterministic: a pre-raised pending SIGUSR1 means the ppoll returns
//! immediately on entry, no timing race.

use conformance_probes::{errno, install_handler, report};

extern "C" fn on_usr1(_: i32) {}

fn main() {
    unsafe {
        install_handler(libc::SIGUSR1, on_usr1, 0);

        // Persistently block SIGUSR1, then raise it so it sits pending.
        let mut blk: libc::sigset_t = core::mem::zeroed();
        libc::sigemptyset(&mut blk);
        libc::sigaddset(&mut blk, libc::SIGUSR1);
        libc::pthread_sigmask(libc::SIG_BLOCK, &blk, core::ptr::null_mut());
        libc::raise(libc::SIGUSR1);

        // A pipe whose read end never becomes readable: ppoll can only return via
        // the (now-unblocked) pending signal or the timeout.
        let mut p = [0i32; 2];
        if libc::pipe(p.as_mut_ptr()) != 0 {
            report!(setup_ok = false);
            return;
        }

        // EMPTY temp mask => SIGUSR1 is unblocked for the wait. Linux delivers the
        // pending SIGUSR1 and ppoll returns EINTR; a 2s timeout bounds the buggy
        // (over-blocked) case so the probe still terminates with a clear verdict.
        let mut empty: libc::sigset_t = core::mem::zeroed();
        libc::sigemptyset(&mut empty);
        let ts = libc::timespec {
            tv_sec: 2,
            tv_nsec: 0,
        };
        let mut pfd = libc::pollfd {
            fd: p[0],
            events: libc::POLLIN,
            revents: 0,
        };
        let r = libc::ppoll(&mut pfd, 1, &ts, &empty);
        let e = errno();

        report!(
            ppoll_returned = true,
            ppoll_eintr = r < 0 && e == libc::EINTR,
            ppoll_timed_out = r == 0,
        );
    }
}
