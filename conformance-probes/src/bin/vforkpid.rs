//! vfork must not leave the parent's fast-path getpid identity stamped with the
//! child's pid. Go's os/signal TestDetectNohup uses vfork/exec before later
//! kill(getpid(), sig) checks; if the EL1 identity page keeps the child's pid,
//! self-kill returns ESRCH and no handler runs.
//!
//! Deterministic only: no raw pids or timings.

use conformance_probes::{errno, install_handler, report};
use std::sync::atomic::{AtomicU32, Ordering};

static USR1_HITS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_usr1(_: i32) {
    USR1_HITS.fetch_add(1, Ordering::SeqCst);
}

fn main() {
    unsafe {
        let _ = install_handler(libc::SIGUSR1, on_usr1, 0);

        let before = libc::getpid();
        let flags = (libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD) as libc::c_long;
        let child = libc::syscall(
            libc::SYS_clone,
            flags,
            0 as libc::c_long,
            0 as libc::c_long,
            0 as libc::c_long,
            0 as libc::c_long,
        ) as libc::pid_t;
        if child == 0 {
            libc::_exit(0);
        }

        let mut status = 0;
        let waited = if child > 0 {
            libc::waitpid(child, &mut status, 0)
        } else {
            -1
        };
        report!(
            vfork_child_created = child > 0,
            vfork_child_reaped = child > 0 && waited == child && libc::WIFEXITED(status),
        );

        let after = libc::getpid();
        report!(getpid_stable_after_vfork = after == before);

        USR1_HITS.store(0, Ordering::SeqCst);
        let rc = libc::kill(after, libc::SIGUSR1);
        let rc_errno = errno();
        report!(
            kill_getpid_after_vfork_rc_zero = rc == 0,
            kill_getpid_after_vfork_not_esrch = rc == 0 || rc_errno != libc::ESRCH,
            kill_getpid_after_vfork_handler_ran = USR1_HITS.load(Ordering::SeqCst) == 1,
        );
    }
}
