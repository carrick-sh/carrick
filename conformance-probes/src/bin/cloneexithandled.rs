//! Caught child-exit SIGCHLD must run before the parent reaps.
//!
//! The parent installs a SIGCHLD handler, creates a fast-exiting child with
//! fork-style clone(SIGCHLD), waits briefly for the handler, then reaps. Repeats
//! catch the race where carrick arms its child-exit watch after the child is
//! already a zombie but receives no async notification.

use conformance_probes::report;
use std::sync::atomic::{AtomicU32, Ordering};

const LINUX_SIGCHLD: i32 = 17;
const ITERS: u32 = 24;
static HITS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_sigchld(_sig: i32) {
    HITS.fetch_add(1, Ordering::SeqCst);
}

unsafe fn raw_clone(flags: u64) -> i64 {
    libc::syscall(libc::SYS_clone, flags as i64, 0i64, 0i64, 0i64, 0i64)
}

fn main() {
    unsafe {
        let install_ok = conformance_probes::install_handler(LINUX_SIGCHLD, on_sigchld, 0);
        let mut all_seen = install_ok;
        let mut cloned_all = true;
        let mut reaped_all = true;

        for expected in 1..=ITERS {
            let child = raw_clone(LINUX_SIGCHLD as u64);
            if child == 0 {
                libc::_exit(0);
            }
            if child < 0 {
                cloned_all = false;
                all_seen = false;
                break;
            }

            for _ in 0..1000 {
                if HITS.load(Ordering::SeqCst) >= expected {
                    break;
                }
                libc::usleep(1000);
            }
            if HITS.load(Ordering::SeqCst) < expected {
                all_seen = false;
            }

            let mut status = 0;
            if libc::waitpid(child as i32, &mut status, 0) != child as i32 {
                reaped_all = false;
                all_seen = false;
                break;
            }
        }

        report!(
            install_ok = install_ok,
            cloned_all = cloned_all,
            reaped_all = reaped_all,
            all_exit_handlers_observed = all_seen,
        );
    }
}
