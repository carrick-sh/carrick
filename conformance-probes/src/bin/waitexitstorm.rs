//! fork -> immediate child _exit -> blocking wait4 storm.
//!
//! This is the C toolchain-driver shape behind `go build <cgo>`: a parent forks
//! one short-lived child at a time and immediately waits for that exact pid.
//! Linux reaps every child. Carrick used to occasionally return ECHILD from the
//! blocking waitpid(pid) path under this storm, meaning some other path consumed
//! the zombie before the re-dispatched wait4 could reap it.

use conformance_probes::{errno, report};

// Must exceed carrick's historical 1024 namespace-member table capacity while
// still fitting inside `scripts/run-probe.sh`'s 60s per-side timeout once fixed.
const ITERS: u64 = 1500;

fn main() {
    unsafe {
        for i in 0..ITERS {
            let pid = libc::fork();
            if pid < 0 {
                report!(fork_ok = false, iter = i);
                return;
            }
            if pid == 0 {
                let spin = (i % 96) * 12;
                for _ in 0..spin {
                    core::hint::spin_loop();
                }
                libc::_exit(0);
            }

            let mut status = 0i32;
            let ret = libc::waitpid(pid, &mut status, 0);
            if ret != pid {
                report!(
                    reaped_ok = false,
                    iter = i,
                    expected = pid,
                    ret = ret,
                    err = errno(),
                );
                return;
            }
        }

        report!(all_reaped = true);
    }
}
