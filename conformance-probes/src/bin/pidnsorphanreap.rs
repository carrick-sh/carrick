//! pidnsorphanreap: the namespace init reaps orphaned grandchildren
//! (pid_namespaces(7) — pid 1 inherits and reaps orphans). This probe acts as a
//! local init: it forks a child that forks a grandchild then exits; the
//! grandchild (orphan) reparents to this process, and exits. This process must
//! be able to wait4(-1) and reap the orphaned grandchild (getting its pid+status),
//! not just its direct child. Both Docker and carrick must reap the orphan.
//! Deterministic booleans.
use conformance_probes::report;
fn main() {
    unsafe {
        let child = libc::fork();
        if child == 0 {
            let grand = libc::fork();
            if grand == 0 {
                // Grandchild: sleep briefly so the child exits first (we become
                // an orphan reparented to the init/this process), then exit 42.
                let ts = libc::timespec { tv_sec: 0, tv_nsec: 100_000_000 };
                libc::nanosleep(&ts, core::ptr::null_mut());
                libc::_exit(42);
            }
            // Child exits immediately, orphaning the grandchild to us.
            libc::_exit(0);
        }
        // We are the local init. Reap EVERYTHING via wait4(-1) until ECHILD.
        let mut reaped = 0;
        let mut saw_42 = false;
        let mut saw_child_exit0 = false;
        loop {
            let mut st = 0i32;
            let r = libc::wait4(-1, &mut st, 0, core::ptr::null_mut());
            if r <= 0 { break; }
            reaped += 1;
            if libc::WIFEXITED(st) {
                let code = libc::WEXITSTATUS(st);
                if code == 42 { saw_42 = true; }
                if code == 0 { saw_child_exit0 = true; }
            }
            if reaped >= 2 { break; }
        }
        report!(
            reaped_two = reaped == 2,
            reaped_direct_child = saw_child_exit0,
            reaped_orphan_grandchild = saw_42,
        );
    }
}
