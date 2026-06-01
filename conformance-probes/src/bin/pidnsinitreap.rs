//! pidnsinitreap: orphan reparenting to the namespace init (pid_namespaces(7)).
//! A child forks a grandchild then exits; the grandchild's parent is now dead,
//! so the grandchild reparents to the PID-namespace init (ns-pid 1). The
//! grandchild waits for its parent to die (poll getppid until it is 1) and
//! reports whether it observed getppid()==1. Both Docker and carrick must agree
//! the orphan reparents to ns-pid 1 (on carrick via the NsSupervisor / the
//! reparent-to-init translation rule). Deterministic boolean output.
use conformance_probes::report;
fn main() {
    unsafe {
        let mut p = [0i32; 2];
        libc::pipe(p.as_mut_ptr());
        let child = libc::fork();
        if child == 0 {
            libc::close(p[0]);
            let grand = libc::fork();
            if grand == 0 {
                // Poll getppid until it becomes 1 (orphan → reparented to init),
                // bounded so a bug fails fast instead of hanging.
                let mut ppid = libc::getppid();
                for _ in 0..500 {
                    if ppid == 1 { break; }
                    let ts = libc::timespec { tv_sec: 0, tv_nsec: 5_000_000 };
                    libc::nanosleep(&ts, core::ptr::null_mut());
                    ppid = libc::getppid();
                }
                let reparented = ppid == 1;
                libc::write(p[1], &reparented as *const bool as *const _, 1);
                libc::_exit(0);
            }
            libc::_exit(0);
        }
        libc::close(p[1]);
        let mut st = 0i32;
        libc::waitpid(child, &mut st, 0);
        let mut buf = [0u8; 1];
        let n = libc::read(p[0], buf.as_mut_ptr() as *mut _, 1);
        report!(
            grandchild_report_ok = n == 1,
            orphan_reparented_to_init = buf[0] == 1,
        );
    }
}
