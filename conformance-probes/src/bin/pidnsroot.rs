//! pidnsroot: the container is placed in a PID namespace. The probe is a child
//! of the container init (the sh that `docker run`/`carrick run` launched), so
//! its parent is ns-pid 1. It forks a child and reaps it, asserting wait4
//! returns that child's own ns-pid and the child sees the probe as its parent.
use conformance_probes::{report, reap};
fn main() {
    unsafe {
        let ppid = libc::getppid();
        // pipe so the child reports its own getpid()/getppid() back deterministically
        let mut fds = [0i32; 2];
        libc::pipe(fds.as_mut_ptr());
        let me = libc::getpid();
        let pid = libc::fork();
        if pid == 0 {
            libc::close(fds[0]);
            let cpid = libc::getpid();
            let cppid = libc::getppid();
            let buf = [cpid, cppid];
            libc::write(fds[1], buf.as_ptr() as *const _, 8);
            libc::_exit(0);
        }
        libc::close(fds[1]);
        let mut buf = [0i32; 2];
        libc::read(fds[0], buf.as_mut_ptr() as *mut _, 8);
        let (reaped, _st) = reap(pid);
        report!(
            parent_is_init = ppid == 1,
            child_parent_is_me = buf[1] == me,
            wait_returned_child = reaped == pid,
            child_pid_eq_fork_ret = buf[0] == pid,
        );
    }
}
