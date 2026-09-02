//! budget_two_proc: Phase G two-process differential conformance probe.
//!
//! Exercises fork inheritance, process accounting, and boundary writes with
//! invariants stated as RELATIONS between the two processes. Raw pid values
//! are environment-dependent (the oracle container and carrick number their
//! tasks differently), so a probe that prints them can never be line-exact.
//!
//! INVARIANTS:
//!   parent_pid_positive=true
//!   child_ppid_matches=true      (written by the child via raw write(2))
//!   child_ok                     (written by the child via raw write(2))
//!   child_forked=true            (parent lines print only after waitpid)
//!   child_pid_distinct=true
//!   child_exited_zero=true
//!   parent_pid_stable=true       (fork does not change the parent's pid)
//!   child_reaped_once=true       (a second waitpid on the reaped child is ECHILD)
//!   parent_write_ok=true

use std::io::Write as _;

fn raw_write(msg: &[u8]) -> bool {
    let written = unsafe {
        libc::write(
            libc::STDOUT_FILENO,
            msg.as_ptr() as *const libc::c_void,
            msg.len(),
        )
    };
    written as usize == msg.len()
}

fn main() {
    let parent = unsafe { libc::getpid() };
    println!("parent_pid_positive={}", parent > 0);
    // Flush before fork so the buffered line is not duplicated by the child.
    std::io::stdout().flush().expect("flush stdout");

    let child = unsafe { libc::fork() };
    if child == 0 {
        // The child inherits `parent` by value and checks its own parent
        // link against it, then reports through the shared stdout fd.
        let ppid = unsafe { libc::getppid() };
        let mut ok = raw_write(if ppid == parent {
            b"child_ppid_matches=true\n"
        } else {
            b"child_ppid_matches=false\n"
        });
        ok &= raw_write(b"child_ok\n");
        unsafe { libc::_exit(if ok { 0 } else { 1 }) };
    }

    // Reap before printing anything else: the child's raw writes and the
    // parent's lines share one pipe, and the gate is line-exact, so the
    // parent must not race the child for output order.
    let mut status = 0;
    let reaped = unsafe { libc::waitpid(child, &mut status, 0) };
    println!("child_forked={}", child > 0);
    println!("child_pid_distinct={}", child != parent);
    let child_exited_zero =
        reaped == child && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
    println!("child_exited_zero={child_exited_zero}");
    println!("parent_pid_stable={}", unsafe { libc::getpid() } == parent);

    let again = unsafe { libc::waitpid(child, &mut status, 0) };
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    println!("child_reaped_once={}", again == -1 && errno == libc::ECHILD);
    std::io::stdout().flush().expect("flush stdout");

    println!("parent_write_ok={}", raw_write(b"parent_ok\n"));
}
