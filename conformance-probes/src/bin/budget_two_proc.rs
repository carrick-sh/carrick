//! budget_two_proc: Phase G two-process differential conformance probe.
//!
//! Exercises fork inheritance, process accounting, and boundary writes.
//!
//! INVARIANTS:
//!   parent_pid=1
//!   child_forked=true
//!   child_exited_zero=true
//!   parent_write_ok=true

fn main() {
    let pid = unsafe { libc::getpid() };
    println!("parent_pid={pid}");

    let child = unsafe { libc::fork() };
    if child == 0 {
        // Child writes a message and exits 0
        let msg = b"child_ok\n";
        let written = unsafe {
            libc::write(
                libc::STDOUT_FILENO,
                msg.as_ptr() as *const libc::c_void,
                msg.len(),
            )
        };
        let exit_code = if written as usize == msg.len() { 0 } else { 1 };
        unsafe { libc::_exit(exit_code) };
    }

    let child_forked = child > 0;
    println!("child_forked={child_forked}");

    let mut status = 0;
    let reaped = unsafe { libc::waitpid(child, &mut status, 0) };
    let child_exited_zero = reaped == child && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
    println!("child_exited_zero={child_exited_zero}");

    let parent_msg = b"parent_ok\n";
    let written = unsafe {
        libc::write(
            libc::STDOUT_FILENO,
            parent_msg.as_ptr() as *const libc::c_void,
            parent_msg.len(),
        )
    };
    let parent_write_ok = written as usize == parent_msg.len();
    println!("parent_write_ok={parent_write_ok}");
}
