//! SP1 fixture: fork(), child writes a marker + _exit(7); parent wait4s and
//! asserts WEXITSTATUS==7. Static-musl x86_64. Exercises the bhyve eager-RAM-
//! copy fork + the shared wait_proc_exit + the normalize_syscall fork desugar.
use std::process;

fn main() {
    // SAFETY: libc::fork in a single-threaded program.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        eprintln!("fork failed");
        process::exit(1);
    }
    if pid == 0 {
        // CHILD: a distinct exit code the parent verifies.
        unsafe { libc::_exit(7) };
    }
    // PARENT: reap the child, check its status.
    let mut status: libc::c_int = 0;
    let w = unsafe { libc::wait4(pid, &mut status, 0, std::ptr::null_mut()) };
    if w != pid {
        eprintln!("wait4 returned {w} (want {pid})");
        process::exit(2);
    }
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    if code != 7 {
        eprintln!("child exit code {code} (want 7)");
        process::exit(3);
    }
    println!("fork ok");
    process::exit(0);
}
