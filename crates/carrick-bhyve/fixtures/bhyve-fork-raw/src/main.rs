//! SP1 bisection fixture: fork via the RAW `SYS_fork` syscall, bypassing musl's
//! `fork()` wrapper (and its child-side post-fork cleanup) entirely. The child
//! `_exit(7)`s immediately — no wait4, no musl wrapper — so the ONLY thing under
//! test is the value carrick delivers in the child's syscall-return register.
//!
//! If this is GREEN (child saw ret==0) but the musl `bhyve-fork` fixture is RED,
//! the bug is in musl's `fork()` wrapper (a register it relies on across its
//! child cleanup is corrupted), not in carrick's child-RAX. If this is ALSO RED,
//! carrick is setting the child's return register wrong.
//!
//! Static-musl x86_64 (same loader requirements as the other bhyve fixtures).
fn main() {
    // SAFETY: a single raw fork(2) in a single-threaded program.
    let ret = unsafe { libc::syscall(libc::SYS_fork) };
    if ret < 0 {
        unsafe { libc::_exit(1) };
    }
    if ret == 0 {
        // CHILD: distinct code, NO musl wrapper, NO wait4.
        unsafe { libc::_exit(7) };
    }
    // PARENT: reap + verify the child's exit status.
    let mut st: libc::c_int = 0;
    let w = unsafe { libc::wait4(ret as i32, &mut st, 0, std::ptr::null_mut()) };
    if w != ret as i32 {
        unsafe { libc::_exit(2) };
    }
    let code = if libc::WIFEXITED(st) {
        libc::WEXITSTATUS(st)
    } else {
        -1
    };
    unsafe { libc::_exit(if code == 7 { 0 } else { 3 }) };
}
