//! M3c fork fixture (audit #1): exercises `fork(2)` + `wait4` + `write` +
//! `exit`. The child writes "child\n" and exits 7; the parent reaps it via
//! `waitpid` and writes "parent-ok\n" iff the child exited 7. Raw `libc::write`
//! (not `println!`) avoids buffered-stdio duplication across the fork.
//!
//! Cross-compiled static x86_64-unknown-linux-musl (non-PIE ET_EXEC) by
//! build.sh. Run under carrick-kvm it proves the x86 KVM `fork()` — the parent
//! keeps its live VM, the child rebuilds a fresh VM over the COW-inherited host
//! mmaps and resumes at the SYSRETQ with RAX=0.
fn main() {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe { libc::write(2, b"fork-failed\n".as_ptr() as *const _, 12) };
        std::process::exit(2);
    }
    if pid == 0 {
        // Child: returned 0 from fork(2).
        unsafe {
            libc::write(1, b"child\n".as_ptr() as *const _, 6);
            libc::_exit(7);
        }
    }
    // Parent: reap the child and verify its exit status.
    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 7 {
        unsafe { libc::write(1, b"parent-ok\n".as_ptr() as *const _, 10) };
    } else {
        unsafe { libc::write(2, b"parent-bad\n".as_ptr() as *const _, 11) };
        std::process::exit(1);
    }
}
