//! Parent-pid probe. A forked child's getppid() must equal the parent's
//! getpid(): carrick mirrors the guest process tree onto the host process
//! tree, so an orphan-detection heuristic (e.g. LTP's tst_test heartbeat,
//! which calls `kill(getppid(), SIGUSR1)` and treats `getppid() == 1` as
//! "main test process exited") must not false-positive. The conformance
//! harness runs this identical static binary under carrick and real Linux
//! and diffs line by line.
//!
//! Deterministic: prints only booleans, never raw pids.

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

fn main() {
    let parent_pid = unsafe { libc::getpid() };

    // The child reports its getppid() back over a pipe, so the comparison is
    // deterministic and doesn't depend on either side's absolute pid values.
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        println!("ppid pipe=ERR:{}", errno());
        return;
    }

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::close(fds[0]) };
        let ppid = unsafe { libc::getppid() };
        let bytes = ppid.to_ne_bytes();
        unsafe { libc::write(fds[1], bytes.as_ptr() as *const libc::c_void, bytes.len()) };
        unsafe { libc::_exit(0) };
    }
    if pid < 0 {
        println!("ppid fork=ERR:{}", errno());
        return;
    }

    unsafe { libc::close(fds[1]) };
    let mut bytes = [0u8; 4];
    let n = unsafe {
        libc::read(fds[0], bytes.as_mut_ptr() as *mut libc::c_void, bytes.len())
    };
    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };

    let child_ppid = i32::from_ne_bytes(bytes);
    println!(
        "ppid read_ok={} child_ppid_eq_parent_pid={}",
        n == 4,
        child_ppid == parent_pid,
    );
}
