//! RLIMIT_NPROC is enforced at fork(2): once the number of live threads owned
//! by the caller's REAL uid reaches the soft limit, fork fails with EAGAIN
//! (setrlimit(2)). Real uid 0 and CAP_SYS_ADMIN/CAP_SYS_RESOURCE holders are
//! exempt, so the probe first drops to an unprivileged real uid with raw
//! setresuid — both the Docker oracle and carrick start the probe as root.
//! carrick stored the limit (default 8192) but never consulted it, so every
//! fork past the limit succeeded. Deterministic booleans only.
//!
//! Sequence (soft limit 2 for the new uid, whose only live thread is this one):
//!   fork A (blocks on a pipe)        -> succeeds (count 1 -> 2)
//!   fork B                           -> EAGAIN   (2 >= 2)
//!   release + reap A, fork C         -> succeeds (count back to 1 -> 2)
//!   raise the soft limit to 3, fork D -> succeeds while C is alive (2 -> 3)
//! Every child _exit(0)s and the parent reaps all of them, so no zombie can
//! leak into the count. UID 47231 is arbitrary and unallocated on both sides:
//! the count is per real uid across the whole (initial) user namespace, so a
//! uid a host daemon might own would make the count nondeterministic.

use conformance_probes::{errno, pipe2};
use std::os::raw::c_void;

const PROBE_UID: i64 = 47231;

fn set_nproc(cur: u64, max: u64) -> bool {
    let rl = libc::rlimit {
        rlim_cur: cur,
        rlim_max: max,
    };
    unsafe {
        libc::syscall(
            libc::SYS_prlimit64,
            0i64,
            libc::RLIMIT_NPROC as i64,
            &rl as *const libc::rlimit as i64,
            0i64,
        ) == 0
    }
}

/// Fork a child that blocks on a 1-byte pipe read and exits 0 when released.
fn fork_blocked() -> (libc::pid_t, i32) {
    let (r, w) = pipe2();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::close(w);
            let mut byte = 0u8;
            libc::read(r, &mut byte as *mut u8 as *mut c_void, 1);
            libc::_exit(0);
        }
    }
    unsafe { libc::close(r) };
    (pid, w)
}

fn release_and_reap(pid: libc::pid_t, w: i32) -> bool {
    let mut status = 0i32;
    unsafe {
        libc::close(w);
        libc::waitpid(pid, &mut status, 0) == pid
            && libc::WIFEXITED(status)
            && libc::WEXITSTATUS(status) == 0
    }
}

/// A fork that must be refused. If it wrongly succeeds, the child exits at
/// once and is reaped so the rest of the sequence stays well-defined.
fn fork_expect_eagain() -> bool {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::_exit(0) };
    }
    if pid > 0 {
        let mut status = 0i32;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        return false;
    }
    errno() == libc::EAGAIN
}

fn main() {
    // Set the limit while still root (soft 2, hard 3): raising a SOFT limit
    // within the hard limit later needs no privilege.
    println!("setrlimit_nproc_2={}", set_nproc(2, 3));
    let dropped = unsafe {
        libc::syscall(libc::SYS_setresuid, PROBE_UID, PROBE_UID, PROBE_UID) == 0
    };
    println!("setresuid_unprivileged={dropped}");
    if !dropped {
        return;
    }

    let (a, a_release) = fork_blocked();
    println!("fork_a_ok={}", a > 0);
    println!("fork_b_eagain={}", fork_expect_eagain());
    println!("reap_a_ok={}", release_and_reap(a, a_release));

    let (c, c_release) = fork_blocked();
    println!("fork_c_after_reap_ok={}", c > 0);

    println!("setrlimit_nproc_3={}", set_nproc(3, 3));
    let (d, d_release) = fork_blocked();
    println!("fork_d_ok={}", d > 0);

    println!("reap_c_ok={}", release_and_reap(c, c_release));
    println!("reap_d_ok={}", release_and_reap(d, d_release));
}
