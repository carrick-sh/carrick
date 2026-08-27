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
///
/// `inherited` lists the release write-ends of children forked EARLIER that
/// this parent still holds. The new child must close them, because `fork`
/// copies the whole descriptor table: a later child holding an earlier
/// child's write end keeps that pipe open, so closing the PARENT's copy never
/// delivers EOF, the earlier child never exits, and `waitpid` on it blocks
/// forever while the child that could release it is itself still blocked.
/// That is a deadlock in the probe, not a runtime divergence, and it strands
/// both children — which then count against this uid's RLIMIT_NPROC and make
/// every later run fail.
///
/// A failed fork returns a negative pid; the caller must not treat that as a
/// child, because `waitpid(-1, ...)` means "any child" and would block on an
/// unrelated one that has not been released yet.
fn fork_blocked(inherited: &[i32]) -> (libc::pid_t, i32) {
    let (r, w) = pipe2();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            for fd in inherited {
                libc::close(*fd);
            }
            // If the harness kills the probe while this child is blocked, the
            // child must not survive: an orphaned PROBE_UID process counts
            // against RLIMIT_NPROC for that uid forever and makes every later
            // run of this probe fail with EAGAIN. Best-effort — an unsupported
            // prctl is ignored, and nothing is printed either way, so the
            // line-exact output is unaffected on both sides of the oracle.
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            libc::close(w);
            let mut byte = 0u8;
            libc::read(r, &mut byte as *mut u8 as *mut c_void, 1);
            libc::_exit(0);
        }
    }
    unsafe { libc::close(r) };
    (pid, w)
}

/// Release a blocked child and reap exactly it.
///
/// The `pid > 0` guard is load-bearing, not defensive: `waitpid` treats a
/// non-positive pid as a wildcard (`-1` = any child, `0` = the process group),
/// so reaping a fork that FAILED would block on whichever other child is still
/// blocked on its own release pipe — a deadlock that leaks both children. The
/// leak is not confined to the run that hangs, because `RLIMIT_NPROC` counts
/// live processes per REAL uid across the whole user namespace: a leaked
/// `PROBE_UID` process makes the NEXT run's forks fail with EAGAIN and hang in
/// turn. One unchecked fork therefore poisons every later run on the machine.
fn release_and_reap(pid: libc::pid_t, w: i32) -> bool {
    let mut status = 0i32;
    unsafe {
        libc::close(w);
        if pid <= 0 {
            return false;
        }
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

    let (a, a_release) = fork_blocked(&[]);
    println!("fork_a_ok={}", a > 0);
    println!("fork_b_eagain={}", fork_expect_eagain());
    println!("reap_a_ok={}", release_and_reap(a, a_release));

    let (c, c_release) = fork_blocked(&[]);
    println!("fork_c_after_reap_ok={}", c > 0);

    println!("setrlimit_nproc_3={}", set_nproc(3, 3));
    let (d, d_release) = fork_blocked(&[c_release]);
    println!("fork_d_ok={}", d > 0);

    println!("reap_c_ok={}", release_and_reap(c, c_release));
    println!("reap_d_ok={}", release_and_reap(d, d_release));
}
