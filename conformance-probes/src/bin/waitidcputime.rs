//! `waitid(2)` must roll a reaped child's CPU into the parent's child-time
//! totals exactly like `wait4`/`waitpid` does — Linux accounts a reaped child's
//! user/system CPU into `RUSAGE_CHILDREN` and `times()`'s `tms_cutime`/`tms_cstime`
//! regardless of WHICH wait syscall consumed the zombie.
//!
//! carrick's `wait4` handler drains the reaped child's guest CPU
//! (`guest_cpu::reap_child_guest_ns` + `add_reaped_child`, `dispatch/proc.rs`),
//! but the `waitid` handler does NOT — it returns the siginfo and never touches
//! the child-time accumulators (`dispatch/proc.rs:1166-1268`). So a CPU-burning
//! child reaped via `waitid` contributes 0 to `RUSAGE_CHILDREN`, while the same
//! child reaped via `wait4` contributes its CPU. This probe makes that
//! asymmetry a deterministic boolean.
//!
//! Deterministic-by-design (mirrors `accounting.rs`): absolute CPU times vary
//! per machine and are NEVER printed. Each observation is reduced to a boolean
//! ("RUSAGE_CHILDREN increased after reaping a CPU-burning child"). The two
//! phases share one invariant: reaping a burner — via wait4 OR via waitid —
//! must make the parent's accumulated child CPU strictly increase.
//!
//! Bounded (never hangs): Phase B does NOT use a blocking waitid. It polls
//! waitid(P_PID, WEXITED|WNOHANG) against a fixed iteration deadline. A
//! WNOHANG waitid that finds the child not-yet-a-zombie returns rc=0 with
//! si_pid==0 (no reap); only the terminal poll returns si_pid==child and
//! consumes the zombie — that is the reap that must drive child-CPU
//! accounting. If carrick's reap path ever wedges, the deadline expires and
//! the probe prints `waitid_reap_ok=false` instead of hanging the harness.
//!
//! Also pins the no-children error path: waitid(P_ALL, WNOHANG) with no
//! children -> -1/ECHILD (anchors the errno-translation half of the finding;
//! ECHILD is 10 on both kernels — in the 1..=34 identity range of
//! macos_to_linux_errno — so it MATCHES today, but it guards against a
//! regression in the central host->linux errno routing the fix introduces).

use conformance_probes::{report, reap};

// waitid raw constants (idtype values / option bits aren't all exposed
// portably on aarch64-musl; waitidspec.rs uses the same literals).
const P_PID: libc::idtype_t = 1;
const P_ALL: libc::idtype_t = 0;
const WEXITED: libc::c_int = 4;
const WNOHANG: libc::c_int = 1;

/// Burn a FIXED amount of user CPU (no wall-clock dependency). Sized — like
/// accounting.rs's burn — so the accrued user time clears the accounting
/// granularity (microsecond `ru_utime`, 10 ms `times` tick) on both Docker and
/// carrick. Pure arithmetic with volatile accumulation: a memory-heavy loop
/// would measure carrick's fault-per-access guest memory, not the syscall.
fn burn_cpu(iters: u64) -> u64 {
    let mut acc: u64 = 1;
    for _ in 0..iters {
        acc = acc.wrapping_mul(6364136223846793005).wrapping_add(1);
        acc ^= acc >> 17;
    }
    acc
}

/// Total accumulated child user+system CPU (microseconds) as reported through
/// getrusage(RUSAGE_CHILDREN). On carrick this is sourced purely from the
/// child-time accumulators that wait4/waitid feed; on Linux it is the kernel's
/// reaped-child rollup. Either way it only moves when a child is reaped.
fn children_cpu_us() -> u64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut ru) } != 0 {
        return 0;
    }
    let us = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
    us(ru.ru_utime) + us(ru.ru_stime)
}

/// Fork a child that burns CPU then exits 0. Returns the child pid.
unsafe fn spawn_burner() -> i32 {
    let pid = libc::fork();
    if pid == 0 {
        std::hint::black_box(burn_cpu(80_000_000));
        libc::_exit(0);
    }
    pid
}

/// Reap `pid` via waitid(P_PID, WEXITED|WNOHANG), polling against a fixed
/// deadline (never blocks). Returns true once waitid consumed THIS child's
/// zombie (rc==0 && si.si_pid==pid). A pre-zombie poll returns rc==0 with
/// si_pid==0 and is retried; on deadline returns false rather than hanging.
unsafe fn waitid_reap_bounded(pid: i32) -> bool {
    // 500 * 10 ms = 5 s cap. The burner exits in well under that on both
    // Docker and carrick; the cap exists only so a wedged reap path prints a
    // deterministic `false` instead of stalling the line-diff harness.
    for _ in 0..500 {
        let mut si: libc::siginfo_t = std::mem::zeroed();
        let rc = libc::waitid(P_PID, pid as libc::id_t, &mut si, WEXITED | WNOHANG);
        if rc == 0 && si.si_pid() == pid {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    false
}

fn main() {
    unsafe {
        // Phase A — control: reap a CPU-burning child via wait4. This is the
        // path carrick already accounts; it establishes that RUSAGE_CHILDREN
        // moves on a reap at all (so a `false` in Phase B is the waitid gap,
        // not a dead accounting subsystem).
        let before_a = children_cpu_us();
        let c1 = spawn_burner();
        let (rc_a, _status) = reap(c1); // wait4-based reap
        let after_a = children_cpu_us();
        report!(
            wait4_reap_ok = rc_a == c1,
            wait4_child_added_cpu = after_a > before_a,
        );

        // Phase B — the finding: reap a CPU-burning child via waitid(P_PID,
        // WEXITED) and require RUSAGE_CHILDREN to increase the SAME way. The
        // snapshot is taken AFTER Phase A so we measure only this child's
        // contribution. Linux: increases. carrick today: unchanged (waitid
        // never drains the reaped child's guest_ns into the accumulators).
        let before_b = children_cpu_us();
        let c2 = spawn_burner();
        let reaped_b = waitid_reap_bounded(c2);
        let after_b = children_cpu_us();
        report!(
            waitid_reap_ok = reaped_b,
            waitid_child_added_cpu = after_b > before_b,
        );

        // Anchor — no-children error path: with every child reaped, a
        // non-blocking waitid(P_ALL, WNOHANG) returns -1/ECHILD. Guards the
        // errno-translation half of the finding (the success-side accounting
        // fix routes errors through the central host->linux errno helper).
        let mut si: libc::siginfo_t = std::mem::zeroed();
        let rc_c = libc::waitid(P_ALL, 0, &mut si, WEXITED | WNOHANG);
        let er = if rc_c == -1 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        };
        report!(
            no_children_rc_neg_one = rc_c == -1,
            no_children_errno_echild = er == libc::ECHILD,
        );
    }
}