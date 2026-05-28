//! `waitid(2)` is a distinct ABI from `wait4`/`waitpid`: it takes an
//! `idtype` (P_PID/P_PGID/P_ALL/P_PIDFD), an `options` bitmask containing
//! `WEXITED|WSTOPPED|WCONTINUED|WNOWAIT|WNOHANG`, and crucially fills a
//! `siginfo_t` instead of returning an encoded `int` wait status. The siginfo
//! `si_code` distinguishes `CLD_EXITED` / `CLD_KILLED` / `CLD_DUMPED` /
//! `CLD_STOPPED` / `CLD_CONTINUED`, and `si_status` carries the exit code or
//! signum. `proclife` / `waitrestart` cover wait4; this pins down waitid's
//! own shape. Stands in for LTP `waitid01` / `waitid02` / `waitid03`.
//!
//! Invariants encoded:
//!   1. P_PID + WEXITED on a normal exit(7): rc=0, siginfo.si_pid==child,
//!      si_code==CLD_EXITED, si_status==7, si_signo==SIGCHLD.
//!   2. P_PID + WEXITED on a SIGKILL'd child: si_code==CLD_KILLED,
//!      si_status==SIGKILL.
//!   3. P_PID + WNOWAIT inspects without consuming: the same waitid() with
//!      WNOWAIT then a follow-up WITHOUT WNOWAIT must both succeed (Linux
//!      keeps the zombie around so a second waitid reaps it).
//!   4. P_ALL + WNOHANG with no children → -1/ECHILD.

use conformance_probes::report;

const P_PID: libc::idtype_t = 1;
const P_ALL: libc::idtype_t = 0;
const WEXITED: libc::c_int = 4;
const WNOHANG: libc::c_int = 1;
const WNOWAIT: libc::c_int = 0x0100_0000;

const CLD_EXITED: libc::c_int = 1;
const CLD_KILLED: libc::c_int = 2;

unsafe fn errno_raw() -> i32 {
    *libc::__errno_location()
}

/// Spawn a child that exits with the given code after a brief delay so the
/// parent has time to land in `waitid`. Returns the child PID.
unsafe fn spawn_exit(code: i32) -> i32 {
    let pid = libc::fork();
    if pid == 0 {
        // Brief delay so the parent can issue waitid first if it wants to.
        libc::usleep(20_000);
        libc::_exit(code);
    }
    pid
}

/// Spawn a child that loops in pause() until killed. Returns the child PID.
unsafe fn spawn_pause() -> i32 {
    let pid = libc::fork();
    if pid == 0 {
        loop {
            libc::pause();
        }
    }
    pid
}

fn main() {
    unsafe {
        // Case 1: clean exit(7).
        let c1 = spawn_exit(7);
        let mut si: libc::siginfo_t = core::mem::zeroed();
        let rc = libc::waitid(P_PID, c1 as libc::id_t, &mut si, WEXITED);
        // siginfo_t accessors aren't stable in Rust libc on aarch64-musl;
        // read the relevant fields via the public glibc layout (si_signo,
        // si_code at fixed offsets; si_status accessible via the union).
        let si_signo = si.si_signo;
        let si_code = si.si_code;
        // `si_status` lives in the union. libc exposes it via si_status()
        // when the platform supports it; otherwise reach for the field name.
        // glibc's siginfo_t layout on Linux: si_status is the 4th int in
        // the _sifields._sigchld struct (offset depends on architecture).
        // Use the libc::siginfo_t::si_status helper.
        let si_status = si.si_status();
        report!(
            waitid_exit7_rc_zero = rc == 0,
            waitid_exit7_si_signo_is_sigchld = si_signo == libc::SIGCHLD,
            waitid_exit7_si_code_is_cld_exited = si_code == CLD_EXITED,
            waitid_exit7_si_status_is_7 = si_status == 7,
        );

        // Case 2: SIGKILL.
        let c2 = spawn_pause();
        libc::usleep(20_000); // let child reach pause()
        libc::kill(c2, libc::SIGKILL);
        let mut si: libc::siginfo_t = core::mem::zeroed();
        let rc = libc::waitid(P_PID, c2 as libc::id_t, &mut si, WEXITED);
        let si_code = si.si_code;
        let si_status = si.si_status();
        report!(
            waitid_kill_rc_zero = rc == 0,
            waitid_kill_si_code_is_cld_killed = si_code == CLD_KILLED,
            waitid_kill_si_status_is_sigkill = si_status == libc::SIGKILL,
        );

        // Case 3: WNOWAIT then a follow-up reaping waitid.
        let c3 = spawn_exit(11);
        let mut si: libc::siginfo_t = core::mem::zeroed();
        let rc_peek = libc::waitid(P_PID, c3 as libc::id_t, &mut si, WEXITED | WNOWAIT);
        let peek_status = si.si_status();
        // Now actually reap.
        let mut si: libc::siginfo_t = core::mem::zeroed();
        let rc_reap = libc::waitid(P_PID, c3 as libc::id_t, &mut si, WEXITED);
        let reap_status = si.si_status();
        report!(
            waitid_wnowait_peek_ok = rc_peek == 0,
            waitid_wnowait_peek_status_is_11 = peek_status == 11,
            waitid_wnowait_reap_ok = rc_reap == 0,
            waitid_wnowait_reap_status_is_11 = reap_status == 11,
        );

        // Case 4: P_ALL + WNOHANG with no children → ECHILD.
        // (All previous children reaped above.)
        let mut si: libc::siginfo_t = core::mem::zeroed();
        let rc = libc::waitid(P_ALL, 0, &mut si, WEXITED | WNOHANG);
        let er = if rc == -1 { errno_raw() } else { 0 };
        report!(
            waitid_no_children_rc_is_neg_one = rc == -1,
            waitid_no_children_errno_is_echild = er == libc::ECHILD,
        );
    }
}
