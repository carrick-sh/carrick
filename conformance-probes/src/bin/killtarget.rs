//! kill / tkill / tgkill targeting semantics. Stands in for LTP `kill02`
//! (self-kill via raise()-equivalent), `kill10/11/12` (process-group kill via
//! negative pid + kill(0,…)), `tgkill02/03` and `tkill02` (argument validation
//! on the per-thread kill syscalls).
//!
//! Invariants encoded, all boolean:
//!
//!   * `kill(getpid(), 0)` — existence check, returns 0 and delivers nothing.
//!   * `kill(getpid(), SIGUSR1)` runs the installed handler exactly once.
//!   * Process-group kill via `kill(-pgid, …)` after `setpgid(0,0)` reaches
//!     the current process (still in its own group).
//!   * `kill(0, sig)` (broadcast to current pgrp) reaches the current process.
//!   * `kill(non_existent_pid, 0)` returns -1 with errno ESRCH. We synthesise
//!     a target PID well outside the system pid range (`0x7FFFFFF0`) so it is
//!     vanishingly unlikely to alias a live process in the container.
//!   * `tkill(invalid_tid, 0)` returns -1; report the errno boolean (Linux
//!     uses ESRCH, but the diff against the oracle is what matters).
//!   * `tgkill(invalid_tgid /* 0 */, valid_tid, 0)` returns -1; report the
//!     errno boolean (Linux uses EINVAL for tgid<=0, ESRCH for "no such").
//!
//! musl doesn't expose `tkill`/`tgkill` as functions, so we go through
//! `libc::syscall(SYS_tkill, …)` / `libc::syscall(SYS_tgkill, …)`.
//!
//! Deterministic only — no PIDs, TIDs, or timestamps in the output.

use conformance_probes::{errno, install_handler, report};
use std::sync::atomic::{AtomicU32, Ordering};

static USR1_HITS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_usr1(_: i32) {
    USR1_HITS.fetch_add(1, Ordering::SeqCst);
}

fn main() {
    unsafe {
        let _ = install_handler(libc::SIGUSR1, on_usr1, 0);

        // kill(pid, 0): existence check on self.
        let self_pid = libc::getpid();
        let exists_rc = libc::kill(self_pid, 0);
        report!(kill_self_sig0_rc_zero = exists_rc == 0);

        // kill(getpid(), SIGUSR1) → handler runs exactly once.
        USR1_HITS.store(0, Ordering::SeqCst);
        let self_rc = libc::kill(self_pid, libc::SIGUSR1);
        // raise is synchronous on Linux when the signal isn't blocked; on
        // return the handler has run.
        report!(
            kill_self_usr1_rc_zero = self_rc == 0,
            kill_self_usr1_handler_ran_once = USR1_HITS.load(Ordering::SeqCst) == 1,
        );

        // Process-group kill. After setpgid(0,0) we lead our own pgrp,
        // so both kill(-pgid, sig) and kill(0, sig) deliver to us.
        let _ = libc::setpgid(0, 0);
        let pgid = libc::getpgrp();

        USR1_HITS.store(0, Ordering::SeqCst);
        let pg_rc = libc::kill(-pgid, libc::SIGUSR1);
        report!(
            kill_neg_pgid_rc_zero = pg_rc == 0,
            kill_neg_pgid_delivered = USR1_HITS.load(Ordering::SeqCst) == 1,
        );

        USR1_HITS.store(0, Ordering::SeqCst);
        let pg0_rc = libc::kill(0, libc::SIGUSR1);
        report!(
            kill_zero_rc_zero = pg0_rc == 0,
            kill_zero_delivered = USR1_HITS.load(Ordering::SeqCst) == 1,
        );

        // kill(non_existent_pid, 0) → -1 / ESRCH. 0x7FFFFFF0 is well above
        // any realistic pid_max (default 2^22 ≈ 4_194_304) and not us.
        let bogus: libc::pid_t = 0x7FFFFFF0;
        let probe_rc = libc::kill(bogus, 0);
        let probe_errno = errno();
        report!(
            kill_bogus_rc_minus_one = probe_rc == -1,
            kill_bogus_errno_is_esrch = probe_errno == libc::ESRCH,
        );

        // tkill(invalid_tid, 0): -1 with errno set. Use an obviously-invalid
        // tid of 0 (kernel rejects tid<=0 / non-existent). We report two
        // booleans: the rc is -1, and the errno is ESRCH (which is what
        // Linux returns for missing-tid; tid==0 specifically yields EINVAL
        // on Linux — we report which it is).
        let tk_rc = libc::syscall(libc::SYS_tkill, 0i32 as libc::c_long, 0i32 as libc::c_long);
        let tk_errno = errno();
        report!(
            tkill_zero_tid_rc_minus_one = tk_rc == -1,
            tkill_zero_tid_errno_is_einval = tk_errno == libc::EINVAL,
        );

        // tkill on a tid that almost certainly doesn't exist (large positive).
        let tk_rc2 = libc::syscall(
            libc::SYS_tkill,
            0x7FFFFFF0i32 as libc::c_long,
            0i32 as libc::c_long,
        );
        let tk_errno2 = errno();
        report!(
            tkill_bogus_tid_rc_minus_one = tk_rc2 == -1,
            tkill_bogus_tid_errno_is_esrch = tk_errno2 == libc::ESRCH,
        );

        // tgkill(invalid_tgid /* 0 */, valid_tid, 0): Linux validates tgid>0
        // first, so this returns -1/EINVAL regardless of the tid argument.
        let tgk_rc = libc::syscall(
            libc::SYS_tgkill,
            0i32 as libc::c_long,
            self_pid as libc::c_long,
            0i32 as libc::c_long,
        );
        let tgk_errno = errno();
        report!(
            tgkill_zero_tgid_rc_minus_one = tgk_rc == -1,
            tgkill_zero_tgid_errno_is_einval = tgk_errno == libc::EINVAL,
        );

        // tgkill(valid_tgid, invalid_tid /* 0 */, 0): same EINVAL class.
        let tgk_rc2 = libc::syscall(
            libc::SYS_tgkill,
            self_pid as libc::c_long,
            0i32 as libc::c_long,
            0i32 as libc::c_long,
        );
        let tgk_errno2 = errno();
        report!(
            tgkill_zero_tid_rc_minus_one = tgk_rc2 == -1,
            tgkill_zero_tid_errno_is_einval = tgk_errno2 == libc::EINVAL,
        );
    }
}
