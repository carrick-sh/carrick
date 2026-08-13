//! A reaped child's CPU is charged to the PARENT'S CHILDREN accounts, never to
//! the parent itself.
//!
//! Linux keeps two separate ledgers per process. `times(2)` reports the calling
//! process's own CPU in `tms_utime`/`tms_stime` and the summed CPU of its
//! *reaped* children in `tms_cutime`/`tms_cstime`; `getrusage(2)` splits the
//! same distinction across `RUSAGE_SELF` and `RUSAGE_CHILDREN`. A parent that
//! only forks and waits therefore reports near-zero self time and the child's
//! full burn under children.
//!
//! Every build tool depends on this. `make`, the shell's `time` builtin, and
//! benchmark harnesses attribute work by reading the children ledger; if a
//! runtime folds child CPU into `RUSAGE_SELF` they report a parent that did all
//! the work and children that did none.
//!
//! carrick sources both ledgers from process-global state — `times` reads
//! `proc_pid_rusage`, which is the whole HOST process — and that was correct
//! only while each Linux process was its own host process. Under the HVPatch
//! backend every Linux process is a THREAD of one host process, so
//! `proc_pid_rusage` returns the summed CPU of every guest process at once and
//! each guest reads that total as its own `RUSAGE_SELF`. The child's burn lands
//! on the parent's SELF line because it is literally inside the same host
//! process, and the children ledger is a global static shared by all guests.
//!
//! Observed on a cold `go build`: the guest shell reported 5.98 CPU-s of self
//! time against a host process that had only spent 4.29 CPU-s, with the build's
//! work attributed to the shell rather than to the compiler processes it forked.
//! Docker attributes the same build to the children line and reports zero on
//! the shell line.
//!
//! The probe reports only orderings and signs, never durations, so it is
//! line-exact across machines of different speeds.

use conformance_probes::report;

/// Spin until `ms` milliseconds of wall time have elapsed. The loop never
/// sleeps or blocks, so wall time is CPU time and the burn is attributable.
fn burn_cpu(ms: u64) {
    let start = monotonic_ms();
    let mut sink: u64 = 0;
    while monotonic_ms().saturating_sub(start) < ms {
        // Enough work per clock read that the syscall/vDSO cost does not
        // dominate, and volatile so it cannot be optimised away.
        for i in 0..20_000_u64 {
            sink = sink.wrapping_add(i).rotate_left(1);
        }
        unsafe { std::ptr::read_volatile(&sink) };
    }
}

fn monotonic_ms() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000 + (ts.tv_nsec as u64) / 1_000_000
}

fn rusage_us(who: libc::c_int) -> i64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(who, &mut usage) } != 0 {
        return -1;
    }
    let user = usage.ru_utime.tv_sec as i64 * 1_000_000 + usage.ru_utime.tv_usec as i64;
    let system = usage.ru_stime.tv_sec as i64 * 1_000_000 + usage.ru_stime.tv_usec as i64;
    user + system
}

fn main() {
    unsafe {
        // Baseline the parent's own CPU before forking, so the comparison is
        // against work this process did, not against zero.
        let self_before_us = rusage_us(libc::RUSAGE_SELF);

        let child = libc::fork();
        if child == 0 {
            burn_cpu(300);
            libc::_exit(0);
        }
        if child < 0 {
            report!(fork_ok = false);
            return;
        }

        // The parent does nothing but block in wait4, so every microsecond the
        // child spends must show up in the children ledger and nowhere else.
        let mut status: libc::c_int = 0;
        let reaped = libc::waitpid(child, &mut status, 0);
        let exited_zero = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;

        let mut tms: libc::tms = std::mem::zeroed();
        let times_rc = libc::times(&mut tms);

        let self_after_us = rusage_us(libc::RUSAGE_SELF);
        let children_us = rusage_us(libc::RUSAGE_CHILDREN);
        let self_delta_us = self_after_us - self_before_us;

        let child_ticks = tms.tms_cutime as i64 + tms.tms_cstime as i64;
        let self_ticks = tms.tms_utime as i64 + tms.tms_stime as i64;

        report!(
            fork_ok = child > 0,
            reaped_the_child = reaped == child,
            child_exited_zero = exited_zero,
            times_rc_valid = times_rc != -1,
            // Linux: true. The child burned 300ms, so the children ledger must
            // have advanced past zero.
            times_children_nonzero = child_ticks > 0,
            // Linux: true. The parent only forked and blocked in wait4, so its
            // own ledger stays below the child's burn. On the bug the child's
            // CPU is inside the same host process and lands here instead.
            times_self_below_children = self_ticks < child_ticks,
            // Linux: true. Same split through the getrusage spelling.
            rusage_children_nonzero = children_us > 0,
            // Linux: true. RUSAGE_SELF must not absorb the child's burn.
            rusage_self_delta_below_children = self_delta_us < children_us,
        );
    }
}
