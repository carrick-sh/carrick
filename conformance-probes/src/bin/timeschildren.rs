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
//!
//! ## The USER/SYSTEM split, and why summing them hid a second bug
//!
//! The assertions above sum `tms_cutime + tms_cstime`, which made them blind to
//! a runtime that reports the whole child burn as USER and zero SYSTEM. carrick
//! did exactly that: its per-vCPU exec clock measures time inside
//! `hv_vcpu_run`, i.e. the guest executing its own instructions, and the CPU
//! carrick spends SERVICING the guest's syscalls happens outside that call and
//! was counted nowhere. On a cold `go build` the guest read
//! `0m2.090000s 0m0.000000s` where Docker read `0m2.28s 0m0.24s` — plausible
//! enough to pass a summed check and wrong for anything that reads `stime`.
//!
//! So the second child below burns SYSTEM time deliberately, with a storm of a
//! real syscall (`getpid` via `syscall(2)`, which is not vDSO-accelerated and
//! which glibc does not cache), and the probe asserts the children SYSTEM
//! ledger advanced across it — a claim summing cannot make.

use conformance_probes::report;

/// Issue `count` real syscalls. `getpid` is chosen because it is the cheapest
/// syscall that genuinely enters the kernel on aarch64 Linux: not vDSO-served,
/// no fd or memory state, and nothing for a compiler to elide. Called through
/// `syscall(2)` so glibc's `getpid` caching cannot turn it into a memory read.
fn burn_system(count: u64) {
    for _ in 0..count {
        unsafe { libc::syscall(libc::SYS_getpid) };
    }
}

fn children_split_us() -> (i64, i64) {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut usage) } != 0 {
        return (-1, -1);
    }
    (
        usage.ru_utime.tv_sec as i64 * 1_000_000 + usage.ru_utime.tv_usec as i64,
        usage.ru_stime.tv_sec as i64 * 1_000_000 + usage.ru_stime.tv_usec as i64,
    )
}

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

        // --- Second child: burn SYSTEM time, so the children ledger's system
        //     half is exercised on its own rather than hidden inside a sum.
        let (_, system_before_us) = children_split_us();
        let syscall_child = libc::fork();
        if syscall_child == 0 {
            burn_system(400_000);
            libc::_exit(0);
        }
        let mut syscall_status: libc::c_int = 0;
        let reaped_syscall_child = syscall_child > 0
            && libc::waitpid(syscall_child, &mut syscall_status, 0) == syscall_child;
        let (_, system_after_us) = children_split_us();

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
            // Linux: true. The syscall-storm child was reaped.
            reaped_syscall_child = reaped_syscall_child,
            // Linux: true. 400k real syscalls is tens of milliseconds of kernel
            // CPU, so the children SYSTEM ledger must advance on its own. A
            // runtime that reports every child burn as USER — which summing
            // user+system cannot detect — reports false here.
            children_system_advanced = system_after_us > system_before_us,
            // Linux: true. The system half is a real, separately-tracked
            // quantity, not a copy of the user half.
            children_system_nonzero = system_after_us > 0,
        );
    }
}
