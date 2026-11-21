//! Fork child reads every ring-served clock through RAW syscalls (#2618).
//! Under Carrick the ARM root reads time through its legacy policy and glibc's
//! vDSO; only a fork child (a ring-owned native task) reaches the ring clock
//! owner. The child never calls libc's clock wrappers, so the vDSO cannot
//! answer for it.
//! Linux authority: clock_gettime(2), gettimeofday(2), times(2).
//!
//! The parent and the child each take two samples of raw
//! `clock_gettime(CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_PROCESS_CPUTIME_ID)`,
//! raw `gettimeofday` and raw `times`, burning at least 50 ms of process CPU
//! between them, and print one boolean per bound:
//!   * every call returns 0 (times: not -1) with a normalized field;
//!   * REALTIME and gettimeofday are a Unix time after 2020 and before 2100,
//!     and agree with each other within one second;
//!   * MONOTONIC advances by at least the CPU burned and by less than the
//!     bound; REALTIME advances by MONOTONIC's step within one second;
//!   * PROCESS_CPUTIME advances by at least 50 ms and by no more than
//!     MONOTONIC's step plus one millisecond (one thread cannot outrun the
//!     wall clock);
//!   * `times` user+system advances by at least four 10 ms ticks, and its
//!     elapsed return never goes backwards.
//!
//! The burn is bounded by raw MONOTONIC (10 s), the child by `alarm`, and the
//! parent's wait by a non-restarting `alarm` that kills and reaps the child.
use conformance_probes::{errno, report};

const NANOS: i128 = 1_000_000_000;
const BURN_NS: i128 = 50_000_000;
const BURN_BOUND_NS: i128 = 10 * NANOS;
const UNIX_2020: i64 = 1_577_836_800;
const UNIX_2100: i64 = 4_102_444_800;

extern "C" fn on_alarm(_signal: libc::c_int) {}

/// One raw `clock_gettime`, or `None` when it failed or returned an
/// unnormalized timespec.
fn raw_clock(clock: libc::clockid_t) -> Option<i128> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::syscall(libc::SYS_clock_gettime, clock as libc::c_long, &mut ts) };
    (rc == 0 && (0..NANOS as libc::c_long).contains(&ts.tv_nsec))
        .then(|| i128::from(ts.tv_sec) * NANOS + i128::from(ts.tv_nsec))
}

fn raw_gettimeofday() -> Option<i128> {
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_gettimeofday,
            &mut tv,
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    (rc == 0 && (0..1_000_000).contains(&tv.tv_usec))
        .then(|| i128::from(tv.tv_sec) * NANOS + i128::from(tv.tv_usec) * 1_000)
}

/// Raw `times`: (elapsed ticks, user + system ticks).
fn raw_times() -> Option<(i64, i64)> {
    let mut tms: libc::tms = unsafe { std::mem::zeroed() };
    let elapsed = unsafe { libc::syscall(libc::SYS_times, &mut tms) };
    (elapsed != -1).then(|| (elapsed as i64, (tms.tms_utime + tms.tms_stime) as i64))
}

struct Sample {
    realtime: i128,
    monotonic: i128,
    cputime: i128,
    gettimeofday: i128,
    times: (i64, i64),
}

fn sample() -> Option<Sample> {
    Some(Sample {
        realtime: raw_clock(libc::CLOCK_REALTIME)?,
        monotonic: raw_clock(libc::CLOCK_MONOTONIC)?,
        cputime: raw_clock(libc::CLOCK_PROCESS_CPUTIME_ID)?,
        gettimeofday: raw_gettimeofday()?,
        times: raw_times()?,
    })
}

/// Spin until this process has burned `BURN_NS` of CPU, bounded by MONOTONIC.
fn burn(first: &Sample) -> bool {
    let mut spins = 0u64;
    loop {
        for _ in 0..10_000 {
            spins = std::hint::black_box(spins.wrapping_add(1));
        }
        let (Some(cpu), Some(now)) = (
            raw_clock(libc::CLOCK_PROCESS_CPUTIME_ID),
            raw_clock(libc::CLOCK_MONOTONIC),
        ) else {
            return false;
        };
        if cpu - first.cputime >= BURN_NS {
            return true;
        }
        if now - first.monotonic >= BURN_BOUND_NS {
            return false;
        }
    }
}

/// Print one line per bound, prefixed with `who`.
fn check(who: &str) {
    let Some(first) = sample() else {
        println!("{who}_calls_ok=false errno={}", errno());
        return;
    };
    let burned = burn(&first);
    let Some(second) = sample() else {
        println!("{who}_calls_ok=false errno={}", errno());
        return;
    };
    let unix =
        |ns: i128| (i128::from(UNIX_2020) * NANOS..i128::from(UNIX_2100) * NANOS).contains(&ns);
    let monotonic_step = second.monotonic - first.monotonic;
    let cpu_step = second.cputime - first.cputime;
    let realtime_step = second.realtime - first.realtime;
    println!("{who}_calls_ok=true");
    for (name, holds) in [
        (
            "realtime_unix",
            unix(first.realtime) && unix(second.realtime),
        ),
        (
            "gettimeofday_unix",
            unix(first.gettimeofday) && unix(second.gettimeofday),
        ),
        (
            "gettimeofday_matches_realtime",
            (first.gettimeofday - first.realtime).abs() < NANOS
                && (second.gettimeofday - second.realtime).abs() < NANOS,
        ),
        ("burned", burned),
        (
            "monotonic_advances",
            monotonic_step >= BURN_NS && monotonic_step < BURN_BOUND_NS + NANOS,
        ),
        (
            "realtime_follows_monotonic",
            (realtime_step - monotonic_step).abs() < NANOS,
        ),
        ("cputime_advances", cpu_step >= BURN_NS),
        (
            "cputime_within_wall",
            cpu_step <= monotonic_step + 1_000_000,
        ),
        ("times_cpu_advances", second.times.1 - first.times.1 >= 4),
        ("times_elapsed_monotonic", second.times.0 >= first.times.0),
    ] {
        println!("{who}_{name}={holds}");
    }
}

fn main() {
    use std::io::Write;
    check("root");
    let _ = std::io::stdout().flush();
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            libc::alarm(20);
            check("child");
            let flushed = std::io::stdout().flush().is_ok();
            libc::_exit(if flushed { 0 } else { 5 });
        }
        if pid < 0 {
            println!("fork_errno={}", errno());
            std::process::exit(1);
        }
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_alarm as extern "C" fn(libc::c_int) as usize;
        action.sa_flags = 0;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGALRM, &action, std::ptr::null_mut());
        libc::alarm(30);
        let mut status = 0;
        let mut timed_out = false;
        let mut reaped = libc::waitpid(pid, &mut status, 0);
        if reaped < 0 && errno() == libc::EINTR {
            timed_out = true;
            libc::kill(pid, libc::SIGKILL);
            reaped = libc::waitpid(pid, &mut status, 0);
        }
        libc::alarm(0);
        let exited = reaped == pid && libc::WIFEXITED(status);
        let signalled = reaped == pid && libc::WIFSIGNALED(status);
        report!(
            child_exit = if exited {
                libc::WEXITSTATUS(status).to_string()
            } else {
                "none".to_owned()
            },
            child_signal = if signalled {
                libc::WTERMSIG(status).to_string()
            } else {
                "none".to_owned()
            },
            child_timeout = timed_out
        );
    }
}
