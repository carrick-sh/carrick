//! Linux personality translations for timers: clock IDs, signal delivery,
//! `itimerspec`/`itimerval` wire conversions, `TIMER_*` flags, and errno semantics.
//!
//! Substrate timer implementations in `carrick-timer-core` remain neutral
//! of `carrick-abi` and Linux-specific constants; this module translates
//! between Linux ABI representations and substrate primitives.

use std::time::Duration;

use carrick_abi::{
    LINUX_CLOCK_BOOTTIME, LINUX_CLOCK_BOOTTIME_ALARM, LINUX_CLOCK_MONOTONIC,
    LINUX_CLOCK_MONOTONIC_COARSE, LINUX_CLOCK_MONOTONIC_RAW, LINUX_CLOCK_PROCESS_CPUTIME_ID,
    LINUX_CLOCK_REALTIME, LINUX_CLOCK_REALTIME_ALARM, LINUX_CLOCK_REALTIME_COARSE, LINUX_CLOCK_TAI,
    LINUX_CLOCK_THREAD_CPUTIME_ID, LINUX_EINVAL, LINUX_SIGALRM, LINUX_SIGPROF, LINUX_SIGVTALRM,
    LINUX_TIMER_ABSTIME, LinuxErrno, LinuxItimerspec, LinuxItimerval, LinuxTimespec, LinuxTimeval,
};
use carrick_timer_core::{ClockKind, TimerSpecNs};

/// Linux mask identifying dynamic per-thread CPU clocks (`CPUCLOCK_PERTHREAD_MASK`).
pub const CPUCLOCK_PERTHREAD_MASK: i32 = 4;

/// Linux signal number delivered when `which`'s interval timer expires.
#[inline]
pub const fn itimer_signum_for(which: usize) -> i32 {
    match which {
        1 => LINUX_SIGVTALRM, // ITIMER_VIRTUAL
        2 => LINUX_SIGPROF,   // ITIMER_PROF
        _ => LINUX_SIGALRM,   // ITIMER_REAL
    }
}

/// Linux CPU-time clocks whose POSIX timers fire off aggregate guest CPU time
/// rather than wall-clock time: `CLOCK_PROCESS_CPUTIME_ID` (2),
/// `CLOCK_THREAD_CPUTIME_ID` (3), or Linux dynamic CPU clock IDs (negative).
#[inline]
pub const fn is_cpu_clock(clock_id: i32) -> bool {
    clock_id < 0
        || clock_id == (LINUX_CLOCK_PROCESS_CPUTIME_ID as i32)
        || clock_id == (LINUX_CLOCK_THREAD_CPUTIME_ID as i32)
}

/// Linux per-thread CPU-time clock: `CLOCK_THREAD_CPUTIME_ID` (3) or dynamic
/// per-thread CPU clock IDs (negative with `CPUCLOCK_PERTHREAD_MASK` bit 2 set).
#[inline]
pub const fn is_thread_cpu_clock(clock_id: i32) -> bool {
    clock_id == (LINUX_CLOCK_THREAD_CPUTIME_ID as i32)
        || (clock_id < 0 && (clock_id & CPUCLOCK_PERTHREAD_MASK) != 0)
}

/// Linux per-process CPU-time clock: `CLOCK_PROCESS_CPUTIME_ID` (2) or dynamic
/// per-process CPU clock IDs (negative with `CPUCLOCK_PERTHREAD_MASK` bit 2 clear).
#[inline]
pub const fn is_process_cpu_clock(clock_id: i32) -> bool {
    clock_id == (LINUX_CLOCK_PROCESS_CPUTIME_ID as i32)
        || (clock_id < 0 && (clock_id & CPUCLOCK_PERTHREAD_MASK) == 0)
}

/// Map a Linux `clock_id` to its neutral substrate [`ClockKind`].
pub fn clock_kind_for(clock_id: i32) -> Option<ClockKind> {
    if is_thread_cpu_clock(clock_id) {
        Some(ClockKind::ThreadCpu)
    } else if is_process_cpu_clock(clock_id) {
        Some(ClockKind::ProcessCpu)
    } else if clock_id >= 0 {
        match clock_id as u64 {
            LINUX_CLOCK_REALTIME
            | LINUX_CLOCK_MONOTONIC
            | LINUX_CLOCK_MONOTONIC_RAW
            | LINUX_CLOCK_REALTIME_COARSE
            | LINUX_CLOCK_MONOTONIC_COARSE
            | LINUX_CLOCK_BOOTTIME
            | LINUX_CLOCK_REALTIME_ALARM
            | LINUX_CLOCK_BOOTTIME_ALARM
            | LINUX_CLOCK_TAI => Some(ClockKind::Wall),
            _ => None,
        }
    } else {
        None
    }
}

/// Pack a timer's `(value, interval)` ns pair into a `LinuxItimerspec` (the
/// Linux kernel ABI `struct __kernel_itimerspec`).
pub fn build_itimerspec_ns(spec: TimerSpecNs) -> LinuxItimerspec {
    let split = |ns: u64| LinuxTimespec {
        tv_sec: i64::try_from(ns / 1_000_000_000).unwrap_or(i64::MAX),
        tv_nsec: i64::try_from(ns % 1_000_000_000).unwrap_or(0),
    };
    LinuxItimerspec::new(split(spec.interval), split(spec.value))
}

/// Pack a timer's `(value, interval)` ns pair into a `LinuxItimerval` (the
/// Linux kernel ABI `struct itimerval`).
pub fn build_itimerval_ns(spec: TimerSpecNs) -> LinuxItimerval {
    let split = |ns: u64| LinuxTimeval {
        tv_sec: i64::try_from(ns / 1_000_000_000).unwrap_or(i64::MAX),
        tv_usec: i64::try_from((ns % 1_000_000_000) / 1_000).unwrap_or(0),
    };
    LinuxItimerval::new(split(spec.interval), split(spec.value))
}

/// Validate flags passed to `timer_settime`. Linux permits only `TIMER_ABSTIME`.
#[inline]
pub fn validate_timer_settime_flags(flags: u64) -> Result<(), LinuxErrno> {
    if flags & !LINUX_TIMER_ABSTIME != 0 {
        Err(LINUX_EINVAL)
    } else {
        Ok(())
    }
}

/// Convert a `LinuxTimespec` to a `Duration`, returning `Err(LINUX_EINVAL)` if
/// `tv_nsec` is outside `0..1_000_000_000` or `tv_sec < 0`. Returns `Ok(None)`
/// for all-zero timespecs (disarm).
pub fn duration_from_linux_timespec(
    timespec: LinuxTimespec,
) -> Result<Option<Duration>, LinuxErrno> {
    let seconds = timespec.tv_sec;
    let nanoseconds = timespec.tv_nsec;
    if seconds < 0 || !(0..1_000_000_000).contains(&nanoseconds) {
        return Err(LINUX_EINVAL);
    }
    if seconds == 0 && nanoseconds == 0 {
        return Ok(None);
    }
    Ok(Some(Duration::new(seconds as u64, nanoseconds as u32)))
}

/// Extract `(interval, value)` durations from a `LinuxItimerspec`.
pub fn itimerspec_durations(
    spec: LinuxItimerspec,
) -> Result<(Option<Duration>, Option<Duration>), LinuxErrno> {
    Ok((
        duration_from_linux_timespec(spec.it_interval)?,
        duration_from_linux_timespec(spec.it_value)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn itimer_signals() {
        assert_eq!(itimer_signum_for(0), LINUX_SIGALRM);
        assert_eq!(itimer_signum_for(1), LINUX_SIGVTALRM);
        assert_eq!(itimer_signum_for(2), LINUX_SIGPROF);
        assert_eq!(itimer_signum_for(99), LINUX_SIGALRM);
    }

    #[test]
    fn clock_classification() {
        assert!(!is_cpu_clock(LINUX_CLOCK_REALTIME as i32));
        assert!(!is_cpu_clock(LINUX_CLOCK_MONOTONIC as i32));
        assert!(is_cpu_clock(LINUX_CLOCK_PROCESS_CPUTIME_ID as i32));
        assert!(is_cpu_clock(LINUX_CLOCK_THREAD_CPUTIME_ID as i32));
        assert!(is_cpu_clock(-1)); // dynamic CPU clock

        assert!(is_process_cpu_clock(LINUX_CLOCK_PROCESS_CPUTIME_ID as i32));
        assert!(!is_process_cpu_clock(LINUX_CLOCK_THREAD_CPUTIME_ID as i32));
        assert!(is_process_cpu_clock(-2 & !CPUCLOCK_PERTHREAD_MASK));

        assert!(is_thread_cpu_clock(LINUX_CLOCK_THREAD_CPUTIME_ID as i32));
        assert!(!is_thread_cpu_clock(LINUX_CLOCK_PROCESS_CPUTIME_ID as i32));
        assert!(is_thread_cpu_clock(-2 | CPUCLOCK_PERTHREAD_MASK));
    }

    #[test]
    fn clock_kind_mapping() {
        assert_eq!(
            clock_kind_for(LINUX_CLOCK_REALTIME as i32),
            Some(ClockKind::Wall)
        );
        assert_eq!(
            clock_kind_for(LINUX_CLOCK_MONOTONIC as i32),
            Some(ClockKind::Wall)
        );
        assert_eq!(
            clock_kind_for(LINUX_CLOCK_PROCESS_CPUTIME_ID as i32),
            Some(ClockKind::ProcessCpu)
        );
        assert_eq!(
            clock_kind_for(LINUX_CLOCK_THREAD_CPUTIME_ID as i32),
            Some(ClockKind::ThreadCpu)
        );
        assert_eq!(clock_kind_for(999), None);
    }

    #[test]
    fn build_itimerspec_roundtrip() {
        let spec = TimerSpecNs {
            value: 2_500_000_000,
            interval: 1_250_000_000,
        };
        let abi = build_itimerspec_ns(spec);
        let val_sec = abi.it_value.tv_sec;
        let val_nsec = abi.it_value.tv_nsec;
        let int_sec = abi.it_interval.tv_sec;
        let int_nsec = abi.it_interval.tv_nsec;
        assert_eq!(val_sec, 2);
        assert_eq!(val_nsec, 500_000_000);
        assert_eq!(int_sec, 1);
        assert_eq!(int_nsec, 250_000_000);

        let (interval_dur, value_dur) = itimerspec_durations(abi).expect("valid durations");
        assert_eq!(value_dur, Some(Duration::new(2, 500_000_000)));
        assert_eq!(interval_dur, Some(Duration::new(1, 250_000_000)));
    }

    #[test]
    fn build_itimerval_wire_format() {
        let spec = TimerSpecNs {
            value: 1_500_000_000,
            interval: 500_000_000,
        };
        let abi = build_itimerval_ns(spec);
        let val_sec = abi.it_value.tv_sec;
        let val_usec = abi.it_value.tv_usec;
        let int_sec = abi.it_interval.tv_sec;
        let int_usec = abi.it_interval.tv_usec;
        assert_eq!(val_sec, 1);
        assert_eq!(val_usec, 500_000);
        assert_eq!(int_sec, 0);
        assert_eq!(int_usec, 500_000);
    }

    #[test]
    fn validate_flags() {
        assert!(validate_timer_settime_flags(0).is_ok());
        assert!(validate_timer_settime_flags(LINUX_TIMER_ABSTIME).is_ok());
        assert_eq!(validate_timer_settime_flags(0x8).unwrap_err(), LINUX_EINVAL);
    }

    #[test]
    fn duration_validation() {
        let invalid = LinuxTimespec {
            tv_sec: 1,
            tv_nsec: 1_000_000_000,
        };
        assert_eq!(
            duration_from_linux_timespec(invalid).unwrap_err(),
            LINUX_EINVAL
        );

        let neg = LinuxTimespec {
            tv_sec: -1,
            tv_nsec: 0,
        };
        assert_eq!(duration_from_linux_timespec(neg).unwrap_err(), LINUX_EINVAL);

        let zero = LinuxTimespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        assert_eq!(duration_from_linux_timespec(zero).unwrap(), None);
    }
}
