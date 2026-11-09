//! Linux `nanosleep(2)` and `clock_nanosleep(2)` for ring-owned processes.
//!
//! A sleep is a signal-interruptible member wait with a deadline and nothing
//! else to wait for. The process owner therefore serves it with the same
//! owner, timer lease and wake channel it uses for `rt_sigtimedwait`: the
//! caller parks (releasing its execution lease), the scheduler's timer index
//! retains the original deadline across executor departure, and a signal
//! publication wakes the parked member. This module owns only the Linux
//! argument contract: clock classification, `timespec` validation and the
//! conversion of an absolute deadline into the guest counter's domain.
//!
//! Clock domains in ring: `CLOCK_MONOTONIC` is the guest counter divided by
//! its frequency, exactly what the raw clock fast path and the vDSO report
//! (on HVF that counter is the host's CLOCK_UPTIME_RAW, the host dispatcher's
//! monotonic clock too).
//! `CLOCK_REALTIME` is that plus the vvar realtime word the caller's own vDSO
//! adds ([`crate::abi::vvar`]). A relative sleep measures the counter whatever
//! its clock id, as POSIX requires for relative sleeps.

use crate::abi::entry::SyscallResult;
use crate::signal::{SignalNative, SignalOutcome};
use carrick_core::user_copy::CopyOutcome;
use carrick_guest_arch::UserVa;
use carrick_syscall_abi::{
    LINUX_CLOCK_BOOTTIME, LINUX_CLOCK_BOOTTIME_ALARM, LINUX_CLOCK_MONOTONIC,
    LINUX_CLOCK_MONOTONIC_COARSE, LINUX_CLOCK_MONOTONIC_RAW, LINUX_CLOCK_PROCESS_CPUTIME_ID,
    LINUX_CLOCK_REALTIME, LINUX_CLOCK_REALTIME_ALARM, LINUX_CLOCK_REALTIME_COARSE, LINUX_CLOCK_TAI,
    LINUX_CLOCK_THREAD_CPUTIME_ID, LINUX_EFAULT, LINUX_EINVAL, LINUX_EOPNOTSUPP,
    LINUX_TIMER_ABSTIME, LinuxErrno,
};

const NANOS_PER_SECOND: u64 = 1_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SleepCall {
    Nanosleep,
    ClockNanosleep,
}

/// The time base an absolute deadline is expressed in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SleepClock {
    Monotonic,
    Realtime,
}

/// Classify a sleep clock exactly as the host dispatcher's
/// `linux_clock_nanosleep_now` does, so the run root (host continuation) and
/// a native child (ring) give one answer: CPU-time clocks are `EOPNOTSUPP`,
/// unknown ids `EINVAL`. BOOTTIME is measured on the guest counter like
/// MONOTONIC: after a host suspend the host's BOOTTIME runs ahead of it, so an
/// absolute BOOTTIME deadline then fires late by the suspended time.
pub fn sleep_clock(clock_id: u64) -> Result<SleepClock, LinuxErrno> {
    match clock_id {
        LINUX_CLOCK_REALTIME
        | LINUX_CLOCK_REALTIME_COARSE
        | LINUX_CLOCK_REALTIME_ALARM
        | LINUX_CLOCK_TAI => Ok(SleepClock::Realtime),
        LINUX_CLOCK_MONOTONIC
        | LINUX_CLOCK_MONOTONIC_RAW
        | LINUX_CLOCK_MONOTONIC_COARSE
        | LINUX_CLOCK_BOOTTIME
        | LINUX_CLOCK_BOOTTIME_ALARM => Ok(SleepClock::Monotonic),
        LINUX_CLOCK_PROCESS_CPUTIME_ID | LINUX_CLOCK_THREAD_CPUTIME_ID => Err(LINUX_EOPNOTSUPP),
        // A dynamic per-task CPU clock is a negative 32-bit id whose low two
        // bits are not CPUCLOCK_FD (3).
        id if (id as i32) < 0 && id & 0b11 != 0b11 => Err(LINUX_EOPNOTSUPP),
        _ => Err(LINUX_EINVAL),
    }
}

/// Validate one copied Linux 64-bit `timespec` and return its nanoseconds.
pub fn timespec_nanos(bytes: [u8; 16]) -> Result<u64, LinuxErrno> {
    let mut seconds = [0; 8];
    let mut nanos = [0; 8];
    seconds.copy_from_slice(&bytes[..8]);
    nanos.copy_from_slice(&bytes[8..]);
    let seconds = i64::from_le_bytes(seconds);
    let nanos = i64::from_le_bytes(nanos);
    if seconds < 0 || !(0..NANOS_PER_SECOND as i64).contains(&nanos) {
        return Err(LINUX_EINVAL);
    }
    Ok((seconds as u64)
        .saturating_mul(NANOS_PER_SECOND)
        .saturating_add(nanos as u64))
}

/// Encode a remaining interval as the Linux 64-bit `timespec` written to `rem`.
pub fn timespec_bytes(nanos: u64) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&((nanos / NANOS_PER_SECOND) as i64).to_le_bytes());
    bytes[8..].copy_from_slice(&((nanos % NANOS_PER_SECOND) as i64).to_le_bytes());
    bytes
}

/// Convert an absolute `CLOCK_REALTIME` deadline into the monotonic domain
/// with the caller's vvar realtime word (`realtime = monotonic + word`,
/// wrapping, as the vDSO computes it). A deadline before the counter's epoch
/// has already passed.
pub fn realtime_to_monotonic(realtime_nanos: u64, vvar_word: u64) -> u64 {
    let monotonic = realtime_nanos.wrapping_sub(vvar_word);
    if (monotonic as i64) < 0 { 0 } else { monotonic }
}

/// The deadline the process owner converts into guest counter ticks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SleepDeadline {
    /// Nanoseconds from now, measured on the guest counter.
    Relative(u64),
    /// Absolute monotonic-domain nanoseconds (guest counter / frequency).
    Monotonic(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SleepRequest {
    pub deadline: SleepDeadline,
    /// Relative sleeps only: where `EINTR` writes the unslept interval.
    pub remaining: Option<UserVa>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SleepOutcome {
    /// The deadline had passed: return 0 without parking.
    Elapsed,
    /// The owner parked the caller and retains its wait; the result is
    /// published when the deadline or a signal resumes it.
    Pending,
}

/// Serve one routed sleep. `None` leaves the call to its host continuation
/// (a caller whose owner does not sleep in ring), before any user access.
pub fn invoke(call: SleepCall, native: &mut dyn SignalNative<'_>) -> Option<SignalOutcome> {
    let returned = |value: i64| {
        Some(SignalOutcome::Returned {
            result: SyscallResult::new(value),
            work: false,
        })
    };
    let args = native.arguments();
    let (clock_id, flags, request, remaining) = match call {
        SleepCall::Nanosleep => (LINUX_CLOCK_MONOTONIC, 0, args[0], args[1]),
        SleepCall::ClockNanosleep => (args[0], args[1], args[2], args[3]),
    };
    if !native.process_signals()?.sleeps_in_ring() {
        return None;
    }
    // Mirror the host dispatcher's flag and clock order.
    if flags & !LINUX_TIMER_ABSTIME != 0 {
        return returned(LINUX_EINVAL.guest_retval());
    }
    let clock = match sleep_clock(clock_id) {
        Ok(clock) => clock,
        Err(errno) => return returned(errno.guest_retval()),
    };
    // As the host dispatcher: page zero is never a guest timespec.
    if request == 0 {
        return returned(LINUX_EFAULT.guest_retval());
    }
    let mut bytes = [0; 16];
    match native.copy_in(&mut bytes, UserVa::new(request)) {
        CopyOutcome::Done => {}
        CopyOutcome::Fault => return returned(LINUX_EFAULT.guest_retval()),
        CopyOutcome::NotYet(request) => return Some(native.wait_guest_copy(request)),
    }
    let nanos = match timespec_nanos(bytes) {
        Ok(nanos) => nanos,
        Err(errno) => return returned(errno.guest_retval()),
    };
    let absolute = flags & LINUX_TIMER_ABSTIME != 0;
    let deadline = match (absolute, clock) {
        (false, _) if nanos == 0 => return returned(0),
        (false, _) => SleepDeadline::Relative(nanos),
        (true, SleepClock::Monotonic) => SleepDeadline::Monotonic(nanos),
        (true, SleepClock::Realtime) => {
            let mut word = [0; 8];
            match native.copy_in(
                &mut word,
                UserVa::new(crate::abi::vvar::LINUX_VVAR_BASE + crate::abi::vvar::REALTIME_OFF_NS),
            ) {
                CopyOutcome::Done => {}
                CopyOutcome::NotYet(request) => return Some(native.wait_guest_copy(request)),
                // No vDSO data page (vDSO disabled): there is no realtime
                // base in this address space. Leave the call unserved.
                CopyOutcome::Fault => return None,
            }
            SleepDeadline::Monotonic(realtime_to_monotonic(nanos, u64::from_le_bytes(word)))
        }
    };
    // An absolute sleep never writes `rem` (clock_nanosleep(2)).
    let remaining = (!absolute && remaining != 0).then_some(UserVa::new(remaining));
    match native.process_signals()?.clock_sleep(SleepRequest {
        deadline,
        remaining,
    }) {
        Ok(SleepOutcome::Elapsed) => returned(0),
        Ok(SleepOutcome::Pending) => Some(SignalOutcome::Transferred {
            progress: carrick_core_abi::Served::Idle,
            result: SyscallResult::new(0),
        }),
        Err(errno) => returned(errno.guest_retval()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sleep_clocks_match_the_host_classification() {
        assert_eq!(sleep_clock(0), Ok(SleepClock::Realtime));
        assert_eq!(sleep_clock(11), Ok(SleepClock::Realtime));
        assert_eq!(sleep_clock(1), Ok(SleepClock::Monotonic));
        assert_eq!(sleep_clock(7), Ok(SleepClock::Monotonic));
        assert_eq!(sleep_clock(2), Err(LINUX_EOPNOTSUPP));
        assert_eq!(sleep_clock(3), Err(LINUX_EOPNOTSUPP));
        // clock_getcpuclockid(pid 1): ~(1 << 3) | CPUCLOCK_SCHED.
        assert_eq!(
            sleep_clock(((!1_u32 << 3) | 2) as u64),
            Err(LINUX_EOPNOTSUPP)
        );
        assert_eq!(sleep_clock(10), Err(LINUX_EINVAL));
        assert_eq!(sleep_clock(u64::from(u32::MAX)), Err(LINUX_EINVAL));
    }

    #[test]
    fn timespecs_validate_and_round_trip() {
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&3_i64.to_le_bytes());
        bytes[8..].copy_from_slice(&5_i64.to_le_bytes());
        assert_eq!(timespec_nanos(bytes), Ok(3_000_000_005));
        assert_eq!(timespec_bytes(3_000_000_005), bytes);
        bytes[8..].copy_from_slice(&1_000_000_000_i64.to_le_bytes());
        assert_eq!(timespec_nanos(bytes), Err(LINUX_EINVAL));
        bytes[8..].copy_from_slice(&(-1_i64).to_le_bytes());
        assert_eq!(timespec_nanos(bytes), Err(LINUX_EINVAL));
        bytes[..8].copy_from_slice(&(-1_i64).to_le_bytes());
        bytes[8..].copy_from_slice(&0_i64.to_le_bytes());
        assert_eq!(timespec_nanos(bytes), Err(LINUX_EINVAL));
    }

    #[test]
    fn realtime_deadlines_before_the_counter_epoch_have_passed() {
        assert_eq!(realtime_to_monotonic(1_000, 400), 600);
        assert_eq!(realtime_to_monotonic(400, 1_000), 0);
        // A negative stored offset wraps exactly as the vDSO adds it.
        assert_eq!(realtime_to_monotonic(100, (-50_i64) as u64), 150);
    }
}
