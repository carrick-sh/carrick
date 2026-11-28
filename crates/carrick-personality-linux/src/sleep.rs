//! Linux `nanosleep(2)` and `clock_nanosleep(2)` for ring-owned processes.
//!
//! A sleep is a signal-interruptible member wait with a deadline and nothing
//! else to wait for. The process owner therefore serves it with the same
//! owner, timer lease and wake channel it uses for `rt_sigtimedwait`: the
//! caller parks (releasing its execution lease), the scheduler's timer index
//! retains the original deadline across executor departure, and a signal
//! publication wakes the parked member. This module owns only the Linux
//! argument contract: clock classification and `timespec` validation.
//!
//! An absolute monotonic wait uses the same guest counter epoch as
//! `clock_gettime(CLOCK_MONOTONIC)`. ARM also projects its BOOTTIME through
//! that epoch. An absolute REALTIME or TAI deadline needs to follow
//! `clock_settime` and remains unserved (#1981).

use crate::abi::entry::SyscallResult;
use crate::signal::{SignalNative, SignalOutcome};
use carrick_core::user_copy::CopyOutcome;
use carrick_guest_arch::{CounterTick, GuestIsa, UserVa};
use carrick_syscall_abi::{
    LINUX_CLOCK_BOOTTIME, LINUX_CLOCK_BOOTTIME_ALARM, LINUX_CLOCK_CPU_PERTHREAD,
    LINUX_CLOCK_CPU_WHICH_MASK, LINUX_CLOCK_FD, LINUX_CLOCK_MONOTONIC,
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

impl SleepCall {
    pub const fn canonical(self) -> carrick_syscall_abi::CanonicalNr {
        match self {
            Self::Nanosleep => crate::crossing::nr::NANOSLEEP,
            Self::ClockNanosleep => crate::crossing::nr::CLOCK_NANOSLEEP,
        }
    }

    /// Whether an owner with a host sleep continuation (the run root) keeps
    /// it for this call on this crossing set. The continuation exists only
    /// where the set carries the call: the x86 set does not, so an x86 run
    /// root sleeps in ring like every other process. Leaving it to the
    /// crossing would answer a counted ENOSYS.
    pub const fn host_continuation(self, crossing: crate::crossing::HostCrossingSet) -> bool {
        crossing.is_allowed(self.canonical())
    }
}

/// The time base an absolute deadline is expressed in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SleepClock {
    /// The guest execution counter epoch.
    Monotonic,
    /// On ARM the vDSO projects BOOTTIME through the same epoch.
    Boottime,
    /// `CLOCK_REALTIME` and `CLOCK_TAI`: settable wall time.
    Realtime,
}

/// What `clock_nanosleep(2)` does with one clock id on Linux.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockClass {
    /// Linux sleeps against this clock and the ring can measure it.
    Sleeps(SleepClock),
    /// Linux sleeps against this clock (or decides after reading the
    /// request), but the ring has no authority for it: leave the call to its
    /// counted crossing refusal, before any user access.
    Unserved,
    /// Linux refuses this clock before reading the request.
    Refused(LinuxErrno),
}

/// Classify a sleep clock as Linux does. Source: clock_nanosleep(2) and a
/// native Linux 6.12 probe (errno numbers): REALTIME, MONOTONIC, BOOTTIME and
/// TAI sleep; MONOTONIC_RAW, the COARSE clocks, CLOCK_THREAD_CPUTIME_ID and
/// posix-clock fds give 95 (EOPNOTSUPP) before the request is read; an
/// unknown static id gives 22 (EINVAL). Linux sleeps on a process CPU-time
/// clock (the man page permits it), and the ALARM clocks (EPERM without
/// CAP_WAKE_ALARM) and dynamic CPU clocks decide only after reading the
/// request: a raw `clock_nanosleep(0xfffffff6, 0, NULL, NULL)` gives 14
/// (EFAULT), and a zero request on a live sibling's per-thread clock gives 0
/// where the caller's own gives 22. The ring measures none of them, so they
/// stay [`ClockClass::Unserved`].
///
/// BOOTTIME is measured on the guest counter like MONOTONIC: after a host
/// suspend the host's BOOTTIME runs ahead of it, so an absolute BOOTTIME
/// deadline then fires late by the suspended time.
pub fn sleep_clock(clock_id: u64) -> ClockClass {
    // `clockid_t` is a C int: Linux never sees the upper half of the register.
    let id = clock_id as u32 as i32;
    if id < 0 {
        // A dynamic clock: `~pid << 3 | which`, or a posix-clock fd.
        let low = id as u32 & (LINUX_CLOCK_CPU_PERTHREAD | LINUX_CLOCK_CPU_WHICH_MASK);
        return if low == LINUX_CLOCK_FD {
            ClockClass::Refused(LINUX_EOPNOTSUPP)
        } else {
            // Process and per-thread CPU clocks: Linux reads the request
            // first and the answer depends on the named task.
            ClockClass::Unserved
        };
    }
    match id as u64 {
        LINUX_CLOCK_REALTIME | LINUX_CLOCK_TAI => ClockClass::Sleeps(SleepClock::Realtime),
        LINUX_CLOCK_MONOTONIC => ClockClass::Sleeps(SleepClock::Monotonic),
        LINUX_CLOCK_BOOTTIME => ClockClass::Sleeps(SleepClock::Boottime),
        LINUX_CLOCK_PROCESS_CPUTIME_ID
        | LINUX_CLOCK_REALTIME_ALARM
        | LINUX_CLOCK_BOOTTIME_ALARM => ClockClass::Unserved,
        LINUX_CLOCK_THREAD_CPUTIME_ID
        | LINUX_CLOCK_MONOTONIC_RAW
        | LINUX_CLOCK_REALTIME_COARSE
        | LINUX_CLOCK_MONOTONIC_COARSE => ClockClass::Refused(LINUX_EOPNOTSUPP),
        _ => ClockClass::Refused(LINUX_EINVAL),
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

/// An absolute deadline on a guest clock, in that clock's nanoseconds. A
/// timed futex wait and an absolute sleep both convert one, once, at entry,
/// with [`AbsoluteDeadline::counter_tick`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbsoluteDeadline {
    /// Monotonic-domain nanoseconds: guest counter / frequency, the epoch of
    /// `clock_gettime(CLOCK_MONOTONIC)` in ring and in the vDSO.
    Monotonic(u64),
    /// `CLOCK_REALTIME` nanoseconds: the monotonic domain plus the carrier's
    /// ring-published realtime offset, as `clock_gettime(CLOCK_REALTIME)`.
    Realtime(u64),
}

impl AbsoluteDeadline {
    /// The first guest counter tick at or after this deadline, for a counter
    /// running at `frequency_hz`: it never fires before the guest clock reads
    /// the deadline. A deadline already past is tick 1, which every timer
    /// owner sees as expired (tick 0 means "no deadline" to the zone).
    ///
    /// A realtime deadline needs `realtime_offset_ns`, the zone's published
    /// calibration; without one it is `None` and the caller leaves the call
    /// unserved rather than guess an epoch.
    ///
    /// Converting a realtime deadline once is exact only while the guest
    /// cannot step `CLOCK_REALTIME` under a parked waiter: Linux re-arms a
    /// realtime futex or `TIMER_ABSTIME` sleep when the clock is set. No ring
    /// venue serves a clock step, and
    /// `tests::no_ring_venue_steps_the_realtime_clock` holds that as a
    /// checked fact: if a venue ever serves `clock_settime`,
    /// `settimeofday`, `adjtimex` or `clock_adjtime`, that test fails, and
    /// the parked realtime waits must re-arm on the step.
    pub fn counter_tick(
        self,
        frequency_hz: u64,
        realtime_offset_ns: Option<u64>,
    ) -> Option<CounterTick> {
        let monotonic = match self {
            Self::Monotonic(nanos) => nanos,
            // Before the counter's epoch is already past.
            Self::Realtime(nanos) => nanos.saturating_sub(realtime_offset_ns?),
        };
        let ticks =
            (u128::from(monotonic) * u128::from(frequency_hz)).div_ceil(NANOS_PER_SECOND.into());
        Some(CounterTick::new(
            u64::try_from(ticks).unwrap_or(u64::MAX).max(1),
        ))
    }
}

/// The deadline the process owner converts into guest counter ticks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SleepDeadline {
    /// Nanoseconds from now, measured on the guest counter.
    Relative(u64),
    /// An absolute deadline; today only [`AbsoluteDeadline::Monotonic`]
    /// (an absolute REALTIME or TAI sleep stays unserved, #1981).
    Absolute(AbsoluteDeadline),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SleepRequest {
    pub deadline: SleepDeadline,
    /// Relative sleeps only: where `EINTR` writes the unslept interval.
    pub remaining: Option<UserVa>,
}

/// Serve one routed sleep for a caller of `isa` under `crossing`. `None`
/// leaves the call to its host continuation or counted crossing refusal,
/// always before any user access: a caller whose owner keeps a host
/// continuation `crossing` carries, a clock the ring cannot measure, or an
/// absolute deadline without a guest-visible epoch.
pub fn invoke(
    call: SleepCall,
    isa: GuestIsa,
    crossing: crate::crossing::HostCrossingSet,
    native: &mut dyn SignalNative<'_>,
) -> Option<SignalOutcome> {
    let returned = |value: i64| {
        Some(SignalOutcome::Returned {
            result: SyscallResult::new(value),
            work: false,
        })
    };
    let args = native.arguments();
    // nanosleep(2) takes no flags and measures CLOCK_MONOTONIC.
    let (clock_id, flags, request, remaining) = match call {
        SleepCall::Nanosleep => (LINUX_CLOCK_MONOTONIC, 0, args[0], args[1]),
        SleepCall::ClockNanosleep => (args[0], args[1], args[2], args[3]),
    };
    if !native.process_signals()?.sleeps_in_ring() && call.host_continuation(crossing) {
        return None;
    }
    // Linux reads only TIMER_ABSTIME; every other flag bit is ignored
    // (clock_nanosleep(2) defines no flag errno; native probe: flags 2,
    // 0x100 and -1 all sleep). The run root's host dispatcher still answers
    // EINVAL for unknown bits.
    let absolute = flags & LINUX_TIMER_ABSTIME != 0;
    let clock = match sleep_clock(clock_id) {
        ClockClass::Sleeps(clock) => clock,
        ClockClass::Unserved => return None,
        ClockClass::Refused(errno) => return returned(errno.guest_retval()),
    };
    if absolute {
        match clock {
            SleepClock::Realtime => return None,
            SleepClock::Boottime if isa == GuestIsa::X86_64 => return None,
            SleepClock::Monotonic | SleepClock::Boottime => {}
        }
    }
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
    let deadline = match absolute {
        false if nanos == 0 => return returned(0),
        false => SleepDeadline::Relative(nanos),
        true => SleepDeadline::Absolute(AbsoluteDeadline::Monotonic(nanos)),
    };
    // An absolute sleep never writes `rem` (clock_nanosleep(2)).
    let remaining = (!absolute && remaining != 0).then_some(UserVa::new(remaining));
    match native.process_signals()?.clock_sleep(SleepRequest {
        deadline,
        remaining,
    }) {
        Ok(outcome) => Some(outcome),
        Err(errno) => returned(errno.guest_retval()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The run root's host sleep continuation is ARM's only: the x86
    /// crossing set does not carry either sleep (#2832 record B).
    #[test]
    fn only_the_arm_root_keeps_a_host_sleep_continuation() {
        use crate::crossing::HostCrossingSet::{Aarch64, X86};
        for call in [SleepCall::Nanosleep, SleepCall::ClockNanosleep] {
            assert!(call.host_continuation(Aarch64), "{call:?}");
            assert!(!call.host_continuation(X86), "{call:?}");
        }
    }

    /// Each row is a native Linux 6.12 `clock_nanosleep` errno number for a
    /// clock given before an unreadable request.
    #[test]
    fn sleep_clocks_match_linux() {
        use ClockClass::{Refused, Sleeps, Unserved};
        let thread_cpu = |pid: u32| u64::from((!pid << 3) | 0b110);
        let process_cpu = |pid: u32| u64::from((!pid << 3) | 0b010);
        let fd = |fd: u32| u64::from((!fd << 3) | 0b011);
        for (clock, class) in [
            (0, Sleeps(SleepClock::Realtime)),
            (1, Sleeps(SleepClock::Monotonic)),
            (2, Unserved),
            (3, Refused(LINUX_EOPNOTSUPP)),
            (4, Refused(LINUX_EOPNOTSUPP)),
            (5, Refused(LINUX_EOPNOTSUPP)),
            (6, Refused(LINUX_EOPNOTSUPP)),
            (7, Sleeps(SleepClock::Boottime)),
            (8, Unserved),
            (9, Unserved),
            (10, Refused(LINUX_EINVAL)),
            (11, Sleeps(SleepClock::Realtime)),
            (12, Refused(LINUX_EINVAL)),
            (u64::from(i32::MAX as u32), Refused(LINUX_EINVAL)),
            // The register's upper half is not part of `clockid_t`.
            (0x1_0000_0001, Sleeps(SleepClock::Monotonic)),
            (0x1_0000_0004, Refused(LINUX_EOPNOTSUPP)),
            (process_cpu(1), Unserved),
            (thread_cpu(1), Unserved),
            (fd(3), Refused(LINUX_EOPNOTSUPP)),
            // CLOCKFD's low bits with the per-thread bit set are not an fd;
            // Linux reads the request before rejecting the clock.
            (u64::from((!1_u32 << 3) | 0b111), Unserved),
        ] {
            assert_eq!(sleep_clock(clock), class, "clock {clock:#x}");
        }
    }

    /// Absolute deadlines convert on the counter epoch, never early, with a
    /// past deadline as an expired tick and no realtime epoch as unserved.
    #[test]
    fn absolute_deadlines_convert_once_on_the_counter_epoch() {
        use AbsoluteDeadline::{Monotonic, Realtime};
        // 24 MHz: 1 ns is 0.024 ticks, so any fraction rounds up.
        let hz = 24_000_000;
        assert_eq!(
            Monotonic(2_000_000_000).counter_tick(hz, None),
            Some(CounterTick::new(48_000_000))
        );
        assert_eq!(
            Monotonic(1).counter_tick(hz, None),
            Some(CounterTick::new(1))
        );
        assert_eq!(
            Monotonic(0).counter_tick(hz, None),
            Some(CounterTick::new(1))
        );
        let offset = 1_700_000_000_000_000_000;
        assert_eq!(
            Realtime(offset + 2_000_000_000).counter_tick(hz, Some(offset)),
            Some(CounterTick::new(48_000_000))
        );
        assert_eq!(
            Realtime(offset - 5).counter_tick(hz, Some(offset)),
            Some(CounterTick::new(1)),
            "a realtime deadline before the counter epoch is past"
        );
        assert_eq!(Realtime(offset).counter_tick(hz, None), None);
        // A deadline past the counter's range saturates; it never wraps early.
        assert_eq!(
            Monotonic(u64::MAX).counter_tick(10_000_000_000, None),
            Some(CounterTick::new(u64::MAX))
        );
    }

    /// The fact [`AbsoluteDeadline::counter_tick`] relies on: no ring venue
    /// steps `CLOCK_REALTIME`. Every clock-step syscall is unrouted on both
    /// ISAs and on neither crossing allowlist, so a guest step is a counted
    /// ENOSYS, and the zone's realtime offset cannot move under a parked
    /// realtime wait. Serving one of these calls must make this test fail,
    /// and the parked realtime waits must then re-arm on the step.
    #[test]
    fn no_ring_venue_steps_the_realtime_clock() {
        use crate::crossing::HostCrossingSet;
        use crate::dispatch::{Family, route_aarch64, route_x86};
        use carrick_syscall_abi::CanonicalNr;
        // Canonical (asm-generic) numbers.
        for (canonical, name) in [
            (112, "clock_settime"),
            (170, "settimeofday"),
            (171, "adjtimex"),
            (266, "clock_adjtime"),
        ] {
            assert_eq!(
                route_aarch64(canonical, u64::MAX),
                Family::Unported,
                "{name}"
            );
            assert_eq!(route_x86(canonical, u64::MAX), Family::Unported, "{name}");
            for set in [HostCrossingSet::Aarch64, HostCrossingSet::X86] {
                assert!(
                    !set.is_allowed(CanonicalNr::new(canonical)),
                    "{name} crosses on {set:?}"
                );
            }
        }
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
}
