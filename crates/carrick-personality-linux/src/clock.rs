//! Linux `clock_gettime(2)`, `clock_getres(2)` and `gettimeofday(2)` for
//! ring-owned processes.
//!
//! This module owns the Linux argument contract only: which clock ids the
//! ring answers, which errno an invalid call gets and in what order, and the
//! `timespec`/`timeval`/`timezone` encodings. A resolution is a constant, so
//! the ring answers `clock_getres` itself. A reading must honour the
//! container's virtual-time policy (frozen, scaled, offset, deterministic), so
//! it crosses as one bounded sample request to the run's `ClockDomain`
//! ([`carrick_core_abi::clock`]); the process owner stages that request on
//! both ISAs from the same [`ClockPlan`].
//!
//! CPU-time clocks and dynamic per-task or posix-clock-fd ids select guest
//! task accounting or a named task, which the ring does not measure here: they
//! stay [`ClockPlan::Unserved`] and keep the counted crossing refusal.

use crate::abi::entry::SyscallResult;
use crate::signal::{SignalNative, SignalOutcome};
use carrick_core::user_copy::CopyOutcome;
use carrick_guest_arch::UserVa;
use carrick_syscall_abi::{
    CanonicalNr, LINUX_CLOCK_BOOTTIME, LINUX_CLOCK_BOOTTIME_ALARM, LINUX_CLOCK_MONOTONIC,
    LINUX_CLOCK_MONOTONIC_COARSE, LINUX_CLOCK_MONOTONIC_RAW, LINUX_CLOCK_PROCESS_CPUTIME_ID,
    LINUX_CLOCK_REALTIME, LINUX_CLOCK_REALTIME_ALARM, LINUX_CLOCK_REALTIME_COARSE,
    LINUX_CLOCK_RESOLUTION_NSEC, LINUX_CLOCK_TAI, LINUX_CLOCK_THREAD_CPUTIME_ID, LINUX_EFAULT,
    LINUX_EINVAL, LinuxErrno,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockCall {
    Gettime,
    Getres,
    Gettimeofday,
}

impl ClockCall {
    /// The canonical ordinal that carries this call's argument contract.
    pub const fn ordinal(self) -> CanonicalNr {
        match self {
            Self::Gettime => crate::crossing::nr::CLOCK_GETTIME,
            Self::Getres => crate::crossing::nr::CLOCK_GETRES,
            Self::Gettimeofday => crate::crossing::nr::GETTIMEOFDAY,
        }
    }

    pub const fn from_canonical(ordinal: CanonicalNr) -> Option<Self> {
        match ordinal.raw() {
            raw if raw == crate::crossing::nr::CLOCK_GETTIME.raw() => Some(Self::Gettime),
            raw if raw == crate::crossing::nr::CLOCK_GETRES.raw() => Some(Self::Getres),
            raw if raw == crate::crossing::nr::GETTIMEOFDAY.raw() => Some(Self::Gettimeofday),
            _ => None,
        }
    }
}

/// Where a sampled reading is written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockOutput {
    /// A 16-byte `struct timespec`.
    Timespec(UserVa),
    /// A 16-byte `struct timeval` and an 8-byte `struct timezone`; either may
    /// be absent (a null pointer).
    Timeval {
        timeval: Option<UserVa>,
        timezone: Option<UserVa>,
    },
}

/// What one call needs, decided from its arguments alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockPlan {
    /// Linux answers with this errno before any other effect.
    Refused(LinuxErrno),
    /// The call succeeds with nothing to write.
    Done,
    /// Write `timespec { 0, nanos }` to `output`.
    Resolution { output: UserVa, nanos: i64 },
    /// Sample this clock id on the container's clock domain.
    Sample { clock_id: u64, output: ClockOutput },
    /// The ring cannot measure this clock; the call keeps its counted
    /// crossing refusal, before any user access.
    Unserved,
}

enum ClockKind {
    /// A clock the container's `ClockDomain` samples.
    Sampled,
    /// A CPU-time clock: its resolution is known, its reading is task state.
    CpuTime,
    /// A dynamic CPU clock or posix-clock fd: the answer depends on the
    /// named task or device.
    Dynamic,
    Invalid,
}

fn classify(clock_id: u64) -> (u64, ClockKind) {
    // `clockid_t` is a C int: Linux never sees the register's upper half.
    let id = clock_id as u32 as i32;
    if id < 0 {
        return (clock_id, ClockKind::Dynamic);
    }
    let id = id as u64;
    let kind = match id {
        LINUX_CLOCK_REALTIME
        | LINUX_CLOCK_MONOTONIC
        | LINUX_CLOCK_MONOTONIC_RAW
        | LINUX_CLOCK_REALTIME_COARSE
        | LINUX_CLOCK_MONOTONIC_COARSE
        | LINUX_CLOCK_BOOTTIME
        | LINUX_CLOCK_REALTIME_ALARM
        | LINUX_CLOCK_BOOTTIME_ALARM
        | LINUX_CLOCK_TAI => ClockKind::Sampled,
        LINUX_CLOCK_PROCESS_CPUTIME_ID | LINUX_CLOCK_THREAD_CPUTIME_ID => ClockKind::CpuTime,
        _ => ClockKind::Invalid,
    };
    (id, kind)
}

/// Decide one call from its arguments, as Linux orders the checks: an
/// invalid clock id is EINVAL before the output is touched, and a null
/// `timespec` is EFAULT only for a clock that would be read.
pub fn plan(call: ClockCall, args: [u64; 2]) -> ClockPlan {
    let user = |address: u64| (address != 0).then(|| UserVa::new(address));
    match call {
        ClockCall::Gettime => {
            let (clock_id, kind) = classify(args[0]);
            match kind {
                ClockKind::Invalid => ClockPlan::Refused(LINUX_EINVAL),
                ClockKind::CpuTime | ClockKind::Dynamic => ClockPlan::Unserved,
                ClockKind::Sampled => match user(args[1]) {
                    Some(output) => ClockPlan::Sample {
                        clock_id,
                        output: ClockOutput::Timespec(output),
                    },
                    None => ClockPlan::Refused(LINUX_EFAULT),
                },
            }
        }
        ClockCall::Getres => {
            let (_, kind) = classify(args[0]);
            match kind {
                ClockKind::Invalid => ClockPlan::Refused(LINUX_EINVAL),
                ClockKind::Dynamic => ClockPlan::Unserved,
                ClockKind::Sampled | ClockKind::CpuTime => match user(args[1]) {
                    // A null `res` is permitted: the call only validates.
                    None => ClockPlan::Done,
                    Some(output) => ClockPlan::Resolution {
                        output,
                        nanos: LINUX_CLOCK_RESOLUTION_NSEC,
                    },
                },
            }
        }
        ClockCall::Gettimeofday => {
            let (timeval, timezone) = (user(args[0]), user(args[1]));
            if timeval.is_none() && timezone.is_none() {
                return ClockPlan::Done;
            }
            ClockPlan::Sample {
                clock_id: LINUX_CLOCK_REALTIME,
                output: ClockOutput::Timeval { timeval, timezone },
            }
        }
    }
}

/// A 64-bit `struct timespec`.
pub fn timespec_bytes(secs: u64, nanos: u64) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&secs.to_le_bytes());
    bytes[8..].copy_from_slice(&nanos.to_le_bytes());
    bytes
}

/// A 64-bit `struct timeval` from a nanosecond-resolution reading.
pub fn timeval_bytes(secs: u64, nanos: u32) -> [u8; 16] {
    timespec_bytes(secs, u64::from(nanos / 1_000))
}

/// The UTC `struct timezone` `gettimeofday(2)` reports.
pub const TIMEZONE_BYTES: [u8; 8] = [0; 8];

/// What the ring decided for one routed call.
#[derive(Debug)]
pub enum ClockServed {
    /// Answered in ring.
    Outcome(SignalOutcome),
    /// A reading: the process owner stages one sample request for the
    /// container's clock domain ([`plan`] again yields the same request).
    Sample,
}

/// Serve the part of one routed call the ring answers itself. `None` hands the
/// call on: the caller keeps its host continuation (the run root), or the
/// counted crossing refusal for a clock the ring cannot measure, always
/// before any user access.
pub fn invoke(
    call: ClockCall,
    ordinal: CanonicalNr,
    native: &mut dyn SignalNative<'_>,
) -> Option<ClockServed> {
    // x86 `time(2)` shares `gettimeofday`'s owner ordinal but not its
    // arguments; only the real ordinal carries this contract.
    if ordinal.raw() != call.ordinal().raw() || !native.process_signals()?.sleeps_in_ring() {
        return None;
    }
    let args = native.arguments();
    let returned = |value: i64| {
        Some(ClockServed::Outcome(SignalOutcome::Returned {
            result: SyscallResult::new(value),
            work: false,
        }))
    };
    match plan(call, [args[0], args[1]]) {
        ClockPlan::Refused(errno) => returned(errno.guest_retval()),
        ClockPlan::Done => returned(0),
        ClockPlan::Resolution { output, nanos } => {
            let bytes = timespec_bytes(0, nanos as u64);
            match native.copy_out(output, &bytes) {
                CopyOutcome::Done => returned(0),
                CopyOutcome::Fault => returned(LINUX_EFAULT.guest_retval()),
                CopyOutcome::NotYet(_) => Some(ClockServed::Outcome(
                    native.finish_signal_output(output, bytes.to_vec()),
                )),
            }
        }
        ClockPlan::Sample { .. } => Some(ClockServed::Sample),
        ClockPlan::Unserved => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUT: u64 = 0x1000;

    fn sample(clock_id: u64) -> ClockPlan {
        ClockPlan::Sample {
            clock_id,
            output: ClockOutput::Timespec(UserVa::new(OUT)),
        }
    }

    /// Errno numbers follow clock_gettime(2) / clock_getres(2) and the legacy
    /// host dispatcher's answers for the same clock ids.
    #[test]
    fn clock_ids_classify_as_linux_answers_them() {
        for id in [0, 1, 4, 5, 6, 7, 8, 9, 11] {
            assert_eq!(plan(ClockCall::Gettime, [id, OUT]), sample(id), "{id}");
        }
        for id in [10, 12, 0x7fff_ffff] {
            assert_eq!(
                plan(ClockCall::Gettime, [id, OUT]),
                ClockPlan::Refused(LINUX_EINVAL),
                "{id}"
            );
        }
        // The register's upper half is not part of `clockid_t`.
        assert_eq!(plan(ClockCall::Gettime, [0x1_0000_0001, OUT]), sample(1));
        for id in [
            2,
            3,
            u64::from(!1_u32 << 3 | 0b010),
            u64::from(!1_u32 << 3 | 0b011),
        ] {
            assert_eq!(
                plan(ClockCall::Gettime, [id, OUT]),
                ClockPlan::Unserved,
                "{id:#x}"
            );
        }
    }

    #[test]
    fn a_null_timespec_is_efault_only_for_a_readable_clock() {
        assert_eq!(
            plan(ClockCall::Gettime, [1, 0]),
            ClockPlan::Refused(LINUX_EFAULT)
        );
        assert_eq!(
            plan(ClockCall::Gettime, [10, 0]),
            ClockPlan::Refused(LINUX_EINVAL)
        );
        assert_eq!(plan(ClockCall::Gettime, [2, 0]), ClockPlan::Unserved);
    }

    #[test]
    fn getres_is_a_constant_and_a_null_res_only_validates() {
        assert_eq!(plan(ClockCall::Getres, [1, 0]), ClockPlan::Done);
        assert_eq!(
            plan(ClockCall::Getres, [5, OUT]),
            ClockPlan::Resolution {
                output: UserVa::new(OUT),
                nanos: LINUX_CLOCK_RESOLUTION_NSEC
            }
        );
        // CPU-time clocks have a resolution even though ring cannot read them.
        assert!(matches!(
            plan(ClockCall::Getres, [2, OUT]),
            ClockPlan::Resolution { .. }
        ));
        assert_eq!(
            plan(ClockCall::Getres, [10, OUT]),
            ClockPlan::Refused(LINUX_EINVAL)
        );
        assert_eq!(
            plan(ClockCall::Getres, [u64::from(!1_u32 << 3 | 0b010), OUT]),
            ClockPlan::Unserved
        );
    }

    #[test]
    fn gettimeofday_samples_realtime_for_whichever_outputs_exist() {
        assert_eq!(plan(ClockCall::Gettimeofday, [0, 0]), ClockPlan::Done);
        assert_eq!(
            plan(ClockCall::Gettimeofday, [0, OUT]),
            ClockPlan::Sample {
                clock_id: LINUX_CLOCK_REALTIME,
                output: ClockOutput::Timeval {
                    timeval: None,
                    timezone: Some(UserVa::new(OUT))
                }
            }
        );
    }

    #[test]
    fn encodings_match_the_linux_64_bit_records() {
        let mut expected = [0; 16];
        expected[..8].copy_from_slice(&7_u64.to_le_bytes());
        expected[8..].copy_from_slice(&123_456_789_u64.to_le_bytes());
        assert_eq!(timespec_bytes(7, 123_456_789), expected);
        expected[8..].copy_from_slice(&123_456_u64.to_le_bytes());
        assert_eq!(timeval_bytes(7, 123_456_789), expected);
    }

    #[test]
    fn calls_round_trip_their_canonical_ordinals() {
        for call in [
            ClockCall::Gettime,
            ClockCall::Getres,
            ClockCall::Gettimeofday,
        ] {
            assert_eq!(ClockCall::from_canonical(call.ordinal()), Some(call));
        }
    }
}
