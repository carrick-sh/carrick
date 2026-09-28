//! Platform-NEUTRAL POSIX per-process timer types and arithmetic.
//!
//! Substrate POSIX timer data types, saturation constants, and remaining-time
//! calculations. Host registry storage (HashMap/Mutex) and thread fallback
//! timing live in the host adapter (`carrick-hal::posix_timer`).

use crate::TimerSpecNs;

/// Linux `DELAYTIMER_MAX`: the overrun counter saturates here rather than
/// wrapping into the negative `int` range (the kernel fix for CVE-2018-12896,
/// exercised by LTP timer_settime03).
pub const OVERRUN_MAX: u32 = i32::MAX as u32;

/// One POSIX timer's arm spec (`timer_settime` value/interval + the signum to
/// deliver). `si_value` carries the `sigev_value` payload for the `SI_TIMER`
/// `siginfo` (default 0; not yet plumbed through the arm path).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PosixTimerSpec {
    /// Linux signum to deliver on expiry (sigev_signo).
    pub signum: i32,
    /// The value/interval ns pair (`spec.value == 0` disarms,
    /// `spec.interval == 0` = one-shot).
    pub spec: TimerSpecNs,
    /// `sigev_value` payload delivered in the `SI_TIMER` siginfo. Default 0.
    pub si_value: i64,
}

/// Compute the remaining value/interval for a timer given its arm spec,
/// the timestamp it was armed at, and the current timestamp.
pub fn remaining_time(spec: TimerSpecNs, armed_at_ns: u64, now_ns: u64) -> TimerSpecNs {
    if armed_at_ns == 0 || spec.value == 0 {
        TimerSpecNs {
            value: 0,
            interval: spec.interval,
        }
    } else {
        let elapsed = now_ns.saturating_sub(armed_at_ns);
        let remaining = spec.value.saturating_sub(elapsed);
        TimerSpecNs {
            value: remaining,
            interval: spec.interval,
        }
    }
}

/// Next saturated overrun counter increment.
pub fn next_overrun(current: u32) -> u32 {
    if current < OVERRUN_MAX {
        current + 1
    } else {
        OVERRUN_MAX
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remaining_time_calculation() {
        let spec = TimerSpecNs {
            value: 1_000_000,
            interval: 500_000,
        };
        assert_eq!(
            remaining_time(spec, 100, 200),
            TimerSpecNs {
                value: 999_900,
                interval: 500_000,
            }
        );
        assert_eq!(
            remaining_time(spec, 0, 200),
            TimerSpecNs {
                value: 0,
                interval: 500_000,
            }
        );
        assert_eq!(
            remaining_time(spec, 100, 2_000_000),
            TimerSpecNs {
                value: 0,
                interval: 500_000,
            }
        );
    }

    #[test]
    fn test_overrun_saturation() {
        assert_eq!(next_overrun(0), 1);
        assert_eq!(next_overrun(OVERRUN_MAX - 1), OVERRUN_MAX);
        assert_eq!(next_overrun(OVERRUN_MAX), OVERRUN_MAX);
    }
}
