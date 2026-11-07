//! Clock transformation policy for a timer's captured creator domain.
//!
//! The sealed record has an explicit layout, but is not a published IPC ABI
//! or domain handle.
//! The owner must authenticate and retain the domain and serialize this view
//! with clock mutations. Host sampling and wake enrollment stay with that owner.

use core::time::Duration;

/// The clock selected when the timer was created; alarm variants use the
/// corresponding realtime or boottime value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Clock {
    Realtime,
    Monotonic,
    Boottime,
}

/// A native sample required by a projection. Elapsed means time since this
/// domain's origin, not uptime since the machine booted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostClock {
    Realtime,
    Monotonic,
    Boottime,
    Elapsed,
}

/// A sealed projection record, immediately consumed by host clock owners.
///
/// This explicit layout is preparation for shared storage, not a domain handle
/// or a published IPC ABI. Constructors are the only import path; callers must
/// still authenticate the creator's identity and serialize changes. No raw-byte
/// import is provided: a containing protocol must validate its own ABI first.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockView {
    mode: Mode,
    reserved: u32,
    realtime_offset_ns: i64,
    realtime: super::DurationRecord,
    monotonic: super::DurationRecord,
    numerator: u32,
    denominator: u32,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Live = 1,
    Frozen = 2,
    Scaled = 3,
    Deterministic = 4,
}

const _: () = {
    assert!(core::mem::size_of::<ClockView>() == 56);
    assert!(core::mem::align_of::<ClockView>() == 8);
    assert!(core::mem::offset_of!(ClockView, mode) == 0);
    assert!(core::mem::offset_of!(ClockView, reserved) == 4);
    assert!(core::mem::offset_of!(ClockView, realtime_offset_ns) == 8);
    assert!(core::mem::offset_of!(ClockView, realtime) == 16);
    assert!(core::mem::offset_of!(ClockView, monotonic) == 32);
    assert!(core::mem::offset_of!(ClockView, numerator) == 48);
    assert!(core::mem::offset_of!(ClockView, denominator) == 52);
};

/// Wake policy derived under the same clock generation as the timer sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeadlinePlan {
    pub host_timeout: Option<Duration>,
    pub virtual_due: Option<Duration>,
}

impl ClockView {
    /// Live native sources, with a signed realtime adjustment.
    pub fn native_sources(realtime_offset_ns: i64) -> Self {
        Self {
            mode: Mode::Live,
            reserved: 0,
            realtime_offset_ns,
            realtime: super::DurationRecord::default(),
            monotonic: super::DurationRecord::default(),
            numerator: 0,
            denominator: 0,
        }
    }

    /// Frozen realtime; monotonic and boottime remain live.
    pub fn frozen(realtime: Duration) -> Self {
        Self {
            mode: Mode::Frozen,
            realtime: super::DurationRecord::encode(Some(realtime)),
            ..Self::native_sources(0)
        }
    }

    /// Rational scaling since the captured domain's native elapsed origin.
    /// Raw ratio values are retained; the existing conversion policy applies
    /// its nonzero divisor guard at use, including for a zero numerator.
    pub fn scaled(realtime: Duration, numerator: u32, denominator: u32) -> Self {
        Self {
            mode: Mode::Scaled,
            realtime: super::DurationRecord::encode(Some(realtime)),
            numerator,
            denominator,
            ..Self::native_sources(0)
        }
    }

    /// Explicit virtual progress; no native sample is used.
    pub fn deterministic(realtime_epoch: Duration, monotonic: Duration) -> Self {
        Self {
            mode: Mode::Deterministic,
            realtime: super::DurationRecord::encode(Some(realtime_epoch)),
            monotonic: super::DurationRecord::encode(Some(monotonic)),
            ..Self::native_sources(0)
        }
    }

    /// Select at most one native source. Frozen realtime and deterministic
    /// clocks do not sample the host at all.
    pub fn now(self, clock: Clock, mut sample: impl FnMut(HostClock) -> Duration) -> Duration {
        match self.mode {
            Mode::Live if clock == Clock::Realtime => {
                let realtime_offset_ns = self.realtime_offset_ns;
                let base = sample(HostClock::Realtime);
                if realtime_offset_ns >= 0 {
                    base.saturating_add(Duration::from_nanos(realtime_offset_ns as u64))
                } else {
                    base.saturating_sub(Duration::from_nanos(realtime_offset_ns.unsigned_abs()))
                }
            }
            Mode::Frozen if clock == Clock::Realtime => self.realtime.decode(),
            Mode::Live | Mode::Frozen => sample(match clock {
                Clock::Realtime => HostClock::Realtime,
                Clock::Monotonic => HostClock::Monotonic,
                Clock::Boottime => HostClock::Boottime,
            }),
            Mode::Scaled => {
                let elapsed = scale(
                    sample(HostClock::Elapsed),
                    self.numerator,
                    self.denominator.max(1),
                );
                if clock == Clock::Realtime {
                    self.realtime.decode().saturating_add(elapsed)
                } else {
                    elapsed
                }
            }
            Mode::Deterministic => {
                if clock == Clock::Realtime {
                    self.realtime
                        .decode()
                        .saturating_add(self.monotonic.decode())
                } else {
                    self.monotonic.decode()
                }
            }
        }
    }

    /// Convert a guest duration to the native wait duration, preserving the
    /// existing zero-speed and u64-nanosecond saturation policy.
    pub fn scale_timeout(self, timeout: Duration) -> Duration {
        match self.mode {
            Mode::Scaled => scale(timeout, self.denominator, self.numerator.max(1)),
            _ => timeout,
        }
    }

    /// Derive a deadline using a fresh sample only when physical time can
    /// advance this timer. Prefer `deadline_at` when refreshing state already
    /// obtained a sample, so refresh and enrollment share that exact value.
    pub fn deadline(
        self,
        clock: Clock,
        deadline: Option<Duration>,
        ready: bool,
        sample: impl FnMut(HostClock) -> Duration,
    ) -> DeadlinePlan {
        let now = if !ready && deadline.is_some() && self.has_physical_deadline(clock) {
            Some(self.now(clock, sample))
        } else {
            None
        };
        self.deadline_at(clock, deadline, ready, now)
    }

    /// Plan from the very sample used to refresh the timer. An unavailable
    /// sample never becomes a physical timeout; the owner must retain the
    /// existing clock-change enrollment when no physical deadline applies.
    pub fn deadline_at(
        self,
        clock: Clock,
        deadline: Option<Duration>,
        ready: bool,
        now: Option<Duration>,
    ) -> DeadlinePlan {
        let host_timeout = if ready {
            Some(Duration::ZERO)
        } else if self.has_physical_deadline(clock) {
            deadline
                .zip(now)
                .map(|(deadline, now)| self.scale_timeout(deadline.saturating_sub(now)))
        } else {
            None
        };
        let virtual_due = match self.mode {
            Mode::Deterministic => deadline.map(|deadline| {
                if clock == Clock::Realtime {
                    deadline.saturating_sub(self.realtime.decode())
                } else {
                    deadline
                }
            }),
            _ => None,
        };
        DeadlinePlan {
            host_timeout,
            virtual_due,
        }
    }

    fn has_physical_deadline(self, clock: Clock) -> bool {
        match self.mode {
            Mode::Deterministic => false,
            Mode::Frozen => clock != Clock::Realtime,
            _ => true,
        }
    }
}

fn scale(value: Duration, numerator: u32, denominator: u32) -> Duration {
    let nanos = value.as_nanos() * u128::from(numerator) / u128::from(denominator);
    Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod record_tests {
    use super::*;

    #[test]
    fn constructors_canonicalize_unused_fields_and_preserve_duration_range() {
        let zero = super::super::DurationRecord::default();
        let live = ClockView::native_sources(i64::MIN);
        assert_eq!(live.realtime, zero);
        assert_eq!(live.monotonic, zero);
        assert_eq!((live.numerator, live.denominator), (0, 0));
        for record in [
            live,
            ClockView::frozen(Duration::MAX),
            ClockView::scaled(Duration::MAX, u32::MAX, 0),
            ClockView::deterministic(Duration::MAX, Duration::MAX),
        ] {
            assert_eq!(record.reserved, 0);
            assert_eq!(record.realtime.reserved, 0);
            assert_eq!(record.monotonic.reserved, 0);
            if record.mode != Mode::Live {
                assert_eq!(record.realtime_offset_ns, 0);
                assert_eq!(record.realtime.decode(), Duration::MAX);
            }
            if record.mode != Mode::Deterministic {
                assert_eq!(record.monotonic, zero);
            } else {
                assert_eq!(record.monotonic.decode(), Duration::MAX);
            }
            if record.mode != Mode::Scaled {
                assert_eq!((record.numerator, record.denominator), (0, 0));
            }
        }
        assert_eq!(
            ClockView::frozen(Duration::MAX).now(Clock::Realtime, |_| unreachable!()),
            Duration::MAX,
        );
        let virtual_clock = ClockView::deterministic(Duration::ZERO, Duration::MAX);
        assert_eq!(
            virtual_clock.now(Clock::Monotonic, |_| unreachable!()),
            Duration::MAX,
        );
    }

    #[test]
    fn raw_zero_denominator_keeps_existing_projection_and_timeout_policy() {
        let view = ClockView::scaled(Duration::ZERO, 3, 0);
        assert_eq!(view.denominator, 0);
        assert_eq!(
            view.now(Clock::Monotonic, |_| Duration::from_secs(2)),
            Duration::from_secs(6),
        );
        assert_eq!(view.scale_timeout(Duration::from_secs(6)), Duration::ZERO);
    }
}
