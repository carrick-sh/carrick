//! Clock transformation policy for a timer's captured creator domain.
//!
//! These are ordinary Rust values, not a shared-memory ABI or domain handle.
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

/// A snapshot of the creator domain's transformation. This contains no host
/// pointer, but does not itself establish the creator's identity or lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockView {
    Live {
        realtime_offset_ns: i64,
    },
    Frozen {
        realtime: Duration,
    },
    Scaled {
        realtime: Duration,
        numerator: u32,
        denominator: u32,
    },
    Deterministic {
        realtime_epoch: Duration,
        monotonic: Duration,
    },
}

/// Wake policy derived under the same clock generation as the timer sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeadlinePlan {
    pub host_timeout: Option<Duration>,
    pub virtual_due: Option<Duration>,
}

impl ClockView {
    /// Select at most one native source. Frozen realtime and deterministic
    /// clocks do not sample the host at all.
    pub fn now(self, clock: Clock, mut sample: impl FnMut(HostClock) -> Duration) -> Duration {
        match self {
            Self::Live { realtime_offset_ns } if clock == Clock::Realtime => {
                let base = sample(HostClock::Realtime);
                if realtime_offset_ns >= 0 {
                    base.saturating_add(Duration::from_nanos(realtime_offset_ns as u64))
                } else {
                    base.saturating_sub(Duration::from_nanos(realtime_offset_ns.unsigned_abs()))
                }
            }
            Self::Frozen { realtime } if clock == Clock::Realtime => realtime,
            Self::Live { .. } | Self::Frozen { .. } => sample(match clock {
                Clock::Realtime => HostClock::Realtime,
                Clock::Monotonic => HostClock::Monotonic,
                Clock::Boottime => HostClock::Boottime,
            }),
            Self::Scaled {
                realtime,
                numerator,
                denominator,
            } => {
                let elapsed = scale(sample(HostClock::Elapsed), numerator, denominator.max(1));
                if clock == Clock::Realtime {
                    realtime.saturating_add(elapsed)
                } else {
                    elapsed
                }
            }
            Self::Deterministic {
                realtime_epoch,
                monotonic,
            } => {
                if clock == Clock::Realtime {
                    realtime_epoch.saturating_add(monotonic)
                } else {
                    monotonic
                }
            }
        }
    }

    /// Convert a guest duration to the native wait duration, preserving the
    /// existing zero-speed and u64-nanosecond saturation policy.
    pub fn scale_timeout(self, timeout: Duration) -> Duration {
        match self {
            Self::Scaled {
                numerator,
                denominator,
                ..
            } => scale(timeout, denominator, numerator.max(1)),
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
        let virtual_due = match self {
            Self::Deterministic { realtime_epoch, .. } => deadline.map(|deadline| {
                if clock == Clock::Realtime {
                    deadline.saturating_sub(realtime_epoch)
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
        match self {
            Self::Deterministic { .. } => false,
            Self::Frozen { .. } => clock != Clock::Realtime,
            _ => true,
        }
    }
}

fn scale(value: Duration, numerator: u32, denominator: u32) -> Duration {
    let nanos = value.as_nanos() * u128::from(numerator) / u128::from(denominator);
    Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}
