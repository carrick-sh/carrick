//! Timerfd state transitions shared by host and ring owners.
//!
//! The caller samples the timer creator’s clock domain and serializes state
//! updates. This module neither selects a clock nor owns readiness delivery.

pub mod clock;

use core::time::Duration;

/// Timerfd state independent of its storage and clock authority.
///
/// The owner serializes access and supplies samples from the clock captured
/// at creation. Neither an fd lookup nor the reading task selects the clock.
/// Readiness delivery and deadline enrollment belong to that owner.
///
/// This pointer-free record has an explicit layout for embedding in the
/// shared timer IPC authority. All fields are private: only these transitions
/// may construct a record, so nanoseconds stay normalized and reserved words
/// stay zero. A containing IPC record must still authenticate its own ABI,
/// creator-clock identity, object generation and lock ownership.
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct State {
    interval: DurationRecord,
    deadline: DurationRecord,
    expirations: u64,
    present: u32,
    reserved: u32,
}

const INTERVAL_PRESENT: u32 = 1;
const DEADLINE_PRESENT: u32 = 2;

/// Explicit seconds/nanoseconds storage; never an `Option` or Rust enum in
/// shared memory. Presence belongs to State and absent values are zeroed.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct DurationRecord {
    seconds: u64,
    nanos: u32,
    reserved: u32,
}

impl DurationRecord {
    fn encode(value: Option<Duration>) -> Self {
        let value = value.unwrap_or(Duration::ZERO);
        Self {
            seconds: value.as_secs(),
            nanos: value.subsec_nanos(),
            reserved: 0,
        }
    }

    const fn decode(self) -> Duration {
        Duration::new(self.seconds, self.nanos)
    }
}

const _: () = {
    assert!(core::mem::size_of::<DurationRecord>() == 16);
    assert!(core::mem::size_of::<State>() == 48);
    assert!(core::mem::align_of::<State>() == 8);
    assert!(core::mem::offset_of!(State, interval) == 0);
    assert!(core::mem::offset_of!(State, deadline) == 16);
    assert!(core::mem::offset_of!(State, expirations) == 32);
    assert!(core::mem::offset_of!(State, present) == 40);
    assert!(core::mem::offset_of!(State, reserved) == 44);
};

/// Interpretation of a nonzero initial expiration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineMode {
    Absolute,
    Relative,
}

impl State {
    /// Configured repeat interval, retained even when the timer is disarmed.
    pub const fn interval(&self) -> Option<Duration> {
        if self.present & INTERVAL_PRESENT != 0 {
            Some(self.interval.decode())
        } else {
            None
        }
    }

    /// Next expiration in the creator's clock domain, or a disarmed timer.
    pub const fn deadline(&self) -> Option<Duration> {
        if self.present & DEADLINE_PRESENT != 0 {
            Some(self.deadline.decode())
        } else {
            None
        }
    }

    /// Already accounted expirations; sampling time is an explicit refresh.
    pub const fn pending(&self) -> u64 {
        self.expirations
    }

    /// Account for all due periods using a single creator-clock sample.
    pub fn refresh(&mut self, now: Option<Duration>) -> u64 {
        let (count, deadline) =
            expirations(now, self.interval(), self.deadline(), self.expirations);
        self.expirations = count;
        self.set_deadline(deadline);
        self.expirations
    }

    /// Replace the arm and discard unread expirations, including on disarm.
    /// A zero initial value is represented by `None` by the ABI decoder.
    pub fn arm(
        &mut self,
        now: Duration,
        interval: Option<Duration>,
        value: Option<Duration>,
        mode: DeadlineMode,
    ) {
        self.interval = DurationRecord::encode(interval);
        self.present = if interval.is_some() {
            INTERVAL_PRESENT
        } else {
            0
        };
        self.set_deadline(value.map(|value| match mode {
            DeadlineMode::Absolute => value,
            DeadlineMode::Relative => now.saturating_add(value),
        }));
        self.expirations = 0;
    }

    fn set_deadline(&mut self, deadline: Option<Duration>) {
        self.deadline = DurationRecord::encode(deadline);
        self.present = (self.present & !DEADLINE_PRESENT)
            | if deadline.is_some() {
                DEADLINE_PRESENT
            } else {
                0
            };
    }

    /// Consume the accumulated count once the output operation owns delivery.
    pub fn consume(&mut self) -> u64 {
        core::mem::take(&mut self.expirations)
    }
}

/// Refresh a timer against one sample from its creator's clock domain.
/// An unavailable sample preserves the previous state. Missed periodic
/// expirations are accumulated in constant work, with saturating counts.
fn expirations(
    now: Option<Duration>,
    interval: Option<Duration>,
    deadline: Option<Duration>,
    expirations: u64,
) -> (u64, Option<Duration>) {
    let Some(deadline) = deadline else {
        return (expirations, None);
    };
    let Some(now) = now else {
        return (expirations, Some(deadline));
    };
    if now < deadline {
        return (expirations, Some(deadline));
    }
    let Some(interval) = interval else {
        return (expirations.saturating_add(1), None);
    };
    if interval.is_zero() {
        return (expirations.saturating_add(1), None);
    }

    let now_nanos = duration_to_nanos(now);
    let deadline_nanos = duration_to_nanos(deadline);
    let interval_nanos = duration_to_nanos(interval);
    let elapsed_periods = ((now_nanos - deadline_nanos) / interval_nanos).saturating_add(1);
    let count = u64::try_from(elapsed_periods).unwrap_or(u64::MAX);
    let next_deadline_nanos =
        deadline_nanos.saturating_add(interval_nanos.saturating_mul(elapsed_periods));
    (
        expirations.saturating_add(count),
        Some(duration_from_nanos_saturating(next_deadline_nanos)),
    )
}

fn duration_to_nanos(duration: Duration) -> u128 {
    const NANOS_PER_SEC: u128 = 1_000_000_000;
    u128::from(duration.as_secs()) * NANOS_PER_SEC + u128::from(duration.subsec_nanos())
}

fn duration_from_nanos_saturating(nanos: u128) -> Duration {
    const NANOS_PER_SEC: u128 = 1_000_000_000;
    let seconds = nanos / NANOS_PER_SEC;
    if seconds > u128::from(u64::MAX) {
        return Duration::new(u64::MAX, 999_999_999);
    }
    Duration::new(seconds as u64, (nanos % NANOS_PER_SEC) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEADLINE: Duration = Duration::from_nanos(100);

    #[test]
    fn shared_timer_state_has_explicit_record_layout() {
        // Timer IPC storage needs an explicit layout, rather than the
        // compiler-selected representation of Option<Duration>.
        assert_eq!(core::mem::size_of::<State>(), 48);
        assert_eq!(core::mem::align_of::<State>(), 8);
        assert_eq!(core::mem::offset_of!(State, interval), 0);
        assert_eq!(core::mem::offset_of!(State, deadline), 16);
        assert_eq!(core::mem::offset_of!(State, expirations), 32);
    }

    #[test]
    fn record_preserves_full_duration_range_and_zero_interval_presence() {
        let mut timer = State::default();
        assert_eq!(timer.interval(), None);
        assert_eq!(timer.deadline(), None);
        for interval in [None, Some(Duration::ZERO), Some(Duration::MAX)] {
            timer.arm(
                Duration::ZERO,
                interval,
                Some(Duration::MAX),
                DeadlineMode::Absolute,
            );
            assert_eq!(timer.interval(), interval);
            assert_eq!(timer.deadline(), Some(Duration::MAX));
            assert_eq!(timer.refresh(None), 0);
            assert_eq!(timer.refresh(Some(Duration::ZERO)), 0);
            assert_eq!(timer.reserved, 0);
            assert_eq!(timer.interval.reserved, 0);
            assert_eq!(timer.deadline.reserved, 0);
            timer.arm(Duration::ZERO, interval, None, DeadlineMode::Relative);
            assert_eq!(timer.interval(), interval);
            assert_eq!(timer.deadline(), None);
            assert_eq!(timer.deadline, DurationRecord::default());
            assert_eq!(timer.present & !(INTERVAL_PRESENT | DEADLINE_PRESENT), 0);
        }
    }

    #[test]
    fn rearm_and_disarm_discard_unread_expirations() {
        let mut timer = State::default();
        timer.arm(
            DEADLINE,
            Some(Duration::from_nanos(10)),
            Some(DEADLINE),
            DeadlineMode::Absolute,
        );
        assert_eq!(timer.refresh(Some(Duration::from_nanos(130))), 4);
        timer.arm(
            DEADLINE,
            None,
            Some(Duration::from_nanos(50)),
            DeadlineMode::Relative,
        );
        assert_eq!(timer.expirations, 0);
        assert_eq!(timer.refresh(Some(Duration::from_nanos(149))), 0);
        assert_eq!(timer.refresh(Some(Duration::from_nanos(150))), 1);
        timer.arm(
            DEADLINE,
            Some(Duration::from_nanos(10)),
            None,
            DeadlineMode::Absolute,
        );
        assert_eq!(timer.refresh(Some(Duration::MAX)), 0);
        assert_eq!(timer.deadline(), None);
    }

    #[test]
    fn reading_a_periodic_count_keeps_the_next_deadline() {
        let mut timer = State::default();
        timer.arm(
            DEADLINE,
            Some(Duration::from_nanos(10)),
            Some(DEADLINE),
            DeadlineMode::Absolute,
        );
        assert_eq!(timer.refresh(Some(Duration::from_nanos(130))), 4);
        assert_eq!(timer.consume(), 4);
        assert_eq!(timer.consume(), 0);
        assert_eq!(timer.refresh(None), 0);
        assert_eq!(timer.refresh(Some(Duration::from_nanos(139))), 0);
        assert_eq!(timer.refresh(Some(Duration::from_nanos(140))), 1);
        assert_eq!(timer.consume(), 1);
    }

    #[test]
    fn disarmed_unavailable_and_early_samples_preserve_state() {
        assert_eq!(expirations(Some(DEADLINE), None, None, 7), (7, None));
        for now in [None, Some(Duration::from_nanos(99))] {
            assert_eq!(
                expirations(now, None, Some(DEADLINE), 7),
                (7, Some(DEADLINE))
            );
        }
    }

    #[test]
    fn one_shot_and_zero_interval_disarm_once_due() {
        for interval in [None, Some(Duration::ZERO)] {
            assert_eq!(
                expirations(Some(DEADLINE), interval, Some(DEADLINE), 7),
                (8, None)
            );
        }
    }

    #[test]
    fn periodic_counts_missed_expirations_without_replaying_periods() {
        let interval = Some(Duration::from_nanos(10));
        for (now, count, next) in [(100, 8, 110), (109, 8, 110), (130, 11, 140)] {
            assert_eq!(
                expirations(Some(Duration::from_nanos(now)), interval, Some(DEADLINE), 7),
                (count, Some(Duration::from_nanos(next))),
            );
        }
        // A per-expiration loop cannot finish this scale point. Arithmetic
        // preserves the existing count/deadline saturation policy.
        assert_eq!(
            expirations(
                Some(Duration::MAX),
                Some(Duration::from_nanos(1)),
                Some(DEADLINE),
                7
            ),
            (u64::MAX, Some(Duration::MAX)),
        );
    }

    #[test]
    fn one_shot_count_saturates() {
        assert_eq!(
            expirations(Some(DEADLINE), None, Some(DEADLINE), u64::MAX),
            (u64::MAX, None)
        );
    }
}

#[cfg(test)]
mod clock_projection_tests {
    use super::clock::{Clock, ClockView, HostClock};
    use core::time::Duration;

    fn host(which: HostClock) -> Duration {
        Duration::from_secs(match which {
            HostClock::Realtime => 1000,
            HostClock::Monotonic => 100,
            HostClock::Boottime => 200,
            HostClock::Elapsed => 10,
        })
    }

    #[test]
    fn creator_projection_keeps_live_clock_sources_distinct() {
        let live = ClockView::Live {
            realtime_offset_ns: -1_000_000_000,
        };
        assert_eq!(live.now(Clock::Realtime, host), Duration::from_secs(999));
        assert_eq!(live.now(Clock::Monotonic, host), Duration::from_secs(100));
        assert_eq!(live.now(Clock::Boottime, host), Duration::from_secs(200));
        assert_eq!(
            ClockView::Live {
                realtime_offset_ns: i64::MIN
            }
            .now(Clock::Realtime, host),
            Duration::ZERO
        );
    }

    #[test]
    fn frozen_realtime_keeps_live_monotonic_and_boottime_deadlines() {
        let frozen = ClockView::Frozen {
            realtime: Duration::from_secs(500),
        };
        assert_eq!(
            frozen.now(Clock::Realtime, |_| panic!("frozen realtime sampled host")),
            Duration::from_secs(500)
        );
        assert_eq!(frozen.now(Clock::Monotonic, host), Duration::from_secs(100));
        assert_eq!(frozen.now(Clock::Boottime, host), Duration::from_secs(200));
        for (clock, timeout) in [
            (Clock::Realtime, None),
            (Clock::Monotonic, Some(Duration::from_secs(500))),
            (Clock::Boottime, Some(Duration::from_secs(400))),
        ] {
            let plan = frozen.deadline(clock, Some(Duration::from_secs(600)), false, host);
            assert_eq!(plan.host_timeout, timeout);
            assert_eq!(plan.virtual_due, None);
        }
    }

    #[test]
    fn scaled_clock_reads_and_deadlines_use_inverse_transforms() {
        let scaled = ClockView::Scaled {
            realtime: Duration::from_secs(500),
            numerator: 3,
            denominator: 2,
        };
        assert_eq!(scaled.now(Clock::Realtime, host), Duration::from_secs(515));
        for clock in [Clock::Monotonic, Clock::Boottime] {
            assert_eq!(scaled.now(clock, host), Duration::from_secs(15));
            assert_eq!(
                scaled
                    .deadline(clock, Some(Duration::from_secs(24)), false, host)
                    .host_timeout,
                Some(Duration::from_secs(6))
            );
        }
        assert_eq!(
            scaled.scale_timeout(Duration::MAX),
            Duration::from_nanos(u64::MAX)
        );
    }

    #[test]
    fn scaled_zero_speed_and_boundaries_keep_existing_conversion_policy() {
        let stopped = ClockView::Scaled {
            realtime: Duration::from_secs(500),
            numerator: 0,
            denominator: 2,
        };
        assert_eq!(stopped.now(Clock::Realtime, host), Duration::from_secs(500));
        assert_eq!(stopped.now(Clock::Monotonic, host), Duration::ZERO);
        // Preserve the current host inverse conversion for zero speed; a
        // different zero-speed wake policy needs its own semantic change.
        assert_eq!(
            stopped.scale_timeout(Duration::from_secs(3)),
            Duration::from_secs(6)
        );
        let saturated = ClockView::Scaled {
            realtime: Duration::MAX,
            numerator: u32::MAX,
            denominator: 1,
        };
        assert_eq!(
            saturated.now(Clock::Realtime, |_| Duration::MAX),
            Duration::MAX
        );
        assert_eq!(
            saturated.now(Clock::Boottime, |_| Duration::MAX),
            Duration::from_nanos(u64::MAX)
        );
    }

    #[test]
    fn a_deadline_samples_its_source_once_and_never_samples_when_disarmed() {
        let view = ClockView::Live {
            realtime_offset_ns: 1_000_000_000,
        };
        let mut calls = 0;
        let plan = view.deadline(
            Clock::Realtime,
            Some(Duration::from_secs(1005)),
            false,
            |source| {
                calls += 1;
                assert_eq!(source, HostClock::Realtime);
                Duration::from_secs(1000)
            },
        );
        assert_eq!(calls, 1);
        assert_eq!(plan.host_timeout, Some(Duration::from_secs(4)));
        assert_eq!(
            view.deadline(Clock::Realtime, None, false, |_| panic!(
                "disarmed timer sampled host"
            ))
            .host_timeout,
            None
        );
        assert_eq!(
            view.deadline_at(Clock::Realtime, Some(Duration::MAX), false, None)
                .host_timeout,
            None
        );
    }

    #[test]
    fn deterministic_deadlines_never_sample_host_or_lose_epoch() {
        let deterministic = ClockView::Deterministic {
            realtime_epoch: Duration::from_secs(500),
            monotonic: Duration::from_secs(10),
        };
        for (clock, deadline) in [
            (Clock::Realtime, 520),
            (Clock::Monotonic, 20),
            (Clock::Boottime, 20),
        ] {
            let plan =
                deterministic.deadline(clock, Some(Duration::from_secs(deadline)), false, |_| {
                    panic!("virtual deadline sampled host")
                });
            assert_eq!(plan.host_timeout, None);
            assert_eq!(plan.virtual_due, Some(Duration::from_secs(20)));
        }
        assert_eq!(
            deterministic.now(Clock::Realtime, |_| panic!("virtual clock sampled host")),
            Duration::from_secs(510)
        );
        let ready = deterministic.deadline(Clock::Realtime, None, true, |_| {
            panic!("ready timer sampled host")
        });
        assert_eq!(ready.host_timeout, Some(Duration::ZERO));
        assert_eq!(ready.virtual_due, None);
    }
}
