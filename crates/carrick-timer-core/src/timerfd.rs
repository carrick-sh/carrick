//! Timerfd state transitions shared by host and ring owners.
//!
//! The caller samples the timer creator’s clock domain and serializes state
//! updates. This module neither selects a clock nor owns readiness delivery.

use core::time::Duration;

/// Timerfd state independent of its storage and clock authority.
///
/// The owner serializes access and supplies samples from the clock captured
/// at creation. Neither an fd lookup nor the reading task selects the clock.
/// Readiness delivery and deadline enrollment belong to that owner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct State {
    interval: Option<Duration>,
    deadline: Option<Duration>,
    expirations: u64,
}

/// Interpretation of a nonzero initial expiration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineMode {
    Absolute,
    Relative,
}

impl State {
    /// Configured repeat interval, retained even when the timer is disarmed.
    pub const fn interval(&self) -> Option<Duration> {
        self.interval
    }

    /// Next expiration in the creator's clock domain, or a disarmed timer.
    pub const fn deadline(&self) -> Option<Duration> {
        self.deadline
    }

    /// Already accounted expirations; sampling time is an explicit refresh.
    pub const fn pending(&self) -> u64 {
        self.expirations
    }

    /// Account for all due periods using a single creator-clock sample.
    pub fn refresh(&mut self, now: Option<Duration>) -> u64 {
        (self.expirations, self.deadline) =
            expirations(now, self.interval, self.deadline, self.expirations);
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
        self.interval = interval;
        self.deadline = value.map(|value| match mode {
            DeadlineMode::Absolute => value,
            DeadlineMode::Relative => now.saturating_add(value),
        });
        self.expirations = 0;
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
        assert_eq!(timer.deadline, None);
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
