//! Timerfd expiration arithmetic shared by host and ring callers.
//!
//! The caller samples the timer creator’s clock domain and serializes state
//! updates. This module neither selects a clock nor owns readiness delivery.

use core::time::Duration;

/// Refresh a timer against one sample from its creator's clock domain.
/// An unavailable sample preserves the previous state. Missed periodic
/// expirations are accumulated in constant work, with saturating counts.
pub fn expirations(
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
