//! Process-owned ITIMER_REAL transitions, clean-room from setitimer(2):
//! <https://man7.org/linux/man-pages/man2/setitimer.2.html>.
//!
//! Clock values/spans are nanoseconds in the same injected monotonic elapsed
//! real-time domain. The caller converts timeval and supplies the clock; this
//! module reads no host clock. Relative setitimer is independent of civil-time
//! adjustments. Expiry returns data for the owner to enqueue one SIGALRM.
//! Pending standard-signal coalescing loses additional expirations as Linux
//! documents. The owner schedules only the returned next ticket, without
//! redispatching setitimer or waiting on a host worker.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ClockInstant(pub u64);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimerSpan(pub u64);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IntervalSpec {
    pub value: TimerSpan,
    pub interval: TimerSpan,
}

/// Completion capability authenticates exact owner, arm sequence and deadline.
/// Reusing a numeric task ID is safe only with the caller's full-generation K.
/// Never recreate a live owner's timer: rearm/cancel the retained authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerTicket<K> {
    owner: K,
    sequence: u64,
    deadline: ClockInstant,
}

impl<K> TimerTicket<K> {
    pub const fn deadline(&self) -> ClockInstant {
        self.deadline
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerUpdate<K> {
    pub previous: IntervalSpec,
    pub ticket: Option<TimerTicket<K>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerExpiry<K> {
    pub owner: K,
    pub next: Option<TimerTicket<K>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerError {
    ClockOverflow,
    SequenceExhausted,
}

/// One interval timer per exact process owner. No Clone implementation: copying
/// a live authority would allow duplicate completion acceptance. Exec retains
/// this authority; fork creates a new, disarmed child timer.
#[derive(Debug, PartialEq, Eq)]
pub struct IntervalTimer<K> {
    owner: K,
    sequence: u64,
    armed: Option<TimerTicket<K>>,
    interval: TimerSpan,
}

impl<K: Copy + Eq> IntervalTimer<K> {
    pub const fn new(owner: K) -> Self {
        Self {
            owner,
            sequence: 0,
            armed: None,
            interval: TimerSpan(0),
        }
    }

    pub const fn for_fork(&self, child: K) -> Self {
        Self::new(child)
    }

    pub fn remaining(&self, now: ClockInstant) -> IntervalSpec {
        IntervalSpec {
            value: TimerSpan(
                self.armed
                    .map_or(0, |ticket| ticket.deadline.0.saturating_sub(now.0)),
            ),
            interval: self.interval,
        }
    }

    /// Validate completely before publication. Zero value disarms even when
    /// interval is nonzero; getitimer still returns the configured interval.
    pub fn set(
        &mut self,
        now: ClockInstant,
        spec: IntervalSpec,
    ) -> Result<TimerUpdate<K>, TimerError> {
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(TimerError::SequenceExhausted)?;
        let ticket = if spec.value.0 == 0 {
            None
        } else {
            Some(TimerTicket {
                owner: self.owner,
                sequence,
                deadline: ClockInstant(
                    now.0
                        .checked_add(spec.value.0)
                        .ok_or(TimerError::ClockOverflow)?,
                ),
            })
        };
        let previous = self.remaining(now);
        self.sequence = sequence;
        self.interval = spec.interval;
        self.armed = ticket;
        Ok(TimerUpdate { previous, ticket })
    }

    /// Cancel the active capability without destroying an already pending
    /// SIGALRM. Rearm advances the sequence, so old callbacks cannot revive it.
    pub fn cancel(&mut self) -> Option<TimerTicket<K>> {
        self.interval = TimerSpan(0);
        self.armed.take()
    }

    /// Accept a current due ticket once. Delayed periodic expiry advances from
    /// the original deadline in O(1) arithmetic, preserving phase without a
    /// per-missed-tick loop. Overflow refuses publication atomically; the owner
    /// must handle the typed error, never treat it as a completed expiration.
    pub fn expire(
        &mut self,
        ticket: TimerTicket<K>,
        now: ClockInstant,
    ) -> Result<Option<TimerExpiry<K>>, TimerError> {
        if self.armed != Some(ticket) || now < ticket.deadline {
            return Ok(None);
        }
        let next = if self.interval.0 == 0 {
            None
        } else {
            // Use u128 so (elapsed / interval + 1) cannot wrap at u64::MAX.
            let elapsed = u128::from(now.0 - ticket.deadline.0);
            let interval = u128::from(self.interval.0);
            let advance = (elapsed / interval + 1) * interval;
            let deadline = u64::try_from(u128::from(ticket.deadline.0) + advance)
                .map_err(|_| TimerError::ClockOverflow)?;
            Some(TimerTicket {
                deadline: ClockInstant(deadline),
                ..ticket
            })
        };
        self.armed = next;
        Ok(Some(TimerExpiry {
            owner: self.owner,
            next,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_exhaustion_cannot_wrap_and_authenticate_an_old_ticket() {
        let mut timer = IntervalTimer::new(1);
        timer.sequence = u64::MAX;
        assert_eq!(
            timer.set(ClockInstant(0), IntervalSpec::default()),
            Err(TimerError::SequenceExhausted)
        );
        assert_eq!(timer.sequence, u64::MAX);
        assert_eq!(timer.armed, None);
    }
}
