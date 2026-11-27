//! What one step of a retired MM's release reports (#3061, PR 1b).
//!
//! A retired fork child or exec predecessor gives back what it held in two
//! phases: the owner decides what is owed, the shell does the I/O after
//! unlocking, and each shell step answers with a [`ReleaseOutcome`]. The
//! three answers are three different things, so they are three variants and
//! never a `bool`:
//!
//! - [`ReleaseOutcome::Done`]: the step finished; the owner may go on.
//! - [`ReleaseOutcome::NotNow`]: the step can't finish yet, and the
//!   [`ReleaseWait`] names the event that reruns the release. The owner keeps
//!   everything held, counts a deferral and changes nothing else. Contention
//!   is "not now", never fatal and never an errno.
//! - [`ReleaseOutcome::Broken`]: the step found a broken invariant (for
//!   example a released slot whose frame some MM still maps, #3132). The
//!   owner stops and hands the verdict to its venue, which ends the carrier.
//!   A broken release is never a deferral: retrying it could only loop while
//!   the guest kept running.

/// The event a deferred release waits for. Each one reruns the drain that
/// retries the release: the guest's unpublish of the space and a root's
/// retirement both reach the carrier's retired-space service, which drains.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReleaseWait {
    /// The guest has not unpublished the MM's space yet: no exclusion of its
    /// editor exists, so nothing of its memory may be released.
    Unpublish,
    /// A root still publishes the MM and owes it returns; those slots are
    /// freed only by the root's own retirement.
    OwedReturns,
    /// A shell step (the frame inventory, the residency rows, a table or
    /// lifecycle clear, the tag retirement) could not finish this time; the
    /// next drain reruns it. Every step is idempotent on retry.
    NextDrain,
}

/// Where a release found a broken invariant.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BrokenRelease {
    site: &'static str,
}

impl BrokenRelease {
    pub const fn at(site: &'static str) -> Self {
        Self { site }
    }
    pub const fn site(self) -> &'static str {
        self.site
    }
}

/// One release step's answer. See the module documentation.
#[must_use = "a release outcome must reach its owner: a dropped Broken would read as success"]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReleaseOutcome {
    Done,
    NotNow(ReleaseWait),
    Broken(BrokenRelease),
}

impl ReleaseOutcome {
    /// `Done` when `finished`, else "not now" until `wait`. Only for a step
    /// whose failure is, by its own contract, a state it leaves intact and
    /// can rerun (never one that may have found a broken invariant).
    pub const fn done_or(finished: bool, wait: ReleaseWait) -> Self {
        if finished {
            Self::Done
        } else {
            Self::NotNow(wait)
        }
    }

    /// Run `next` only after this step is `Done`; "not now" and broken stop
    /// the release where they are.
    pub fn then(self, next: impl FnOnce() -> Self) -> Self {
        match self {
            Self::Done => next(),
            stopped => stopped,
        }
    }

    pub const fn is_done(self) -> bool {
        matches!(self, Self::Done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn then_runs_only_after_done() {
        let broken = BrokenRelease::at("test");
        assert_eq!(
            ReleaseOutcome::Done.then(|| ReleaseOutcome::Broken(broken)),
            ReleaseOutcome::Broken(broken)
        );
        let mut ran = false;
        assert_eq!(
            ReleaseOutcome::NotNow(ReleaseWait::Unpublish).then(|| {
                ran = true;
                ReleaseOutcome::Done
            }),
            ReleaseOutcome::NotNow(ReleaseWait::Unpublish)
        );
        assert!(!ran);
        assert_eq!(
            ReleaseOutcome::done_or(false, ReleaseWait::NextDrain),
            ReleaseOutcome::NotNow(ReleaseWait::NextDrain)
        );
    }
}
