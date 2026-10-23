//! Settlement of an internal owner-memory wait, independent of its venue.
//!
//! Readiness never authorizes a syscall by itself. Both an enrollment shortcut
//! and a scheduled wake must settle through this owner. Dependencies (including
//! physical writer exclusion) are released before the retained operation is
//! returned for re-preparation. Fatal state is sampled again after release.

use carrick_kernel::kernel::continuation::OwnerWaitCancellation;

pub(super) struct OwnerWait<D, R> {
    dependency: D,
    resume: R,
}

pub(super) enum Settlement<D, R> {
    Waiting(OwnerWait<D, R>),
    Resume(R),
    Cancelled(OwnerWaitCancellation),
}

impl<D, R> OwnerWait<D, R> {
    pub(super) fn new(dependency: D, resume: R) -> Self {
        Self { dependency, resume }
    }

    /// The cancellation query must read the process's fatal obligation, not
    /// attempt to reserve delivery for this particular waiter. Ordinary signals
    /// and stops are absent from that query's result type.
    pub(super) fn settle(
        self,
        mut cancellation: impl FnMut() -> Option<OwnerWaitCancellation>,
        ready: impl FnOnce(&D) -> bool,
    ) -> Settlement<D, R> {
        if let Some(cancelled) = cancellation() {
            return Settlement::Cancelled(cancelled);
        }
        if !ready(&self.dependency) {
            return Settlement::Waiting(self);
        }
        let Self { dependency, resume } = self;
        drop(dependency);
        if let Some(cancelled) = cancellation() {
            return Settlement::Cancelled(cancelled);
        }
        Settlement::Resume(resume)
    }
}
