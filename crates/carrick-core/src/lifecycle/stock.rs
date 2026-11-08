//! Standing thread-birth stock policy shared by host and native owners.
use super::{GateState, Lifecycle};

pub const DEFAULT_THREAD_POOL_DEPTH: usize = 4;

/// The graph adapter retains identity, control and limit custody before it
/// publishes a stock entry. A refusal leaves all of that custody with it.
pub trait ThreadStock {
    fn page(&self) -> &dyn Lifecycle;
    fn standing(&self) -> usize;
    fn reserve_and_stock(&mut self) -> bool;
}

/// Refill after a birth or retirement, through the same admission transaction
/// as initial stock. Closed admission never acquires a new reservation.
pub fn replenish(stock: &mut impl ThreadStock, depth: usize) {
    while stock.page().gate() == GateState::Open && stock.standing() < depth {
        if !stock.reserve_and_stock() {
            break;
        }
    }
}

/// Identities retained by a stock owner until both lifecycle exit and the final
/// control pin have settled. `I` owns the adapter's namespace reservation.
pub struct StockEntries<I> {
    identities: alloc::vec::Vec<(super::EntryRef, I)>,
}

impl<I> Default for StockEntries<I> {
    fn default() -> Self {
        Self {
            identities: alloc::vec::Vec::new(),
        }
    }
}

/// Queue-locked admission result. Changed must be probed again, never slept
/// on: a final control release raced the notification enrollment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StockAdmission {
    Ready,
    Waiting,
    Exhausted,
    Changed,
}

impl<I> StockEntries<I> {
    /// Root admission may issue stock only on a page with no borrowed pool
    /// identity. Fork-child pages instead retain their existing leader entry.
    pub fn for_fresh_root(page: &impl Lifecycle) -> Result<Self, super::TransitionError> {
        for index in 0..page.entry_count() {
            let (_, state) = page
                .state(index)
                .ok_or(super::TransitionError::NoSuchEntry)?;
            if state != super::EntryState::Vacant {
                return Err(super::TransitionError::WrongState(state));
            }
        }
        Ok(Self::default())
    }

    /// Withdraw only this stock owner's unused identities after terminal
    /// admission closes. A racing claimant keeps its own live/rollback and
    /// settlement authority; its later settlement calls this owner again.
    pub fn drain_closed<T: super::MemberControl>(
        &mut self,
        page: &dyn Lifecycle,
        controls: &[T],
    ) -> Result<(), super::TransitionError> {
        use super::{EntryState, TransitionError};
        if !page.gate().is_terminal() {
            return Ok(());
        }
        for (entry, _) in &self.identities {
            let (generation, state) = page
                .state(entry.index())
                .ok_or(TransitionError::NoSuchEntry)?;
            if generation != entry.generation() {
                return Err(TransitionError::StaleGeneration);
            }
            if state == EntryState::Reserved {
                match super::revoke_unborn_control(page, *entry, &controls[entry.index() + 1]) {
                    Ok(()) | Err(TransitionError::WrongState(EntryState::Claimed)) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        self.settle(page, controls)
    }

    pub fn insert(&mut self, entry: super::EntryRef, identity: I) {
        self.identities.push((entry, identity));
    }

    /// Reap only exact exited incarnations whose control references are gone.
    /// Namespace custody drops here, before the next reservation can reuse it.
    pub fn settle<T: super::MemberControl>(
        &mut self,
        page: &dyn Lifecycle,
        controls: &[T],
    ) -> Result<(), super::TransitionError> {
        use super::{EntryState, TransitionError};
        let mut index = 0;
        while index < self.identities.len() {
            let entry = self.identities[index].0;
            let (generation, state) = page
                .state(entry.index())
                .ok_or(TransitionError::StaleGeneration)?;
            if generation != entry.generation() {
                return Err(TransitionError::StaleGeneration);
            }
            if matches!(
                state,
                EntryState::ExitedInZone | EntryState::Reaped | EntryState::Revoked
            ) && !controls[entry.index() + 1].exit_custody().referenced()
            {
                if state == EntryState::ExitedInZone {
                    page.reap(entry)?;
                }
                self.identities.swap_remove(index);
            } else {
                index += 1;
            }
        }
        Ok(())
    }

    pub fn standing(&self, page: &dyn Lifecycle) -> usize {
        self.identities
            .iter()
            .filter(|(entry, _)| {
                page.state(entry.index()) == Some((entry.generation(), super::EntryState::Reserved))
            })
            .count()
    }

    /// Select only a returned slot with no predecessor control pins. The
    /// adapter must still acquire the control's reset authority before stock.
    pub fn recyclable<T: super::MemberControl>(
        &self,
        page: &dyn Lifecycle,
        controls: &[T],
    ) -> Option<usize> {
        (0..page.entry_count()).find(|&index| {
            page.state(index).is_some_and(|(_, state)| {
                matches!(
                    state,
                    super::EntryState::Vacant
                        | super::EntryState::Reaped
                        | super::EntryState::Revoked
                )
            }) && !controls[index + 1].exit_custody().referenced()
        })
    }

    /// Decide admission and arm every possible final-pin source under the
    /// caller's already-enrolled object queue. Claimed births are notified by
    /// birth settlement; host claims are deliberately outside this stock.
    ///
    /// # Safety
    /// The retained release source and controls must remain reachable in the
    /// execution lane which drops the final pin (see `arm_member_release`).
    /// The caller excludes control reuse during this call, and every probe of
    /// the same incarnation must name the same broadcast notification source.
    pub unsafe fn admission<'a, T: super::MemberControl, R: super::MemberControlRelease + 'a>(
        &self,
        page: &dyn Lifecycle,
        controls: &'a [T],
        release: alloc::sync::Arc<R>,
    ) -> StockAdmission {
        use super::EntryState;
        if self.standing(page) != 0 {
            return StockAdmission::Ready;
        }
        let mut pending = (0..page.entry_count()).any(|index| {
            page.state(index)
                .is_some_and(|(_, state)| state == EntryState::Claimed)
        });
        for (entry, _) in &self.identities {
            if page
                .state(entry.index())
                .is_some_and(|(generation, state)| {
                    generation == entry.generation()
                        && matches!(
                            state,
                            EntryState::ExitingBorn
                                | EntryState::ExitingPublished
                                | EntryState::ExitedInZone
                                | EntryState::Reaped
                                | EntryState::Revoked
                        )
                })
            {
                // SAFETY: the caller retains this source in the final-pin lane.
                if !unsafe {
                    super::arm_member_release(&controls[entry.index() + 1], release.clone())
                } {
                    return StockAdmission::Changed;
                }
                pending = true;
            }
        }
        if pending {
            StockAdmission::Waiting
        } else {
            StockAdmission::Exhausted
        }
    }
}
