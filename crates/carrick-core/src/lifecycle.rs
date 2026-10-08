//! Neutral exact-incarnation lifecycle transitions over retained storage.
pub use carrick_core_abi::lifecycle::*;
use core::sync::atomic::{AtomicU32, Ordering};

/// The exact page owns the storage and retains its ledger notification authority.
/// Linux payload initialization happens between reserve and release publication.
pub trait Lifecycle {
    fn gate_word(&self) -> &AtomicU32;
    fn live_word(&self) -> &AtomicU32;
    fn entry_count(&self) -> usize;
    fn entry_word(&self, index: usize) -> Option<&AtomicEntry>;
    fn activity(&self) -> Option<&ThreadLedgerActivity>;
    // ---- gate ----

    fn gate(&self) -> GateState {
        GateState::from_raw(self.gate_word().load(Ordering::SeqCst))
    }
    /// Fork begins: `Open -> ForkClosing`. New claims back out from here on.
    fn close_for_fork(&self) -> Result<(), GateState> {
        self.gate_word()
            .compare_exchange(
                GateState::Open as u32,
                GateState::ForkClosing as u32,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .map(|_| ())
            .map_err(GateState::from_raw)
    }
    /// Fork committed: `ForkClosing -> Open`.
    fn reopen_after_fork(&self) -> Result<(), GateState> {
        self.gate_word()
            .compare_exchange(
                GateState::ForkClosing as u32,
                GateState::Open as u32,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .map(|_| ())
            .map_err(GateState::from_raw)
    }
    /// Reserve host authority while the post-exec image has no birth binding.
    fn close_awaiting_exec_binding(&self) -> Result<(), GateState> {
        self.transition_gate(GateState::AwaitingExecBinding, GateState::ForkClosing)
    }
    /// Release host authority without admitting births into an unbound image.
    fn await_exec_binding(&self) -> Result<(), GateState> {
        self.transition_gate(GateState::ForkClosing, GateState::AwaitingExecBinding)
    }
    /// The new image's executable capacity is installed. This cannot release
    /// a fork's temporary close or a tracer's terminal close.
    fn reopen_after_exec_binding(&self) -> Result<(), GateState> {
        self.transition_gate(GateState::AwaitingExecBinding, GateState::Open)
    }
    fn transition_gate(&self, from: GateState, to: GateState) -> Result<(), GateState> {
        self.gate_word()
            .compare_exchange(from as u32, to as u32, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| ())
            .map_err(GateState::from_raw)
    }
    /// Terminal admission close, from any state.
    fn close(&self) {
        self.gate_word()
            .store(GateState::Closed as u32, Ordering::SeqCst);
    }
    /// Clone and exit admissions a host must drain after `close_for_fork`.
    /// `SeqCst` scan (second half of both claim/gate pairs).
    fn claimed_count(&self) -> usize {
        (0..self.entry_count())
            .filter(|&index| {
                self.entry_word(index).is_some_and(|e| {
                    matches!(
                        unpack(e.load(Ordering::SeqCst)).1,
                        EntryState::Claimed
                            | EntryState::ExitingBorn
                            | EntryState::ExitingPublished
                    )
                })
            })
            .count()
    }

    // ---- live count ----

    fn live(&self) -> u32 {
        self.live_word().load(Ordering::SeqCst)
    }
    /// A thread was born: `n -> n+1`. Returns the new count, `None` on
    /// overflow.
    fn thread_born(&self) -> Option<u32> {
        self.live_word()
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
            .ok()
            .map(|n| n + 1)
    }
    /// Release one live membership only above the caller-selected floor.
    /// Returns the new count; the owner never chooses terminal-exit policy.
    fn release_live(&self, minimum: u32) -> Result<u32, MembershipFloor> {
        self.live_word()
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                if n > minimum { Some(n - 1) } else { None }
            })
            .map(|n| n - 1)
            .map_err(|_| MembershipFloor)
    }

    fn state(&self, index: usize) -> Option<(u64, EntryState)> {
        self.entry_word(index)
            .map(|word| unpack(word.load(Ordering::Acquire)))
    }
    fn transition(
        &self,
        r: EntryRef,
        from: &[EntryState],
        to: EntryState,
        order: Ordering,
    ) -> Result<(), TransitionError> {
        let e = self
            .entry_word(r.index())
            .ok_or(TransitionError::NoSuchEntry)?;
        let cur = e.load(Ordering::Acquire);
        let (generation, state) = unpack(cur);
        if generation != r.generation() {
            return Err(TransitionError::StaleGeneration);
        }
        if !from.contains(&state) {
            return Err(TransitionError::WrongState(state));
        }
        match e.compare_exchange(cur, pack(generation, to), order, Ordering::Acquire) {
            Ok(_) => Ok(()),
            Err(now) => {
                let (g, s) = unpack(now);
                if g != r.generation() {
                    Err(TransitionError::StaleGeneration)
                } else {
                    Err(TransitionError::WrongState(s))
                }
            }
        }
    }

    /// Reserve payload initialization in a `Vacant`, `Reaped` or `Revoked` entry,
    /// bumping the generation. Returns the reference to the new incarnation.
    fn reserve_stock(&self, index: usize) -> Result<EntryRef, TransitionError> {
        let e = self.entry_word(index).ok_or(TransitionError::NoSuchEntry)?;
        let cur = e.load(Ordering::Acquire);
        let (generation, state) = unpack(cur);
        if !matches!(
            state,
            EntryState::Vacant | EntryState::Reaped | EntryState::Revoked
        ) {
            return Err(TransitionError::WrongState(state));
        }
        let next = generation + 1;
        e.compare_exchange(
            cur,
            pack(next, EntryState::Stocking),
            Ordering::Acquire,
            Ordering::Acquire,
        )
        .map_err(|now| TransitionError::WrongState(unpack(now).1))?;
        Ok(EntryRef::new(index as u32, next))
    }

    /// EL1 clone: CAS `Reserved -> Claimed`, then check the gate (Dekker with
    /// [`Self::close_for_fork`]). A closed gate backs the claim out.
    fn claim(&self, r: EntryRef) -> Result<ClaimedEntry, TransitionError> {
        self.transition(
            r,
            &[EntryState::Reserved],
            EntryState::Claimed,
            Ordering::SeqCst,
        )?;
        let gate = GateState::from_raw(self.gate_word().load(Ordering::SeqCst));
        if gate != GateState::Open {
            // We own the entry (Claimed): only we can move it, so this
            // store cannot race another transition.
            let e = self
                .entry_word(r.index())
                .ok_or(TransitionError::NoSuchEntry)?;
            e.store(pack(r.generation(), EntryState::Reserved), Ordering::SeqCst);
            return Err(TransitionError::GateClosed(gate));
        }
        Ok(ClaimedEntry(r))
    }

    /// EL1 clone: claim the first `Reserved` entry ([`Self::claim`]).
    /// `GateClosed` as soon as the gate refuses a claim; `PoolEmpty` when no
    /// entry could be claimed (another claimant may have won each one).
    fn claim_any(&self) -> Result<ClaimedEntry, TransitionError> {
        for index in 0..self.entry_count() {
            let e = self.entry_word(index).ok_or(TransitionError::NoSuchEntry)?;
            let (generation, state) = unpack(e.load(Ordering::Acquire));
            if state != EntryState::Reserved {
                continue;
            }
            let r = EntryRef::new(index as u32, generation);
            match self.claim(r) {
                Ok(claimed) => return Ok(claimed),
                Err(closed @ TransitionError::GateClosed(_)) => return Err(closed),
                Err(_) => {}
            }
        }
        Err(TransitionError::PoolEmpty)
    }

    /// EL1 clone backs out after a successful claim (the child could not be
    /// created): `Claimed -> Reserved`, the identity unused and still issued.
    fn unclaim(&self, claim: ClaimedEntry) -> Result<EntryRef, TransitionError> {
        let r = claim.0;
        self.transition(
            r,
            &[EntryState::Claimed],
            EntryState::Reserved,
            Ordering::SeqCst,
        )?;
        Ok(r)
    }

    /// Kernel: withdraw an unused entry, `Reserved -> Revoked`. Loses to a
    /// concurrent claim.
    fn revoke(&self, r: EntryRef) -> Result<(), TransitionError> {
        self.transition(
            r,
            &[EntryState::Reserved],
            EntryState::Revoked,
            Ordering::SeqCst,
        )
    }

    /// EL1 clone: record the Born payload and move `Claimed -> Born`.
    fn complete_birth(&self, claim: ClaimedEntry) -> Result<EntryRef, TransitionError> {
        let r = claim.0;
        let activity = self.activity();
        if let Some(activity) = activity {
            activity.announce();
        }
        let result = self.transition(
            r,
            &[EntryState::Claimed],
            EntryState::Born,
            Ordering::Release,
        );
        if result.is_err()
            && let Some(activity) = activity
        {
            let _ = activity.complete(1);
        }
        result?;
        Ok(r)
    }

    /// Host settle: `Born -> Published`.
    fn publish(&self, r: EntryRef) -> Result<(), TransitionError> {
        loop {
            let (generation, state) = self.state(r.index()).ok_or(TransitionError::NoSuchEntry)?;
            if generation != r.generation() {
                return Err(TransitionError::StaleGeneration);
            }
            let target = match state {
                EntryState::Born => EntryState::Published,
                EntryState::ExitingBorn => EntryState::ExitingPublished,
                _ => return Err(TransitionError::WrongState(state)),
            };
            match self.transition(r, &[state], target, Ordering::AcqRel) {
                Err(TransitionError::WrongState(_)) => continue,
                result => return result,
            }
        }
    }

    /// Claim exit admission before reading the gate (the Dekker peer of
    /// close and drain). A close either refuses us or observes our window.
    fn begin_exit(&self, r: EntryRef) -> Result<ExitAdmission<'_>, TransitionError>
    where
        Self: Sized,
    {
        loop {
            let (generation, state) = self.state(r.index()).ok_or(TransitionError::NoSuchEntry)?;
            if generation != r.generation() {
                return Err(TransitionError::StaleGeneration);
            }
            let target = match state {
                EntryState::Born => EntryState::ExitingBorn,
                EntryState::Published => EntryState::ExitingPublished,
                _ => return Err(TransitionError::WrongState(state)),
            };
            match self.transition(r, &[state], target, Ordering::SeqCst) {
                Err(TransitionError::WrongState(_)) => continue,
                Err(error) => return Err(error),
                Ok(()) => break,
            }
        }
        let admission = ExitAdmission {
            page: self,
            entry: r,
            committed: false,
        };
        let gate = self.gate();
        if gate != GateState::Open {
            return Err(TransitionError::GateClosed(gate));
        }
        Ok(admission)
    }

    /// Canonical host retirement of an adopted birth. The host owns execution
    /// and has already decremented the live census; no EL1 activity is owed.
    fn retire_published(&self, r: EntryRef) -> Result<(), TransitionError> {
        self.transition(
            r,
            &[EntryState::Published],
            EntryState::Reaped,
            Ordering::AcqRel,
        )
    }

    /// Host settle folded the exit: `ExitedInZone -> Reaped`.
    fn reap(&self, r: EntryRef) -> Result<(), TransitionError> {
        self.transition(
            r,
            &[EntryState::ExitedInZone],
            EntryState::Reaped,
            Ordering::AcqRel,
        )
    }
}
/// Non-cloneable ownership of the bounded EL1 exit window. Dropping an
/// unfinished exit restores membership, including a concurrent publication.
pub struct ExitAdmission<'a> {
    page: &'a dyn Lifecycle,
    entry: EntryRef,
    committed: bool,
}

impl ExitAdmission<'_> {
    pub fn commit(mut self) -> Result<(), TransitionError> {
        let activity = self.page.activity();
        if let Some(activity) = activity {
            activity.announce();
        }
        let result = self.page.transition(
            self.entry,
            &[EntryState::ExitingBorn, EntryState::ExitingPublished],
            EntryState::ExitedInZone,
            Ordering::SeqCst,
        );
        if result.is_err()
            && let Some(activity) = activity
        {
            let _ = activity.complete(1);
        }
        self.committed = result.is_ok();
        result
    }
}

impl Drop for ExitAdmission<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        // Publication can race this rollback, so retry only that exact CAS
        // conflict; no guest wait or authority acquisition occurs here.
        loop {
            let Some((generation, state)) = self.page.state(self.entry.index()) else {
                return;
            };
            if generation != self.entry.generation() {
                return;
            }
            let restored = match state {
                EntryState::ExitingBorn => EntryState::Born,
                EntryState::ExitingPublished => EntryState::Published,
                _ => return,
            };
            if self
                .page
                .transition(self.entry, &[state], restored, Ordering::SeqCst)
                .is_ok()
            {
                return;
            }
        }
    }
}

/// Proof of a successful claim. Not `Copy`/`Clone`: the owner birth publication
/// consumes it, so a claim is completed at most once.
#[derive(::core::fmt::Debug, ::core::cmp::PartialEq, ::core::cmp::Eq)]
pub struct ClaimedEntry(EntryRef);
impl ClaimedEntry {
    pub const fn entry(&self) -> EntryRef {
        self.0
    }
}
