//! The wait ledger: ghost state that records every actor's waits, so the
//! harness checks I1 to I5 for every protocol the same way.
//!
//! It is also the model of the wait queue, and it owns every wait's epoch
//! (its revision), so an epoch only ever moves forward, by
//! [`WaitLedger::advance`]. A protocol's step calls the production pair the
//! ledger models: [`advance`](WaitLedger::advance) where production bumps
//! the queue's revision, and [`wake`](WaitLedger::wake) where it wakes the
//! queue ([`publish`](WaitLedger::publish) does both). The ledger never
//! wakes anyone on its own: a step that advances without waking leaves its
//! waiter parked on a moved epoch (I1), and a wake without an advance (or a
//! committed close) of the same wait in the same step is a spurious wake
//! (I4). It is plain data, compared and hashed with the protocol's state.
//!
//! The queue it models wakes everyone (wake-all). A wake-one queue, whose
//! woken waiter passes the wake on, is outside it: I1 as stated would call
//! the waiters it leaves parked lost. Such a protocol states its own
//! hand-off invariant until the ledger models it (#3181 follow-up).

use std::collections::{BTreeMap, BTreeSet};
use std::format;
use std::string::String;
use std::vec::Vec;

use crate::{Class, Effect, Enrolment, InvariantId, ObjectId, OpKind, WaitId};

/// The step that woke a parked actor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Waker {
    pub actor: usize,
    pub kind: OpKind,
}

/// One parked actor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Park {
    /// The wait it enrolled on.
    pub wait: WaitId,
    /// The epoch of the wait it observed before it parked.
    pub epoch: u64,
    /// The step whose wake claimed it, if one has.
    pub woken: Option<Waker>,
}

/// The ledger. See the module documentation.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct WaitLedger {
    /// Every wait's epoch; absent is zero.
    epochs: BTreeMap<WaitId, u64>,
    parked: BTreeMap<usize, Park>,
    closed: BTreeSet<WaitId>,
    corrupted: BTreeSet<ObjectId>,
    /// The stale observations each actor's reruns have been paid by: one
    /// observation pays one rerun.
    paid: BTreeMap<usize, BTreeSet<Enrolment>>,
    ended: bool,
    /// The step running now, for [`Waker`].
    stepping: Option<Waker>,
    /// The waits the running step advanced.
    advanced: BTreeSet<WaitId>,
    /// The waits the running step's wakes woke someone on.
    woke: BTreeSet<WaitId>,
}

/// A harness invariant the ledger found broken.
pub type Broken = (InvariantId, String);

/// What the explorer knows about one step, for [`WaitLedger::account`].
pub(crate) struct Facts {
    pub actor: usize,
    pub kind: OpKind,
    pub class: Class,
    /// The protocol state equals its value before the step.
    pub state_unchanged: bool,
    /// The step reads an object a `Corrupt` step corrupted.
    pub reads_corruption: bool,
    /// The step panicked (its class is then `Broken`).
    pub panic: Option<String>,
}

impl WaitLedger {
    /// `wait`'s epoch: what an actor observes before it decides to park.
    pub fn epoch(&self, wait: WaitId) -> u64 {
        self.epochs.get(&wait).copied().unwrap_or(0)
    }

    /// The production revision bump of `wait` ran.
    pub fn advance(&mut self, wait: WaitId) {
        *self.epochs.entry(wait).or_insert(0) += 1;
        self.advanced.insert(wait);
    }

    /// The production wake of `wait`'s queue ran: every actor parked on it
    /// is woken, by the step running now.
    pub fn wake(&mut self, wait: WaitId) {
        let waker = self.stepping.unwrap_or(Waker {
            actor: usize::MAX,
            kind: OpKind::Begin,
        });
        for park in self.parked.values_mut() {
            if park.wait == wait && park.woken.is_none() {
                park.woken = Some(waker);
                self.woke.insert(wait);
            }
        }
    }

    /// A publication of `wait`: [`advance`](Self::advance), then
    /// [`wake`](Self::wake).
    pub fn publish(&mut self, wait: WaitId) {
        self.advance(wait);
        self.wake(wait);
    }

    /// Whether `actor` may run: not parked, or woken.
    pub fn is_runnable(&self, actor: usize) -> bool {
        self.parked
            .get(&actor)
            .is_none_or(|park| park.woken.is_some())
    }

    /// Where `actor` is parked, if it is.
    pub fn parked(&self, actor: usize) -> Option<Park> {
        self.parked.get(&actor).copied()
    }

    /// Whether a step returned `Broken`: the world has ended.
    pub fn ended(&self) -> bool {
        self.ended
    }

    /// Whether a `Corrupt` step has corrupted `object`.
    pub fn corrupted(&self, object: ObjectId) -> bool {
        self.corrupted.contains(&object)
    }

    /// The objects corrupted so far.
    pub fn corruptions(&self) -> impl Iterator<Item = ObjectId> + '_ {
        self.corrupted.iter().copied()
    }

    /// The step about to run, so a wake inside it records its waker.
    pub(crate) fn begin_step(&mut self, actor: usize, kind: OpKind) {
        self.stepping = Some(Waker { actor, kind });
    }

    /// Account one step and check the step-local invariants. `before` is
    /// the ledger as the step found it.
    pub(crate) fn account(&mut self, facts: Facts, before: &WaitLedger) -> Result<(), Broken> {
        let Facts {
            actor,
            kind,
            class,
            state_unchanged,
            reads_corruption,
            panic,
        } = facts;
        self.stepping = None;
        let woke = core::mem::take(&mut self.woke);
        let advanced = core::mem::take(&mut self.advanced);
        // I5: broken is fatal, contention is not, per object.
        let broken = class == Class::Broken;
        if reads_corruption && !broken {
            return Err((
                InvariantId::I5,
                format!("actor {actor} read a corrupted object and answered {class:?}, not Broken"),
            ));
        }
        if broken && !reads_corruption {
            let what = panic.map_or_else(
                || String::from("answered Broken"),
                |why| format!("panicked ({why})"),
            );
            return Err((
                InvariantId::I5,
                format!("actor {actor}'s step reads no corrupted object, and it {what}"),
            ));
        }
        if broken {
            self.ended = true;
        }
        // I4: a wake is a publication's or a committed close's. A wake of a
        // wait the step didn't advance (and didn't close) is spurious: the
        // waiter re-probes an unmoved epoch, which is polling.
        let closes = match (class, kind.effect()) {
            (Class::Done, Effect::Close(wait)) => Some(wait),
            _ => None,
        };
        if let Some(&wait) = woke
            .iter()
            .find(|&&wait| !advanced.contains(&wait) && closes != Some(wait))
        {
            return Err((
                InvariantId::I4,
                format!(
                    "actor {actor}'s {kind:?} ({class:?}) woke the waiters of {wait:?} without \
                     advancing or closing it: a spurious wake"
                ),
            ));
        }
        if let (OpKind::Corrupt(object), Class::Done) = (kind, class) {
            self.corrupted.insert(object);
        }
        self.parked.remove(&actor);
        match class {
            Class::NotNow(Enrolment { wait, observed }) => {
                let now = self.epoch(wait);
                if now != observed {
                    return Err((
                        InvariantId::I1,
                        format!(
                            "actor {actor} parked on {wait:?} at the epoch {observed} it observed; \
                             it is already at {now}, and nothing will wake it"
                        ),
                    ));
                }
                if !state_unchanged || !advanced.is_empty() {
                    return Err((
                        InvariantId::I4,
                        format!("actor {actor}'s \"not now\" on {wait:?} changed the state"),
                    ));
                }
                if self.closed.contains(&wait) {
                    return Err((
                        InvariantId::I3,
                        format!("actor {actor} parked on {wait:?} after its close"),
                    ));
                }
                self.parked.insert(
                    actor,
                    Park {
                        wait,
                        epoch: observed,
                        woken: None,
                    },
                );
            }
            Class::Rerun(enrolment @ Enrolment { wait, observed }) => {
                if before.epoch(wait) == observed {
                    return Err((
                        InvariantId::I4,
                        format!(
                            "actor {actor} reran on {wait:?} observed at epoch {observed}, and the \
                             wait is still there: nothing moved under the observation"
                        ),
                    ));
                }
                if !self.paid.entry(actor).or_default().insert(enrolment) {
                    return Err((
                        InvariantId::I4,
                        format!(
                            "actor {actor} reran again on its observation of {wait:?} at epoch \
                             {observed}: one stale observation pays one rerun"
                        ),
                    ));
                }
            }
            Class::Done | Class::Answer(_) | Class::Broken => {}
        }
        // Only a committed step publishes or closes: a "not now" close
        // closes nothing.
        if class == Class::Done {
            match kind.effect() {
                Effect::Publish(wait) if !advanced.contains(&wait) => {
                    return Err((
                        InvariantId::I1,
                        format!(
                            "actor {actor}'s committed {kind:?} left {wait:?} at epoch {}",
                            self.epoch(wait)
                        ),
                    ));
                }
                Effect::Close(wait) => {
                    self.closed.insert(wait);
                    if let Some((&waiter, _)) = self
                        .parked
                        .iter()
                        .find(|(_, park)| park.wait == wait && park.woken.is_none())
                    {
                        return Err((
                            InvariantId::I3,
                            format!("the close of {wait:?} left actor {waiter} parked"),
                        ));
                    }
                }
                Effect::Publish(_) | Effect::None => {}
            }
        }
        Ok(())
    }

    /// I4, in every state of a live world: every parked, unwoken actor
    /// waits on a wait with a live publisher. `publishers` lists who can
    /// publish a wait, and `can_step` whether an actor has an enabled
    /// operation, both in the state reached. A world a legal `Broken` ended
    /// owes no one a wake.
    pub(crate) fn check_stranded(
        &self,
        publishers: impl Fn(WaitId) -> Vec<usize>,
        can_step: impl Fn(usize) -> bool,
    ) -> Result<(), Broken> {
        if self.ended {
            return Ok(());
        }
        for (&actor, park) in &self.parked {
            if park.woken.is_some() {
                continue;
            }
            let mut visited = BTreeSet::from([actor]);
            if !self.live_publisher(park.wait, &publishers, &can_step, &mut visited) {
                return Err((
                    InvariantId::I4,
                    format!(
                        "actor {actor} waits on {:?}, and no peer that can run will publish it \
                         (publishers {:?})",
                        park.wait,
                        publishers(park.wait)
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Whether some publisher of `wait` outside `visited` can run: it is
    /// runnable and has an enabled operation, or it is parked on a wait
    /// that, in turn, has one (a chain of waits ending at an actor that can
    /// step). A cycle back to `visited` (the waiter itself, to start with)
    /// is a deadlock, not a publisher.
    fn live_publisher(
        &self,
        wait: WaitId,
        publishers: &impl Fn(WaitId) -> Vec<usize>,
        can_step: &impl Fn(usize) -> bool,
        visited: &mut BTreeSet<usize>,
    ) -> bool {
        for peer in publishers(wait) {
            if !visited.insert(peer) {
                continue;
            }
            match self.parked.get(&peer) {
                Some(park) if park.woken.is_none() => {
                    if self.live_publisher(park.wait, publishers, can_step, visited) {
                        return true;
                    }
                }
                _ => {
                    if can_step(peer) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// I1, in every state: no parked actor's wait moved past the epoch it
    /// parked at without a wake for it.
    pub(crate) fn check_wakes(&self) -> Result<(), Broken> {
        for (&actor, park) in &self.parked {
            let now = self.epoch(park.wait);
            if park.woken.is_none() && now != park.epoch {
                return Err((
                    InvariantId::I1,
                    format!(
                        "actor {actor} parked on {:?} at epoch {}; it is at {now} and no wake is pending",
                        park.wait, park.epoch
                    ),
                ));
            }
        }
        Ok(())
    }
}
