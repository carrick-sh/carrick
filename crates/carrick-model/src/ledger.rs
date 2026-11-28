//! The wait ledger: ghost state that records every actor's waits, so the
//! harness checks I1 to I5 for every protocol the same way.
//!
//! It is also the model of the wait queue: a protocol's production notify
//! calls [`WaitLedger::notify`], which wakes every actor parked on the wait.
//! What the ledger never does is wake anyone on its own: a step that
//! publishes without notifying leaves its waiter parked, and I1 or I3 finds
//! it. It is plain data, compared and hashed with the protocol's state.

use std::collections::{BTreeMap, BTreeSet};
use std::format;
use std::string::String;

use crate::{Class, InvariantId, OpKind, WaitId};

/// One parked actor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Park {
    /// The wait it enrolled on.
    pub wait: WaitId,
    /// The wait's epoch when it probed and parked.
    pub epoch: u64,
    /// Whether a notify has claimed it since.
    pub woken: bool,
}

/// The ledger. See the module documentation.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct WaitLedger {
    parked: BTreeMap<usize, Park>,
    /// Each actor's last "not now", while its attempts keep answering it.
    last_not_now: BTreeMap<usize, (WaitId, u64)>,
    closed: BTreeSet<WaitId>,
    /// Publications and closes committed so far, by anyone.
    publications: u64,
    /// `publications` as of each actor's last step.
    seen: BTreeMap<usize, u64>,
    corrupted: bool,
    ended: bool,
}

/// A harness invariant the ledger found broken.
pub type Broken = (InvariantId, String);

impl WaitLedger {
    /// The production notify of `wait` ran: every actor parked on it is
    /// woken.
    pub fn notify(&mut self, wait: WaitId) {
        for park in self.parked.values_mut() {
            if park.wait == wait {
                park.woken = true;
            }
        }
    }

    /// Whether `actor` may run: not parked, or woken.
    pub fn is_runnable(&self, actor: usize) -> bool {
        self.parked.get(&actor).is_none_or(|park| park.woken)
    }

    /// Where `actor` is parked, if it is.
    pub fn parked(&self, actor: usize) -> Option<Park> {
        self.parked.get(&actor).copied()
    }

    /// Whether a step returned `Broken`: the world has ended.
    pub fn ended(&self) -> bool {
        self.ended
    }

    /// Whether a `Corrupt` step has run.
    pub fn corrupted(&self) -> bool {
        self.corrupted
    }

    /// How many publications and closes have committed.
    pub fn publications(&self) -> u64 {
        self.publications
    }

    /// Account one step of `actor` and check the step-local invariants.
    /// `unchanged` is whether the protocol state equals its value before the
    /// step; `reads_corruption` whether the step reads a corrupted state.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn account(
        &mut self,
        actor: usize,
        kind: OpKind,
        class: Class,
        unchanged: bool,
        reads_corruption: bool,
        epoch: impl Fn(WaitId) -> u64,
        has_publisher: impl Fn(WaitId) -> bool,
    ) -> Result<(), Broken> {
        // I5: broken is fatal, contention is not.
        if self.corrupted && reads_corruption && class != Class::Broken {
            return Err((
                InvariantId::I5,
                format!("actor {actor} read a corruption and answered {class:?}, not Broken"),
            ));
        }
        if !self.corrupted && class == Class::Broken {
            return Err((
                InvariantId::I5,
                format!("actor {actor}'s legal step answered Broken"),
            ));
        }
        if class == Class::Broken {
            self.ended = true;
        }
        if kind == OpKind::Corrupt {
            self.corrupted = true;
        }
        self.parked.remove(&actor);
        match class {
            Class::NotNow(wait) => {
                if !unchanged {
                    return Err((
                        InvariantId::I4,
                        format!("actor {actor}'s \"not now\" on {wait:?} changed the state"),
                    ));
                }
                if !has_publisher(wait) {
                    return Err((
                        InvariantId::I4,
                        format!("actor {actor} waits on {wait:?}, which nothing will publish"),
                    ));
                }
                if self.closed.contains(&wait) {
                    return Err((
                        InvariantId::I3,
                        format!("actor {actor} parked on {wait:?} after its close"),
                    ));
                }
                let now = epoch(wait);
                if self.last_not_now.get(&actor) == Some(&(wait, now)) {
                    return Err((
                        InvariantId::I4,
                        format!("actor {actor} polled {wait:?} at epoch {now} with no advance"),
                    ));
                }
                self.parked.insert(
                    actor,
                    Park {
                        wait,
                        epoch: now,
                        woken: false,
                    },
                );
                self.last_not_now.insert(actor, (wait, now));
            }
            Class::Rerun => {
                if self.seen.get(&actor).copied().unwrap_or(0) == self.publications {
                    return Err((
                        InvariantId::I4,
                        format!("actor {actor} reran with no peer publication since its last step"),
                    ));
                }
                self.last_not_now.remove(&actor);
            }
            Class::Done | Class::Answer | Class::Broken => {
                self.last_not_now.remove(&actor);
            }
        }
        match kind {
            OpKind::Publish(_) => self.publications += 1,
            OpKind::Close(wait) => {
                self.publications += 1;
                self.closed.insert(wait);
                if let Some((&waiter, _)) = self
                    .parked
                    .iter()
                    .find(|(_, park)| park.wait == wait && !park.woken)
                {
                    return Err((
                        InvariantId::I3,
                        format!("the close of {wait:?} left actor {waiter} parked"),
                    ));
                }
            }
            OpKind::Begin | OpKind::Finish | OpKind::Corrupt => {}
        }
        self.seen.insert(actor, self.publications);
        Ok(())
    }

    /// I1, in every state: no parked actor's wait moved past the epoch it
    /// parked at without a wake for it.
    pub(crate) fn check_wakes(&self, epoch: impl Fn(WaitId) -> u64) -> Result<(), Broken> {
        for (&actor, park) in &self.parked {
            let now = epoch(park.wait);
            if !park.woken && now != park.epoch {
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
