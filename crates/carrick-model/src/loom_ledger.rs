//! The wait ledger for loom models (#3061 S1), and the interrupt model a
//! venue's halt runs against.
//!
//! A loom model runs the production code on loom's threads, so it has no
//! explorer step to account. Its actors tell the [`LoomLedger`] what they
//! did instead, at the points that matter to I1: the read of the conditions
//! a wait guards ([`LoomLedger::probe`]), a publication
//! ([`LoomLedger::publish`]), a notify, and a park. The ledger is the same
//! [`WaitLedger`] the explorer uses, and I1 is checked at the end of each
//! execution ([`LoomLedger::finish`]), once every actor has run to its end
//! and so every wake a publisher owes has been sent.
//!
//! Never at a halt: a publisher may advance the epoch, then reach a loom
//! scheduling point before it sends the wake, and a waiter that halts in
//! between is woken by that send. A halt-time check would call that correct
//! protocol a lost wake (#3061 S1 pre-review).
//!
//! **The probe's contract.** An actor probes a wait right before the read
//! of the conditions it guards, and parks (halts) only when that read found
//! nothing to do. A publisher publishes once what it published is visible
//! to that read: in a model, right after the production call that made it
//! visible returns, never before. So a publication after the probe either
//! was seen by the read (the actor didn't park) or needs a wake, and the
//! probe's epoch is the one the park waits from. The ghost epoch may lag
//! the real publication, never lead it, so it can miss no lost wake that
//! the end state shows.
//!
//! It sits behind a `std` mutex, never a loom one: it is ghost state, so it
//! adds no interleavings of its own, and each call is one indivisible step
//! between the model's loom operations, as one ICR write or one `sti; hlt`
//! is on a CPU.
//!
//! [`ModelIrq`] is the interrupt semantics, per actor: a send sets the
//! target's pending bit and notifies its wait, the pass's drain clears the
//! bit, and a halt returns at once while the bit is set and otherwise
//! sleeps (parks on the wait). Nothing else wakes a sleeping actor.

use std::collections::BTreeMap;
use std::format;
use std::sync::Mutex;

use crate::ledger::{Broken, WaitLedger};
use crate::{Class, InvariantId, OpKind, WaitId};

#[derive(Default)]
struct Inner {
    ledger: WaitLedger,
    epochs: BTreeMap<WaitId, u64>,
    /// Each actor's last probe: the wait and its epoch when the actor read
    /// the conditions that wait guards.
    probes: BTreeMap<usize, (WaitId, u64)>,
    /// [`ModelIrq`]'s pending bits, by actor.
    pending: BTreeMap<usize, bool>,
}

impl Inner {
    fn epoch(&self, wait: WaitId) -> u64 {
        self.epochs.get(&wait).copied().unwrap_or(0)
    }

    fn account(
        &mut self,
        actor: usize,
        kind: OpKind,
        class: Class,
        epoch: u64,
    ) -> Result<(), Broken> {
        // A loom actor's waits all have a publisher in the model: its peers
        // run production code that may publish them. I1 finds the ones that
        // never do.
        self.ledger
            .account(actor, kind, class, true, false, |_| epoch, |_| true)
    }

    fn check(&self) -> Result<(), Broken> {
        self.ledger.check_wakes(|wait| self.epoch(wait))
    }
}

/// See the module documentation. Make one per loom execution.
#[derive(Default)]
pub struct LoomLedger {
    inner: Mutex<Inner>,
}

impl LoomLedger {
    pub fn new() -> Self {
        Self::default()
    }

    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        // A panic inside an earlier call already failed the execution.
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut inner)
    }

    /// `actor` is about to read the conditions `wait` guards: a park that
    /// follows waits from this epoch, so any publication after it needs a
    /// wake.
    pub fn probe(&self, actor: usize, wait: WaitId) {
        self.with(|inner| {
            let epoch = inner.epoch(wait);
            inner.probes.insert(actor, (wait, epoch));
        });
    }

    /// `actor` published what `wait` guards: its epoch advances. The
    /// publication's notify is separate ([`Self::notify`], or a
    /// [`ModelIrq::send`]); one that never comes is what I1 finds.
    pub fn publish(&self, actor: usize, wait: WaitId) {
        self.with(|inner| {
            *inner.epochs.entry(wait).or_insert(0) += 1;
            let epoch = inner.epoch(wait);
            raise(inner.account(actor, OpKind::Publish(wait), Class::Done, epoch));
        });
    }

    /// The production notify of `wait`: every actor parked on it is woken.
    pub fn notify(&self, wait: WaitId) {
        self.with(|inner| inner.ledger.notify(wait));
    }

    /// I1 at the end of an execution: nobody sleeps past a publication with
    /// no wake for it.
    pub fn finish(&self) {
        self.with(|inner| raise(inner.check()));
    }

    #[allow(
        clippy::panic,
        reason = "a loom execution fails only by panicking: a park with no probe is a broken model"
    )]
    fn park(inner: &mut Inner, actor: usize, wait: WaitId) {
        let epoch = match inner.probes.get(&actor) {
            Some(&(probed, epoch)) if probed == wait => epoch,
            _ => panic!("actor {actor} parks on {wait:?} with no probe of it"),
        };
        inner.epochs.entry(wait).or_insert(0);
        raise(inner.account(actor, OpKind::Begin, Class::NotNow(wait), epoch));
    }

    fn unpark(inner: &mut Inner, actor: usize) {
        let epoch = inner.probes.get(&actor).map_or(0, |&(_, epoch)| epoch);
        raise(inner.account(actor, OpKind::Begin, Class::Done, epoch));
    }
}

/// A broken harness invariant fails the loom execution, named first so a
/// mutant's test can tell which invariant killed it.
#[allow(
    clippy::panic,
    reason = "a loom execution fails only by panicking; the message names the invariant"
)]
fn raise(result: Result<(), Broken>) {
    if let Err((invariant, message)) = result {
        panic!("{}", broken_message(invariant, &message));
    }
}

/// The panic message for a broken invariant: `"I1: ..."`.
pub fn broken_message(invariant: InvariantId, message: &str) -> std::string::String {
    format!("{invariant:?}: {message}")
}

/// See the module documentation. Actor `n`'s vector wait is
/// [`ModelIrq::wait`]`(n)`.
pub struct ModelIrq<'a> {
    ledger: &'a LoomLedger,
}

impl<'a> ModelIrq<'a> {
    pub fn new(ledger: &'a LoomLedger) -> Self {
        Self { ledger }
    }

    /// The wait a halted `actor` sleeps on: its vector.
    pub const fn wait(actor: usize) -> WaitId {
        WaitId::hardware(actor as u64)
    }

    /// Send `actor` its vector: set its pending bit, wake its halt.
    pub fn send(&self, actor: usize) {
        self.ledger.with(|inner| {
            inner.pending.insert(actor, true);
            inner.ledger.notify(Self::wait(actor));
        });
    }

    /// `actor`'s pass drains its vectors (`sti; nop; cli`, or ARM's
    /// unmasked window): the pending bit clears.
    pub fn drain(&self, actor: usize) {
        self.ledger.with(|inner| {
            inner.pending.insert(actor, false);
        });
    }

    /// `actor` is about to read the conditions its vector's senders
    /// publish ([`LoomLedger::probe`] on its vector wait).
    pub fn probe(&self, actor: usize) {
        self.ledger.probe(actor, Self::wait(actor));
    }

    /// `actor` halts (`sti; hlt`, WFI). Returns `true` if it sleeps: no
    /// vector was pending. A pending vector ends the halt at once and is
    /// taken. A sleeping actor stays parked until a send wakes it; whether
    /// one ever does is [`LoomLedger::finish`]'s I1.
    pub fn halt(&self, actor: usize) -> bool {
        self.ledger.with(|inner| {
            LoomLedger::park(inner, actor, Self::wait(actor));
            let pending = inner.pending.insert(actor, false).unwrap_or(false);
            if pending {
                LoomLedger::unpark(inner, actor);
            }
            !pending
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]
    use super::*;

    fn panics_with(f: impl FnOnce() + std::panic::UnwindSafe) -> std::string::String {
        let payload = std::panic::catch_unwind(f).expect_err("the ledger should have failed");
        payload
            .downcast_ref::<std::string::String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).into()))
            .unwrap_or_default()
    }

    #[test]
    fn a_vector_sent_before_the_halt_ends_it_at_once() {
        let ledger = LoomLedger::new();
        let irq = ModelIrq::new(&ledger);
        irq.probe(1);
        ledger.publish(0, ModelIrq::wait(1));
        irq.send(1);
        assert!(!irq.halt(1));
        ledger.finish();
    }

    #[test]
    fn a_vector_sent_after_the_halt_wakes_it() {
        let ledger = LoomLedger::new();
        let irq = ModelIrq::new(&ledger);
        irq.probe(1);
        assert!(irq.halt(1));
        ledger.publish(0, ModelIrq::wait(1));
        irq.send(1);
        ledger.finish();
    }

    #[test]
    fn a_drained_vector_no_longer_ends_the_halt() {
        let ledger = LoomLedger::new();
        let irq = ModelIrq::new(&ledger);
        irq.send(1);
        irq.drain(1);
        irq.probe(1);
        assert!(irq.halt(1));
        ledger.finish();
    }

    #[test]
    fn a_publication_with_no_vector_is_a_lost_wake() {
        // Published after the halt: found at the end.
        let message = panics_with(|| {
            let ledger = LoomLedger::new();
            let irq = ModelIrq::new(&ledger);
            irq.probe(1);
            assert!(irq.halt(1));
            ledger.publish(0, ModelIrq::wait(1));
            ledger.finish();
        });
        assert!(message.starts_with("I1: "), "{message}");
        // Published between the probe and the halt, never sent: found at
        // the end too.
        let message = panics_with(|| {
            let ledger = LoomLedger::new();
            let irq = ModelIrq::new(&ledger);
            irq.probe(1);
            ledger.publish(0, ModelIrq::wait(1));
            assert!(irq.halt(1));
            ledger.finish();
        });
        assert!(message.starts_with("I1: "), "{message}");
    }

    #[test]
    fn a_halt_between_the_publication_and_its_send_is_woken_by_the_send() {
        // The publisher advances the epoch, the waiter halts, then the send
        // comes: a correct protocol, never a lost wake.
        let ledger = LoomLedger::new();
        let irq = ModelIrq::new(&ledger);
        irq.probe(1);
        ledger.publish(0, ModelIrq::wait(1));
        assert!(irq.halt(1));
        irq.send(1);
        ledger.finish();
    }
}
