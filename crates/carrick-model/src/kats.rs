//! Known answers for the checker itself (#3181's pre-reviews). Each seeded
//! broken protocol here is one an earlier checker passed.
//!
//! - The first review's set, written against the first API, fails on
//!   `df3815c4d` (run in commit `45e8b4689`).
//! - Of the second review's additions, the continuation's paid rerun, the
//!   vanished publisher and the spurious wake fail on the first fix round,
//!   `eb4cacbdf` (run with its API). The other three (the later drain
//!   order, the drain edge, the primed unpaid rerun) pass there: they pin
//!   the mechanism against a weaker checker than `eb4cacbdf` (a list-order
//!   drain, unchecked drain edges, a refusal of every first-step rerun),
//!   which the first checker was.

use std::vec::Vec;

use crate::explore::{Bound, Protocol, explore, replay};
use crate::ledger::WaitLedger;
use crate::{Answer, Class, Effect, InvariantId, ObjectId, OpKind, WaitId};

const W1: WaitId = WaitId::software(1);
const W2: WaitId = WaitId::software(2);

fn killed_by<P: Protocol>(protocol: &P, bound: Bound, expected: InvariantId) -> usize {
    match explore(protocol, bound) {
        Ok(report) => panic!(
            "{} passed {} states; {expected:?} should have failed it",
            P::NAME,
            report.states
        ),
        Err(counterexample) => {
            std::println!("{counterexample:?}");
            assert_eq!(counterexample.invariant, expected, "{counterexample:?}");
            counterexample.trace.len()
        }
    }
}

#[derive(Debug)]
enum Never {}

/// I1: a waiter observes the empty slot, a put lands (and wakes nobody,
/// since nobody is parked yet), then the waiter parks on its stale
/// observation. The first checker stamped the park with the epoch after the
/// put, so it saw nothing wrong.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Slot {
    observed: Option<u64>,
    full: bool,
    taken: bool,
    put: bool,
    bumped: bool,
    epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum SlotOp {
    Observe,
    Settle,
    Put,
    /// A publication of W1 that doesn't fill the slot.
    Bump,
}

struct StaleObservation {
    fixed: bool,
    /// The waiter enters the model mid-operation, holding an observation
    /// of epoch 0 (a continuation).
    start_observed: bool,
}

impl Protocol for StaleObservation {
    type State = Slot;
    type Op = SlotOp;
    type Violation = Never;
    const NAME: &'static str = "kat-stale-observation";

    fn init(&self) -> Slot {
        Slot {
            observed: self.start_observed.then_some(0),
            full: false,
            taken: false,
            put: false,
            bumped: false,
            epoch: 0,
        }
    }
    fn enabled(&self, s: &Slot, out: &mut Vec<SlotOp>) {
        if !s.taken && s.observed.is_none() {
            out.push(SlotOp::Observe);
        }
        if !s.taken && s.observed.is_some() {
            out.push(SlotOp::Settle);
        }
        if !s.put {
            out.push(SlotOp::Put);
        }
        if self.fixed && !s.bumped {
            out.push(SlotOp::Bump);
        }
    }
    fn actor(&self, op: SlotOp) -> usize {
        usize::from(matches!(op, SlotOp::Put | SlotOp::Bump))
    }
    fn kind(&self, op: SlotOp) -> OpKind {
        match op {
            SlotOp::Observe | SlotOp::Settle => OpKind::Begin,
            SlotOp::Put | SlotOp::Bump => OpKind::Commit(Effect::Publish(W1)),
        }
    }
    fn step(&self, s: &mut Slot, op: SlotOp, ledger: &mut WaitLedger) -> Result<Class, Never> {
        Ok(match op {
            SlotOp::Observe => {
                if s.full {
                    s.full = false;
                    s.taken = true;
                } else {
                    s.observed = Some(s.epoch);
                }
                Class::Done
            }
            // The bug: it parks on what it observed, without a probe. The
            // fixed waiter reruns when the epoch moved under it.
            SlotOp::Settle if s.full && self.fixed => {
                s.full = false;
                s.taken = true;
                s.observed = None;
                Class::Done
            }
            SlotOp::Settle if self.fixed && s.observed != Some(s.epoch) => {
                let observed = s.observed.take().unwrap_or(0);
                Class::Rerun(W1.at(observed))
            }
            SlotOp::Settle => Class::NotNow(W1.at(s.observed.unwrap_or(0))),
            SlotOp::Put => {
                s.put = true;
                s.full = true;
                s.epoch += 1;
                ledger.notify(W1);
                Class::Done
            }
            SlotOp::Bump => {
                s.bumped = true;
                s.epoch += 1;
                ledger.notify(W1);
                Class::Done
            }
        })
    }
    fn check(&self, _: &Slot) -> Result<(), Never> {
        Ok(())
    }
    fn invariant(&self, v: &Never) -> &'static str {
        match *v {}
    }
    fn epoch(&self, s: &Slot, _: WaitId) -> u64 {
        s.epoch
    }
    fn publishers(&self, _: &Slot, _: WaitId, out: &mut Vec<usize>) {
        out.push(1);
    }
    fn reads(&self, _: &Slot, _: SlotOp, _: ObjectId) -> bool {
        false
    }
}

#[test]
fn a_park_on_a_stale_observation_is_a_lost_wakeup() {
    // Observe (empty, epoch 0), Put (epoch 1), Settle parks.
    let broken = StaleObservation {
        fixed: false,
        start_observed: false,
    };
    let depth = killed_by(&broken, Bound::depth(4), InvariantId::I1);
    assert_eq!(depth, 3);
    // The fixed waiter, which reruns on the moved epoch, passes.
    let fixed = StaleObservation {
        fixed: true,
        start_observed: false,
    };
    explore(&fixed, Bound::depth(6)).expect("the fixed waiter");
    // And its rerun branch runs: Observe, Bump (epoch 1, slot empty),
    // Settle reruns on its observation of epoch 0.
    let trace = replay(&fixed, &[0, 2, 0], Bound::depth(6)).expect("a legal path");
    assert_eq!(trace[2].class, Class::Rerun(W1.at(0)));
}

/// I4's payment, from the inside: a continuation enters the model holding
/// an observation, a peer publishes before its first modelled step, and its
/// rerun is paid. `eb4cacbdf` owed payments only to actors that had already
/// stepped, and refused this correct rerun.
#[test]
fn a_continuations_rerun_on_a_moved_observation_is_paid() {
    let continuation = StaleObservation {
        fixed: true,
        start_observed: true,
    };
    explore(&continuation, Bound::depth(6)).expect("the continuation is correct");
    // Bump (index 2: epoch 1), then Settle reruns on its starting
    // observation.
    let trace = replay(&continuation, &[2, 0], Bound::depth(6)).expect("a legal path");
    assert_eq!(trace[1].class, Class::Rerun(W1.at(0)));
}

/// I2: two peer finishes are in flight. A release, and a divert that
/// claims the next release for its own actor. The take answers "nothing"
/// with both in flight. The first-listed order (divert, then release) never
/// frees anything, in any prefix; only "release first" shows the answer
/// refused contention. The first checker drained in list order and retried
/// once at the end; `eb4cacbdf`'s order witness would also have passed a
/// list-order drain that retried after every prefix. This one wouldn't.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Race {
    free: u8,
    release_in_flight: bool,
    divert_in_flight: bool,
    diverted: bool,
    answered: bool,
    epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum RaceOp {
    Take,
    FinishDivert,
    FinishRelease,
}

struct Race2 {
    /// The take is non-blocking: its answer is Linux's EAGAIN, legal with
    /// a release in flight.
    nonblocking: bool,
}

impl Protocol for Race2 {
    type State = Race;
    type Op = RaceOp;
    type Violation = Never;
    const NAME: &'static str = "kat-drain-order";

    fn init(&self) -> Race {
        Race {
            free: 0,
            release_in_flight: true,
            divert_in_flight: true,
            diverted: false,
            answered: false,
            epoch: 0,
        }
    }
    fn enabled(&self, s: &Race, out: &mut Vec<RaceOp>) {
        if !s.answered {
            out.push(RaceOp::Take);
        }
        if s.divert_in_flight {
            out.push(RaceOp::FinishDivert);
        }
        if s.release_in_flight {
            out.push(RaceOp::FinishRelease);
        }
    }
    fn actor(&self, op: RaceOp) -> usize {
        match op {
            RaceOp::Take => 0,
            RaceOp::FinishRelease => 1,
            RaceOp::FinishDivert => 2,
        }
    }
    fn kind(&self, op: RaceOp) -> OpKind {
        match op {
            RaceOp::Take => OpKind::Begin,
            RaceOp::FinishRelease => OpKind::Finish(Effect::Publish(W1)),
            RaceOp::FinishDivert => OpKind::Finish(Effect::None),
        }
    }
    fn step(&self, s: &mut Race, op: RaceOp, ledger: &mut WaitLedger) -> Result<Class, Never> {
        Ok(match op {
            RaceOp::Take => {
                s.answered = true;
                if s.free > 0 {
                    s.free -= 1;
                    Class::Done
                } else if self.nonblocking {
                    Class::Answer(Answer::Declined)
                } else {
                    Class::Answer(Answer::Settled)
                }
            }
            RaceOp::FinishRelease => {
                s.release_in_flight = false;
                if !s.diverted {
                    s.free += 1;
                }
                s.epoch += 1;
                ledger.notify(W1);
                Class::Done
            }
            RaceOp::FinishDivert => {
                s.divert_in_flight = false;
                s.diverted = true;
                Class::Done
            }
        })
    }
    fn check(&self, _: &Race) -> Result<(), Never> {
        Ok(())
    }
    fn invariant(&self, v: &Never) -> &'static str {
        match *v {}
    }
    fn epoch(&self, s: &Race, _: WaitId) -> u64 {
        s.epoch
    }
    fn publishers(&self, s: &Race, _: WaitId, out: &mut Vec<usize>) {
        if s.release_in_flight {
            out.push(1);
        }
    }
    fn reads(&self, _: &Race, _: RaceOp, _: ObjectId) -> bool {
        false
    }
}

#[test]
fn a_refusal_that_only_a_later_drain_order_exposes_is_found() {
    let depth = killed_by(
        &Race2 { nonblocking: false },
        Bound::depth(1),
        InvariantId::I2,
    );
    assert_eq!(depth, 1);
}

#[test]
fn a_nonblocking_answer_to_contention_is_not_a_false_refusal() {
    let report = explore(&Race2 { nonblocking: true }, Bound::depth(3));
    assert!(
        report.is_ok(),
        "EAGAIN on a non-blocking take is Linux: {report:?}",
        report = report.err()
    );
}

/// I2's drain edges are checked: a peer finish that breaks the protocol's
/// own invariant, met only inside the drain (the outer depth is one), is a
/// counterexample. The first checker ignored a failing peer step, and
/// `eb4cacbdf` had no witness for it.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Edge {
    in_flight: bool,
    broke: bool,
    answered: bool,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum EdgeOp {
    Take,
    Finish,
}

#[derive(Debug)]
struct EdgeBroke;

struct DrainEdge;

impl Protocol for DrainEdge {
    type State = Edge;
    type Op = EdgeOp;
    type Violation = EdgeBroke;
    const NAME: &'static str = "kat-drain-edge";

    fn init(&self) -> Edge {
        Edge {
            in_flight: true,
            broke: false,
            answered: false,
        }
    }
    fn enabled(&self, s: &Edge, out: &mut Vec<EdgeOp>) {
        if !s.answered {
            out.push(EdgeOp::Take);
        }
        if s.in_flight {
            out.push(EdgeOp::Finish);
        }
    }
    fn actor(&self, op: EdgeOp) -> usize {
        usize::from(op == EdgeOp::Finish)
    }
    fn kind(&self, op: EdgeOp) -> OpKind {
        match op {
            EdgeOp::Take => OpKind::Begin,
            EdgeOp::Finish => OpKind::Finish(Effect::None),
        }
    }
    fn step(&self, s: &mut Edge, op: EdgeOp, _: &mut WaitLedger) -> Result<Class, EdgeBroke> {
        Ok(match op {
            EdgeOp::Take => {
                s.answered = true;
                Class::Answer(Answer::Settled)
            }
            EdgeOp::Finish => {
                s.in_flight = false;
                s.broke = true;
                Class::Done
            }
        })
    }
    fn check(&self, s: &Edge) -> Result<(), EdgeBroke> {
        if s.broke { Err(EdgeBroke) } else { Ok(()) }
    }
    fn invariant(&self, _: &EdgeBroke) -> &'static str {
        "edge"
    }
    fn epoch(&self, _: &Edge, _: WaitId) -> u64 {
        0
    }
    fn publishers(&self, _: &Edge, _: WaitId, _: &mut Vec<usize>) {}
    fn reads(&self, _: &Edge, _: EdgeOp, _: ObjectId) -> bool {
        false
    }
}

#[test]
fn a_peer_finish_that_breaks_an_invariant_inside_the_drain_is_found() {
    let counterexample = explore(&DrainEdge, Bound::depth(1)).expect_err("the drain edge breaks");
    assert_eq!(counterexample.invariant, InvariantId::Protocol("edge"));
    assert!(
        counterexample.violation.contains("in the I2 drain"),
        "{counterexample:?}"
    );
    assert_eq!(counterexample.trace.len(), 1);
}

/// I4: a peer commits a publication on an unrelated wait, and the actor
/// reruns as though its own observation had moved. The first checker
/// counted any publication as payment.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Unpaid {
    primed: bool,
    published: bool,
    reran: bool,
    done: bool,
    epoch2: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum UnpaidOp {
    /// The actor's first step, so its rerun is not its first (a checker
    /// that refused every first-step rerun would pass this one).
    Prime,
    PublishOther,
    Try,
}

struct UnpaidRerun;

impl Protocol for UnpaidRerun {
    type State = Unpaid;
    type Op = UnpaidOp;
    type Violation = Never;
    const NAME: &'static str = "kat-unpaid-rerun";

    fn init(&self) -> Unpaid {
        Unpaid {
            primed: false,
            published: false,
            reran: false,
            done: false,
            epoch2: 0,
        }
    }
    fn enabled(&self, s: &Unpaid, out: &mut Vec<UnpaidOp>) {
        if !s.primed {
            out.push(UnpaidOp::Prime);
        }
        if s.primed && !s.published {
            out.push(UnpaidOp::PublishOther);
        }
        if s.published && !s.done {
            out.push(UnpaidOp::Try);
        }
    }
    fn actor(&self, op: UnpaidOp) -> usize {
        usize::from(op != UnpaidOp::PublishOther)
    }
    fn kind(&self, op: UnpaidOp) -> OpKind {
        match op {
            UnpaidOp::PublishOther => OpKind::Commit(Effect::Publish(W2)),
            UnpaidOp::Prime | UnpaidOp::Try => OpKind::Begin,
        }
    }
    fn step(&self, s: &mut Unpaid, op: UnpaidOp, ledger: &mut WaitLedger) -> Result<Class, Never> {
        Ok(match op {
            UnpaidOp::Prime => {
                s.primed = true;
                Class::Done
            }
            UnpaidOp::PublishOther => {
                s.published = true;
                s.epoch2 += 1;
                ledger.notify(W2);
                Class::Done
            }
            // The bug: it claims its observation of W1 moved; nothing did.
            UnpaidOp::Try if !s.reran => {
                s.reran = true;
                Class::Rerun(W1.at(0))
            }
            UnpaidOp::Try => {
                s.done = true;
                Class::Done
            }
        })
    }
    fn check(&self, _: &Unpaid) -> Result<(), Never> {
        Ok(())
    }
    fn invariant(&self, v: &Never) -> &'static str {
        match *v {}
    }
    fn epoch(&self, s: &Unpaid, wait: WaitId) -> u64 {
        if wait == W2 { s.epoch2 } else { 0 }
    }
    fn publishers(&self, _: &Unpaid, _: WaitId, out: &mut Vec<usize>) {
        out.push(0);
    }
    fn reads(&self, _: &Unpaid, _: UnpaidOp, _: ObjectId) -> bool {
        false
    }
}

#[test]
fn a_rerun_paid_by_an_unrelated_publication_is_unpaid() {
    let depth = killed_by(&UnpaidRerun, Bound::depth(4), InvariantId::I4);
    assert_eq!(depth, 3);
}

/// I4: two actors each park on a wait only the other publishes. The first
/// checker asked only whether a publisher existed, not whether it could
/// run, so the deadlock passed.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
struct Pair;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum PairOp {
    WaitForOne,
    WaitForZero,
}

struct Deadlock;

impl Protocol for Deadlock {
    type State = Pair;
    type Op = PairOp;
    type Violation = Never;
    const NAME: &'static str = "kat-stranded-publisher";

    fn init(&self) -> Pair {
        Pair
    }
    fn enabled(&self, _: &Pair, out: &mut Vec<PairOp>) {
        out.push(PairOp::WaitForOne);
        out.push(PairOp::WaitForZero);
    }
    fn actor(&self, op: PairOp) -> usize {
        usize::from(op == PairOp::WaitForZero)
    }
    fn kind(&self, _: PairOp) -> OpKind {
        OpKind::Begin
    }
    fn step(&self, _: &mut Pair, op: PairOp, _: &mut WaitLedger) -> Result<Class, Never> {
        Ok(match op {
            // Actor 0 waits on W1, which actor 1 publishes; actor 1 waits on
            // W2, which actor 0 publishes.
            PairOp::WaitForOne => Class::NotNow(W1.at(0)),
            PairOp::WaitForZero => Class::NotNow(W2.at(0)),
        })
    }
    fn check(&self, _: &Pair) -> Result<(), Never> {
        Ok(())
    }
    fn invariant(&self, v: &Never) -> &'static str {
        match *v {}
    }
    fn epoch(&self, _: &Pair, _: WaitId) -> u64 {
        0
    }
    fn publishers(&self, _: &Pair, wait: WaitId, out: &mut Vec<usize>) {
        out.push(if wait == W1 { 1 } else { 0 });
    }
    fn reads(&self, _: &Pair, _: PairOp, _: ObjectId) -> bool {
        false
    }
}

#[test]
fn a_wait_whose_only_publisher_is_parked_is_stranded() {
    let depth = killed_by(&Deadlock, Bound::depth(3), InvariantId::I4);
    assert_eq!(depth, 2);
}

/// I4: a waiter's only publisher leaves without publishing. The waiter
/// parked while the publisher could run, so `eb4cacbdf`, which checked
/// liveness only at the park, passed it.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Leaving {
    gone: bool,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum LeavingOp {
    Wait,
    Leave,
}

struct VanishedPublisher;

impl Protocol for VanishedPublisher {
    type State = Leaving;
    type Op = LeavingOp;
    type Violation = Never;
    const NAME: &'static str = "kat-vanished-publisher";

    fn init(&self) -> Leaving {
        Leaving { gone: false }
    }
    fn enabled(&self, s: &Leaving, out: &mut Vec<LeavingOp>) {
        if !s.gone {
            out.push(LeavingOp::Wait);
            out.push(LeavingOp::Leave);
        }
    }
    fn actor(&self, op: LeavingOp) -> usize {
        usize::from(op == LeavingOp::Leave)
    }
    fn kind(&self, _: LeavingOp) -> OpKind {
        OpKind::Begin
    }
    fn step(&self, s: &mut Leaving, op: LeavingOp, _: &mut WaitLedger) -> Result<Class, Never> {
        Ok(match op {
            LeavingOp::Wait => Class::NotNow(W1.at(0)),
            // The bug: it leaves with a waiter enrolled, and never publishes.
            LeavingOp::Leave => {
                s.gone = true;
                Class::Done
            }
        })
    }
    fn check(&self, _: &Leaving) -> Result<(), Never> {
        Ok(())
    }
    fn invariant(&self, v: &Never) -> &'static str {
        match *v {}
    }
    fn epoch(&self, _: &Leaving, _: WaitId) -> u64 {
        0
    }
    fn publishers(&self, s: &Leaving, _: WaitId, out: &mut Vec<usize>) {
        if !s.gone {
            out.push(1);
        }
    }
    fn reads(&self, _: &Leaving, _: LeavingOp, _: ObjectId) -> bool {
        false
    }
}

#[test]
fn a_waiter_whose_publisher_leaves_is_stranded() {
    let depth = killed_by(&VanishedPublisher, Bound::depth(3), InvariantId::I4);
    assert_eq!(depth, 2);
}

/// I4: a spurious wake. A nudger wakes the parked waiter without
/// publishing its wait (or, in the second form, from inside its own "not
/// now"), so the waiter re-probes an unmoved epoch: polling. The first
/// checker caught only a re-probe of the same `(wait, epoch)` twice in a
/// row, and `eb4cacbdf` only a "not now" that woke someone.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Nudged {
    nudges: u8,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum NudgeOp {
    Wait,
    Nudge,
}

struct SpuriousWake {
    /// The nudge is itself a "not now" (on W2, which actor 2 publishes).
    from_not_now: bool,
}

impl Protocol for SpuriousWake {
    type State = Nudged;
    type Op = NudgeOp;
    type Violation = Never;
    const NAME: &'static str = "kat-spurious-wake";

    fn init(&self) -> Nudged {
        Nudged { nudges: 0 }
    }
    fn enabled(&self, s: &Nudged, out: &mut Vec<NudgeOp>) {
        out.push(NudgeOp::Wait);
        if s.nudges < 2 {
            out.push(NudgeOp::Nudge);
        }
    }
    fn actor(&self, op: NudgeOp) -> usize {
        usize::from(op == NudgeOp::Nudge)
    }
    fn kind(&self, _: NudgeOp) -> OpKind {
        OpKind::Begin
    }
    fn step(&self, s: &mut Nudged, op: NudgeOp, ledger: &mut WaitLedger) -> Result<Class, Never> {
        Ok(match op {
            NudgeOp::Wait => Class::NotNow(W1.at(0)),
            NudgeOp::Nudge => {
                ledger.notify(W1);
                if self.from_not_now {
                    Class::NotNow(W2.at(0))
                } else {
                    s.nudges += 1;
                    Class::Done
                }
            }
        })
    }
    fn check(&self, _: &Nudged) -> Result<(), Never> {
        Ok(())
    }
    fn invariant(&self, v: &Never) -> &'static str {
        match *v {}
    }
    fn epoch(&self, _: &Nudged, _: WaitId) -> u64 {
        0
    }
    fn publishers(&self, _: &Nudged, wait: WaitId, out: &mut Vec<usize>) {
        out.push(if wait == W1 { 1 } else { 2 });
    }
    fn reads(&self, _: &Nudged, _: NudgeOp, _: ObjectId) -> bool {
        false
    }
}

#[test]
fn a_wake_without_a_publication_is_polling() {
    for from_not_now in [false, true] {
        let protocol = SpuriousWake { from_not_now };
        let depth = killed_by(&protocol, Bound::depth(5), InvariantId::I4);
        // Wait parks, Nudge wakes it.
        assert_eq!(depth, 2, "from_not_now {from_not_now}");
    }
}

/// I5: the shell corrupts object A; a step that reads only object B
/// answers Broken. The first checker allowed Broken anywhere once anything
/// was corrupted.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Objects {
    a_corrupt: bool,
    b_reads: u8,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ObjectsOp {
    CorruptA,
    ReadB,
    Panic,
}

const A: ObjectId = ObjectId(1);
const B: ObjectId = ObjectId(2);

struct WrongObject {
    panics: bool,
}

impl Protocol for WrongObject {
    type State = Objects;
    type Op = ObjectsOp;
    type Violation = Never;
    const NAME: &'static str = "kat-wrong-object";

    fn init(&self) -> Objects {
        Objects {
            a_corrupt: false,
            b_reads: 0,
        }
    }
    fn enabled(&self, s: &Objects, out: &mut Vec<ObjectsOp>) {
        if !s.a_corrupt {
            out.push(ObjectsOp::CorruptA);
        }
        if s.a_corrupt && s.b_reads == 0 {
            out.push(ObjectsOp::ReadB);
        }
        if self.panics && s.b_reads == 0 {
            out.push(ObjectsOp::Panic);
        }
    }
    fn actor(&self, op: ObjectsOp) -> usize {
        usize::from(op != ObjectsOp::CorruptA)
    }
    fn kind(&self, op: ObjectsOp) -> OpKind {
        match op {
            ObjectsOp::CorruptA => OpKind::Corrupt(A),
            ObjectsOp::ReadB | ObjectsOp::Panic => OpKind::Begin,
        }
    }
    fn step(&self, s: &mut Objects, op: ObjectsOp, _: &mut WaitLedger) -> Result<Class, Never> {
        Ok(match op {
            ObjectsOp::CorruptA => {
                s.a_corrupt = true;
                Class::Done
            }
            // The bug: B is fine, but the step reports A's corruption.
            ObjectsOp::ReadB => {
                s.b_reads += 1;
                Class::Broken
            }
            ObjectsOp::Panic => panic!("a legal step panicked"),
        })
    }
    fn check(&self, _: &Objects) -> Result<(), Never> {
        Ok(())
    }
    fn invariant(&self, v: &Never) -> &'static str {
        match *v {}
    }
    fn epoch(&self, _: &Objects, _: WaitId) -> u64 {
        0
    }
    fn publishers(&self, _: &Objects, _: WaitId, _: &mut Vec<usize>) {}
    fn reads(&self, _: &Objects, op: ObjectsOp, object: ObjectId) -> bool {
        // ReadB reads only B; nothing reads A.
        op == ObjectsOp::ReadB && object == B
    }
}

#[test]
fn broken_on_an_object_the_step_never_read_is_fatal_contention() {
    let depth = killed_by(
        &WrongObject { panics: false },
        Bound::depth(3),
        InvariantId::I5,
    );
    assert_eq!(depth, 2);
}

#[test]
fn a_panicking_step_is_a_named_counterexample() {
    let explored = std::panic::catch_unwind(|| {
        explore(&WrongObject { panics: true }, Bound::depth(3)).map(|report| report.states)
    });
    let Ok(Err(counterexample)) = explored else {
        panic!("a panic must come back as a counterexample, not escape or pass");
    };
    assert_eq!(counterexample.invariant, InvariantId::I5);
    assert_eq!(counterexample.trace.len(), 1);
}

/// The initial state is checked: a protocol that starts broken fails at
/// depth zero.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
struct Born;

#[derive(Debug)]
struct BornBroken;

struct StartsBroken;

impl Protocol for StartsBroken {
    type State = Born;
    type Op = SlotOp;
    type Violation = BornBroken;
    const NAME: &'static str = "kat-starts-broken";

    fn init(&self) -> Born {
        Born
    }
    fn enabled(&self, _: &Born, _: &mut Vec<SlotOp>) {}
    fn actor(&self, _: SlotOp) -> usize {
        0
    }
    fn kind(&self, _: SlotOp) -> OpKind {
        OpKind::Begin
    }
    fn step(&self, _: &mut Born, _: SlotOp, _: &mut WaitLedger) -> Result<Class, BornBroken> {
        Ok(Class::Done)
    }
    fn check(&self, _: &Born) -> Result<(), BornBroken> {
        Err(BornBroken)
    }
    fn invariant(&self, _: &BornBroken) -> &'static str {
        "born"
    }
    fn epoch(&self, _: &Born, _: WaitId) -> u64 {
        0
    }
    fn publishers(&self, _: &Born, _: WaitId, _: &mut Vec<usize>) {}
    fn reads(&self, _: &Born, _: SlotOp, _: ObjectId) -> bool {
        false
    }
}

#[test]
fn a_protocol_that_starts_broken_fails_at_depth_zero() {
    let depth = killed_by(
        &StartsBroken,
        Bound::depth(3),
        InvariantId::Protocol("born"),
    );
    assert_eq!(depth, 0);
}

/// The P1 half: a close that is itself "not now" (its lock is held)
/// closes nothing, so the consumer parked before it is still legally
/// parked. The first ledger marked the wait closed on any close attempt
/// and failed this correct protocol on I3.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Gate {
    locked: bool,
    lock_epoch: u64,
    closed: bool,
    item_epoch: u64,
    answered: bool,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum GateOp {
    Take,
    Close,
    Unlock,
}

struct BusyClose;

impl Protocol for BusyClose {
    type State = Gate;
    type Op = GateOp;
    type Violation = Never;
    const NAME: &'static str = "kat-busy-close";

    fn init(&self) -> Gate {
        Gate {
            locked: true,
            lock_epoch: 0,
            closed: false,
            item_epoch: 0,
            answered: false,
        }
    }
    fn enabled(&self, s: &Gate, out: &mut Vec<GateOp>) {
        if !s.answered {
            out.push(GateOp::Take);
        }
        if !s.closed {
            out.push(GateOp::Close);
        }
        if s.locked {
            out.push(GateOp::Unlock);
        }
    }
    fn actor(&self, op: GateOp) -> usize {
        match op {
            GateOp::Take => 0,
            GateOp::Close => 1,
            GateOp::Unlock => 2,
        }
    }
    fn kind(&self, op: GateOp) -> OpKind {
        match op {
            GateOp::Take => OpKind::Begin,
            GateOp::Close => OpKind::Commit(Effect::Close(W1)),
            GateOp::Unlock => OpKind::Finish(Effect::Publish(W2)),
        }
    }
    fn step(&self, s: &mut Gate, op: GateOp, ledger: &mut WaitLedger) -> Result<Class, Never> {
        Ok(match op {
            GateOp::Take if s.closed => {
                s.answered = true;
                Class::Answer(Answer::Settled)
            }
            GateOp::Take => Class::NotNow(W1.at(s.item_epoch)),
            GateOp::Close if s.locked => Class::NotNow(W2.at(s.lock_epoch)),
            GateOp::Close => {
                s.closed = true;
                s.item_epoch += 1;
                ledger.notify(W1);
                Class::Done
            }
            GateOp::Unlock => {
                s.locked = false;
                s.lock_epoch += 1;
                ledger.notify(W2);
                Class::Done
            }
        })
    }
    fn check(&self, _: &Gate) -> Result<(), Never> {
        Ok(())
    }
    fn invariant(&self, v: &Never) -> &'static str {
        match *v {}
    }
    fn epoch(&self, s: &Gate, wait: WaitId) -> u64 {
        if wait == W1 {
            s.item_epoch
        } else {
            s.lock_epoch
        }
    }
    fn publishers(&self, s: &Gate, wait: WaitId, out: &mut Vec<usize>) {
        if wait == W1 && !s.closed {
            out.push(1);
        }
        if wait == W2 && s.locked {
            out.push(2);
        }
    }
    fn reads(&self, _: &Gate, _: GateOp, _: ObjectId) -> bool {
        false
    }
}

#[test]
fn a_close_that_is_not_now_closes_nothing() {
    let report = explore(&BusyClose, Bound::depth(6)).expect("a busy close is legal");
    assert!(report.states > 1);
}
