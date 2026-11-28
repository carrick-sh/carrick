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
                    s.observed = Some(ledger.epoch(W1));
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
            SlotOp::Settle if self.fixed && s.observed != Some(ledger.epoch(W1)) => {
                let observed = s.observed.take().unwrap_or(0);
                Class::Rerun(W1.at(observed))
            }
            SlotOp::Settle => Class::NotNow(W1.at(s.observed.unwrap_or(0))),
            SlotOp::Put => {
                s.put = true;
                s.full = true;
                ledger.publish(W1);
                Class::Done
            }
            SlotOp::Bump => {
                s.bumped = true;
                ledger.publish(W1);
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
                ledger.publish(W1);
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
    closed: bool,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum EdgeOp {
    Take,
    Finish,
    /// Actor 2 parks on W1 (the `Close` form only).
    Wait,
}

#[derive(Debug)]
struct EdgeBroke;

/// What goes wrong inside the drain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EdgeMode {
    /// The peer finish breaks the protocol's own invariant.
    Check,
    /// The retry answers Broken on a legal state (I5): `eb4cacbdf`'s retry
    /// bypassed every check and would have passed it.
    Retry,
    /// The peer finish is a two-phase close that forgets its wake (I3),
    /// met as a drain edge.
    Close,
}

struct DrainEdge {
    mode: EdgeMode,
}

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
            closed: false,
        }
    }
    fn enabled(&self, s: &Edge, out: &mut Vec<EdgeOp>) {
        if !s.answered {
            out.push(EdgeOp::Take);
        }
        if s.in_flight {
            out.push(EdgeOp::Finish);
        }
        if self.mode == EdgeMode::Close && !s.closed {
            out.push(EdgeOp::Wait);
        }
    }
    fn actor(&self, op: EdgeOp) -> usize {
        match op {
            EdgeOp::Take => 0,
            EdgeOp::Finish => 1,
            EdgeOp::Wait => 2,
        }
    }
    fn kind(&self, op: EdgeOp) -> OpKind {
        match (op, self.mode) {
            (EdgeOp::Finish, EdgeMode::Close) => OpKind::Finish(Effect::Close(W1)),
            (EdgeOp::Finish, _) => OpKind::Finish(Effect::None),
            (EdgeOp::Take | EdgeOp::Wait, _) => OpKind::Begin,
        }
    }
    fn step(&self, s: &mut Edge, op: EdgeOp, ledger: &mut WaitLedger) -> Result<Class, EdgeBroke> {
        Ok(match op {
            EdgeOp::Take if self.mode == EdgeMode::Retry && !s.in_flight => Class::Broken,
            EdgeOp::Take => {
                s.answered = true;
                Class::Answer(Answer::Settled)
            }
            EdgeOp::Finish => {
                s.in_flight = false;
                match self.mode {
                    EdgeMode::Check => s.broke = true,
                    // The bug: the close forgets `ledger.wake(W1)`.
                    EdgeMode::Close => s.closed = true,
                    EdgeMode::Retry => {}
                }
                Class::Done
            }
            EdgeOp::Wait => Class::NotNow(W1.at(ledger.epoch(W1))),
        })
    }
    fn check(&self, s: &Edge) -> Result<(), EdgeBroke> {
        if s.broke { Err(EdgeBroke) } else { Ok(()) }
    }
    fn invariant(&self, _: &EdgeBroke) -> &'static str {
        "edge"
    }
    fn publishers(&self, s: &Edge, _: WaitId, out: &mut Vec<usize>) {
        if s.in_flight {
            out.push(1);
        }
    }
    fn reads(&self, _: &Edge, _: EdgeOp, _: ObjectId) -> bool {
        false
    }
}

#[test]
fn a_failure_inside_the_drain_is_found_through_the_drain() {
    // Each is reported through the drain first: the outer exploration
    // meets the same failure no earlier.
    for (mode, depth, expected) in [
        (EdgeMode::Check, 1, InvariantId::Protocol("edge")),
        (EdgeMode::Retry, 1, InvariantId::I5),
        (EdgeMode::Close, 2, InvariantId::I3),
    ] {
        let counterexample =
            explore(&DrainEdge { mode }, Bound::depth(depth)).expect_err("the drain fails");
        assert_eq!(
            counterexample.invariant, expected,
            "{mode:?}: {counterexample:?}"
        );
        assert!(
            counterexample.violation.contains("in the I2 drain"),
            "{mode:?}: {counterexample:?}"
        );
        assert_eq!(counterexample.trace.len(), depth, "{mode:?}");
    }
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
                ledger.publish(W2);
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
                ledger.wake(W1);
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
    fn publishers(&self, _: &Nudged, wait: WaitId, out: &mut Vec<usize>) {
        out.push(if wait == W1 { 1 } else { 0 });
    }
    fn reads(&self, _: &Nudged, _: NudgeOp, _: ObjectId) -> bool {
        false
    }
}

#[test]
fn a_wake_without_a_publication_is_polling() {
    for from_not_now in [false, true] {
        let protocol = SpuriousWake { from_not_now };
        let counterexample = explore(&protocol, Bound::depth(5)).expect_err("a spurious wake");
        assert_eq!(counterexample.invariant, InvariantId::I4);
        assert!(
            counterexample.violation.contains("spurious"),
            "{counterexample:?}"
        );
        // Wait parks, Nudge wakes it.
        assert_eq!(counterexample.trace.len(), 2, "from_not_now {from_not_now}");
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
    closed: bool,
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
            closed: false,
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
            GateOp::Take => Class::NotNow(W1.at(ledger.epoch(W1))),
            GateOp::Close if s.locked => Class::NotNow(W2.at(ledger.epoch(W2))),
            GateOp::Close => {
                s.closed = true;
                ledger.publish(W1);
                Class::Done
            }
            GateOp::Unlock => {
                s.locked = false;
                ledger.publish(W2);
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

/// I4: one stale observation pays one rerun. The broken retry never
/// refreshes its observation, so it reruns forever on the same one;
/// `7c4387f47` accepted every such rerun.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Retrying {
    observed: Option<u64>,
    published: bool,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum RetryOp {
    Observe,
    Publish,
    Retry,
}

struct RerunLoop;

impl Protocol for RerunLoop {
    type State = Retrying;
    type Op = RetryOp;
    type Violation = Never;
    const NAME: &'static str = "kat-rerun-loop";

    fn init(&self) -> Retrying {
        Retrying {
            observed: None,
            published: false,
        }
    }
    fn enabled(&self, s: &Retrying, out: &mut Vec<RetryOp>) {
        if s.observed.is_none() {
            out.push(RetryOp::Observe);
        } else {
            out.push(RetryOp::Retry);
        }
        if !s.published {
            out.push(RetryOp::Publish);
        }
    }
    fn actor(&self, op: RetryOp) -> usize {
        usize::from(op == RetryOp::Publish)
    }
    fn kind(&self, op: RetryOp) -> OpKind {
        match op {
            RetryOp::Publish => OpKind::Commit(Effect::Publish(W1)),
            RetryOp::Observe | RetryOp::Retry => OpKind::Begin,
        }
    }
    fn step(&self, s: &mut Retrying, op: RetryOp, ledger: &mut WaitLedger) -> Result<Class, Never> {
        Ok(match op {
            RetryOp::Observe => {
                s.observed = Some(ledger.epoch(W1));
                Class::Done
            }
            RetryOp::Publish => {
                s.published = true;
                ledger.publish(W1);
                Class::Done
            }
            // The bug: it reruns, keeping the stale observation.
            RetryOp::Retry if s.observed != Some(ledger.epoch(W1)) => {
                Class::Rerun(W1.at(s.observed.unwrap_or(0)))
            }
            RetryOp::Retry => Class::Done,
        })
    }
    fn check(&self, _: &Retrying) -> Result<(), Never> {
        Ok(())
    }
    fn invariant(&self, v: &Never) -> &'static str {
        match *v {}
    }
    fn publishers(&self, _: &Retrying, _: WaitId, out: &mut Vec<usize>) {
        out.push(1);
    }
    fn reads(&self, _: &Retrying, _: RetryOp, _: ObjectId) -> bool {
        false
    }
}

#[test]
fn one_stale_observation_pays_one_rerun() {
    // Observe, Publish, Retry (paid), Retry (the same observation again).
    let depth = killed_by(&RerunLoop, Bound::depth(5), InvariantId::I4);
    assert_eq!(depth, 4);
}

/// The inverse: one atomic step that publishes two waits (a shutdown that
/// wakes two queues) is legal. `7c4387f47` allowed a step to wake only the
/// one wait its kind names.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Shutdown {
    shut: bool,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ShutdownOp {
    WaitOne,
    WaitTwo,
    Shut,
}

struct MultiQueue;

impl Protocol for MultiQueue {
    type State = Shutdown;
    type Op = ShutdownOp;
    type Violation = Never;
    const NAME: &'static str = "kat-multi-queue";

    fn init(&self) -> Shutdown {
        Shutdown { shut: false }
    }
    fn enabled(&self, s: &Shutdown, out: &mut Vec<ShutdownOp>) {
        out.push(ShutdownOp::WaitOne);
        out.push(ShutdownOp::WaitTwo);
        if !s.shut {
            out.push(ShutdownOp::Shut);
        }
    }
    fn actor(&self, op: ShutdownOp) -> usize {
        match op {
            ShutdownOp::WaitOne => 0,
            ShutdownOp::Shut => 1,
            ShutdownOp::WaitTwo => 2,
        }
    }
    fn kind(&self, op: ShutdownOp) -> OpKind {
        match op {
            ShutdownOp::Shut => OpKind::Commit(Effect::Publish(W1)),
            ShutdownOp::WaitOne | ShutdownOp::WaitTwo => OpKind::Begin,
        }
    }
    fn step(
        &self,
        s: &mut Shutdown,
        op: ShutdownOp,
        ledger: &mut WaitLedger,
    ) -> Result<Class, Never> {
        Ok(match op {
            ShutdownOp::WaitOne | ShutdownOp::WaitTwo if s.shut => Class::Done,
            ShutdownOp::WaitOne => Class::NotNow(W1.at(ledger.epoch(W1))),
            ShutdownOp::WaitTwo => Class::NotNow(W2.at(ledger.epoch(W2))),
            ShutdownOp::Shut => {
                s.shut = true;
                ledger.publish(W1);
                ledger.publish(W2);
                Class::Done
            }
        })
    }
    fn check(&self, _: &Shutdown) -> Result<(), Never> {
        Ok(())
    }
    fn invariant(&self, v: &Never) -> &'static str {
        match *v {}
    }
    fn publishers(&self, s: &Shutdown, _: WaitId, out: &mut Vec<usize>) {
        if !s.shut {
            out.push(1);
        }
    }
    fn reads(&self, _: &Shutdown, _: ShutdownOp, _: ObjectId) -> bool {
        false
    }
}

#[test]
fn one_step_may_publish_two_waits() {
    explore(&MultiQueue, Bound::depth(6)).expect("an atomic two-queue publication is legal");
    // Both wait, then the shutdown wakes both.
    let (_, _, ledger) =
        crate::explore::replay_to(&MultiQueue, &[0, 0, 0], Bound::depth(6)).expect("a legal path");
    assert!(ledger.parked(0).is_some_and(|park| park.woken.is_some()));
    assert!(ledger.parked(2).is_some_and(|park| park.woken.is_some()));
}

/// I4: the waiter's publisher is not parked, but it has nothing it can
/// run: its release is enabled only after the waiter arms it, and the
/// waiter parked first. `7c4387f47` counted any unparked publisher as live.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Arming {
    armed: bool,
    released: bool,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ArmingOp {
    Wait,
    Arm,
    Release,
}

struct DisabledPublisher;

impl Protocol for DisabledPublisher {
    type State = Arming;
    type Op = ArmingOp;
    type Violation = Never;
    const NAME: &'static str = "kat-disabled-publisher";

    fn init(&self) -> Arming {
        Arming {
            armed: false,
            released: false,
        }
    }
    fn enabled(&self, s: &Arming, out: &mut Vec<ArmingOp>) {
        if !s.released {
            out.push(ArmingOp::Wait);
        }
        if !s.armed {
            out.push(ArmingOp::Arm);
        }
        if s.armed && !s.released {
            out.push(ArmingOp::Release);
        }
    }
    fn actor(&self, op: ArmingOp) -> usize {
        usize::from(op == ArmingOp::Release)
    }
    fn kind(&self, op: ArmingOp) -> OpKind {
        match op {
            ArmingOp::Release => OpKind::Commit(Effect::Publish(W1)),
            ArmingOp::Wait | ArmingOp::Arm => OpKind::Begin,
        }
    }
    fn step(&self, s: &mut Arming, op: ArmingOp, ledger: &mut WaitLedger) -> Result<Class, Never> {
        Ok(match op {
            // The bug: it waits before it arms its own release.
            ArmingOp::Wait => Class::NotNow(W1.at(ledger.epoch(W1))),
            ArmingOp::Arm => {
                s.armed = true;
                Class::Done
            }
            ArmingOp::Release => {
                s.released = true;
                ledger.publish(W1);
                Class::Done
            }
        })
    }
    fn check(&self, _: &Arming) -> Result<(), Never> {
        Ok(())
    }
    fn invariant(&self, v: &Never) -> &'static str {
        match *v {}
    }
    fn publishers(&self, s: &Arming, _: WaitId, out: &mut Vec<usize>) {
        if !s.released {
            out.push(1);
        }
    }
    fn reads(&self, _: &Arming, _: ArmingOp, _: ObjectId) -> bool {
        false
    }
}

#[test]
fn a_publisher_with_nothing_enabled_is_not_live() {
    let depth = killed_by(&DisabledPublisher, Bound::depth(4), InvariantId::I4);
    assert_eq!(depth, 1);
}
