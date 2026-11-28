//! The harness's known answer: a one-slot mailbox with a "not now" wait.
//!
//! A producer puts items in two phases (begin, then a finish that publishes
//! the item wait) and may close the mailbox; two consumers take. A take of
//! an empty, open mailbox is "not now" on the item wait; a take of a closed,
//! empty one answers (end of file). An adversarial shell may corrupt the
//! slot once, and the next take must be `Broken`.
//!
//! Six seeded mutants each restore one classic bug, and each must be
//! killed by its own invariant, I1 to I5, at a known shortest depth. The
//! correct protocol's state count is asserted, so a change to the explorer
//! or the ledger that explores less (or more) shows.

use std::vec::Vec;

use crate::explore::{
    Bound, Coverage, Protocol, explore, mutants_killed, replay, replay_line, replay_to,
};
use crate::ledger::WaitLedger;
use crate::{Answer, Class, Effect, InvariantId, ObjectId, OpKind, WaitId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mutant {
    NoWakeOnPut,
    FalseEmpty,
    CloseNoWake,
    NotNowCounts,
    BusyIsBroken,
    SilentPut,
}
crate::mutants!(Mutant {
    NoWakeOnPut,
    FalseEmpty,
    CloseNoWake,
    NotNowCounts,
    BusyIsBroken,
    SilentPut
});
use crate::Mutant as _;
use crate::mutant;

const ITEM: WaitId = WaitId::software(1);
const SLOT: ObjectId = ObjectId(0);
const PRODUCER: usize = 0;
const SHELL: usize = 3;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Mailbox {
    slot: Option<u8>,
    put_in_flight: bool,
    puts_left: u8,
    closed: bool,
    corrupt: bool,
    /// The item wait's revision: every publication and the close advance it.
    item_epoch: u64,
    taken: [u8; 2],
    /// Only the `NotNowCounts` mutant writes it.
    misses: u8,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Op {
    BeginPut,
    FinishPut,
    Close,
    Take(usize),
    Corrupt,
}

#[derive(Debug)]
enum Violation {
    /// An item was taken twice or lost.
    Conservation,
}

struct Toy;

impl Protocol for Toy {
    type State = Mailbox;
    type Op = Op;
    type Violation = Violation;
    const NAME: &'static str = "toy-mailbox";

    fn init(&self) -> Mailbox {
        Mailbox {
            slot: None,
            put_in_flight: false,
            puts_left: 2,
            closed: false,
            corrupt: false,
            item_epoch: 0,
            taken: [0; 2],
            misses: 0,
        }
    }

    fn enabled(&self, s: &Mailbox, out: &mut Vec<Op>) {
        if !s.closed && !s.put_in_flight && s.slot.is_none() && s.puts_left > 0 {
            out.push(Op::BeginPut);
        }
        if s.put_in_flight {
            out.push(Op::FinishPut);
        }
        if !s.closed && !s.put_in_flight {
            out.push(Op::Close);
        }
        out.push(Op::Take(1));
        out.push(Op::Take(2));
        if !s.corrupt {
            out.push(Op::Corrupt);
        }
    }

    fn actor(&self, op: Op) -> usize {
        match op {
            Op::BeginPut | Op::FinishPut | Op::Close => PRODUCER,
            Op::Take(consumer) => consumer,
            Op::Corrupt => SHELL,
        }
    }

    fn kind(&self, op: Op) -> OpKind {
        match op {
            Op::BeginPut | Op::Take(_) => OpKind::Begin,
            Op::FinishPut => OpKind::Finish(Effect::Publish(ITEM)),
            Op::Close => OpKind::Commit(Effect::Close(ITEM)),
            Op::Corrupt => OpKind::Corrupt(SLOT),
        }
    }

    fn step(&self, s: &mut Mailbox, op: Op, ledger: &mut WaitLedger) -> Result<Class, Violation> {
        Ok(match op {
            Op::BeginPut => {
                s.put_in_flight = true;
                s.puts_left -= 1;
                Class::Done
            }
            Op::FinishPut => {
                s.put_in_flight = false;
                s.slot = Some(2 - s.puts_left);
                if !mutant::is(Mutant::SilentPut) {
                    s.item_epoch += 1;
                    if !mutant::is(Mutant::NoWakeOnPut) {
                        ledger.notify(ITEM);
                    }
                }
                Class::Done
            }
            Op::Close => {
                s.closed = true;
                if !mutant::is(Mutant::CloseNoWake) {
                    s.item_epoch += 1;
                    ledger.notify(ITEM);
                }
                Class::Done
            }
            Op::Take(consumer) => {
                if s.corrupt {
                    Class::Broken
                } else if let Some(_item) = s.slot.take() {
                    s.taken[consumer - 1] += 1;
                    Class::Done
                } else if s.closed || (s.put_in_flight && mutant::is(Mutant::FalseEmpty)) {
                    Class::Answer(Answer::Settled)
                } else if s.put_in_flight && mutant::is(Mutant::BusyIsBroken) {
                    Class::Broken
                } else {
                    if mutant::is(Mutant::NotNowCounts) {
                        s.misses += 1;
                    }
                    Class::NotNow(ITEM.at(s.item_epoch))
                }
            }
            Op::Corrupt => {
                s.corrupt = true;
                Class::Done
            }
        })
    }

    fn check(&self, s: &Mailbox) -> Result<(), Violation> {
        let made = 2 - s.puts_left - u8::from(s.put_in_flight);
        let held = u8::from(s.slot.is_some());
        if s.taken[0] + s.taken[1] + held != made {
            return Err(Violation::Conservation);
        }
        Ok(())
    }

    fn invariant(&self, violation: &Violation) -> &'static str {
        match violation {
            Violation::Conservation => "conservation",
        }
    }

    fn epoch(&self, s: &Mailbox, wait: WaitId) -> u64 {
        if wait == ITEM { s.item_epoch } else { 0 }
    }

    fn publishers(&self, s: &Mailbox, wait: WaitId, out: &mut Vec<usize>) {
        // The producer can still put or close.
        if wait == ITEM && !s.closed {
            out.push(PRODUCER);
        }
    }

    fn reads(&self, _: &Mailbox, op: Op, object: ObjectId) -> bool {
        object == SLOT && matches!(op, Op::Take(_))
    }

    fn reached(&self, s: &Mailbox, ledger: &WaitLedger, coverage: &mut Coverage) {
        if s.taken.iter().all(|&taken| taken > 0) {
            coverage.note("both consumers took an item");
        }
        let woken = ledger.parked(1).and_then(|park| park.woken);
        if woken.is_some() {
            coverage.note("parked, then woken");
        }
        if woken.is_some_and(|waker| waker.kind == OpKind::Commit(Effect::Close(ITEM))) {
            coverage.note("parked, then woken by the close");
        }
        if ledger.ended() {
            coverage.note("corruption read as broken");
        }
    }
}

/// Deep enough for both items to reach both consumers past a park, a close
/// and the corruption.
const DEPTH: usize = 9;

#[test]
fn the_toy_mailbox_has_its_known_state_count_and_coverage() {
    let report = explore(&Toy, Bound::depth(DEPTH)).expect("the correct mailbox keeps I1 to I5");
    std::println!(
        "toy-mailbox: {} states, {} transitions to depth {DEPTH}; coverage {:?}",
        report.states,
        report.transitions,
        report.coverage.shapes().collect::<Vec<_>>()
    );
    for shape in [
        "both consumers took an item",
        "parked, then woken",
        "parked, then woken by the close",
        "corruption read as broken",
    ] {
        assert!(report.coverage.has(shape), "missing coverage: {shape}");
    }
    assert_eq!(report.states, TOY_STATES, "the known answer moved");
}

/// The correct mailbox's distinct states (protocol state and ledger) to
/// [`DEPTH`]. A pin: an explorer or ledger change that moves it must say why.
/// 582 to 320 (#3181 fixes): the ledger now holds who woke each park, and
/// no longer the publication counters or the last "not now" per actor (a
/// rerun carries its observation, and a spurious wake is refused at the
/// waker), so it stops telling apart states that differ only in those.
const TOY_STATES: usize = 320;

#[test]
fn each_toy_mutant_is_killed_by_its_invariant_at_its_shortest_depth() {
    let cases = [
        (
            Mutant::NoWakeOnPut,
            Mutant::NoWakeOnPut.name(),
            InvariantId::I1,
        ),
        (
            Mutant::FalseEmpty,
            Mutant::FalseEmpty.name(),
            InvariantId::I2,
        ),
        (
            Mutant::CloseNoWake,
            Mutant::CloseNoWake.name(),
            InvariantId::I3,
        ),
        (
            Mutant::NotNowCounts,
            Mutant::NotNowCounts.name(),
            InvariantId::I4,
        ),
        (
            Mutant::BusyIsBroken,
            Mutant::BusyIsBroken.name(),
            InvariantId::I5,
        ),
        (Mutant::SilentPut, Mutant::SilentPut.name(), InvariantId::I1),
    ];
    assert_eq!(cases.len(), Mutant::ALL.len());
    let found = mutants_killed(&cases, |which| {
        mutant::with(which, || explore(&Toy, Bound::depth(DEPTH)))
    })
    .unwrap_or_else(|why| panic!("{why}"));
    let lengths: Vec<usize> = found.iter().map(|c| c.trace.len()).collect();
    for counterexample in &found {
        std::println!("{counterexample:?}");
        // The replay line alone reproduces the same kill: no mutant is
        // active here, the line names it.
        let line = counterexample.replay_line();
        let replayed =
            replay_line::<Toy, Mutant>(&Toy, &line).expect_err("the replay reproduces the kill");
        assert_eq!(replayed.invariant, counterexample.invariant);
        assert_eq!(replayed.trace.len(), counterexample.trace.len());
    }
    assert_eq!(lengths, TOY_KILL_LENGTHS, "the shortest kills moved");
}

/// Each mutant's shortest kill, derived by hand before the first run:
/// - NoWakeOnPut: take parks, begin, finish (the epoch moves, no wake): 3;
/// - FalseEmpty: begin, take answers (a drain's finish makes it Done): 2;
/// - CloseNoWake: take parks, close leaves it parked: 2;
/// - NotNowCounts: the first take's "not now" writes the state: 1;
/// - BusyIsBroken: begin, take meets the put in flight as Broken: 2;
/// - SilentPut: begin, finish commits without advancing the epoch: 2.
const TOY_KILL_LENGTHS: [usize; 6] = [3, 2, 2, 1, 2, 2];

#[test]
fn a_correct_path_replays_clean() {
    // Take(1) parks; begin, finish; Take(1) runs and takes.
    let trace = replay(&Toy, &[2, 0, 0, 1], Bound::depth(DEPTH)).expect("a legal path replays");
    let classes: Vec<Class> = trace.iter().map(|step| step.class).collect();
    assert_eq!(
        classes,
        [
            Class::NotNow(ITEM.at(0)),
            Class::Done,
            Class::Done,
            Class::Done
        ]
    );
}

/// A nested `mutant::with` restores the outer scope's mutant when it ends,
/// on unwind too (#3181 pre-review).
#[test]
fn a_nested_mutant_scope_restores_the_outer_mutant() {
    use crate::mutant;
    mutant::with(Mutant::FalseEmpty, || {
        mutant::with(Mutant::CloseNoWake, || {
            assert!(mutant::is(Mutant::CloseNoWake) && !mutant::is(Mutant::FalseEmpty));
        });
        assert!(mutant::is(Mutant::FalseEmpty), "the outer mutant came back");
        let unwound = std::panic::catch_unwind(|| {
            mutant::with(Mutant::NotNowCounts, || panic!("inner scope unwinds"))
        });
        assert!(unwound.is_err());
        assert!(mutant::is(Mutant::FalseEmpty), "and after an unwind");
    });
    assert!(
        !mutant::is(Mutant::FalseEmpty),
        "no mutant outside every scope"
    );
}

/// The replay line alone reproduces a mutant's kill: it names the mutant
/// and the drain bound (#3181 pre-review).
#[test]
fn a_replay_line_names_its_mutant_and_drain() {
    let counterexample = mutant::with(Mutant::FalseEmpty, || explore(&Toy, Bound::depth(DEPTH)))
        .expect_err("FalseEmpty is killed");
    let line = counterexample.replay_line();
    assert!(line.contains("mutant=FalseEmpty"), "no mutant in {line}");
    assert!(line.contains("drain=32"), "no drain bound in {line}");
    // Outside the mutant's scope, the line still replays the kill.
    let replayed = replay_line::<Toy, Mutant>(&Toy, &line).expect_err("the line replays the kill");
    assert_eq!(replayed.invariant, InvariantId::I2);
}

/// With no drain budget, an answer during a put in flight is unproven, not
/// green (#3181 pre-review).
#[test]
fn an_exhausted_drain_budget_is_not_a_pass() {
    let bound = Bound {
        depth: DEPTH,
        drain: 0,
    };
    let explored = mutant::with(Mutant::FalseEmpty, || explore(&Toy, bound));
    let counterexample = explored.expect_err("a partial drain certifies nothing");
    assert_eq!(counterexample.invariant, InvariantId::I2);
    assert!(
        counterexample.violation.contains("unproven"),
        "{counterexample:?}"
    );
    // The correct mailbox's settled answers (closed, nothing in flight)
    // need no drain, so they pass on no budget.
    explore(&Toy, bound).expect("a settled answer with nothing in flight needs no drain");
}

/// "Woken by the close" means the close did the wake: here the put woke the
/// consumer, and then the producer closed.
#[test]
fn a_wake_by_an_earlier_put_is_not_a_wake_by_the_close() {
    // Take(1) parks; begin, finish (the put wakes it); close.
    let (_, state, ledger) =
        replay_to(&Toy, &[2, 0, 0, 0], Bound::depth(DEPTH)).expect("a legal path");
    assert!(ledger.parked(1).is_some_and(|park| park.woken.is_some()));
    let mut coverage = Coverage::default();
    Toy.reached(&state, &ledger, &mut coverage);
    assert!(
        !coverage.has("parked, then woken by the close"),
        "the put woke it: {:?}",
        coverage.shapes().collect::<Vec<_>>()
    );
}

/// The positive half of the close-wake shape: a close that wakes a parked
/// consumer is noted.
#[test]
fn a_wake_by_the_close_is_noted() {
    // Take(1) parks; close.
    let (_, state, ledger) = replay_to(&Toy, &[2, 1], Bound::depth(DEPTH)).expect("a legal path");
    let mut coverage = Coverage::default();
    Toy.reached(&state, &ledger, &mut coverage);
    assert!(coverage.has("parked, then woken by the close"));
}

/// A `mutant=none` line replays clean even inside a mutant's scope, and a
/// line's drain bound is the one the replay runs with (#3181's second
/// pre-review).
#[test]
fn a_replay_line_runs_with_its_own_mutant_and_drain() {
    // Begin, then Take(1) meets the put in flight: clean, it parks; under
    // FalseEmpty, it answers.
    let clean = "CARRICK_MODEL_REPLAY=toy-mailbox:mutant=none:drain=32:0,1";
    let trace = mutant::with(Mutant::FalseEmpty, || {
        replay_line::<Toy, Mutant>(&Toy, clean)
    })
    .expect("a clean line replays clean");
    assert_eq!(trace[1].class, Class::NotNow(ITEM.at(0)));
    let unproven = replay_line::<Toy, Mutant>(
        &Toy,
        "CARRICK_MODEL_REPLAY=toy-mailbox:mutant=FalseEmpty:drain=0:0,1",
    )
    .expect_err("FalseEmpty answers");
    assert!(unproven.violation.contains("unproven"), "{unproven:?}");
    let refused = replay_line::<Toy, Mutant>(
        &Toy,
        "CARRICK_MODEL_REPLAY=toy-mailbox:mutant=FalseEmpty:drain=32:0,1",
    )
    .expect_err("FalseEmpty answers");
    assert!(refused.violation.contains("it is Done"), "{refused:?}");
}
