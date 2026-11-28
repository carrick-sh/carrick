//! Known answers for the checker itself (#3181 pre-review). Each seeded
//! broken protocol here is one the first checker passed: the same tests,
//! written against its API, fail on `df3815c4d` (commit `45e8b4689`).

use std::vec::Vec;

use crate::explore::{Bound, Protocol, explore};
use crate::ledger::WaitLedger;
use crate::{Answer, Class, InvariantId, ObjectId, OpKind, WaitId};

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
    epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum SlotOp {
    Observe,
    Settle,
    Put,
}

struct StaleObservation {
    fixed: bool,
}

impl Protocol for StaleObservation {
    type State = Slot;
    type Op = SlotOp;
    type Violation = Never;
    const NAME: &'static str = "kat-stale-observation";

    fn init(&self) -> Slot {
        Slot {
            observed: None,
            full: false,
            taken: false,
            put: false,
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
    }
    fn actor(&self, op: SlotOp) -> usize {
        usize::from(op == SlotOp::Put)
    }
    fn kind(&self, op: SlotOp) -> OpKind {
        match op {
            SlotOp::Observe | SlotOp::Settle => OpKind::Begin,
            SlotOp::Put => OpKind::Publish(W1),
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
                s.observed = None;
                Class::Rerun(W1)
            }
            SlotOp::Settle => Class::NotNow(W1.at(s.observed.unwrap_or(0))),
            SlotOp::Put => {
                s.put = true;
                s.full = true;
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
    let depth = killed_by(
        &StaleObservation { fixed: false },
        Bound::depth(4),
        InvariantId::I1,
    );
    assert_eq!(depth, 3);
    // The fixed waiter, which reruns on the moved epoch, passes.
    explore(&StaleObservation { fixed: true }, Bound::depth(6)).expect("the fixed waiter");
}

/// I2: two peer finishes are in flight. The first releases the resource;
/// the second takes any release it finds. The take answers "nothing" with
/// both in flight. Only the order "first finish, then retry" shows the
/// answer refused contention; the first checker drained both peers before
/// it retried, so it saw nothing wrong.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Race {
    free: u8,
    release_in_flight: bool,
    grab_in_flight: bool,
    answered: bool,
    epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum RaceOp {
    Take,
    FinishRelease,
    FinishGrab,
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
            grab_in_flight: true,
            answered: false,
            epoch: 0,
        }
    }
    fn enabled(&self, s: &Race, out: &mut Vec<RaceOp>) {
        if !s.answered {
            out.push(RaceOp::Take);
        }
        if s.release_in_flight {
            out.push(RaceOp::FinishRelease);
        }
        if s.grab_in_flight {
            out.push(RaceOp::FinishGrab);
        }
    }
    fn actor(&self, op: RaceOp) -> usize {
        match op {
            RaceOp::Take => 0,
            RaceOp::FinishRelease => 1,
            RaceOp::FinishGrab => 2,
        }
    }
    fn kind(&self, op: RaceOp) -> OpKind {
        match op {
            RaceOp::Take => OpKind::Begin,
            RaceOp::FinishRelease => OpKind::Finish(Some(W1)),
            RaceOp::FinishGrab => OpKind::Finish(None),
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
                s.free += 1;
                s.epoch += 1;
                ledger.notify(W1);
                Class::Done
            }
            RaceOp::FinishGrab => {
                s.grab_in_flight = false;
                s.free = s.free.saturating_sub(1);
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
fn a_refusal_that_one_drain_order_exposes_is_found() {
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

/// I4: a peer commits a publication on an unrelated wait, and the actor
/// reruns as though its own observation had moved. The first checker
/// counted any publication as payment.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Unpaid {
    published: bool,
    reran: bool,
    done: bool,
    epoch2: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum UnpaidOp {
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
            published: false,
            reran: false,
            done: false,
            epoch2: 0,
        }
    }
    fn enabled(&self, s: &Unpaid, out: &mut Vec<UnpaidOp>) {
        if !s.published {
            out.push(UnpaidOp::PublishOther);
        }
        if s.published && !s.done {
            out.push(UnpaidOp::Try);
        }
    }
    fn actor(&self, op: UnpaidOp) -> usize {
        usize::from(op == UnpaidOp::Try)
    }
    fn kind(&self, op: UnpaidOp) -> OpKind {
        match op {
            UnpaidOp::PublishOther => OpKind::Publish(W2),
            UnpaidOp::Try => OpKind::Begin,
        }
    }
    fn step(&self, s: &mut Unpaid, op: UnpaidOp, ledger: &mut WaitLedger) -> Result<Class, Never> {
        Ok(match op {
            UnpaidOp::PublishOther => {
                s.published = true;
                s.epoch2 += 1;
                ledger.notify(W2);
                Class::Done
            }
            // The bug: it claims its observation of W1 moved; nothing did.
            UnpaidOp::Try if !s.reran => {
                s.reran = true;
                Class::Rerun(W1)
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
    let depth = killed_by(&UnpaidRerun, Bound::depth(3), InvariantId::I4);
    assert_eq!(depth, 2);
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

/// I4 at the ledger: an actor alternates its "not now" between two waits,
/// woken each time by a notify that advances neither epoch. The first
/// ledger remembered only the last probe.
#[test]
fn alternating_unchanged_probes_are_polling() {
    use crate::ledger::Facts;
    let mut ledger = WaitLedger::default();
    let probe = |ledger: &mut WaitLedger, wait: WaitId| {
        ledger.account(
            Facts {
                actor: 0,
                kind: OpKind::Begin,
                class: Class::NotNow(wait.at(0)),
                state_unchanged: true,
                notified_nobody: true,
                reads_corruption: false,
                panic: None,
            },
            |_, _| 0,
            |_| std::vec![1],
        )
    };
    probe(&mut ledger, W1).expect("the first probe of W1 parks");
    ledger.notify(W1);
    probe(&mut ledger, W2).expect("the first probe of W2 parks");
    ledger.notify(W2);
    let again = probe(&mut ledger, W1);
    assert!(
        matches!(again, Err((InvariantId::I4, _))),
        "W1 at epoch 0 again, with no progress between: {again:?}"
    );
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
            GateOp::Close => OpKind::Close(W1),
            GateOp::Unlock => OpKind::Finish(Some(W2)),
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
