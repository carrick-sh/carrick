//! The bounded breadth-first explorer, generalised from the memory core's
//! three explorers (`carrick-core` `mm/own`): every sequence of enabled
//! operations up to a depth, states deduplicated by equality (a hash
//! collision never merges two), the protocol's own invariants and the
//! ledger's I1 to I5 checked after every step. Breadth first, so the first
//! counterexample found is a shortest one.
//!
//! A protocol models its production calls: its state holds the production
//! state by value and its steps call the production functions, never a
//! paraphrase of them.

use core::fmt;
use std::boxed::Box;
use std::collections::{BTreeSet, HashSet, VecDeque};
use std::format;
use std::string::String;
use std::vec::Vec;

use crate::ledger::WaitLedger;
use crate::{Class, InvariantId, OpKind, Step, WaitId};

/// A protocol the explorer can run. Generic over its state and operations;
/// nothing is `dyn`.
pub trait Protocol {
    /// The production state, by value.
    type State: Clone + Eq + core::hash::Hash + fmt::Debug;
    /// One production call by one actor.
    type Op: Copy + Eq + core::hash::Hash + fmt::Debug;
    /// A protocol invariant's failure.
    type Violation: fmt::Debug;

    /// The protocol's name, in counterexamples and replay lines.
    const NAME: &'static str;

    fn init(&self) -> Self::State;
    /// The operations enabled in `state`, in a fixed order (replay names
    /// them by index). The explorer drops those of parked actors.
    fn enabled(&self, state: &Self::State, out: &mut Vec<Self::Op>);
    fn actor(&self, op: Self::Op) -> usize;
    fn kind(&self, op: Self::Op) -> OpKind;
    /// Run `op`. A production notify calls [`WaitLedger::notify`]. `Err` is
    /// a protocol invariant broken inside the step.
    fn step(
        &self,
        state: &mut Self::State,
        op: Self::Op,
        ledger: &mut WaitLedger,
    ) -> Result<Class, Self::Violation>;
    /// The protocol's own invariants, after every step.
    fn check(&self, state: &Self::State) -> Result<(), Self::Violation>;
    /// The name of a protocol invariant's failure (`"V5"`, `"G5"`).
    fn invariant(&self, violation: &Self::Violation) -> &'static str;
    /// The epoch of `wait` in `state`: in production, the queue's revision.
    fn epoch(&self, state: &Self::State, wait: WaitId) -> u64;
    /// Whether something in `state` can still publish `wait` (I4b).
    fn has_publisher(&self, state: &Self::State, wait: WaitId) -> bool;
    /// Whether `op` reads what a `Corrupt` step corrupted (I5b).
    fn reads_corruption(&self, _state: &Self::State, _op: Self::Op) -> bool {
        true
    }
    /// Record the coverage shapes `state` reaches.
    fn reached(&self, _state: &Self::State, _ledger: &WaitLedger, _coverage: &mut Coverage) {}
}

/// How far to explore.
#[derive(Clone, Copy, Debug)]
pub struct Bound {
    /// The longest operation sequence.
    pub depth: usize,
    /// How many peer finishes and publications the I2 drain may run.
    pub drain: usize,
}

impl Bound {
    pub const fn depth(depth: usize) -> Self {
        Self { depth, drain: 32 }
    }
}

/// Coverage shapes a run reached ("busy once, then success"), so a green
/// run can't mean the exploration stopped short of the bug.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Coverage(BTreeSet<&'static str>);

impl Coverage {
    pub fn note(&mut self, shape: &'static str) {
        self.0.insert(shape);
    }
    pub fn has(&self, shape: &'static str) -> bool {
        self.0.contains(shape)
    }
    pub fn shapes(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.0.iter().copied()
    }
}

/// A green run's receipt.
#[derive(Clone, Debug)]
pub struct Report {
    /// Distinct states (protocol state and ledger) reached.
    pub states: usize,
    /// Steps taken, duplicates included.
    pub transitions: usize,
    pub coverage: Coverage,
}

/// A shortest trace to a broken invariant.
#[derive(Clone)]
pub struct Counterexample<Op> {
    pub protocol: &'static str,
    pub invariant: InvariantId,
    pub violation: String,
    pub trace: Vec<Step<Op>>,
    /// The op indices, into each state's enabled list, that replay it.
    pub path: Vec<usize>,
    /// Distinct states stored when it was found.
    pub states: usize,
    /// The seeded mutant that was active, if any.
    pub mutant: Option<&'static str>,
}

impl<Op> Counterexample<Op> {
    /// `CARRICK_MODEL_REPLAY=<protocol>:i,j,k`, for [`replay`].
    pub fn replay_line(&self) -> String {
        let path: Vec<String> = self.path.iter().map(|i| format!("{i}")).collect();
        format!("CARRICK_MODEL_REPLAY={}:{}", self.protocol, path.join(","))
    }
}

impl<Op: fmt::Debug> fmt::Debug for Counterexample<Op> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{} broke {:?}{}: {} ({} states)",
            self.protocol,
            self.invariant,
            self.mutant
                .map(|m| format!(" under mutant {m}"))
                .unwrap_or_default(),
            self.violation,
            self.states
        )?;
        for (i, step) in self.trace.iter().enumerate() {
            writeln!(
                f,
                "  {i:>2}. actor {} {:?} -> {:?}",
                step.actor, step.op, step.class
            )?;
        }
        write!(f, "  {}", self.replay_line())
    }
}

/// One step from `(state, ledger)`, with every check. `Err` names the
/// broken invariant.
fn advance<P: Protocol>(
    protocol: &P,
    state: &P::State,
    ledger: &WaitLedger,
    op: P::Op,
    bound: Bound,
) -> Result<(P::State, WaitLedger, Class), (InvariantId, String)> {
    let mut next = state.clone();
    let mut next_ledger = ledger.clone();
    let actor = protocol.actor(op);
    let reads = protocol.reads_corruption(state, op);
    let class = protocol
        .step(&mut next, op, &mut next_ledger)
        .map_err(|v| {
            (
                InvariantId::Protocol(protocol.invariant(&v)),
                format!("{v:?}"),
            )
        })?;
    protocol.check(&next).map_err(|v| {
        (
            InvariantId::Protocol(protocol.invariant(&v)),
            format!("{v:?}"),
        )
    })?;
    let unchanged = next == *state;
    next_ledger.account(
        actor,
        protocol.kind(op),
        class,
        unchanged,
        reads,
        |w| protocol.epoch(&next, w),
        |w| protocol.has_publisher(state, w),
    )?;
    next_ledger.check_wakes(|w| protocol.epoch(&next, w))?;
    if class == Class::Answer {
        no_false_refusal(protocol, state, ledger, op, bound)?;
    }
    Ok((next, next_ledger, class))
}

/// The operations enabled in `state` for actors the ledger lets run.
fn runnable<P: Protocol>(protocol: &P, state: &P::State, ledger: &WaitLedger) -> Vec<P::Op> {
    if ledger.ended() {
        return Vec::new();
    }
    let mut ops = Vec::new();
    protocol.enabled(state, &mut ops);
    ops.retain(|&op| ledger.is_runnable(protocol.actor(op)));
    ops
}

/// I2: run the peers' enabled finishes and publications until none is
/// left, then rerun `op`; if it is `Done` there, its `Answer` refused
/// contention.
fn no_false_refusal<P: Protocol>(
    protocol: &P,
    state: &P::State,
    ledger: &WaitLedger,
    op: P::Op,
    bound: Bound,
) -> Result<(), (InvariantId, String)> {
    let actor = protocol.actor(op);
    let mut drained = state.clone();
    let mut drained_ledger = ledger.clone();
    for _ in 0..bound.drain {
        let Some(peer) = runnable(protocol, &drained, &drained_ledger)
            .into_iter()
            .find(|&peer| {
                protocol.actor(peer) != actor
                    && matches!(protocol.kind(peer), OpKind::Finish | OpKind::Publish(_))
            })
        else {
            break;
        };
        if protocol
            .step(&mut drained, peer, &mut drained_ledger)
            .is_err()
        {
            return Ok(());
        }
    }
    let mut enabled = Vec::new();
    protocol.enabled(&drained, &mut enabled);
    if !enabled.contains(&op) {
        return Ok(());
    }
    let mut rerun = drained.clone();
    match protocol.step(&mut rerun, op, &mut drained_ledger.clone()) {
        Ok(Class::Done) => Err((
            InvariantId::I2,
            format!(
                "actor {actor}'s {op:?} answered, but after the peers' finishes and publications it is Done"
            ),
        )),
        _ => Ok(()),
    }
}

/// Explore every operation sequence of `protocol` up to `bound`.
pub fn explore<P: Protocol>(
    protocol: &P,
    bound: Bound,
) -> Result<Report, Box<Counterexample<P::Op>>> {
    let root = (protocol.init(), WaitLedger::default());
    let mut coverage = Coverage::default();
    protocol.reached(&root.0, &root.1, &mut coverage);
    let mut seen = HashSet::new();
    let mut queue = VecDeque::new();
    let mut transitions = 0;
    seen.insert(root.clone());
    queue.push_back((root, Vec::new(), Vec::new()));
    while let Some(((state, ledger), trace, path)) = queue.pop_front() {
        if trace.len() == bound.depth {
            continue;
        }
        for (index, op) in runnable(protocol, &state, &ledger).into_iter().enumerate() {
            transitions += 1;
            let mut next_trace: Vec<Step<P::Op>> = trace.clone();
            let mut next_path: Vec<usize> = path.clone();
            next_path.push(index);
            match advance(protocol, &state, &ledger, op, bound) {
                Ok((next, next_ledger, class)) => {
                    next_trace.push(Step {
                        actor: protocol.actor(op),
                        op,
                        class,
                    });
                    protocol.reached(&next, &next_ledger, &mut coverage);
                    let node = (next, next_ledger);
                    if seen.insert(node.clone()) {
                        queue.push_back((node, next_trace, next_path));
                    }
                }
                Err((invariant, violation)) => {
                    next_trace.push(Step {
                        actor: protocol.actor(op),
                        op,
                        class: Class::Broken,
                    });
                    return Err(Box::new(Counterexample {
                        protocol: P::NAME,
                        invariant,
                        violation,
                        trace: next_trace,
                        path: next_path,
                        states: seen.len(),
                        mutant: None,
                    }));
                }
            }
        }
    }
    Ok(Report {
        states: seen.len(),
        transitions,
        coverage,
    })
}

/// A replayed trace, or the counterexample it reproduces.
pub type Verdicts<Op> = Result<Vec<Step<Op>>, Box<Counterexample<Op>>>;

/// Rerun one path of op indices (a [`Counterexample::path`]) with every
/// check, and return its trace, or the counterexample it reproduces.
pub fn replay<P: Protocol>(protocol: &P, path: &[usize], bound: Bound) -> Verdicts<P::Op> {
    let mut state = protocol.init();
    let mut ledger = WaitLedger::default();
    let mut trace = Vec::new();
    for (depth, &index) in path.iter().enumerate() {
        let Some(op) = runnable(protocol, &state, &ledger).get(index).copied() else {
            return Err(Box::new(Counterexample {
                protocol: P::NAME,
                invariant: InvariantId::Protocol("replay"),
                violation: format!("step {depth}: no enabled op {index}"),
                trace,
                path: path[..=depth].to_vec(),
                states: 0,
                mutant: None,
            }));
        };
        match advance(protocol, &state, &ledger, op, bound) {
            Ok((next, next_ledger, class)) => {
                trace.push(Step {
                    actor: protocol.actor(op),
                    op,
                    class,
                });
                state = next;
                ledger = next_ledger;
            }
            Err((invariant, violation)) => {
                trace.push(Step {
                    actor: protocol.actor(op),
                    op,
                    class: Class::Broken,
                });
                return Err(Box::new(Counterexample {
                    protocol: P::NAME,
                    invariant,
                    violation,
                    trace,
                    path: path[..=depth].to_vec(),
                    states: 0,
                    mutant: None,
                }));
            }
        }
    }
    Ok(trace)
}

/// Parse a replay line's path for `protocol` (`<protocol>:i,j,k`).
pub fn parse_replay(protocol: &str, line: &str) -> Option<Vec<usize>> {
    let path = line.strip_prefix(protocol)?.strip_prefix(':')?;
    if path.is_empty() {
        return Some(Vec::new());
    }
    path.split(',').map(|i| i.parse().ok()).collect()
}

/// Run each seeded mutant and require that its named invariant kills it.
/// A survivor, or a kill by any other invariant, is an `Err` naming it.
/// Returns the counterexamples, in order, for their known-answer checks.
pub fn mutants_killed<M: Copy + fmt::Debug, Op: fmt::Debug>(
    cases: &[(M, &'static str, InvariantId)],
    mut run: impl FnMut(M) -> Result<Report, Box<Counterexample<Op>>>,
) -> Result<Vec<Counterexample<Op>>, String> {
    let mut found = Vec::new();
    for &(mutant, name, expected) in cases {
        match run(mutant) {
            Ok(report) => {
                return Err(format!(
                    "mutant {mutant:?} survived {} states: {expected:?} should have killed it",
                    report.states
                ));
            }
            Err(mut counterexample) => {
                counterexample.mutant = Some(name);
                if counterexample.invariant != expected {
                    return Err(format!(
                        "mutant {mutant:?} was killed by {:?}, not {expected:?}:\n{counterexample:?}",
                        counterexample.invariant
                    ));
                }
                found.push(*counterexample);
            }
        }
    }
    Ok(found)
}
