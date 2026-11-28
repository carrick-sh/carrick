//! The bounded breadth-first explorer, generalised from the memory core's
//! three explorers (`carrick-core` `mm/own`): every sequence of enabled
//! operations up to a depth, states deduplicated by equality (a hash
//! collision never merges two), the protocol's own invariants and the
//! ledger's I1 to I5 checked in the initial state and after every step.
//! Breadth first, so the first counterexample found is a shortest one.
//!
//! A protocol models its production calls: its state holds the production
//! state by value and its steps call the production functions, never a
//! paraphrase of them.

use core::fmt;
use std::boxed::Box;
use std::collections::{BTreeSet, HashSet, VecDeque};
use std::format;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::string::{String, ToString};
use std::vec::Vec;

use crate::ledger::{Facts, WaitLedger};
use crate::{Answer, Class, InvariantId, Mutant, ObjectId, OpKind, Step, WaitId, mutant};

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
    /// a protocol invariant broken inside the step. A panic is caught and
    /// judged as `Broken` (I5).
    fn step(
        &self,
        state: &mut Self::State,
        op: Self::Op,
        ledger: &mut WaitLedger,
    ) -> Result<Class, Self::Violation>;
    /// The protocol's own invariants, in the initial state and after every
    /// step, the I2 drain's peer finishes and retries included.
    fn check(&self, state: &Self::State) -> Result<(), Self::Violation>;
    /// The name of a protocol invariant's failure (`"V5"`, `"G5"`).
    fn invariant(&self, violation: &Self::Violation) -> &'static str;
    /// The epoch of `wait` in `state`: in production, the queue's revision.
    fn epoch(&self, state: &Self::State, wait: WaitId) -> u64;
    /// The actors that can still publish `wait` in `state` (I4: one of them,
    /// other than the waiter, must be runnable).
    fn publishers(&self, state: &Self::State, wait: WaitId, out: &mut Vec<usize>);
    /// Whether `op` reads `object` (I5 is per object). No default: a wrong
    /// guess either way hides a bug.
    fn reads(&self, state: &Self::State, op: Self::Op, object: ObjectId) -> bool;
    /// Record the coverage shapes `state` reaches.
    fn reached(&self, _state: &Self::State, _ledger: &WaitLedger, _coverage: &mut Coverage) {}
}

/// How far to explore.
#[derive(Clone, Copy, Debug)]
pub struct Bound {
    /// The longest operation sequence.
    pub depth: usize,
    /// How many peer finishes one I2 drain may run, over every order. A
    /// drain that needs more fails: it proved nothing.
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
    /// Each step with the class it returned; a step that panicked or broke
    /// a protocol invariant inside itself reads `Broken`.
    pub trace: Vec<Step<Op>>,
    /// The op indices, into each state's enabled list, that replay it.
    pub path: Vec<usize>,
    /// Distinct states stored when it was found.
    pub states: usize,
    /// The seeded mutant that was active, if any.
    pub mutant: Option<&'static str>,
    /// The I2 drain bound it ran with.
    pub drain: usize,
}

impl<Op> Counterexample<Op> {
    /// `CARRICK_MODEL_REPLAY=<protocol>:mutant=<name|none>:drain=<n>:i,j,k`,
    /// which [`replay_line`] (or [`replay_env`]) reruns as it is.
    pub fn replay_line(&self) -> String {
        let path: Vec<String> = self.path.iter().map(|i| format!("{i}")).collect();
        format!(
            "{REPLAY_VAR}={}:mutant={}:drain={}:{}",
            self.protocol,
            self.mutant.unwrap_or("none"),
            self.drain,
            path.join(",")
        )
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

/// The environment variable [`replay_env`] reads.
pub const REPLAY_VAR: &str = "CARRICK_MODEL_REPLAY";

/// A checker failure: the invariant, why, and the class the step returned
/// (`None` when the step itself failed or panicked).
type Fail = (InvariantId, String, Option<Class>);

/// One step from `(state, ledger)`, with every check. `judge` runs the I2
/// drain for a settled answer (the drain's own peer steps don't recurse).
fn advance<P: Protocol>(
    protocol: &P,
    state: &P::State,
    ledger: &WaitLedger,
    op: P::Op,
    bound: Bound,
    judge: bool,
) -> Result<(P::State, WaitLedger, Class), Fail> {
    let mut next = state.clone();
    let mut next_ledger = ledger.clone();
    let actor = protocol.actor(op);
    let kind = protocol.kind(op);
    let reads_corruption = ledger
        .corruptions()
        .any(|object| protocol.reads(state, op, object));
    next_ledger.begin_step(actor, kind);
    let stepped = catch_unwind(AssertUnwindSafe(|| {
        protocol.step(&mut next, op, &mut next_ledger)
    }));
    let (class, panic) = match stepped {
        Ok(Ok(class)) => (class, None),
        Ok(Err(v)) => {
            return Err((
                InvariantId::Protocol(protocol.invariant(&v)),
                format!("{v:?}"),
                None,
            ));
        }
        Err(payload) => {
            let why = payload
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| String::from("a non-string panic"));
            (Class::Broken, Some(why))
        }
    };
    let with_class = |(invariant, why): (InvariantId, String)| (invariant, why, Some(class));
    if panic.is_none() {
        protocol.check(&next).map_err(|v| {
            (
                InvariantId::Protocol(protocol.invariant(&v)),
                format!("{v:?}"),
                Some(class),
            )
        })?;
    }
    let facts = Facts {
        actor,
        kind,
        class,
        state_unchanged: next == *state,
        reads_corruption,
        panic,
    };
    next_ledger
        .account(facts, |after, w| {
            if after {
                protocol.epoch(&next, w)
            } else {
                protocol.epoch(state, w)
            }
        })
        .map_err(with_class)?;
    next_ledger
        .check_wakes(|w| protocol.epoch(&next, w))
        .map_err(with_class)?;
    next_ledger
        .check_stranded(|w| {
            let mut out = Vec::new();
            protocol.publishers(&next, w, &mut out);
            out
        })
        .map_err(with_class)?;
    if judge && class == Class::Answer(Answer::Settled) {
        no_false_refusal(protocol, state, ledger, op, bound).map_err(with_class)?;
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

/// I2: from the state before `op` answered, explore every order of the
/// peers' in-flight finishes (breadth first, every step checked), and retry
/// `op` in each state reached. A retry that is `Done` means the answer
/// refused contention. A drain that runs out of budget before it has seen
/// every order fails: it proved nothing.
fn no_false_refusal<P: Protocol>(
    protocol: &P,
    state: &P::State,
    ledger: &WaitLedger,
    op: P::Op,
    bound: Bound,
) -> Result<(), (InvariantId, String)> {
    let actor = protocol.actor(op);
    let mut seen = HashSet::new();
    let mut queue = VecDeque::new();
    seen.insert((state.clone(), ledger.clone()));
    queue.push_back((state.clone(), ledger.clone(), Vec::new()));
    let mut budget = bound.drain;
    while let Some((drained, drained_ledger, finishes)) = queue.pop_front() {
        if !finishes.is_empty()
            && drained_ledger.is_runnable(actor)
            && runnable(protocol, &drained, &drained_ledger).contains(&op)
        {
            // The retry is a step like any other: every check runs on it,
            // and a failure is a counterexample, not a pass.
            let retried = advance(protocol, &drained, &drained_ledger, op, bound, false).map_err(
                |(invariant, why, _)| {
                    (
                        invariant,
                        format!("in the I2 drain, retrying {op:?} after the finishes {finishes:?}: {why}"),
                    )
                },
            )?;
            if retried.2 == Class::Done {
                return Err((
                    InvariantId::I2,
                    format!(
                        "actor {actor}'s {op:?} answered as settled, but after the peers' \
                         finishes {finishes:?} it is Done"
                    ),
                ));
            }
        }
        for peer in runnable(protocol, &drained, &drained_ledger) {
            if protocol.actor(peer) == actor || !matches!(protocol.kind(peer), OpKind::Finish(_)) {
                continue;
            }
            if budget == 0 {
                return Err((
                    InvariantId::I2,
                    format!(
                        "actor {actor}'s settled answer to {op:?} is unproven: the drain ran out \
                         of its budget of {} peer finishes with orders left",
                        bound.drain
                    ),
                ));
            }
            budget -= 1;
            let mut path = finishes.clone();
            path.push(peer);
            let (next, next_ledger, _) =
                advance(protocol, &drained, &drained_ledger, peer, bound, false).map_err(
                    |(invariant, why, _)| {
                        (
                            invariant,
                            format!(
                                "in the I2 drain of {op:?}, after the finishes {path:?}: {why}"
                            ),
                        )
                    },
                )?;
            if seen.insert((next.clone(), next_ledger.clone())) {
                queue.push_back((next, next_ledger, path));
            }
        }
    }
    Ok(())
}

/// The protocol's own invariant over its initial state, as a zero-step
/// counterexample when it fails.
fn initial_check<P: Protocol>(
    protocol: &P,
    init: &P::State,
    bound: Bound,
) -> Result<(), Box<Counterexample<P::Op>>> {
    protocol.check(init).map_err(|v| {
        Box::new(Counterexample {
            protocol: P::NAME,
            invariant: InvariantId::Protocol(protocol.invariant(&v)),
            violation: format!("the initial state: {v:?}"),
            trace: Vec::new(),
            path: Vec::new(),
            states: 1,
            mutant: mutant::active(),
            drain: bound.drain,
        })
    })
}

/// Explore every operation sequence of `protocol` up to `bound`.
pub fn explore<P: Protocol>(
    protocol: &P,
    bound: Bound,
) -> Result<Report, Box<Counterexample<P::Op>>> {
    let root = (protocol.init(), WaitLedger::default());
    // The initial state is checked too: a protocol that starts broken has a
    // zero-step counterexample, the shortest there is.
    initial_check(protocol, &root.0, bound)?;
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
            match advance(protocol, &state, &ledger, op, bound, true) {
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
                Err((invariant, violation, class)) => {
                    next_trace.push(Step {
                        actor: protocol.actor(op),
                        op,
                        class: class.unwrap_or(Class::Broken),
                    });
                    return Err(Box::new(Counterexample {
                        protocol: P::NAME,
                        invariant,
                        violation,
                        trace: next_trace,
                        path: next_path,
                        states: seen.len(),
                        mutant: mutant::active(),
                        drain: bound.drain,
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

/// A replayed trace with the state and ledger it ends in.
pub type Ending<P> = (
    Vec<Step<<P as Protocol>::Op>>,
    <P as Protocol>::State,
    WaitLedger,
);

/// Rerun one path of op indices (a [`Counterexample::path`]) with every
/// check, under whatever mutant is active, and return its trace, or the
/// counterexample it reproduces.
pub fn replay<P: Protocol>(protocol: &P, path: &[usize], bound: Bound) -> Verdicts<P::Op> {
    replay_to(protocol, path, bound).map(|(trace, _, _)| trace)
}

/// [`replay`], keeping the state and ledger the path ends in.
pub fn replay_to<P: Protocol>(
    protocol: &P,
    path: &[usize],
    bound: Bound,
) -> Result<Ending<P>, Box<Counterexample<P::Op>>> {
    let mut state = protocol.init();
    initial_check(protocol, &state, bound)?;
    let mut ledger = WaitLedger::default();
    let mut trace = Vec::new();
    let failed = |invariant, violation, trace, depth: usize| {
        Box::new(Counterexample {
            protocol: P::NAME,
            invariant,
            violation,
            trace,
            path: path[..=depth].to_vec(),
            states: 0,
            mutant: mutant::active(),
            drain: bound.drain,
        })
    };
    for (depth, &index) in path.iter().enumerate() {
        let Some(op) = runnable(protocol, &state, &ledger).get(index).copied() else {
            return Err(failed(
                InvariantId::Protocol("replay"),
                format!("step {depth}: no enabled op {index}"),
                trace,
                depth,
            ));
        };
        match advance(protocol, &state, &ledger, op, bound, true) {
            Ok((next, next_ledger, class)) => {
                trace.push(Step {
                    actor: protocol.actor(op),
                    op,
                    class,
                });
                state = next;
                ledger = next_ledger;
            }
            Err((invariant, violation, class)) => {
                trace.push(Step {
                    actor: protocol.actor(op),
                    op,
                    class: class.unwrap_or(Class::Broken),
                });
                return Err(failed(invariant, violation, trace, depth));
            }
        }
    }
    Ok((trace, state, ledger))
}

/// A parsed replay line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayLine {
    pub protocol: String,
    pub mutant: Option<String>,
    pub drain: usize,
    pub path: Vec<usize>,
}

impl ReplayLine {
    /// Parse `[CARRICK_MODEL_REPLAY=]<protocol>:mutant=<name|none>:drain=<n>:i,j,k`.
    pub fn parse(line: &str) -> Option<Self> {
        let line = line
            .strip_prefix(REPLAY_VAR)
            .and_then(|rest| rest.strip_prefix('='))
            .unwrap_or(line);
        let mut fields = line.splitn(4, ':');
        let protocol = fields.next()?.to_string();
        let mutant = fields.next()?.strip_prefix("mutant=")?;
        let drain = fields.next()?.strip_prefix("drain=")?.parse().ok()?;
        let path = fields.next()?;
        let path = if path.is_empty() {
            Vec::new()
        } else {
            path.split(',')
                .map(|i| i.parse().ok())
                .collect::<Option<Vec<usize>>>()?
        };
        Some(Self {
            protocol,
            mutant: (mutant != "none").then(|| mutant.to_string()),
            drain,
            path,
        })
    }
}

/// Rerun a replay line as it is: its protocol, its mutant (one of `M`) and
/// its drain bound. A line for another protocol, a mutant `M` doesn't name,
/// or a malformed line is an `Err` that says so.
pub fn replay_line<P: Protocol, M: Mutant>(protocol: &P, line: &str) -> Verdicts<P::Op> {
    let refuse = |why: String| {
        Box::new(Counterexample {
            protocol: P::NAME,
            invariant: InvariantId::Protocol("replay"),
            violation: why,
            trace: Vec::new(),
            path: Vec::new(),
            states: 0,
            mutant: None,
            drain: 0,
        })
    };
    let Some(parsed) = ReplayLine::parse(line) else {
        return Err(refuse(format!("not a replay line: {line}")));
    };
    if parsed.protocol != P::NAME {
        return Err(refuse(format!(
            "the line replays {}, not {}",
            parsed.protocol,
            P::NAME
        )));
    }
    let bound = Bound {
        depth: parsed.path.len(),
        drain: parsed.drain,
    };
    match parsed.mutant {
        // A clean line replays clean, even inside a mutant's scope.
        None => mutant::none(|| replay(protocol, &parsed.path, bound)),
        Some(name) => {
            let Some(&which) = M::ALL.iter().find(|m| m.name() == name) else {
                return Err(refuse(format!("no mutant {name} in {}", P::NAME)));
            };
            mutant::with(which, || replay(protocol, &parsed.path, bound))
        }
    }
}

/// [`replay_line`] on `CARRICK_MODEL_REPLAY`, if it is set for `protocol`.
pub fn replay_env<P: Protocol, M: Mutant>(protocol: &P) -> Option<Verdicts<P::Op>> {
    let line = std::env::var(REPLAY_VAR).ok()?;
    let parsed = ReplayLine::parse(&line)?;
    (parsed.protocol == P::NAME).then(|| replay_line::<P, M>(protocol, &line))
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
            Err(counterexample) => {
                if counterexample.mutant != Some(name) {
                    return Err(format!(
                        "mutant {mutant:?}'s run recorded mutant {:?}: run it under mutant::with",
                        counterexample.mutant
                    ));
                }
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
