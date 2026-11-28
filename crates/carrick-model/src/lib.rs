//! One model-check harness for Carrick's "not now" protocols (#3061, H0).
//!
//! The protocols that keep producing race P0s (the scheduler's idle and wake
//! pass, the enrol-then-probe object waits, fault settlement against sibling
//! edits, and the memory-ownership core) share one shape: an operation is
//! done, is "not now" and waits on a named release, reruns because its
//! observation went stale, answers the caller, or finds a broken invariant.
//! This crate gives them one vocabulary for that shape and one way to check
//! it, so each protocol models its own production calls and the harness, not
//! the protocol's author, checks the waits.
//!
//! - **Always compiled, `no_std`, no alloc:** [`Class`] (with its
//!   [`Enrolment`] and [`Answer`]), [`Verdict`], [`WaitId`], [`ObjectId`],
//!   [`InvariantId`], [`OpKind`] (with its [`Effect`]), [`Step`] and the named stop
//!   points ([`StopPoint`], [`Stops`]). Production outcome types implement
//!   [`Verdict`] in their own crates, with an exhaustive match, so a new
//!   variant fails to compile until it is classified.
//! - **`std` feature (dev-dependencies only):** the breadth-first
//!   [`explore`](explore::explore) over a [`Protocol`](explore::Protocol),
//!   the [`WaitLedger`](ledger::WaitLedger) that checks I1 to I5, the
//!   shortest [`Counterexample`](explore::Counterexample) with a replay line
//!   that names its mutant and drain bound
//!   ([`replay_line`](explore::replay_line), `CARRICK_MODEL_REPLAY`), and
//!   the seeded-[`mutant`] runner ([`mutants!`] declares the enum).
//!
//! Everything is generic: no `dyn`, so a venue that implements [`Stops`] in
//! a small CPL0 or EL1 frame pays nothing for it.
#![no_std]

#[cfg(any(test, feature = "std"))]
extern crate std;

#[cfg(any(test, feature = "std"))]
pub mod explore;
#[cfg(test)]
mod kats;
#[cfg(any(test, feature = "std"))]
pub mod ledger;
#[cfg(any(test, feature = "std"))]
pub mod mutant;
#[cfg(test)]
mod toy;

/// How one step of a protocol ended.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Class {
    /// The operation took effect.
    Done,
    /// Contention: the operation keeps its request, enrols on the wait's
    /// release, probes once and parks. Never an errno, never fatal. The
    /// [`Enrolment`] carries the epoch the actor actually observed, so a
    /// park on a stale observation is a lost wakeup (I1).
    NotNow(Enrolment),
    /// The operation's observation of the wait went stale: rerun now. The
    /// [`Enrolment`] is the observation it acted on, and it is paid for only
    /// if the wait had already moved past it before this step (I4).
    Rerun(Enrolment),
    /// A broken invariant (`Stale`, `Invalid`, `Quarantined`): fatal.
    Broken,
    /// The operation answered its caller (a Linux result, an errno).
    Answer(Answer),
}

/// Why an operation answered its caller instead of waiting.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Answer {
    /// The answer claims no peer's finish could change it (end of file,
    /// `ENOENT`). I2 judges it: if a drain of the peers' in-flight finishes
    /// makes the retry `Done`, it refused contention.
    Settled,
    /// Linux's own answer to contention the caller asked not to wait on
    /// (`EAGAIN` under `O_NONBLOCK`, `EBUSY` from a trylock). I2 leaves it.
    Declined,
}

/// A "not now"'s enrolment: the wait, and the epoch of it the actor
/// observed before it decided to park. In production, the
/// `ObjectWaitSnapshot` the probe compares against.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Enrolment {
    pub wait: WaitId,
    pub observed: u64,
}

/// A production outcome's class. Implement it in the outcome's own crate
/// with an exhaustive `match` and no wildcard arm.
pub trait Verdict {
    fn class(&self) -> Class;
}

impl Verdict for Class {
    fn class(&self) -> Class {
        *self
    }
}

/// What a wait's release is produced by.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WaitKind {
    /// A software producer: a lock release, a publication, a close.
    Software,
    /// A hardware producer: an interrupt vector, a device completion.
    Hardware,
}

/// One wait a "not now" names: the release it enrols on. In production the
/// key is the wait-queue key and its epoch is `ObjectWaitSnapshot::revision`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WaitId {
    pub key: u64,
    pub kind: WaitKind,
}

impl WaitId {
    pub const fn software(key: u64) -> Self {
        Self {
            key,
            kind: WaitKind::Software,
        }
    }
    pub const fn hardware(key: u64) -> Self {
        Self {
            key,
            kind: WaitKind::Hardware,
        }
    }
    /// Enrol on this wait, having observed it at `observed`.
    pub const fn at(self, observed: u64) -> Enrolment {
        Enrolment {
            wait: self,
            observed,
        }
    }
}

/// One object a protocol's state holds, as far as corruption goes: a
/// `Corrupt` step names the one it corrupts, and a step reads a set of them
/// (I5 is per object).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObjectId(pub u64);

/// The harness's own invariants. A protocol's own (`V1`, `G5`, `L2`, ...)
/// are [`InvariantId::Protocol`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvariantId {
    /// No lost wakeup: an actor parks only on the epoch it observed, and
    /// one parked on `(w, e)` sees `e(w) = e`, or a wake for it is pending;
    /// a committed publication advances its wait's epoch.
    I1,
    /// No false refusal: a settled `Answer` that some order of the peers'
    /// in-flight finishes would turn into `Done` was a refusal of
    /// contention. A drain that runs out of budget proves nothing, and fails.
    I2,
    /// A close wakes every actor enrolled before it, and a later enrolment
    /// on the closed wait doesn't park.
    I3,
    /// "Not now" never polls: it changes no protocol state; every parked
    /// actor, in every state, waits on a wait with a live publisher
    /// (runnable, or parked on a chain of waits that ends at a runnable
    /// one); only a committed publication or close of a wait wakes its
    /// waiters (so a re-probe always sees a moved epoch, by I1); and a
    /// `Rerun` acts on an observation the wait had already moved past.
    I4,
    /// Broken is fatal and contention is not: a step is `Broken` (or
    /// panics) exactly when it reads a corrupted object.
    I5,
    /// The protocol's own invariant, by name.
    Protocol(&'static str),
}

/// What a committed step does to a wait.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Effect {
    /// Nothing the ledger tracks.
    None,
    /// Publishes the wait's release: advances its epoch and wakes its queue.
    Publish(WaitId),
    /// Closes the wait: every waiter is woken and no later enrolment parks.
    Close(WaitId),
}

/// What an operation is, for the ledger and the I2 drain. Its effect counts
/// only when its step is `Done`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OpKind {
    /// Starts an operation (it may hold something until its finish). No
    /// effect.
    Begin,
    /// Completes an operation in flight, with its effect (a two-phase put's
    /// publication, a two-phase close). The I2 drain runs only these.
    Finish(Effect),
    /// A new single-step commit with its effect: not a finish of anything in
    /// flight, so the I2 drain doesn't run it.
    Commit(Effect),
    /// Corrupts one object on purpose (an adversarial shell): every later
    /// step that reads it must be `Broken`.
    Corrupt(ObjectId),
}

impl OpKind {
    /// This kind's effect on a wait.
    pub const fn effect(self) -> Effect {
        match self {
            OpKind::Finish(effect) | OpKind::Commit(effect) => effect,
            OpKind::Begin | OpKind::Corrupt(_) => Effect::None,
        }
    }
}

/// One step of a trace: who ran which operation, and how it ended.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Step<Op> {
    pub actor: usize,
    pub op: Op,
    pub class: Class,
}

/// A crate's seeded mutants (see [`mutants!`]): an enum listing every
/// mutant, each with its name.
pub trait Mutant: Copy + Eq + core::fmt::Debug + 'static {
    const ALL: &'static [Self];
    fn name(self) -> &'static str;
}

/// A named point inside a production loop where a witness or a model may
/// stop the lane (`after_drain`, `before_halt`, `after_final_recheck`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StopPoint(pub &'static str);

/// The stop points a venue offers. Generic, never `dyn`: [`NoStops`] is a
/// zero-sized venue whose calls compile away.
pub trait Stops {
    fn at(&self, point: StopPoint);
}

/// The production venue: no stops.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoStops;

impl Stops for NoStops {
    #[inline(always)]
    fn at(&self, _: StopPoint) {}
}
