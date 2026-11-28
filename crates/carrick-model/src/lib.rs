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
//! - **Always compiled, `no_std`, no alloc:** [`Class`], [`Verdict`],
//!   [`WaitId`], [`InvariantId`], [`OpKind`], [`Step`] and the named stop
//!   points ([`StopPoint`], [`Stops`]). Production outcome types implement
//!   [`Verdict`] in their own crates, with an exhaustive match, so a new
//!   variant fails to compile until it is classified.
//! - **`std` feature (dev-dependencies only):** the breadth-first
//!   [`explore`](explore::explore) over a [`Protocol`](explore::Protocol),
//!   the [`WaitLedger`](ledger::WaitLedger) that checks I1 to I5, the
//!   shortest [`Counterexample`](explore::Counterexample) with a replay line,
//!   and the seeded-[`mutant`] runner ([`mutants!`] declares the enum).
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
    /// Contention: the operation keeps its request, enrols on `WaitId`'s
    /// release, probes once and parks. Never an errno, never fatal.
    NotNow(WaitId),
    /// The operation's observation went stale (a peer committed under it):
    /// rerun now. A peer's committed publication pays for it (I4d).
    Rerun,
    /// A broken invariant (`Stale`, `Invalid`, `Quarantined`): fatal.
    Broken,
    /// The operation answered its caller (a Linux result, an errno).
    Answer,
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
}

/// The harness's own invariants. A protocol's own (`V1`, `G5`, `L2`, ...)
/// are [`InvariantId::Protocol`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvariantId {
    /// No lost wakeup: an actor parked on `(w, e)` sees `e(w) = e`, or a
    /// wake for it is pending.
    I1,
    /// No false refusal: an `Answer` that a drain of the peers' finishes and
    /// publications would turn into `Done` was a refusal of contention.
    I2,
    /// A close wakes every actor enrolled before it, and a later enrolment
    /// on the closed wait doesn't park.
    I3,
    /// "Not now" never polls: it changes no protocol state, names a wait
    /// with a publisher, and an actor's next "not now" on the same wait
    /// follows an epoch advance; a `Rerun` is paid for by a peer.
    I4,
    /// Broken is fatal and contention is not: no legal step is `Broken`,
    /// and the first step that reads a corruption is.
    I5,
    /// The protocol's own invariant, by name.
    Protocol(&'static str),
}

/// What an operation does to its protocol's waits, for the ledger and the
/// I2 drain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OpKind {
    /// Starts an operation (it may hold something until its finish).
    Begin,
    /// Completes a held operation.
    Finish,
    /// Publishes `WaitId`'s release (advances its epoch, wakes its queue).
    Publish(WaitId),
    /// Closes `WaitId`: every waiter is woken and no later enrolment parks.
    Close(WaitId),
    /// Corrupts the state on purpose (an adversarial shell): the next step
    /// that reads it must be `Broken`.
    Corrupt,
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
