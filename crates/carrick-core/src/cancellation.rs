//! Process cancellation and bounded host-effect ordering.
//!
//! Requesting cancellation closes admission. Publication waits for previously
//! admitted effects, before any signal queue or wake is published. Effects
//! own secured output and cannot be retained across a guest wait. This is a
//! reader/writer protocol: independent effects do not serialize each other.
use core::sync::atomic::{AtomicU32, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ProcessCancellation {
    FatalSignal = 1,
    GroupExit = 2,
}

const CAUSE: u32 = 3;
const PUBLISHED: u32 = 4;
const CONSUMED: u32 = 8;
const EFFECT: u32 = 16;

/// Atomic venue for the same protocol in production and model checking.
pub trait CancellationWord {
    fn load(&self, order: Ordering) -> u32;
    fn compare_exchange(
        &self,
        old: u32,
        new: u32,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u32, u32>;
    fn fetch_sub(&self, value: u32, order: Ordering) -> u32;
    fn fetch_or(&self, value: u32, order: Ordering) -> u32;
}
impl CancellationWord for AtomicU32 {
    fn load(&self, order: Ordering) -> u32 {
        self.load(order)
    }
    fn compare_exchange(
        &self,
        old: u32,
        new: u32,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u32, u32> {
        self.compare_exchange(old, new, success, failure)
    }
    fn fetch_sub(&self, value: u32, order: Ordering) -> u32 {
        self.fetch_sub(value, order)
    }
    fn fetch_or(&self, value: u32, order: Ordering) -> u32 {
        self.fetch_or(value, order)
    }
}

#[repr(transparent)]
#[derive(Debug, Default)]
pub struct CancellationAuthority<W = AtomicU32>(W);
impl CancellationAuthority {
    pub const fn new() -> Self {
        Self(AtomicU32::new(0))
    }
}
impl<W: CancellationWord> CancellationAuthority<W> {
    pub const fn with_word(word: W) -> Self {
        Self(word)
    }

    fn cause(word: u32) -> Option<ProcessCancellation> {
        match word & CAUSE {
            1 => Some(ProcessCancellation::FatalSignal),
            2 => Some(ProcessCancellation::GroupExit),
            _ => None,
        }
    }

    /// Requests bar new effects immediately, including an already-ready retry.
    pub fn requested(&self) -> Option<ProcessCancellation> {
        Self::cause(self.0.load(Ordering::Acquire))
    }

    /// No effect can occur after this publication. Queue publication follows
    /// this method, and must not hold a lock needed by an admitted effect.
    pub fn publish(&self, cause: ProcessCancellation, wait: impl FnMut()) {
        self.request(cause).publish(wait);
    }

    /// Close admission while the caller validates its exact target. This does
    /// not wait; release topology/signal locks before publishing the ticket.
    pub fn request(&self, cause: ProcessCancellation) -> CancellationPublication<'_, W> {
        let mut word = self.0.load(Ordering::Acquire);
        loop {
            if Self::cause(word).is_some() {
                break;
            }
            match self.0.compare_exchange(
                word,
                word | cause as u32,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => word = observed,
            }
        }
        CancellationPublication(self)
    }

    pub fn published(&self) -> Option<ProcessCancellation> {
        let word = self.0.load(Ordering::Acquire);
        (word & PUBLISHED != 0).then(|| Self::cause(word)).flatten()
    }

    pub(crate) fn consume(&self) {
        self.0.fetch_or(CONSUMED, Ordering::AcqRel);
    }
}

/// A validated monotonic cancellation request. Dropping it never reopens
/// admission; a publisher must drain outside locks needed by bounded effects.
#[must_use = "publish cancellation after releasing target-validation locks"]
pub struct CancellationPublication<'a, W: CancellationWord>(&'a CancellationAuthority<W>);
/// The atomic publication elects one caller to fan out a new wake.
/// Repeated requests retain cancellation but must not multiply notifications.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationPublicationStatus {
    First,
    AlreadyPublished,
}

impl<W: CancellationWord> CancellationPublication<'_, W> {
    pub fn publish(self, mut wait: impl FnMut()) -> CancellationPublicationStatus {
        while self.0.0.load(Ordering::Acquire) >= EFFECT {
            wait();
        }
        if self.0.0.fetch_or(PUBLISHED, Ordering::Release) & PUBLISHED == 0 {
            CancellationPublicationStatus::First
        } else {
            CancellationPublicationStatus::AlreadyPublished
        }
    }
}

/// Retains the exact process incarnation for the entire effect scope.
pub trait CancellationOwner {
    type Word: CancellationWord;
    fn cancellation_authority(&self) -> &CancellationAuthority<Self::Word>;
}
impl<W: CancellationWord> CancellationOwner for &CancellationAuthority<W> {
    type Word = W;
    fn cancellation_authority(&self) -> &CancellationAuthority<W> {
        self
    }
}

/// Non-cloneable custody, acquired only after securing every output. Drop it
/// after source consumption, copyout and related cursor/descriptor publication,
/// before notifying waiters. Never store it in an owned continuation.
#[must_use]
pub struct ProcessEffect<P: CancellationOwner>(P, core::marker::PhantomData<*mut ()>);
impl<P: CancellationOwner> ProcessEffect<P> {
    pub fn acquire(owner: P) -> Result<Self, ProcessCancellation> {
        let state = &owner.cancellation_authority().0;
        let mut word = state.load(Ordering::Acquire);
        loop {
            if let Some(cause) = CancellationAuthority::<P::Word>::cause(word) {
                return Err(cause);
            }
            let Some(next) = word.checked_add(EFFECT) else {
                // Impossible for an admitted process population; fail closed.
                return Err(ProcessCancellation::GroupExit);
            };
            match state.compare_exchange(word, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Ok(Self(owner, core::marker::PhantomData)),
                Err(observed) => word = observed,
            }
        }
    }
}
impl<P: CancellationOwner> Drop for ProcessEffect<P> {
    fn drop(&mut self) {
        self.0
            .cancellation_authority()
            .0
            .fetch_sub(EFFECT, Ordering::Release);
    }
}

#[cfg(all(test, feature = "loom"))]
#[path = "cancellation/loom_tests.rs"]
mod loom_models;
