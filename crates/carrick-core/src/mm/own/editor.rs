//! The guest MM editor, as core state (#3061, PR 1a).
//!
//! The editor itself is the guest's try-lock in guest memory: CPL0 and EL1
//! edit their own tables in ring, with no crossing, so the lock can't move
//! into the host. The shell takes it **before** any core transition, never
//! blocks on it, and never holds the core across it. A `Busy` there is "not
//! now" and reaches no transition, so it changes nothing in the core.
//!
//! What the core owns is the record of who holds it while a host edit is in
//! progress. A transition that edits an MM's descriptors or grants takes an
//! [`ExcludedMm`] (borrowed from the guest's exclusion proof) and
//! records [`MmEditor::Host`] until the matching finish. [`MmEditor::Guest`]
//! is the guest adversary's state: the explorer and loom hold it at any step,
//! and a transition offered an exclusion the core sees as the guest's
//! answers [`NotNow::EditorRelease`].

use super::grant::GrantId;
use super::mm::MmKey;

/// Which host edit holds an MM's editor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HostEdit {
    /// A copy-on-write grant is being supplied; the grant is `Supplying`.
    CowSupply(GrantId),
    /// The shell is mapping a chunk of the MM's replacement arena.
    CowChunk,
    /// The MM's completed copy-on-write grants are being settled.
    Settle,
}

/// Who holds an MM's editor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MmEditor {
    Free,
    /// A guest member edits the MM in ring.
    Guest,
    /// The shell edits the MM under its exclusion.
    Host(HostEdit),
}

/// The shell's proof that it holds the guest editor of one MM, borrowed
/// from the guest's own exclusion proof, so it can't outlive the exclusion.
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Clone, Hash))]
pub struct ExcludedMm<'a> {
    mm: MmKey,
    _excluded: core::marker::PhantomData<&'a ()>,
}

impl<'a> ExcludedMm<'a> {
    /// The core's view of a guest exclusion. `None` for the null key, which
    /// names no address space.
    pub fn of(excluded: &'a carrick_sched_core::spaces::ExcludedEditor<'_>) -> Option<Self> {
        Some(Self {
            mm: MmKey::new(core::num::NonZeroU64::new(excluded.key())?),
            _excluded: core::marker::PhantomData,
        })
    }

    /// An exclusion the explorer's adversarial shell claims without the
    /// guest's proof; the core must still answer the guest's hold.
    #[cfg(test)]
    pub(super) const fn claimed(mm: MmKey) -> Self {
        Self {
            mm,
            _excluded: core::marker::PhantomData,
        }
    }

    pub const fn mm(&self) -> MmKey {
        self.mm
    }
}

/// Contention: the caller keeps its request and reruns it after the event.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NotNow {
    /// A guest member holds the MM's editor: rerun after its release.
    EditorRelease(MmKey),
}
