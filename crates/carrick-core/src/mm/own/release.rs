//! An MM's lifecycle and its two-phase release (#3061, PR 1b).
//!
//! An MM is [`MmLife::Live`] while members can edit it. When its last member
//! leaves (a fork child retires, an exec replaces it), the shell records
//! [`CarrierCore::exit_mm`] and it is `Exiting`: no member will take its
//! editor again, and no host edit is admitted for it. Its release then runs
//! in two phases:
//!
//! 1. [`CarrierCore::begin_release`] moves it to `Releasing` and hands the
//!    shell a [`ReleaseTicket`] and everything the core held for it (its
//!    copy-on-write grants; its arena chunks leave the core with it). The
//!    shell unlocks and does the I/O.
//! 2. [`CarrierCore::finish_release`] takes the ticket and the shell's
//!    [`ReleaseOutcome`]: `Done` retires the record; `NotNow` returns it to
//!    `Exiting`, to be released again when the wait fires; `Broken` leaves it
//!    `Releasing` and hands the verdict back, and the venue ends the carrier.
//!
//! Invariants, checked by [`CarrierCore::check_invariants`]:
//! - **L1** an MM that is not `Live` has a free editor;
//! - **L2** a `Releasing` MM holds no grant and no chunk.
//!
//! The explorer adds **L3**: the shell holds exactly one ticket per
//! `Releasing` MM, and a `NotNow` leaves the MM releasable again.

use alloc::vec::Vec;

pub use carrick_core_abi::mm::{BrokenRelease, ReleaseOutcome, ReleaseWait};

use super::editor::{MmEditor, NotNow};
use super::grant::MmRefusal;
use super::grant::{GrantPayload, GrantState};
use super::mm::{MmKey, MmRecord};
use super::{CarrierCore, CarrierId, CoreVenue, Refusal, Refused, Violation};

/// Where an MM is in its life.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MmLife {
    Live,
    /// Its last member left; it waits for (or was deferred in) its release.
    Exiting,
    /// A [`ReleaseTicket`] for it is out.
    Releasing,
}

/// The release of one exiting MM is owed to the shell.
#[must_use = "a release ticket must be finished with CarrierCore::finish_release"]
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Clone, Hash))]
pub struct ReleaseTicket {
    carrier: CarrierId,
    mm: MmKey,
}

impl ReleaseTicket {
    pub const fn mm(&self) -> MmKey {
        self.mm
    }
}

/// Seeded mutants for the explorer (#3061 PR 1b): each one breaks one rule
/// of the release, and the explorer must find it. Outside tests no mutant is
/// ever active, so every mutant branch folds away.
pub(super) mod mutant {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(in super::super) enum Mutant {
        None,
        /// `finish_release` retires the MM on "not now".
        NotNowRetires,
        /// `begin_release` admits a live MM.
        ReleasesLive,
        /// `exit_mm` leaves the MM live, so a host edit is still admitted.
        EditsAfterExit,
        /// `finish_release` reads `Broken` as "not now".
        BrokenDefers,
    }

    #[cfg(test)]
    std::thread_local! {
        static ACTIVE: core::cell::Cell<Mutant> = const { core::cell::Cell::new(Mutant::None) };
    }

    #[cfg(test)]
    pub(in super::super) fn active() -> Mutant {
        ACTIVE.with(core::cell::Cell::get)
    }

    #[cfg(not(test))]
    #[inline(always)]
    pub(in super::super) const fn active() -> Mutant {
        Mutant::None
    }

    /// Run `run` with `mutant` active on this thread.
    #[cfg(test)]
    pub(in super::super) fn with<T>(mutant: Mutant, run: impl FnOnce() -> T) -> T {
        ACTIVE.with(|cell| cell.set(mutant));
        let out = run();
        ACTIVE.with(|cell| cell.set(Mutant::None));
        out
    }
}

use mutant::Mutant as M;

fn mutated(which: M) -> bool {
    mutant::active() == which
}

impl<V: CoreVenue, M_, B, G: GrantPayload> CarrierCore<V, M_, B, G> {
    /// The MM's last member left. It is admitted if the core never saw it.
    /// Idempotent while it is `Exiting`. A guest hold of its editor is "not
    /// now" (the member's exit releases it); a host edit in progress, or a
    /// release already out, is a shell that nested two transitions.
    pub fn exit_mm(&mut self, mm: MmKey) -> Result<(), MmRefusal> {
        let record = self.mms.entry(mm).or_insert_with(MmRecord::admitted);
        match (record.life, record.editor) {
            (MmLife::Exiting, _) => Ok(()),
            (MmLife::Releasing, _) => Err(MmRefusal::Refused(Refusal::InFlight)),
            (MmLife::Live, MmEditor::Free) => {
                if !mutated(M::EditsAfterExit) {
                    record.life = MmLife::Exiting;
                }
                Ok(())
            }
            (MmLife::Live, MmEditor::Guest) => Err(MmRefusal::NotNow(NotNow::EditorRelease(mm))),
            (MmLife::Live, MmEditor::Host(_)) => Err(MmRefusal::Refused(Refusal::InFlight)),
        }
    }

    /// Phase 1 of an exiting MM's release: it becomes `Releasing`, and its
    /// grants (provisioned payloads; a grant still supplying can't exist,
    /// L1) come back for the shell to drop after it unlocks. Its arena
    /// chunks leave the core with it, as the shell's chunk mappings leave
    /// with the MM's own retirement. A live MM is refused: releasing it would
    /// pull memory out from under its members.
    pub fn begin_release(&mut self, mm: MmKey) -> Result<(ReleaseTicket, Vec<G>), MmRefusal> {
        let record = self.mms.entry(mm).or_insert_with(|| MmRecord {
            life: MmLife::Exiting,
            ..MmRecord::admitted()
        });
        match record.life {
            MmLife::Exiting => {}
            MmLife::Live if mutated(M::ReleasesLive) => {}
            MmLife::Live => return Err(MmRefusal::Refused(Refusal::Live)),
            MmLife::Releasing => return Err(MmRefusal::Refused(Refusal::InFlight)),
        }
        record.life = MmLife::Releasing;
        record.chunk = None;
        self.chunks.retain(|_, chunk| chunk.mm != mm);
        let bases: Vec<u64> = self
            .grants
            .iter()
            .filter(|(_, g)| g.mm == mm)
            .map(|(&base, _)| base)
            .collect();
        let mut returned = Vec::new();
        for base in bases {
            if let Some(grant) = self.grants.remove(&base)
                && let GrantState::Provisioned(payload) = grant.state
            {
                returned.push(payload);
            }
        }
        Ok((
            ReleaseTicket {
                carrier: self.carrier,
                mm,
            },
            returned,
        ))
    }

    /// Phase 2: the shell's outcome for the release. `Done` retires the MM
    /// (its record leaves the core); `NotNow` returns it to `Exiting`;
    /// `Broken` leaves it `Releasing`, and the venue ends the carrier. The
    /// outcome comes back for the shell to act on.
    pub fn finish_release(
        &mut self,
        ticket: ReleaseTicket,
        outcome: ReleaseOutcome,
    ) -> Result<ReleaseOutcome, Refused<ReleaseTicket>> {
        let owed = ticket.carrier == self.carrier
            && self
                .mms
                .get(&ticket.mm)
                .is_some_and(|record| record.life == MmLife::Releasing);
        if !owed {
            return Err(Refused {
                offered: ticket,
                reason: Refusal::NotFound,
            });
        }
        match outcome {
            ReleaseOutcome::Done => {
                self.mms.remove(&ticket.mm);
            }
            ReleaseOutcome::NotNow(_) if mutated(M::NotNowRetires) => {
                self.mms.remove(&ticket.mm);
            }
            ReleaseOutcome::NotNow(_) => {
                if let Some(record) = self.mms.get_mut(&ticket.mm) {
                    record.life = MmLife::Exiting;
                }
            }
            ReleaseOutcome::Broken(_) if mutated(M::BrokenDefers) => {
                if let Some(record) = self.mms.get_mut(&ticket.mm) {
                    record.life = MmLife::Exiting;
                }
                return Ok(ReleaseOutcome::NotNow(ReleaseWait::NextDrain));
            }
            ReleaseOutcome::Broken(_) => {}
        }
        Ok(outcome)
    }
}

impl<V: CoreVenue, M_, B, G> CarrierCore<V, M_, B, G> {
    /// The core's view of an MM's life; `None` if it was never admitted or
    /// has retired.
    pub fn mm_life(&self, mm: MmKey) -> Option<MmLife> {
        self.mms.get(&mm).map(|record| record.life)
    }

    /// L1 and L2.
    pub(super) fn check_release_invariants(&self) -> Result<(), Violation> {
        for (&mm, record) in &self.mms {
            if record.life != MmLife::Live && record.editor != MmEditor::Free {
                return Err(Violation::EditorAfterExit);
            }
            if record.life == MmLife::Releasing
                && (record.chunk.is_some()
                    || self.grants.values().any(|g| g.mm == mm)
                    || self.chunks.values().any(|c| c.mm == mm))
            {
                return Err(Violation::ReleasingHolds);
            }
        }
        Ok(())
    }
}
