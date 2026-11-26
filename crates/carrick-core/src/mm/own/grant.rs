//! Copy-on-write replacement grants, owned by their MM (#3061, PR 1a).
//!
//! A COW grant is one replacement compound the carrier publishes to an MM's
//! guest pool. Any member of that MM may claim it, for any of its COW pages,
//! from either CPU, so the grant belongs to the MM, never to the CPU or lane
//! that asked (#2749). It has three transitions, each under an exclusion of
//! its MM:
//! - [`CarrierCore::supply_cow`] reserves the replacement extent and records
//!   the MM's editor as `Host(CowSupply)`. The demand is the same whether an
//!   EL0 write fault or a kernel user copy published it: the core never
//!   knows which. The shell then maps and publishes the grant, and reports
//!   with [`CarrierCore::finish_supply_cow`]: `Published` makes it
//!   `Provisioned`, holding the shell's payload; `Failed` releases the
//!   reservation.
//! - [`CarrierCore::begin_settle`], [`CarrierCore::settle_cow`] and
//!   [`CarrierCore::finish_settle`] hand back, one by one, the completed
//!   grants the guest's receipts name, for the shell to publish.
//! - [`CarrierCore::retire_mm`] returns every grant of a retired MM, claimed
//!   or not: no member is left to complete one.
//!
//! Invariants, checked by [`CarrierCore::check_invariants`]:
//! - **G1** no two grants' replacement extents overlap;
//! - **G2** every grant names an admitted MM;
//! - **G3** a grant is `Supplying` exactly while its MM's editor is
//!   `Host(CowSupply(that grant))`.

use alloc::vec::Vec;

use super::editor::{ExcludedMm, HostEdit, MmEditor, NotNow};
use super::mm::{MmKey, MmRecord};
use super::{CarrierCore, CarrierId, CoreVenue, GpaExtent, Refusal, Refused};

/// The shell's record of one published grant, and the incarnation its
/// guest completion names.
pub trait GrantPayload {
    /// Equal only for the same publication, never for a successor over the
    /// same extent.
    type Key: Eq;
    fn key(&self) -> &Self::Key;
}

/// One grant of one carrier.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct GrantId {
    pub(super) carrier: CarrierId,
    pub(super) raw: u64,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) enum GrantState<G> {
    /// The shell is mapping and publishing it under the MM's exclusion.
    Supplying,
    /// Published to the MM's pool; holds the shell's payload until its
    /// completion settles or the MM retires.
    Provisioned(G),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct CowGrantRecord<G> {
    pub(super) id: GrantId,
    pub(super) mm: MmKey,
    pub(super) extent: GpaExtent,
    pub(super) state: GrantState<G>,
}

/// One copy-on-write demand of an excluded MM: the faulting page and the
/// replacement extent the shell will map for it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CowDemand {
    pub page: u64,
    pub replacement: GpaExtent,
}

/// A supply is owed to the shell's backend and pool.
#[must_use = "a supply ticket must be finished with CarrierCore::finish_supply_cow"]
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Clone, Hash))]
pub struct SupplyTicket {
    grant: GrantId,
    mm: MmKey,
    extent: GpaExtent,
}

impl SupplyTicket {
    pub fn grant(&self) -> GrantId {
        self.grant
    }
    pub fn mm(&self) -> MmKey {
        self.mm
    }
    pub fn extent(&self) -> GpaExtent {
        self.extent
    }
}

/// The shell's report on a supply.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Supplied<G> {
    /// Mapped and published to the MM's pool.
    Published(G),
    /// The map or the publication failed and left nothing exposed.
    Failed,
}

/// Why an MM transition did not run.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MmRefusal {
    NotNow(NotNow),
    Refused(Refusal),
}

/// The MM's editor is recorded as `Host(Settle)` while this is out.
#[must_use = "a settle proof must be returned with CarrierCore::finish_settle"]
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Clone, Hash))]
pub struct SettleProof {
    carrier: CarrierId,
    mm: MmKey,
}

impl SettleProof {
    pub fn mm(&self) -> MmKey {
        self.mm
    }
}

impl<V: CoreVenue, M, B, G: GrantPayload> CarrierCore<V, M, B, G> {
    /// Admit `mm` if it is new, and take its editor for `edit`. The guest's
    /// hold is "not now"; a host edit already in progress is a shell that
    /// nested two transitions, a broken invariant.
    fn take_editor(&mut self, excluded: &ExcludedMm<'_>, edit: HostEdit) -> Result<(), MmRefusal> {
        let record = self
            .mms
            .entry(excluded.mm())
            .or_insert_with(MmRecord::admitted);
        match record.editor {
            MmEditor::Free => {
                record.editor = MmEditor::Host(edit);
                Ok(())
            }
            MmEditor::Guest => Err(MmRefusal::NotNow(NotNow::EditorRelease(excluded.mm()))),
            MmEditor::Host(_) => Err(MmRefusal::Refused(Refusal::InFlight)),
        }
    }

    /// Reserve a replacement grant for one COW demand of the excluded MM.
    /// The shell maps and publishes it, then reports with
    /// [`Self::finish_supply_cow`]. A refusal leaves the core unchanged.
    pub fn supply_cow(
        &mut self,
        excluded: &ExcludedMm<'_>,
        demand: CowDemand,
    ) -> Result<SupplyTicket, MmRefusal> {
        let extent = demand.replacement;
        if demand.page & 0xfff != 0 {
            return Err(MmRefusal::Refused(Refusal::NotFound));
        }
        if super::collides(&self.grants, extent, |g| g.extent.end()) {
            return Err(MmRefusal::Refused(Refusal::Collision));
        }
        let Some(next) = self.next_grant.checked_add(1) else {
            return Err(MmRefusal::Refused(Refusal::Exhausted));
        };
        let grant = GrantId {
            carrier: self.carrier,
            raw: self.next_grant,
        };
        // The last check: a refusal here leaves the core unchanged.
        self.take_editor(excluded, HostEdit::CowSupply(grant))?;
        self.next_grant = next;
        self.grants.insert(
            extent.ipa(),
            CowGrantRecord {
                id: grant,
                mm: excluded.mm(),
                extent,
                state: GrantState::Supplying,
            },
        );
        Ok(SupplyTicket {
            grant,
            mm: excluded.mm(),
            extent,
        })
    }

    /// The shell reported on a supply. `Published` provisions the grant with
    /// its payload; `Failed` releases the reservation. Either way the MM's
    /// editor returns to the shell's exclusion (`Free` in the core).
    pub fn finish_supply_cow(
        &mut self,
        ticket: SupplyTicket,
        outcome: Supplied<G>,
    ) -> Result<GrantId, Refused<(SupplyTicket, Supplied<G>)>> {
        let owed = self
            .grants
            .get(&ticket.extent.ipa())
            .is_some_and(|g| g.id == ticket.grant && matches!(g.state, GrantState::Supplying))
            && self.mms.get(&ticket.mm).map(|m| m.editor)
                == Some(MmEditor::Host(HostEdit::CowSupply(ticket.grant)));
        if !owed {
            return Err(Refused {
                offered: (ticket, outcome),
                reason: Refusal::NotFound,
            });
        }
        if let Some(record) = self.mms.get_mut(&ticket.mm) {
            record.editor = MmEditor::Free;
        }
        match outcome {
            Supplied::Published(payload) => {
                if let Some(grant) = self.grants.get_mut(&ticket.extent.ipa()) {
                    grant.state = GrantState::Provisioned(payload);
                }
            }
            Supplied::Failed => {
                self.grants.remove(&ticket.extent.ipa());
            }
        }
        Ok(ticket.grant)
    }

    /// Take the excluded MM's editor to settle its completed grants.
    pub fn begin_settle(&mut self, excluded: &ExcludedMm) -> Result<SettleProof, MmRefusal> {
        self.take_editor(excluded, HostEdit::Settle)?;
        Ok(SettleProof {
            carrier: self.carrier,
            mm: excluded.mm(),
        })
    }

    /// Hand back the provisioned grant of the settling MM that `key` names,
    /// for the shell to publish. A key of another MM's grant, of a grant
    /// still being supplied, or of no grant is refused: a completion settles
    /// only under its own MM's exclusion.
    pub fn settle_cow(&mut self, proof: &SettleProof, key: &G::Key) -> Result<G, Refusal> {
        if proof.carrier != self.carrier
            || self.mms.get(&proof.mm).map(|m| m.editor) != Some(MmEditor::Host(HostEdit::Settle))
        {
            return Err(Refusal::NotFound);
        }
        let base = self
            .grants
            .iter()
            .find(|(_, g)| {
                g.mm == proof.mm
                    && matches!(&g.state, GrantState::Provisioned(payload) if payload.key() == key)
            })
            .map(|(&base, _)| base)
            .ok_or(Refusal::NotFound)?;
        match self.grants.remove(&base).map(|g| g.state) {
            Some(GrantState::Provisioned(payload)) => Ok(payload),
            _ => Err(Refusal::NotFound),
        }
    }

    /// Return the settling MM's editor to the shell's exclusion.
    pub fn finish_settle(&mut self, proof: SettleProof) -> Result<(), Refused<SettleProof>> {
        match self.mms.get_mut(&proof.mm) {
            Some(record)
                if proof.carrier == self.carrier
                    && record.editor == MmEditor::Host(HostEdit::Settle) =>
            {
                record.editor = MmEditor::Free;
                Ok(())
            }
            _ => Err(Refused {
                offered: proof,
                reason: Refusal::NotFound,
            }),
        }
    }

    /// The MM left the carrier: every grant it holds, claimed or not, comes
    /// back to the shell, and its record goes. "Not now" while the guest
    /// holds its editor; a host edit in progress is a broken invariant.
    pub fn retire_mm(&mut self, mm: MmKey) -> Result<Vec<G>, MmRefusal> {
        match self.mms.get(&mm).map(|record| record.editor) {
            None => return Ok(Vec::new()),
            Some(MmEditor::Free) => {}
            Some(MmEditor::Guest) => return Err(MmRefusal::NotNow(NotNow::EditorRelease(mm))),
            Some(MmEditor::Host(_)) => return Err(MmRefusal::Refused(Refusal::InFlight)),
        }
        self.mms.remove(&mm);
        let mut returned = Vec::new();
        let bases: Vec<u64> = self
            .grants
            .iter()
            .filter(|(_, g)| g.mm == mm)
            .map(|(&base, _)| base)
            .collect();
        for base in bases {
            if let Some(CowGrantRecord {
                state: GrantState::Provisioned(payload),
                ..
            }) = self.grants.remove(&base)
            {
                returned.push(payload);
            }
        }
        Ok(returned)
    }

    /// The carrier is ending: every MM retires. Refused, with nothing
    /// changed, while any editor is held.
    pub fn retire_all_mms(&mut self) -> Result<Vec<G>, MmRefusal> {
        if let Some((&mm, record)) = self
            .mms
            .iter()
            .find(|(_, record)| record.editor != MmEditor::Free)
        {
            return Err(match record.editor {
                MmEditor::Guest => MmRefusal::NotNow(NotNow::EditorRelease(mm)),
                _ => MmRefusal::Refused(Refusal::InFlight),
            });
        }
        let mut returned = Vec::new();
        let mms: Vec<MmKey> = self.mms.keys().copied().collect();
        for mm in mms {
            returned.extend(self.retire_mm(mm)?);
        }
        Ok(returned)
    }

    /// How many grants the core holds, in any state.
    pub fn grant_count(&self) -> usize {
        self.grants.len()
    }

    /// The editor state of `mm`, if it is admitted.
    pub fn editor(&self, mm: MmKey) -> Option<MmEditor> {
        self.mms.get(&mm).map(|record| record.editor)
    }
}

impl<V: CoreVenue, M, B, G> CarrierCore<V, M, B, G> {
    /// The guest adversary takes or releases an MM's editor (explorer and
    /// loom only; in production the guest's own try-lock is that state).
    #[cfg(test)]
    pub(super) fn guest_editor(&mut self, mm: MmKey, hold: bool) -> bool {
        let record = self.mms.entry(mm).or_insert_with(MmRecord::admitted);
        match (record.editor, hold) {
            (MmEditor::Free, true) => record.editor = MmEditor::Guest,
            (MmEditor::Guest, false) => record.editor = MmEditor::Free,
            _ => return false,
        }
        true
    }

    /// G1 to G3.
    pub(super) fn check_grant_invariants(&self) -> Result<(), super::Violation> {
        use super::Violation;
        let mut previous_end = None;
        for (&base, grant) in &self.grants {
            if base != grant.extent.ipa() || grant.id.carrier != self.carrier {
                return Err(Violation::IndexKey);
            }
            if previous_end.is_some_and(|end| end > base) {
                return Err(Violation::GrantsOverlap);
            }
            previous_end = Some(grant.extent.end());
            let Some(record) = self.mms.get(&grant.mm) else {
                return Err(Violation::GrantWithoutMm);
            };
            let supplying = matches!(grant.state, GrantState::Supplying);
            let edited = record.editor == MmEditor::Host(HostEdit::CowSupply(grant.id));
            if supplying != edited {
                return Err(Violation::SupplyWithoutEditor);
            }
        }
        for record in self.mms.values() {
            if let MmEditor::Host(HostEdit::CowSupply(id)) = record.editor
                && !self
                    .grants
                    .values()
                    .any(|g| g.id == id && matches!(g.state, GrantState::Supplying))
            {
                return Err(Violation::SupplyWithoutEditor);
            }
        }
        Ok(())
    }
}
