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
//! Replacements come from a **per-MM arena** (#3099): the core carves each
//! grant from the MM's current chunk, and asks the shell for a new chunk
//! ([`CowSupply::NeedsChunk`]) only when the MM has none with room. The shell
//! installs one backend mapping per chunk (one KVM memslot for 128 grants),
//! never one per grant, and the chunk lives exactly as long as its MM: it
//! leaves the core with [`CarrierCore::retire_mm`], as the shell's chunk
//! mapping leaves with the MM's retirement.
//!
//! Invariants, checked by [`CarrierCore::check_invariants`]:
//! - **G1** no two grants' replacement extents overlap;
//! - **G2** every grant names an admitted MM;
//! - **G3** a grant is `Supplying` exactly while its MM's editor is
//!   `Host(CowSupply(that grant))`;
//! - **G4** every grant lies inside the carved prefix of a chunk of its own
//!   MM; chunks never overlap, are of the arena's chunk size and belong to
//!   an admitted MM; an MM has at most one chunk with room, and its record
//!   names exactly that one.

use alloc::vec::Vec;
use core::num::NonZeroU64;

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

/// The sizes of an MM's replacement arena: each grant, and each chunk the
/// shell maps for grants to be carved from.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CowArenaGeometry {
    grant: NonZeroU64,
    chunk: NonZeroU64,
}

impl CowArenaGeometry {
    /// Production: 16 KiB grants (`COW_GRANT_SIZE`) from 2 MiB chunks, so
    /// one backend mapping serves 128 copy-on-write pages.
    pub const PRODUCTION: Self = Self {
        grant: NonZeroU64::new(carrick_core_abi::COW_GRANT_SIZE).unwrap(),
        chunk: NonZeroU64::new(2 * 1024 * 1024).unwrap(),
    };

    /// `None` unless the grant is a power of two and the chunk a non-zero
    /// multiple of it.
    pub const fn new(grant: u64, chunk: u64) -> Option<Self> {
        match (NonZeroU64::new(grant), NonZeroU64::new(chunk)) {
            (Some(g), Some(c)) if grant.is_power_of_two() && chunk.is_multiple_of(grant) => {
                Some(Self { grant: g, chunk: c })
            }
            _ => None,
        }
    }
    pub const fn grant(self) -> u64 {
        self.grant.get()
    }
    pub const fn chunk(self) -> u64 {
        self.chunk.get()
    }
}

/// One chunk of an MM's replacement arena. Grants are carved from its base
/// up; `carved` bytes are in use or were.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct ChunkRecord {
    pub(super) mm: MmKey,
    pub(super) extent: GpaExtent,
    pub(super) carved: u64,
}

impl ChunkRecord {
    fn has_room(&self) -> bool {
        self.carved < self.extent.len().get()
    }
    fn carved_end(&self) -> u64 {
        self.extent.ipa() + self.carved
    }
}

/// The excluded MM has no chunk with room: the shell maps one of
/// [`Self::len`] bytes and returns it with [`CarrierCore::admit_chunk`], or
/// reports that it could not with [`CarrierCore::cancel_chunk`]. The MM's
/// editor is recorded as `Host(CowChunk)` while this is out.
#[must_use = "a chunk demand must be answered with admit_chunk or cancel_chunk"]
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Clone, Hash))]
pub struct ChunkDemand {
    carrier: CarrierId,
    mm: MmKey,
    len: u64,
}

impl ChunkDemand {
    pub fn mm(&self) -> MmKey {
        self.mm
    }
    /// The chunk size; the shell aligns the chunk to the grant size.
    pub fn len(&self) -> u64 {
        self.len
    }
}

/// What a copy-on-write supply needs next.
#[must_use = "a COW supply must be finished or its chunk demand answered"]
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Clone, Hash))]
pub enum CowSupply {
    /// A grant was carved from the MM's current chunk: the shell publishes
    /// it (no backend mapping call) and finishes the ticket.
    Carved(SupplyTicket),
    /// The MM's arena has no room: the shell maps a chunk first.
    NeedsChunk(ChunkDemand),
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

    /// The geometry this core carves replacement arenas with.
    pub fn cow_geometry(&self) -> CowArenaGeometry {
        self.cow_geometry
    }

    /// Use `geometry` for every arena (explorer and tests: a small chunk).
    /// Refused once any chunk exists.
    pub fn set_cow_geometry(&mut self, geometry: CowArenaGeometry) -> Result<(), Refusal> {
        if !self.chunks.is_empty() {
            return Err(Refusal::InFlight);
        }
        self.cow_geometry = geometry;
        Ok(())
    }

    /// The next grant id, or `Exhausted`.
    fn next_grant_id(&self) -> Result<(GrantId, u64), MmRefusal> {
        let next = self
            .next_grant
            .checked_add(1)
            .ok_or(MmRefusal::Refused(Refusal::Exhausted))?;
        Ok((
            GrantId {
                carrier: self.carrier,
                raw: self.next_grant,
            },
            next,
        ))
    }

    /// Carve the next grant of the chunk at `base` for `mm` and record it
    /// `Supplying`. The caller has checked the chunk has room and set the
    /// MM's editor to `Host(CowSupply(grant))`.
    fn carve_grant(&mut self, base: u64, grant: GrantId, next: u64) -> Option<SupplyTicket> {
        let size = self.cow_geometry.grant();
        let chunk = self.chunks.get_mut(&base)?;
        let extent = GpaExtent::new(chunk.carved_end(), size)?;
        let mm = chunk.mm;
        chunk.carved += size;
        let room = chunk.has_room();
        if let Some(record) = self.mms.get_mut(&mm) {
            record.chunk = room.then_some(base);
        }
        self.next_grant = next;
        self.grants.insert(
            extent.ipa(),
            CowGrantRecord {
                id: grant,
                mm,
                extent,
                state: GrantState::Supplying,
            },
        );
        Some(SupplyTicket { grant, mm, extent })
    }

    /// Supply one copy-on-write demand of the excluded MM, for the page at
    /// `page`. The grant is carved from the MM's current chunk when it has
    /// room ([`CowSupply::Carved`]); otherwise the shell maps a chunk first
    /// ([`CowSupply::NeedsChunk`]). The demand is the same whether an EL0
    /// write fault or a kernel user copy published it. A refusal leaves the
    /// core unchanged.
    pub fn supply_cow(
        &mut self,
        excluded: &ExcludedMm<'_>,
        page: u64,
    ) -> Result<CowSupply, MmRefusal> {
        if page & 0xfff != 0 {
            return Err(MmRefusal::Refused(Refusal::NotFound));
        }
        let (grant, next) = self.next_grant_id()?;
        let current = self.mms.get(&excluded.mm()).and_then(|record| record.chunk);
        let Some(base) = current else {
            // The last check: a refusal here leaves the core unchanged.
            self.take_editor(excluded, HostEdit::CowChunk)?;
            return Ok(CowSupply::NeedsChunk(ChunkDemand {
                carrier: self.carrier,
                mm: excluded.mm(),
                len: self.cow_geometry.chunk(),
            }));
        };
        self.take_editor(excluded, HostEdit::CowSupply(grant))?;
        match self.carve_grant(base, grant, next) {
            Some(ticket) => Ok(CowSupply::Carved(ticket)),
            // G4 says the current chunk exists and has room.
            None => Err(MmRefusal::Refused(Refusal::NotFound)),
        }
    }

    /// The shell mapped `extent` as a chunk of the demanding MM's arena:
    /// admit it and carve the demand's grant from it. A refusal (another
    /// carrier's demand, the wrong size or alignment, an overlap with a
    /// chunk) hands the demand back with nothing changed; the shell then
    /// unmaps the extent and cancels.
    pub fn admit_chunk(
        &mut self,
        demand: ChunkDemand,
        extent: GpaExtent,
    ) -> Result<SupplyTicket, Refused<ChunkDemand>> {
        let refuse = |demand, reason| {
            Err(Refused {
                offered: demand,
                reason,
            })
        };
        let owed = demand.carrier == self.carrier
            && self.mms.get(&demand.mm).map(|m| m.editor)
                == Some(MmEditor::Host(HostEdit::CowChunk));
        if !owed {
            return refuse(demand, Refusal::NotFound);
        }
        if extent.len().get() != self.cow_geometry.chunk()
            || !extent.ipa().is_multiple_of(self.cow_geometry.grant())
        {
            return refuse(demand, Refusal::NotInsideAnInstalledMapping);
        }
        if super::collides(&self.chunks, extent, |c| c.extent.end()) {
            return refuse(demand, Refusal::Collision);
        }
        let Ok((grant, next)) = self.next_grant_id() else {
            return refuse(demand, Refusal::Exhausted);
        };
        self.chunks.insert(
            extent.ipa(),
            ChunkRecord {
                mm: demand.mm,
                extent,
                carved: 0,
            },
        );
        if let Some(record) = self.mms.get_mut(&demand.mm) {
            record.editor = MmEditor::Host(HostEdit::CowSupply(grant));
        }
        match self.carve_grant(extent.ipa(), grant, next) {
            Some(ticket) => Ok(ticket),
            None => refuse(demand, Refusal::NotFound),
        }
    }

    /// The shell could not map the demanded chunk: return the MM's editor
    /// to its exclusion, with nothing supplied.
    pub fn cancel_chunk(&mut self, demand: ChunkDemand) -> Result<(), Refused<ChunkDemand>> {
        match self.mms.get_mut(&demand.mm) {
            Some(record)
                if demand.carrier == self.carrier
                    && record.editor == MmEditor::Host(HostEdit::CowChunk) =>
            {
                record.editor = MmEditor::Free;
                Ok(())
            }
            _ => Err(Refused {
                offered: demand,
                reason: Refusal::NotFound,
            }),
        }
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
                // The grant was its chunk's last carve (the MM's editor
                // kept every other carve out): give the space back.
                if let Some((&base, chunk)) = self
                    .chunks
                    .range_mut(..=ticket.extent.ipa())
                    .next_back()
                    .filter(|(_, c)| c.carved_end() == ticket.extent.end())
                {
                    chunk.carved -= ticket.extent.len().get();
                    if let Some(record) = self.mms.get_mut(&ticket.mm) {
                        record.chunk = Some(base);
                    }
                }
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
        // Its arena goes with it: the shell's chunk mappings retire with
        // the MM (on x86, `CarrierMemory::retire_child`).
        self.chunks.retain(|_, chunk| chunk.mm != mm);
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

    /// How many arena chunks the core holds, over every MM.
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
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

    /// G4: the arenas.
    fn check_arena_invariants(&self) -> Result<(), super::Violation> {
        use super::Violation;
        let geometry = self.cow_geometry;
        let mut previous_end = None;
        for (&base, chunk) in &self.chunks {
            if base != chunk.extent.ipa() {
                return Err(Violation::IndexKey);
            }
            if previous_end.is_some_and(|end| end > base) {
                return Err(Violation::ChunksOverlap);
            }
            previous_end = Some(chunk.extent.end());
            let room = chunk.has_room();
            if chunk.extent.len().get() != geometry.chunk()
                || !base.is_multiple_of(geometry.grant())
                || chunk.carved > geometry.chunk()
                || !chunk.carved.is_multiple_of(geometry.grant())
            {
                return Err(Violation::ChunkShape);
            }
            let Some(record) = self.mms.get(&chunk.mm) else {
                return Err(Violation::ChunkWithoutMm);
            };
            if room != (record.chunk == Some(base)) {
                return Err(Violation::ChunkRoom);
            }
        }
        for (mm, record) in &self.mms {
            if let Some(base) = record.chunk
                && self
                    .chunks
                    .get(&base)
                    .is_none_or(|chunk| chunk.mm != *mm || !chunk.has_room())
            {
                return Err(Violation::ChunkRoom);
            }
        }
        for grant in self.grants.values() {
            let inside = super::holder(&self.chunks, grant.extent.ipa(), |c| c.extent.end())
                .is_some_and(|(_, chunk)| {
                    chunk.mm == grant.mm
                        && grant.extent.len().get() == geometry.grant()
                        && grant.extent.end() <= chunk.carved_end()
                });
            if !inside {
                return Err(Violation::GrantOutsideChunk);
            }
        }
        Ok(())
    }

    /// G1 to G4.
    pub(super) fn check_grant_invariants(&self) -> Result<(), super::Violation> {
        use super::Violation;
        self.check_arena_invariants()?;
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
