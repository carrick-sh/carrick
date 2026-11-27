//! The memory-ownership core (#3061), PR 0: one carrier's VM generation,
//! its backend mappings and the frame extents carved inside them, as one
//! state machine with one owner.
//!
//! Every operation is a transition on [`CarrierCore`], taken under the
//! carrier's one lock by its shell. A transition never performs I/O: when the
//! backend must act (map, unmap, destroy) it returns a typed action and a
//! linear ticket, the shell runs the action **after unlocking**, and reports
//! the result back through the ticket (the two-phase rule). The in-flight
//! state reserves its extent, so no second mapper can collide with it.
//!
//! **Who owns what.** A backend mapping owns the host allocation it maps
//! (`M`); the core returns it only once the backend no longer maps it: after
//! a failed map, a successful unmap, or a committed destroy. A frame extent
//! holds a sub-lease (`B`) inside its mapping and its host address is derived
//! from the mapping's, so releasing an extent never frees mapped memory.
//!
//! The invariants of #3061 that this slice owns, checked by
//! [`CarrierCore::check_invariants`] after every transition in the bounded
//! explorer (`own/explore.rs`) and in the loom model:
//! - **V1** no two backend mappings overlap, in any state;
//! - **V2** no two frame extents overlap;
//! - **V3** every frame extent that is not terminalized lies inside exactly
//!   one `Installed` backend mapping, whose carve count matches;
//! - **V4** a backend action is issued only for a `Creating` or `Live`
//!   generation, and once a destroy commits no backend mapping survives;
//! - **V5** a pinned extent is never released, and only a live extent is
//!   found or pinned;
//! - **V6** nothing is dropped silently: a core whose generation is not
//!   `Vacant` or `Gone`, or that still holds a mapping, an extent or a
//!   copy-on-write grant, or whose shell still holds an MM's editor, is a
//!   broken invariant reported through its venue.
//!
//! PR 1a adds the MMs (`own/mm.rs`), their editor (`own/editor.rs`) and
//! their copy-on-write grants (`own/grant.rs`, invariants G1 to G3).
//! `own/holds.rs` owns each backing slot's holders, so a slot is released
//! exactly when its last holder lets go (#3127, invariants H1 to H3).
//!
//! The index structure is the step-1a table (#1236): records never overlap,
//! so the only record that can hold an address is the one with the greatest
//! base at or below it, and every address lookup is one ordered-map probe.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::num::NonZeroU64;

mod editor;
#[cfg(test)]
mod explore;
mod grant;
mod holds;
mod mm;
mod release;

pub use editor::{ExcludedMm, HostEdit, MmEditor, NotNow};
pub use grant::{
    ChunkDemand, CowArenaGeometry, CowSupply, GrantId, GrantPayload, MmRefusal, SettleProof,
    Supplied, SupplyTicket,
};
pub use holds::{DrainContext, HoldError, HoldRetirement, SlotHolds};
pub use mm::MmKey;
pub use release::{BrokenRelease, MmLife, ReleaseOutcome, ReleaseTicket, ReleaseWait};
#[cfg(all(test, feature = "loom"))]
mod loom_models;
#[cfg(all(test, not(feature = "loom")))]
mod tests;

/// What a dropped core still held.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Holding {
    pub state: GenerationState,
    pub mappings: usize,
    pub extents: usize,
    pub grants: usize,
    /// Replacement-arena chunks of MMs that never retired.
    pub chunks: usize,
    /// MMs whose editor the shell or the guest still holds.
    pub editors: usize,
}

/// The shell's answer to a broken invariant. Production venues end the
/// carrier (`carrick_fatal`, which aborts without unwinding); the core itself
/// never aborts.
pub trait CoreVenue {
    /// A core was dropped holding something: its generation was not ended,
    /// or a mapping or extent was never settled.
    fn dropped_holding(holding: Holding) -> !;
}

/// A non-empty guest-physical extent `[ipa, ipa + len)` whose end does not
/// overflow.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct GpaExtent {
    ipa: u64,
    len: NonZeroU64,
}

impl GpaExtent {
    /// `None` for an empty extent or one whose end overflows.
    pub fn new(ipa: u64, len: u64) -> Option<Self> {
        let len = NonZeroU64::new(len)?;
        ipa.checked_add(len.get())?;
        Some(Self { ipa, len })
    }
    pub const fn ipa(self) -> u64 {
        self.ipa
    }
    pub const fn len(self) -> NonZeroU64 {
        self.len
    }
    /// One past the last address; construction proved it doesn't overflow.
    pub const fn end(self) -> u64 {
        self.ipa.wrapping_add(self.len.get())
    }
    pub const fn contains(self, other: Self) -> bool {
        other.ipa >= self.ipa && other.end() <= self.end()
    }
    pub const fn overlaps(self, other: Self) -> bool {
        self.ipa < other.end() && other.ipa < self.end()
    }
}

/// The carrier a core belongs to. Every token and record id carries it, so
/// one core refuses another's.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct CarrierId(NonZeroU64);

impl CarrierId {
    /// # Safety
    ///
    /// No other live [`CarrierCore`] may hold this id: two cores with one id
    /// would accept each other's tickets and pins. The shell's carrier
    /// allocator (a monotonic, never-reused carrier identity) upholds this.
    pub const unsafe fn assume_unique(raw: NonZeroU64) -> Self {
        Self(raw)
    }
    /// A carrier identity never issued before in this process, from the one
    /// carrier allocator: a carrier shell's own VM identity is drawn from
    /// it too (x86 `CarrierVmId`), so the core and its carrier share it.
    pub fn allocate() -> Option<Self> {
        static CARRIERS: carrick_sched_core::process::identity_allocator::SerialAllocator =
            carrick_sched_core::process::identity_allocator::SerialAllocator::new();
        CARRIERS.allocate().map(Self)
    }
    pub const fn raw(self) -> NonZeroU64 {
        self.0
    }
}

/// One VM incarnation of the carrier; every token carries it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct GenerationId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GenerationState {
    Vacant,
    Creating,
    Live,
    Destroying,
    Gone,
}

/// One backend mapping of one carrier.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct MappingId {
    carrier: CarrierId,
    raw: u64,
}

/// One frame extent of one carrier.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct ExtentId {
    carrier: CarrierId,
    raw: u64,
}

impl ExtentId {
    /// The extent's grant token: never zero, unique in its carrier and never
    /// reused, so a successor carved over the same range carries another.
    pub const fn token(self) -> u64 {
        self.raw
    }
}

/// A read-only view of one live frame extent and its lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveExtentView<'a, B> {
    pub id: ExtentId,
    pub extent: GpaExtent,
    pub host_addr: usize,
    pub lease: &'a B,
}

/// A read-only view of one installed backend mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstalledView<'a, M> {
    pub id: MappingId,
    pub extent: GpaExtent,
    pub host_addr: usize,
    pub host: &'a M,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MappingState {
    /// The backend map is in flight; the extent is reserved.
    Mapping,
    Installed,
    /// The backend unmap is in flight; nothing is carved inside.
    Unmapping,
}

/// What a caller maps: the extent, the host address mapped at its base, and
/// the host allocation `M` the mapping owns until the backend lets it go.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MappingSpec<M> {
    pub extent: GpaExtent,
    pub host_addr: usize,
    pub host: M,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Mapping<M> {
    id: MappingId,
    spec: MappingSpec<M>,
    state: MappingState,
    carved: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExtentState {
    Live,
    /// Retirement was requested while pinned; the last unpin releases it.
    Retiring,
    /// Its generation was destroyed while it was pinned: no backend mapping
    /// remains. The shell keeps the host memory alive for the pins (it got
    /// the mapping's `M` back from the destroy) until the last unpin.
    Terminal,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FrameExtent<B> {
    id: ExtentId,
    mapping: MappingId,
    extent: GpaExtent,
    host_addr: usize,
    lease: B,
    state: ExtentState,
    pins: u64,
}

/// Why a transition refused. Contention (`InFlight`) is "not now": the
/// caller keeps its request and reruns it after the in-flight call reports
/// (or, for `create`, after the last terminal pin returns).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Refusal {
    /// The generation is not in a state that admits this transition.
    Generation(GenerationState),
    /// The extent overlaps an existing mapping or extent.
    Collision,
    /// No installed mapping holds the whole extent.
    NotInsideAnInstalledMapping,
    /// The host range is null or overflows.
    HostRange,
    /// Not found, of another carrier, or not in the state the request needs.
    NotFound,
    /// The mapping still has extents carved inside.
    Carved,
    /// A backend call or a terminal pin is outstanding; rerun after it settles.
    InFlight,
    /// An id or pin counter is exhausted.
    Exhausted,
    /// The MM is live: its members may still use what a release would take.
    Live,
}

/// A refusal that hands back what the caller offered.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Refused<T> {
    pub offered: T,
    pub reason: Refusal,
}

/// The backend's result for one action. `Failed` promises the backend left
/// its prior state intact; an uncertain result must end the carrier instead.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BackendResult {
    Done,
    Failed,
}

/// A backend action for the shell to run after it unlocks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BackendAction {
    Map { extent: GpaExtent, host_addr: usize },
    Unmap(GpaExtent),
    Destroy,
}

/// The map of one reserved mapping is owed to the backend.
#[must_use = "a map ticket must be finished with CarrierCore::finish_map"]
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Clone, Hash))]
pub struct MapTicket {
    generation: GenerationId,
    mapping: MappingId,
    extent: GpaExtent,
}

/// The unmap of one mapping is owed to the backend.
#[must_use = "an unmap ticket must be finished with CarrierCore::finish_unmap"]
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Clone, Hash))]
pub struct UnmapTicket {
    generation: GenerationId,
    mapping: MappingId,
    extent: GpaExtent,
}

/// The destroy of the generation is owed to the backend.
#[must_use = "a destroy ticket must be finished with CarrierCore::finish_destroy"]
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Clone, Hash))]
pub struct DestroyTicket {
    carrier: CarrierId,
    generation: GenerationId,
}

/// A pin on one live extent. While it is outstanding the extent is not
/// released. Return it with [`CarrierCore::unpin`].
#[must_use = "a pin must be returned with CarrierCore::unpin"]
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Clone, Hash))]
pub struct Pin {
    extent: ExtentId,
    base: u64,
    selected: GpaExtent,
    host_addr: usize,
}

impl Pin {
    pub fn extent(&self) -> ExtentId {
        self.extent
    }
    pub fn selected(&self) -> GpaExtent {
        self.selected
    }
    /// Host address of `selected().ipa()`.
    pub fn host_addr(&self) -> usize {
        self.host_addr
    }
}

impl MapTicket {
    pub fn mapping(&self) -> MappingId {
        self.mapping
    }
    pub fn extent(&self) -> GpaExtent {
        self.extent
    }
}

impl UnmapTicket {
    pub fn extent(&self) -> GpaExtent {
        self.extent
    }
}

/// Why [`CarrierCore::pin`] refused.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PinRefusal {
    EmptyRange,
    /// No live extent holds the first address. The owner may select again.
    NoLiveExtent,
    /// A live extent holds the first address but the range runs past it.
    Overruns(ExtentId),
    Exhausted(ExtentId),
}

/// An extent leaving the core, with its lease.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Released<B> {
    pub id: ExtentId,
    pub extent: GpaExtent,
    pub lease: B,
}

/// The result of asking to retire an extent.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Retire<B> {
    Released(Released<B>),
    /// Pins are outstanding; the last unpin releases it.
    Deferred,
}

/// What a committed destroy hands back: every mapping's host allocation (the
/// backend no longer maps any of them) and every unpinned extent's lease.
/// Pinned extents stay as terminal until their last unpin.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Destroyed<M, B> {
    pub hosts: Vec<M>,
    pub extents: Vec<Released<B>>,
}

/// See the module documentation.
#[derive(Debug)]
#[cfg_attr(test, derive(Clone, Hash, PartialEq, Eq))]
pub struct CarrierCore<V: CoreVenue, M, B, G = ()> {
    carrier: CarrierId,
    generation: GenerationId,
    state: GenerationState,
    /// The state a destroy started from, restored if the backend refuses it.
    destroy_from: GenerationState,
    next_mapping: u64,
    next_extent: u64,
    mappings: BTreeMap<u64, Mapping<M>>,
    extents: BTreeMap<u64, FrameExtent<B>>,
    next_grant: u64,
    mms: BTreeMap<MmKey, mm::MmRecord>,
    /// Copy-on-write grants, by replacement base (G1: they never overlap).
    grants: BTreeMap<u64, grant::CowGrantRecord<G>>,
    /// The MMs' replacement arenas, by chunk base (G4).
    chunks: BTreeMap<u64, grant::ChunkRecord>,
    cow_geometry: grant::CowArenaGeometry,
    _venue: core::marker::PhantomData<fn() -> V>,
}

/// The one entry of a non-overlapping index that could hold `ipa`.
fn holder<T>(index: &BTreeMap<u64, T>, ipa: u64, end: impl Fn(&T) -> u64) -> Option<(&u64, &T)> {
    index
        .range(..=ipa)
        .next_back()
        .filter(|(_, entry)| end(entry) > ipa)
}

/// Whether any entry of a non-overlapping index overlaps `extent`: only the
/// entry with the greatest base below `extent.end()` can.
fn collides<T>(index: &BTreeMap<u64, T>, extent: GpaExtent, end: impl Fn(&T) -> u64) -> bool {
    index
        .range(..extent.end())
        .next_back()
        .is_some_and(|(_, entry)| end(entry) > extent.ipa())
}

fn host_range_fits(host_addr: usize, extent: GpaExtent) -> bool {
    host_addr != 0
        && usize::try_from(extent.len().get())
            .ok()
            .and_then(|len| host_addr.checked_add(len))
            .is_some()
}

impl<V: CoreVenue, M, B, G> CarrierCore<V, M, B, G> {
    pub fn new(carrier: CarrierId) -> Self {
        Self {
            carrier,
            generation: GenerationId(0),
            state: GenerationState::Vacant,
            destroy_from: GenerationState::Vacant,
            next_mapping: 1,
            next_extent: 1,
            mappings: BTreeMap::new(),
            extents: BTreeMap::new(),
            next_grant: 1,
            mms: BTreeMap::new(),
            grants: BTreeMap::new(),
            chunks: BTreeMap::new(),
            cow_geometry: grant::CowArenaGeometry::PRODUCTION,
            _venue: core::marker::PhantomData,
        }
    }

    pub fn carrier(&self) -> CarrierId {
        self.carrier
    }

    pub fn generation(&self) -> (GenerationId, GenerationState) {
        (self.generation, self.state)
    }

    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }

    pub fn extent_count(&self) -> usize {
        self.extents.len()
    }

    /// The mapping with the greatest base at or below `ipa`, in one index
    /// probe, if it is installed. Mappings never overlap, so it is the only
    /// one that can contain `ipa`; the caller checks how far it reaches. If
    /// that mapping is still being mapped or unmapped, this returns `None`.
    pub fn installed_at_or_below(&self, ipa: u64) -> Option<InstalledView<'_, M>> {
        let (_, mapping) = self.mappings.range(..=ipa).next_back()?;
        (mapping.state == MappingState::Installed).then_some(InstalledView {
            id: mapping.id,
            extent: mapping.spec.extent,
            host_addr: mapping.spec.host_addr,
            host: &mapping.spec.host,
        })
    }

    /// The live frame extent holding `ipa`, in one index probe. A retiring
    /// or terminal extent is not found.
    pub fn live_extent_at(&self, ipa: u64) -> Option<LiveExtentView<'_, B>> {
        let (_, entry) = holder(&self.extents, ipa, |e| e.extent.end())?;
        (entry.state == ExtentState::Live).then_some(LiveExtentView {
            id: entry.id,
            extent: entry.extent,
            host_addr: entry.host_addr,
            lease: &entry.lease,
        })
    }

    /// Every reserved backend extent, in any state, in address order: what
    /// an address allocator must not hand out again.
    pub fn reserved_extents(&self) -> impl Iterator<Item = GpaExtent> + '_ {
        self.mappings.values().map(|mapping| mapping.spec.extent)
    }

    fn in_flight(&self) -> bool {
        self.mappings
            .values()
            .any(|mapping| mapping.state != MappingState::Installed)
    }

    fn admits_backend(&self) -> Result<(), Refusal> {
        match self.state {
            GenerationState::Creating | GenerationState::Live => Ok(()),
            other => Err(Refusal::Generation(other)),
        }
    }

    /// Start a new generation, from `Vacant`, or from `Gone` once its
    /// terminal extents have all been released.
    pub fn create(&mut self) -> Result<GenerationId, Refusal> {
        match self.state {
            GenerationState::Vacant | GenerationState::Gone if self.extents.is_empty() => {}
            GenerationState::Gone => return Err(Refusal::InFlight),
            other => return Err(Refusal::Generation(other)),
        }
        let next = self.generation.0.checked_add(1).ok_or(Refusal::Exhausted)?;
        self.generation = GenerationId(next);
        self.state = GenerationState::Creating;
        Ok(self.generation)
    }

    pub fn commit_create(&mut self) -> Result<(), Refusal> {
        if self.state != GenerationState::Creating {
            return Err(Refusal::Generation(self.state));
        }
        self.state = GenerationState::Live;
        Ok(())
    }

    /// Reserve `spec.extent` for a backend mapping that will own `spec.host`.
    /// A refusal hands the spec back. The shell runs the returned action
    /// after unlocking, then reports through the ticket.
    pub fn begin_map(
        &mut self,
        spec: MappingSpec<M>,
    ) -> Result<(MapTicket, BackendAction), Refused<MappingSpec<M>>> {
        let refuse = |spec, reason| {
            Err(Refused {
                offered: spec,
                reason,
            })
        };
        if let Err(reason) = self.admits_backend() {
            return refuse(spec, reason);
        }
        let extent = spec.extent;
        if !host_range_fits(spec.host_addr, extent) {
            return refuse(spec, Refusal::HostRange);
        }
        if collides(&self.mappings, extent, |m| m.spec.extent.end()) {
            return refuse(spec, Refusal::Collision);
        }
        let Some(next) = self.next_mapping.checked_add(1) else {
            return refuse(spec, Refusal::Exhausted);
        };
        let mapping = MappingId {
            carrier: self.carrier,
            raw: self.next_mapping,
        };
        self.next_mapping = next;
        let action = BackendAction::Map {
            extent,
            host_addr: spec.host_addr,
        };
        self.mappings.insert(
            extent.ipa(),
            Mapping {
                id: mapping,
                spec,
                state: MappingState::Mapping,
                carved: 0,
            },
        );
        Ok((
            MapTicket {
                generation: self.generation,
                mapping,
                extent,
            },
            action,
        ))
    }

    /// The backend reported on a map. `Done` installs it; `Failed` releases
    /// the reservation and hands the host allocation back.
    pub fn finish_map(
        &mut self,
        ticket: MapTicket,
        result: BackendResult,
    ) -> Result<Option<M>, Refused<MapTicket>> {
        let owed = ticket.generation == self.generation
            && self
                .mappings
                .get(&ticket.extent.ipa())
                .is_some_and(|m| m.id == ticket.mapping && m.state == MappingState::Mapping);
        if !owed {
            return Err(Refused {
                offered: ticket,
                reason: Refusal::NotFound,
            });
        }
        match result {
            BackendResult::Done => {
                if let Some(mapping) = self.mappings.get_mut(&ticket.extent.ipa()) {
                    mapping.state = MappingState::Installed;
                }
                Ok(None)
            }
            BackendResult::Failed => Ok(self
                .mappings
                .remove(&ticket.extent.ipa())
                .map(|mapping| mapping.spec.host)),
        }
    }

    /// Carve a frame extent holding `lease` inside one installed mapping.
    /// Its host address is the mapping's at the same offset. A collision is
    /// refused before anything is stored, and the lease comes back.
    pub fn carve(&mut self, extent: GpaExtent, lease: B) -> Result<ExtentId, Refused<B>> {
        let refuse = |lease, reason| {
            Err(Refused {
                offered: lease,
                reason,
            })
        };
        if let Err(reason) = self.admits_backend() {
            return refuse(lease, reason);
        }
        let Some((&mapping_base, mapping)) =
            holder(&self.mappings, extent.ipa(), |m| m.spec.extent.end())
        else {
            return refuse(lease, Refusal::NotInsideAnInstalledMapping);
        };
        if mapping.state != MappingState::Installed || !mapping.spec.extent.contains(extent) {
            return refuse(lease, Refusal::NotInsideAnInstalledMapping);
        }
        if collides(&self.extents, extent, |e| e.extent.end()) {
            return refuse(lease, Refusal::Collision);
        }
        // Inside the mapping, whose host range registration proved fits.
        let Some(host_addr) = usize::try_from(extent.ipa() - mapping_base)
            .ok()
            .and_then(|offset| mapping.spec.host_addr.checked_add(offset))
        else {
            return refuse(lease, Refusal::HostRange);
        };
        let mapping_id = mapping.id;
        let Some(next) = self.next_extent.checked_add(1) else {
            return refuse(lease, Refusal::Exhausted);
        };
        let Some(mapping) = self.mappings.get_mut(&mapping_base) else {
            return refuse(lease, Refusal::NotFound);
        };
        let Some(carved) = mapping.carved.checked_add(1) else {
            return refuse(lease, Refusal::Exhausted);
        };
        mapping.carved = carved;
        let id = ExtentId {
            carrier: self.carrier,
            raw: self.next_extent,
        };
        self.next_extent = next;
        self.extents.insert(
            extent.ipa(),
            FrameExtent {
                id,
                mapping: mapping_id,
                extent,
                host_addr,
                lease,
                state: ExtentState::Live,
                pins: 0,
            },
        );
        Ok(id)
    }

    /// Pin the live extent covering `[ipa, ipa + len)`, in one index probe.
    pub fn pin(&mut self, ipa: u64, len: u64) -> Result<Pin, PinRefusal> {
        let selected = GpaExtent::new(ipa, len).ok_or(PinRefusal::EmptyRange)?;
        let (&base, entry) = self
            .extents
            .range_mut(..=ipa)
            .next_back()
            .filter(|(_, e)| e.state == ExtentState::Live && e.extent.end() > ipa)
            .ok_or(PinRefusal::NoLiveExtent)?;
        if !entry.extent.contains(selected) {
            return Err(PinRefusal::Overruns(entry.id));
        }
        let host_addr = usize::try_from(ipa - base)
            .ok()
            .and_then(|offset| entry.host_addr.checked_add(offset))
            .ok_or(PinRefusal::Overruns(entry.id))?;
        entry.pins = entry
            .pins
            .checked_add(1)
            .ok_or(PinRefusal::Exhausted(entry.id))?;
        Ok(Pin {
            extent: entry.id,
            base,
            selected,
            host_addr,
        })
    }

    /// Return a pin. The last pin of a retiring or terminal extent releases
    /// it. Within one core a terminal extent always belongs to the last
    /// generation (`create` waits for terminal pins), so the pin's carrier
    /// and extent id are its whole identity.
    pub fn unpin(&mut self, pin: Pin) -> Result<Option<Released<B>>, Refused<Pin>> {
        let Some(entry) = self
            .extents
            .get_mut(&pin.base)
            .filter(|e| e.id == pin.extent && e.pins > 0)
        else {
            return Err(Refused {
                offered: pin,
                reason: Refusal::NotFound,
            });
        };
        entry.pins -= 1;
        if entry.pins > 0 || entry.state == ExtentState::Live {
            return Ok(None);
        }
        Ok(self.release(pin.base))
    }

    /// Remove the extent at `base` and settle its mapping's carve count.
    fn release(&mut self, base: u64) -> Option<Released<B>> {
        let entry = self.extents.remove(&base)?;
        if entry.state != ExtentState::Terminal
            && let Some((_, mapping)) = self
                .mappings
                .range_mut(..=base)
                .next_back()
                .filter(|(_, m)| m.id == entry.mapping)
        {
            mapping.carved -= 1;
        }
        Some(Released {
            id: entry.id,
            extent: entry.extent,
            lease: entry.lease,
        })
    }

    /// Stop finding and pinning `id`; release it now if unpinned.
    pub fn retire_extent(&mut self, id: ExtentId) -> Result<Retire<B>, Refusal> {
        let (&base, entry) = self
            .extents
            .iter_mut()
            .find(|(_, e)| e.id == id)
            .ok_or(Refusal::NotFound)?;
        if entry.state != ExtentState::Live {
            return Err(Refusal::NotFound);
        }
        if entry.pins > 0 {
            entry.state = ExtentState::Retiring;
            return Ok(Retire::Deferred);
        }
        self.release(base)
            .map(Retire::Released)
            .ok_or(Refusal::NotFound)
    }

    /// Start unmapping an installed mapping with nothing carved inside.
    pub fn begin_unmap(&mut self, id: MappingId) -> Result<(UnmapTicket, BackendAction), Refusal> {
        self.admits_backend()?;
        let mapping = self
            .mappings
            .values_mut()
            .find(|m| m.id == id && m.state == MappingState::Installed)
            .ok_or(Refusal::NotFound)?;
        if mapping.carved > 0 {
            return Err(Refusal::Carved);
        }
        mapping.state = MappingState::Unmapping;
        let extent = mapping.spec.extent;
        Ok((
            UnmapTicket {
                generation: self.generation,
                mapping: id,
                extent,
            },
            BackendAction::Unmap(extent),
        ))
    }

    /// The backend reported on an unmap. `Done` releases the extent and hands
    /// the host allocation back; `Failed` keeps the mapping installed for a
    /// later retry.
    pub fn finish_unmap(
        &mut self,
        ticket: UnmapTicket,
        result: BackendResult,
    ) -> Result<Option<M>, Refused<UnmapTicket>> {
        let owed = ticket.generation == self.generation
            && self
                .mappings
                .get(&ticket.extent.ipa())
                .is_some_and(|m| m.id == ticket.mapping && m.state == MappingState::Unmapping);
        if !owed {
            return Err(Refused {
                offered: ticket,
                reason: Refusal::NotFound,
            });
        }
        match result {
            BackendResult::Done => Ok(self
                .mappings
                .remove(&ticket.extent.ipa())
                .map(|mapping| mapping.spec.host)),
            BackendResult::Failed => {
                if let Some(mapping) = self.mappings.get_mut(&ticket.extent.ipa()) {
                    mapping.state = MappingState::Installed;
                }
                Ok(None)
            }
        }
    }

    /// Start destroying the generation. "Not now" while a backend map or
    /// unmap is in flight: its result must land in this generation first.
    pub fn begin_destroy(&mut self) -> Result<(DestroyTicket, BackendAction), Refusal> {
        self.admits_backend()?;
        if self.in_flight() {
            return Err(Refusal::InFlight);
        }
        self.destroy_from = self.state;
        self.state = GenerationState::Destroying;
        Ok((
            DestroyTicket {
                carrier: self.carrier,
                generation: self.generation,
            },
            BackendAction::Destroy,
        ))
    }

    /// The backend reported on the destroy. `Done` ends the generation: every
    /// mapping's host allocation comes back, unpinned extents are released,
    /// pinned ones become terminal until their last unpin. `Failed` returns
    /// the generation to the state the destroy started from.
    pub fn finish_destroy(
        &mut self,
        ticket: DestroyTicket,
        result: BackendResult,
    ) -> Result<Destroyed<M, B>, Refused<DestroyTicket>> {
        if ticket.carrier != self.carrier
            || ticket.generation != self.generation
            || self.state != GenerationState::Destroying
        {
            return Err(Refused {
                offered: ticket,
                reason: Refusal::NotFound,
            });
        }
        let mut destroyed = Destroyed {
            hosts: Vec::new(),
            extents: Vec::new(),
        };
        if result == BackendResult::Failed {
            self.state = self.destroy_from;
            return Ok(destroyed);
        }
        self.state = GenerationState::Gone;
        destroyed.hosts = core::mem::take(&mut self.mappings)
            .into_values()
            .map(|mapping| mapping.spec.host)
            .collect();
        for (base, mut entry) in core::mem::take(&mut self.extents) {
            if entry.pins > 0 {
                entry.state = ExtentState::Terminal;
                self.extents.insert(base, entry);
            } else {
                destroyed.extents.push(Released {
                    id: entry.id,
                    extent: entry.extent,
                    lease: entry.lease,
                });
            }
        }
        Ok(destroyed)
    }

    fn holding(&self) -> Option<Holding> {
        let ended = matches!(self.state, GenerationState::Vacant | GenerationState::Gone);
        let editors = self
            .mms
            .values()
            .filter(|record| record.editor != MmEditor::Free)
            .count();
        (!ended
            || !self.mappings.is_empty()
            || !self.extents.is_empty()
            || !self.grants.is_empty()
            || !self.chunks.is_empty()
            || editors != 0)
            .then_some(Holding {
                state: self.state,
                mappings: self.mappings.len(),
                extents: self.extents.len(),
                grants: self.grants.len(),
                chunks: self.chunks.len(),
                editors,
            })
    }

    /// Consume a core that holds nothing: its generation is `Vacant` or
    /// `Gone`, and every mapping and extent is settled. Otherwise it comes
    /// back, and its owner must destroy the generation and settle its pins.
    pub fn teardown(self) -> Result<(), alloc::boxed::Box<Self>> {
        if self.holding().is_none() {
            drop(self);
            Ok(())
        } else {
            Err(alloc::boxed::Box::new(self))
        }
    }

    /// End the generation and forget every mapping and extent without the
    /// drop check: only the explorer, which drops thousands of
    /// mid-operation states, may do this.
    #[cfg(test)]
    fn forget_for_explorer(&mut self) {
        self.state = GenerationState::Gone;
        self.mappings.clear();
        self.extents.clear();
        self.mms.clear();
        self.grants.clear();
        self.chunks.clear();
    }

    /// Check V1 to V4, G1 to G4 and the carve accounting (V5 and V6 hold by the
    /// transitions' types; the explorer checks V5 against the pins it holds).
    pub fn check_invariants(&self) -> Result<(), Violation> {
        let mut previous_end = None;
        for (&base, mapping) in &self.mappings {
            if base != mapping.spec.extent.ipa() || mapping.id.carrier != self.carrier {
                return Err(Violation::IndexKey);
            }
            if previous_end.is_some_and(|end| end > base) {
                return Err(Violation::MappingsOverlap);
            }
            previous_end = Some(mapping.spec.extent.end());
        }
        let mut previous_end = None;
        let mut carved = BTreeMap::<MappingId, u32>::new();
        for (&base, extent) in &self.extents {
            if base != extent.extent.ipa() || extent.id.carrier != self.carrier {
                return Err(Violation::IndexKey);
            }
            if previous_end.is_some_and(|end| end > base) {
                return Err(Violation::ExtentsOverlap);
            }
            previous_end = Some(extent.extent.end());
            match extent.state {
                ExtentState::Terminal => {
                    if extent.pins == 0 || self.state != GenerationState::Gone {
                        return Err(Violation::TerminalExtent);
                    }
                }
                state => {
                    if state == ExtentState::Retiring && extent.pins == 0 {
                        return Err(Violation::UnpinnedRetiring);
                    }
                    let inside = holder(&self.mappings, base, |m| m.spec.extent.end()).is_some_and(
                        |(&mapping_base, m)| {
                            m.id == extent.mapping
                                && m.state == MappingState::Installed
                                && m.spec.extent.contains(extent.extent)
                                && usize::try_from(base - mapping_base)
                                    .ok()
                                    .and_then(|offset| m.spec.host_addr.checked_add(offset))
                                    == Some(extent.host_addr)
                        },
                    );
                    if !inside {
                        return Err(Violation::ExtentOutsideInstalledMapping);
                    }
                    *carved.entry(extent.mapping).or_default() += 1;
                }
            }
        }
        for mapping in self.mappings.values() {
            if carved.get(&mapping.id).copied().unwrap_or(0) != mapping.carved {
                return Err(Violation::CarveCount);
            }
        }
        self.check_grant_invariants()?;
        self.check_release_invariants()?;
        match self.state {
            GenerationState::Vacant | GenerationState::Gone if !self.mappings.is_empty() => {
                Err(Violation::MappingOutlivesGeneration)
            }
            GenerationState::Destroying if self.in_flight() => Err(Violation::InFlightAtDestroy),
            _ => Ok(()),
        }
    }
}

/// An invariant [`CarrierCore::check_invariants`] found broken.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Violation {
    IndexKey,
    MappingsOverlap,
    ExtentsOverlap,
    ExtentOutsideInstalledMapping,
    CarveCount,
    UnpinnedRetiring,
    TerminalExtent,
    MappingOutlivesGeneration,
    InFlightAtDestroy,
    GrantsOverlap,
    GrantWithoutMm,
    SupplyWithoutEditor,
    ChunksOverlap,
    ChunkShape,
    ChunkWithoutMm,
    ChunkRoom,
    GrantOutsideChunk,
    /// L1: an MM that is not live has an editor held.
    EditorAfterExit,
    /// L2: a releasing or broken MM still holds a grant or a chunk.
    ReleasingHolds,
}

impl<V: CoreVenue, M, B, G> Drop for CarrierCore<V, M, B, G> {
    /// V6: a core dropped with its generation not ended, or with anything
    /// unsettled, would lose a VM or free memory the backend may still map.
    fn drop(&mut self) {
        if let Some(holding) = self.holding() {
            V::dropped_holding(holding);
        }
    }
}
