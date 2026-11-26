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
//! The invariants of #3061 that this slice owns, checked by
//! [`CarrierCore::check_invariants`] after every transition in the bounded
//! explorer (`own/explore.rs`) and in the loom model:
//! - **V1** no two backend mappings overlap, in any state;
//! - **V2** no two frame extents overlap;
//! - **V3** every frame extent that is not terminalized lies inside exactly
//!   one `Installed` backend mapping, whose carve count matches;
//! - **V4** a backend action is issued only for a `Creating` or `Live`
//!   generation (destroy: `Creating` or `Live`, as it enters `Destroying`),
//!   and once a destroy commits no backend mapping survives;
//! - **V5** a pinned extent is never released, and only a live extent is
//!   found or pinned;
//! - **V6** nothing is dropped silently: a core still holding a mapping or an
//!   extent is a broken invariant, reported through its venue before any
//!   field destructor can release a backing.
//!
//! The index structure is the step-1a table (#1236): records never overlap,
//! so the only record that can hold an address is the one with the greatest
//! base at or below it, and every lookup is one ordered-map probe.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::num::NonZeroU64;

#[cfg(test)]
mod explore;
#[cfg(all(test, feature = "loom"))]
mod loom_models;
#[cfg(all(test, not(feature = "loom")))]
mod tests;

/// The shell's answer to a broken invariant. Production venues end the
/// carrier (`carrick_fatal`); the core itself never unwinds or aborts.
pub trait CoreVenue {
    /// Called when a core is dropped while it still holds `mappings` backend
    /// mappings and `extents` frame extents.
    fn dropped_holding(mappings: usize, extents: usize) -> !;
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

/// The carrier this core belongs to; every token carries it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CarrierId(pub NonZeroU64);

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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct MappingId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct ExtentId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MappingState {
    /// The backend map is in flight; the extent is reserved.
    Mapping,
    Installed,
    /// The backend unmap is in flight; nothing is carved inside.
    Unmapping,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Mapping {
    id: MappingId,
    extent: GpaExtent,
    state: MappingState,
    carved: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExtentState {
    Live,
    /// Retirement was requested while pinned; the last unpin releases it.
    Retiring,
    /// Its generation was destroyed while it was pinned: no backend mapping
    /// remains, and only the host backing is retained until the last unpin.
    Terminal,
}

/// What a caller carves inside an installed mapping.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ExtentSpec<B> {
    pub extent: GpaExtent,
    /// Host address mapped at `extent.ipa()`.
    pub host_addr: usize,
    pub backing: B,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FrameExtent<B> {
    id: ExtentId,
    mapping: MappingId,
    spec: ExtentSpec<B>,
    state: ExtentState,
    pins: u64,
}

/// Why a transition refused. Contention (`InFlight`) is "not now": the
/// caller reruns after the in-flight backend call reports.
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
    /// Not found, or not in the state the request needs.
    NotFound,
    /// The mapping still has extents carved inside.
    Carved,
    /// A backend call is in flight; rerun after it reports.
    InFlight,
    /// An id or pin counter is exhausted.
    Exhausted,
}

/// A refusal that hands back what the caller offered.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Refused<T> {
    pub offered: T,
    pub reason: Refusal,
}

/// The backend's result for one action.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BackendResult {
    Done,
    Failed,
}

/// A backend action for the shell to run after it unlocks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BackendAction {
    Map(GpaExtent),
    Unmap(GpaExtent),
    Destroy,
}

/// The map of one reserved mapping is owed to the backend.
#[must_use = "a map ticket must be finished with CarrierCore::finish_map"]
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Clone, Hash))]
pub struct MapTicket {
    carrier: CarrierId,
    generation: GenerationId,
    mapping: MappingId,
    extent: GpaExtent,
}

/// The unmap of one mapping is owed to the backend.
#[must_use = "an unmap ticket must be finished with CarrierCore::finish_unmap"]
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Clone, Hash))]
pub struct UnmapTicket {
    carrier: CarrierId,
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
    carrier: CarrierId,
    generation: GenerationId,
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

/// An extent leaving the core, with its backing.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Released<B> {
    pub id: ExtentId,
    pub spec: ExtentSpec<B>,
}

/// The result of asking to retire an extent.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Retire<B> {
    Released(Released<B>),
    /// Pins are outstanding; the last unpin releases it.
    Deferred,
}

/// See the module documentation.
#[derive(Debug)]
#[cfg_attr(test, derive(Clone, Hash, PartialEq, Eq))]
pub struct CarrierCore<V: CoreVenue, B> {
    carrier: CarrierId,
    generation: GenerationId,
    state: GenerationState,
    next_mapping: u64,
    next_extent: u64,
    mappings: BTreeMap<u64, Mapping>,
    extents: BTreeMap<u64, FrameExtent<B>>,
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

impl<V: CoreVenue, B> CarrierCore<V, B> {
    pub fn new(carrier: CarrierId) -> Self {
        Self {
            carrier,
            generation: GenerationId(0),
            state: GenerationState::Vacant,
            next_mapping: 1,
            next_extent: 1,
            mappings: BTreeMap::new(),
            extents: BTreeMap::new(),
            _venue: core::marker::PhantomData,
        }
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

    fn owns(&self, carrier: CarrierId, generation: GenerationId) -> bool {
        carrier == self.carrier && generation == self.generation
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

    /// Start a new generation. Only from `Vacant`, or `Gone` once its
    /// terminalized extents have all been released.
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

    /// Reserve `extent` for a backend mapping. The shell runs the returned
    /// action after unlocking, then reports through the ticket.
    pub fn begin_map(&mut self, extent: GpaExtent) -> Result<(MapTicket, BackendAction), Refusal> {
        self.admits_backend()?;
        if collides(&self.mappings, extent, |m| m.extent.end()) {
            return Err(Refusal::Collision);
        }
        let next = self.next_mapping.checked_add(1).ok_or(Refusal::Exhausted)?;
        let mapping = MappingId(self.next_mapping);
        self.next_mapping = next;
        self.mappings.insert(
            extent.ipa(),
            Mapping {
                id: mapping,
                extent,
                state: MappingState::Mapping,
                carved: 0,
            },
        );
        Ok((
            MapTicket {
                carrier: self.carrier,
                generation: self.generation,
                mapping,
                extent,
            },
            BackendAction::Map(extent),
        ))
    }

    /// The backend reported on a map: install it, or release the reservation.
    pub fn finish_map(
        &mut self,
        ticket: MapTicket,
        result: BackendResult,
    ) -> Result<Option<MappingId>, Refused<MapTicket>> {
        let owed = self.owns(ticket.carrier, ticket.generation)
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
                Ok(Some(ticket.mapping))
            }
            BackendResult::Failed => {
                self.mappings.remove(&ticket.extent.ipa());
                Ok(None)
            }
        }
    }

    /// Carve a frame extent inside one installed mapping. A collision or a
    /// bad host range is refused before anything is stored, and the spec
    /// comes back whole.
    pub fn carve(&mut self, spec: ExtentSpec<B>) -> Result<ExtentId, Refused<ExtentSpec<B>>> {
        let extent = spec.extent;
        let refuse = |spec, reason| {
            Err(Refused {
                offered: spec,
                reason,
            })
        };
        if let Err(reason) = self.admits_backend() {
            return refuse(spec, reason);
        }
        let host_fits = usize::try_from(extent.len().get())
            .ok()
            .and_then(|len| spec.host_addr.checked_add(len))
            .is_some();
        if spec.host_addr == 0 || !host_fits {
            return refuse(spec, Refusal::HostRange);
        }
        let Some((&mapping_base, mapping)) =
            holder(&self.mappings, extent.ipa(), |m| m.extent.end())
        else {
            return refuse(spec, Refusal::NotInsideAnInstalledMapping);
        };
        if mapping.state != MappingState::Installed || !mapping.extent.contains(extent) {
            return refuse(spec, Refusal::NotInsideAnInstalledMapping);
        }
        if collides(&self.extents, extent, |e| e.spec.extent.end()) {
            return refuse(spec, Refusal::Collision);
        }
        let Some(next) = self.next_extent.checked_add(1) else {
            return refuse(spec, Refusal::Exhausted);
        };
        let mapping_id = mapping.id;
        let Some(mapping) = self.mappings.get_mut(&mapping_base) else {
            return refuse(spec, Refusal::NotFound);
        };
        let Some(carved) = mapping.carved.checked_add(1) else {
            return refuse(spec, Refusal::Exhausted);
        };
        mapping.carved = carved;
        let id = ExtentId(self.next_extent);
        self.next_extent = next;
        self.extents.insert(
            extent.ipa(),
            FrameExtent {
                id,
                mapping: mapping_id,
                spec,
                state: ExtentState::Live,
                pins: 0,
            },
        );
        Ok(id)
    }

    /// Pin the live extent covering `[ipa, ipa + len)`, in one index probe.
    pub fn pin(&mut self, ipa: u64, len: u64) -> Result<Pin, PinRefusal> {
        let selected = GpaExtent::new(ipa, len).ok_or(PinRefusal::EmptyRange)?;
        let (carrier, generation) = (self.carrier, self.generation);
        let (&base, entry) = self
            .extents
            .range_mut(..=ipa)
            .next_back()
            .filter(|(_, e)| e.state == ExtentState::Live && e.spec.extent.end() > ipa)
            .ok_or(PinRefusal::NoLiveExtent)?;
        if !entry.spec.extent.contains(selected) {
            return Err(PinRefusal::Overruns(entry.id));
        }
        let host_addr = usize::try_from(ipa - base)
            .ok()
            .and_then(|offset| entry.spec.host_addr.checked_add(offset))
            .ok_or(PinRefusal::Overruns(entry.id))?;
        entry.pins = entry
            .pins
            .checked_add(1)
            .ok_or(PinRefusal::Exhausted(entry.id))?;
        Ok(Pin {
            carrier,
            generation,
            extent: entry.id,
            base,
            selected,
            host_addr,
        })
    }

    /// Return a pin. The last pin of a retiring or terminalized extent
    /// releases it.
    pub fn unpin(&mut self, pin: Pin) -> Result<Option<Released<B>>, Refused<Pin>> {
        let held = pin.carrier == self.carrier
            && self
                .extents
                .get(&pin.base)
                .is_some_and(|e| e.id == pin.extent && e.pins > 0);
        // A terminalized extent outlives its generation; its pins do too.
        let generation_ok = pin.generation == self.generation
            || self
                .extents
                .get(&pin.base)
                .is_some_and(|e| e.state == ExtentState::Terminal);
        if !held || !generation_ok {
            return Err(Refused {
                offered: pin,
                reason: Refusal::NotFound,
            });
        }
        let Some(entry) = self.extents.get_mut(&pin.base) else {
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
            && let Some(mapping) = self.mappings.values_mut().find(|m| m.id == entry.mapping)
        {
            mapping.carved = mapping.carved.saturating_sub(1);
        }
        Some(Released {
            id: entry.id,
            spec: entry.spec,
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
        let extent = mapping.extent;
        Ok((
            UnmapTicket {
                carrier: self.carrier,
                generation: self.generation,
                mapping: id,
                extent,
            },
            BackendAction::Unmap(extent),
        ))
    }

    /// The backend reported on an unmap: release the extent, or keep the
    /// mapping installed for a later retry.
    pub fn finish_unmap(
        &mut self,
        ticket: UnmapTicket,
        result: BackendResult,
    ) -> Result<(), Refused<UnmapTicket>> {
        let owed = self.owns(ticket.carrier, ticket.generation)
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
            BackendResult::Done => {
                self.mappings.remove(&ticket.extent.ipa());
            }
            BackendResult::Failed => {
                if let Some(mapping) = self.mappings.get_mut(&ticket.extent.ipa()) {
                    mapping.state = MappingState::Installed;
                }
            }
        }
        Ok(())
    }

    /// Start destroying the generation. "Not now" while a backend map or
    /// unmap is in flight: its result must land in this generation first.
    pub fn begin_destroy(&mut self) -> Result<(DestroyTicket, BackendAction), Refusal> {
        self.admits_backend()?;
        if self.in_flight() {
            return Err(Refusal::InFlight);
        }
        self.state = GenerationState::Destroying;
        Ok((
            DestroyTicket {
                carrier: self.carrier,
                generation: self.generation,
            },
            BackendAction::Destroy,
        ))
    }

    /// The backend reported on the destroy. On success every mapping is gone:
    /// unpinned extents are released, pinned ones are terminalized (host
    /// backing only) until their last unpin. On failure the generation is
    /// live again.
    pub fn finish_destroy(
        &mut self,
        ticket: DestroyTicket,
        result: BackendResult,
    ) -> Result<Vec<Released<B>>, Refused<DestroyTicket>> {
        if !self.owns(ticket.carrier, ticket.generation)
            || self.state != GenerationState::Destroying
        {
            return Err(Refused {
                offered: ticket,
                reason: Refusal::NotFound,
            });
        }
        if result == BackendResult::Failed {
            self.state = GenerationState::Live;
            return Ok(Vec::new());
        }
        self.state = GenerationState::Gone;
        self.mappings.clear();
        let mut released = Vec::new();
        let extents = core::mem::take(&mut self.extents);
        for (base, mut entry) in extents {
            if entry.pins > 0 {
                entry.state = ExtentState::Terminal;
                self.extents.insert(base, entry);
            } else {
                released.push(Released {
                    id: entry.id,
                    spec: entry.spec,
                });
            }
        }
        Ok(released)
    }

    /// Consume a core that holds nothing. A core still holding anything comes
    /// back: its owner must destroy the generation and settle its pins first.
    pub fn teardown(self) -> Result<(), Self> {
        if self.mappings.is_empty() && self.extents.is_empty() {
            drop(self);
            Ok(())
        } else {
            Err(self)
        }
    }

    /// Forget every mapping and extent without the drop check: only the
    /// explorer, which drops thousands of mid-operation states, may do this.
    #[cfg(test)]
    fn forget_for_explorer(&mut self) {
        self.mappings.clear();
        self.extents.clear();
    }

    /// Check V1 to V4 (V5 and V6 hold by the transitions' types; the explorer
    /// checks V5 against the pins it holds). Returns the first violation.
    pub fn check_invariants(&self) -> Result<(), Violation> {
        let mut previous_end = None;
        for (&base, mapping) in &self.mappings {
            if base != mapping.extent.ipa() {
                return Err(Violation::IndexKey);
            }
            if previous_end.is_some_and(|end| end > base) {
                return Err(Violation::MappingsOverlap);
            }
            previous_end = Some(mapping.extent.end());
        }
        let mut previous_end = None;
        let mut carved = BTreeMap::<MappingId, u32>::new();
        for (&base, extent) in &self.extents {
            if base != extent.spec.extent.ipa() {
                return Err(Violation::IndexKey);
            }
            if previous_end.is_some_and(|end| end > base) {
                return Err(Violation::ExtentsOverlap);
            }
            previous_end = Some(extent.spec.extent.end());
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
                    let inside =
                        holder(&self.mappings, base, |m| m.extent.end()).is_some_and(|(_, m)| {
                            m.id == extent.mapping
                                && m.state == MappingState::Installed
                                && m.extent.contains(extent.spec.extent)
                        });
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
}

impl<V: CoreVenue, B> Drop for CarrierCore<V, B> {
    /// V6: a core dropped while it holds anything would free backings the
    /// backend may still map. The venue ends the carrier before any field
    /// destructor runs.
    fn drop(&mut self) {
        if !self.mappings.is_empty() || !self.extents.is_empty() {
            V::dropped_holding(self.mappings.len(), self.extents.len());
        }
    }
}
