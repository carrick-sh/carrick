//! The stage-2 record table of one stage-2 generation: which host backing is
//! mapped at each guest-physical extent, which records are pinned, and which
//! are retiring.
//!
//! The table holds its invariants by construction (#3056):
//! - **One record per IPA.** No two records of the table overlap, whether
//!   live or retiring: a retiring record still owns its backend mapping, so
//!   its extent stays reserved until [`Stage2RecordTable::finish_retire`].
//! - **A collision is refused before a record exists.** [`Stage2RecordTable::register`]
//!   checks the extent first and hands the whole spec, backing included, back
//!   to the caller on refusal.
//! - **Covering lookup is O(log n).** Because records never overlap, the only
//!   record that can cover an IPA is the one with the greatest base at or
//!   below it: one ordered-map probe, with no scan window.
//! - **An empty range covers nothing.** A zero-length lookup or pin is `None`.
//! - **Only a live record is found or pinned**, and a pinned record's unmap
//!   is owed only after its last pin returns.
//! - **A table with records cannot be dropped silently.** [`Stage2RecordTable::teardown`]
//!   returns every record (live, pinned or owing its unmap) to the owner;
//!   dropping a non-empty table is a broken invariant and is fatal.
//!
//! The table is plain data: its owner (the carrier's stage-2 custody) holds it
//! under the custody lock, and drives the backend map and unmap around it.
//! Pins and unmap tokens carry the table's identity, so a token from another
//! table (another VM, or another generation of the same VM) is refused.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use carrick_core_abi::mm::custody::{CarrierLogicalOwner, CarrierStage2RecordId};
use carrick_hal::MemPerms;
use core::num::NonZeroU64;

#[cfg(test)]
mod tests;

/// A non-empty guest-physical extent `[ipa, ipa + len)` whose end does not
/// overflow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2Extent {
    ipa: u64,
    len: NonZeroU64,
}

impl Stage2Extent {
    /// `None` for an empty extent or one whose end overflows.
    pub fn new(ipa: u64, len: u64) -> Option<Self> {
        let len = NonZeroU64::new(len)?;
        ipa.checked_add(len.get())?;
        Some(Self { ipa, len })
    }

    /// First guest-physical address of the extent.
    pub const fn ipa(self) -> u64 {
        self.ipa
    }

    /// Length in bytes; never zero.
    pub const fn len(self) -> NonZeroU64 {
        self.len
    }

    /// One past the last address. Construction proved it does not overflow.
    pub const fn end(self) -> u64 {
        self.ipa.wrapping_add(self.len.get())
    }

    /// Whether `other` lies wholly inside this extent.
    pub const fn contains(self, other: Self) -> bool {
        other.ipa >= self.ipa && other.end() <= self.end()
    }

    /// Whether the two extents share any address.
    pub const fn overlaps(self, other: Self) -> bool {
        self.ipa < other.end() && other.ipa < self.end()
    }
}

/// What a caller registers: the extent, the host backing mapped there, and
/// the backend's own lease or mapping object `B`.
#[derive(Debug)]
pub struct Stage2RecordSpec<B> {
    pub extent: Stage2Extent,
    /// Host address mapped at `extent.ipa()`.
    pub host_addr: usize,
    pub perms: MemPerms,
    pub logical_owner: Option<CarrierLogicalOwner>,
    pub backing: B,
}

/// Why [`Stage2RecordTable::register`] refused. The spec comes back whole, so
/// the caller still owns its backing.
#[derive(Debug)]
pub struct Stage2RegisterRefused<B> {
    pub spec: Stage2RecordSpec<B>,
    pub reason: Stage2RegisterRefusal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage2RegisterRefusal {
    /// A record (live or retiring) already holds part of the extent.
    Collision(CarrierStage2RecordId),
    /// The table has issued every record id.
    IdsExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordState {
    Live,
    /// Retirement was requested. The record is no longer found or pinned,
    /// but it keeps its extent until its unmap is finished.
    Retiring {
        unmap_issued: bool,
    },
}

#[derive(Debug)]
struct Entry<B> {
    id: CarrierStage2RecordId,
    spec: Stage2RecordSpec<B>,
    state: RecordState,
    pins: u64,
}

/// A live record that covers a looked-up range.
#[derive(Debug)]
pub struct Stage2Covering<'a, B> {
    pub id: CarrierStage2RecordId,
    pub extent: Stage2Extent,
    pub host_addr: usize,
    pub perms: MemPerms,
    pub logical_owner: Option<CarrierLogicalOwner>,
    pub backing: &'a B,
}

/// A pin on one live record. While it is outstanding, the record's unmap is
/// not owed. Return it with [`Stage2RecordTable::unpin`].
#[must_use = "a pin must be returned with Stage2RecordTable::unpin"]
#[derive(Debug, Eq, PartialEq)]
pub struct Stage2Pin {
    table: u64,
    id: CarrierStage2RecordId,
    base: u64,
    selected: Stage2Extent,
    host_addr: usize,
}

impl Stage2Pin {
    pub fn record(&self) -> CarrierStage2RecordId {
        self.id
    }
    /// The pinned range, as requested.
    pub fn selected(&self) -> Stage2Extent {
        self.selected
    }
    /// Host address of `selected().ipa()`.
    pub fn host_addr(&self) -> usize {
        self.host_addr
    }
}

/// The unmap of a retiring record is now owed. Unmap `extent()` at the
/// backend, then return the token with [`Stage2RecordTable::finish_retire`] to
/// release the extent and take the backing back. If the backend unmap fails,
/// keep the token and retry; the extent stays reserved.
#[must_use = "an owed unmap must be finished with Stage2RecordTable::finish_retire"]
#[derive(Debug, Eq, PartialEq)]
pub struct Stage2Unmap {
    table: u64,
    id: CarrierStage2RecordId,
    extent: Stage2Extent,
}

impl Stage2Unmap {
    pub fn record(&self) -> CarrierStage2RecordId {
        self.id
    }
    pub fn extent(&self) -> Stage2Extent {
        self.extent
    }
}

/// The result of asking to retire a record.
#[derive(Debug, Eq, PartialEq)]
pub enum Stage2Retire {
    /// No pin is outstanding: the unmap is owed now.
    Unmap(Stage2Unmap),
    /// Pins are outstanding. The last [`Stage2RecordTable::unpin`] returns the
    /// owed unmap.
    DeferredPinned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage2RetireRefused {
    NotFound,
    AlreadyRetiring,
}

/// A token was not minted by this table, or names a record it no longer
/// holds in the state the token claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2TokenRefused;

/// A record returned by [`Stage2RecordTable::teardown`].
#[derive(Debug)]
pub struct Stage2Remnant<B> {
    pub id: CarrierStage2RecordId,
    pub spec: Stage2RecordSpec<B>,
    pub state: Stage2RemnantState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage2RemnantState {
    /// Still live; `pins` pins are outstanding.
    Live { pins: u64 },
    /// Retiring with `pins` pins outstanding; its unmap was never owed.
    RetiringPinned { pins: u64 },
    /// Its unmap was owed and never finished.
    UnmapOwed,
}

static NEXT_TABLE: AtomicU64 = AtomicU64::new(1);

/// See the module documentation.
#[derive(Debug)]
pub struct Stage2RecordTable<B> {
    table: u64,
    next_id: u64,
    /// Every record, keyed by base IPA. Extents never overlap.
    by_base: BTreeMap<u64, Entry<B>>,
    /// Record id to base IPA.
    ids: BTreeMap<CarrierStage2RecordId, u64>,
    /// Index entries examined by lookups, so a witness can observe the cost.
    #[cfg(test)]
    probes: core::sync::atomic::AtomicUsize,
}

impl<B> Default for Stage2RecordTable<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B> Stage2RecordTable<B> {
    pub fn new() -> Self {
        Self {
            table: NEXT_TABLE.fetch_add(1, Ordering::Relaxed),
            next_id: 1,
            by_base: BTreeMap::new(),
            ids: BTreeMap::new(),
            #[cfg(test)]
            probes: core::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Number of records, live or retiring.
    pub fn len(&self) -> usize {
        self.by_base.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_base.is_empty()
    }

    /// The one record whose extent could hold `ipa`: the greatest base at or
    /// below it. Records never overlap, so no other record can.
    fn candidate(&self, ipa: u64) -> Option<&Entry<B>> {
        #[cfg(test)]
        self.probes
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        self.by_base
            .range(..=ipa)
            .next_back()
            .map(|(_, entry)| entry)
            .filter(|entry| entry.spec.extent.end() > ipa)
    }

    /// Register a record. A collision with any record, live or retiring, is
    /// refused before anything is stored, and the spec comes back whole.
    pub fn register(
        &mut self,
        spec: Stage2RecordSpec<B>,
    ) -> Result<CarrierStage2RecordId, Stage2RegisterRefused<B>> {
        let extent = spec.extent;
        // The record with the greatest base below `extent.end()` has the
        // greatest end of all records starting before it; if it ends at or
        // before `extent.ipa()`, nothing overlaps.
        if let Some((_, existing)) = self.by_base.range(..extent.end()).next_back()
            && existing.spec.extent.overlaps(extent)
        {
            return Err(Stage2RegisterRefused {
                spec,
                reason: Stage2RegisterRefusal::Collision(existing.id),
            });
        }
        let Some(next) = self.next_id.checked_add(1) else {
            return Err(Stage2RegisterRefused {
                spec,
                reason: Stage2RegisterRefusal::IdsExhausted,
            });
        };
        let id = CarrierStage2RecordId(self.next_id);
        self.next_id = next;
        self.ids.insert(id, extent.ipa());
        self.by_base.insert(
            extent.ipa(),
            Entry {
                id,
                spec,
                state: RecordState::Live,
                pins: 0,
            },
        );
        Ok(id)
    }

    /// The live record covering all of `[ipa, ipa + len)`. `None` for an
    /// empty or overflowing range, a range no record covers, a range that
    /// runs past its record, or a retiring record.
    pub fn covering(&self, ipa: u64, len: u64) -> Option<Stage2Covering<'_, B>> {
        let selected = Stage2Extent::new(ipa, len)?;
        let entry = self.candidate(ipa)?;
        if entry.state != RecordState::Live || !entry.spec.extent.contains(selected) {
            return None;
        }
        Some(Stage2Covering {
            id: entry.id,
            extent: entry.spec.extent,
            host_addr: entry.spec.host_addr,
            perms: entry.spec.perms,
            logical_owner: entry.spec.logical_owner,
            backing: &entry.spec.backing,
        })
    }

    /// Pin the live record covering `[ipa, ipa + len)`. `None` exactly when
    /// [`Self::covering`] is `None`.
    pub fn pin(&mut self, ipa: u64, len: u64) -> Option<Stage2Pin> {
        let selected = Stage2Extent::new(ipa, len)?;
        let base = {
            let entry = self.candidate(ipa)?;
            if entry.state != RecordState::Live || !entry.spec.extent.contains(selected) {
                return None;
            }
            entry.spec.extent.ipa()
        };
        let entry = self.by_base.get_mut(&base)?;
        entry.pins = entry.pins.checked_add(1)?;
        Some(Stage2Pin {
            table: self.table,
            id: entry.id,
            base,
            selected,
            host_addr: entry.spec.host_addr.wrapping_add((ipa - base) as usize),
        })
    }

    /// Return a pin. When it was the last pin of a retiring record, the
    /// record's unmap is owed now and comes back.
    pub fn unpin(&mut self, pin: Stage2Pin) -> Result<Option<Stage2Unmap>, Stage2TokenRefused> {
        if pin.table != self.table {
            return Err(Stage2TokenRefused);
        }
        let entry = self
            .by_base
            .get_mut(&pin.base)
            .filter(|entry| entry.id == pin.id && entry.pins > 0)
            .ok_or(Stage2TokenRefused)?;
        entry.pins -= 1;
        match entry.state {
            RecordState::Retiring {
                unmap_issued: false,
            } if entry.pins == 0 => {
                entry.state = RecordState::Retiring { unmap_issued: true };
                Ok(Some(Stage2Unmap {
                    table: self.table,
                    id: entry.id,
                    extent: entry.spec.extent,
                }))
            }
            _ => Ok(None),
        }
    }

    /// Stop finding and pinning `id`. Its extent stays reserved until the
    /// owed unmap is finished.
    pub fn begin_retire(
        &mut self,
        id: CarrierStage2RecordId,
    ) -> Result<Stage2Retire, Stage2RetireRefused> {
        let base = *self.ids.get(&id).ok_or(Stage2RetireRefused::NotFound)?;
        let entry = self
            .by_base
            .get_mut(&base)
            .ok_or(Stage2RetireRefused::NotFound)?;
        if entry.state != RecordState::Live {
            return Err(Stage2RetireRefused::AlreadyRetiring);
        }
        if entry.pins > 0 {
            entry.state = RecordState::Retiring {
                unmap_issued: false,
            };
            return Ok(Stage2Retire::DeferredPinned);
        }
        entry.state = RecordState::Retiring { unmap_issued: true };
        Ok(Stage2Retire::Unmap(Stage2Unmap {
            table: self.table,
            id,
            extent: entry.spec.extent,
        }))
    }

    /// The backend unmapped the token's extent: release the extent and return
    /// the record's spec, backing included.
    pub fn finish_retire(
        &mut self,
        unmap: Stage2Unmap,
    ) -> Result<Stage2RecordSpec<B>, Stage2TokenRefused> {
        if unmap.table != self.table {
            return Err(Stage2TokenRefused);
        }
        match self.by_base.get(&unmap.extent.ipa()) {
            Some(entry)
                if entry.id == unmap.id
                    && entry.state == (RecordState::Retiring { unmap_issued: true }) => {}
            _ => return Err(Stage2TokenRefused),
        }
        self.ids.remove(&unmap.id);
        self.by_base
            .remove(&unmap.extent.ipa())
            .map(|entry| entry.spec)
            .ok_or(Stage2TokenRefused)
    }

    /// Empty the table, returning every record to the owner, which must
    /// account for each (normally by destroying the whole stage-2 address
    /// space, then releasing the backings).
    pub fn teardown(mut self) -> Vec<Stage2Remnant<B>> {
        self.ids.clear();
        core::mem::take(&mut self.by_base)
            .into_values()
            .map(|entry| Stage2Remnant {
                id: entry.id,
                state: match entry.state {
                    RecordState::Live => Stage2RemnantState::Live { pins: entry.pins },
                    RecordState::Retiring {
                        unmap_issued: false,
                    } => Stage2RemnantState::RetiringPinned { pins: entry.pins },
                    RecordState::Retiring { unmap_issued: true } => Stage2RemnantState::UnmapOwed,
                },
                spec: entry.spec,
            })
            .collect()
    }
}

impl<B> Drop for Stage2RecordTable<B> {
    /// Dropping a table that still holds records is a broken invariant: each
    /// record names a backend mapping and a backing nobody would release
    /// (#3057's class). An unwinding owner is already failing.
    fn drop(&mut self) {
        if !self.by_base.is_empty() && !std::thread::panicking() {
            carrick_fatal::carrick_fatal!(
                "aarch64::stage2_records",
                "stage-2 record table dropped with {} records; its owner must tear it down",
                self.by_base.len()
            );
        }
    }
}
