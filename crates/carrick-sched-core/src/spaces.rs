//! Address spaces EL1 may install on a vCPU itself (EL1 increment 2, step 2).
//!
//! The host publishes an address space here when an executor first loads one
//! of its threads on a zone vCPU: its key (the zone key, the host's exact MM
//! id), its translation roots (`TTBR0_EL1`/`TTBR1_EL1`, ASID included) and a
//! gate. EL1 switches a vCPU to another process's thread only through an
//! entry here, in the order every installer of an address space follows
//! ([`crate::occupancy`]): publish the slot's occupancy word, then read the
//! gate. So the entry carries the MM's fence into the shared region:
//!
//! - every page-table pause of the MM raises the gate before it scans the
//!   occupancy table and lowers it when it ends (on the host the pause is
//!   the MM's `PtQuiesce`, which raises the gate with its own fence);
//! - [`GATE_CLOSED`] is set while the entry is being published and from the
//!   moment the MM's ASID starts retiring, so EL1 never installs an address
//!   space whose translations are about to be invalidated for reuse.
//!
//! EL1 installs the space only when it reads the gate open after publishing
//! the slot; a pause or retirement that raised or closed it later scans the
//! slot and drains the vCPU (Dekker, every access `SeqCst`).
//!
//! A foreign-COW publication for the MM (its translations changed while it
//! was paused) is counted in the entry; the first EL1 switch into the space
//! after it runs one broadcast `TLBI ASIDE1IS` and records what it covered.
//! The host keeps its own count for the vCPUs it loads.
//!
//! Entries never move: a lookup probes from `key % ADDRESS_SPACES`, stops at
//! an empty entry and skips freed ones, and a key is never published again
//! after its entry is freed (the MM is gone), so a reader that re-checks the
//! key after the gate knows the gate was that MM's. All-zero bytes are an
//! empty table. Only the host mutates entries, serialized by its own lock;
//! EL1 only reads them and records COW coverage.

use core::sync::atomic::{AtomicU64, Ordering};

/// Entries in the table: the address spaces the host has published at once.
/// A full table leaves an MM unpublished, so its threads reach a vCPU
/// through their executors, as before this step.
pub const ADDRESS_SPACES: usize = 1024;

/// Gate bit: EL1 may not install the address space (being published, or
/// its ASID is retiring). The low bits count the raised page-table pauses.
pub const GATE_CLOSED: u64 = 1 << 63;

/// A freed entry (skipped by lookups, reused by publications).
const FREED: u64 = u64::MAX;

/// One published address space.
#[repr(C, align(64))]
pub struct SpaceEntry {
    key: AtomicU64,
    ttbr0: AtomicU64,
    ttbr1: AtomicU64,
    /// [`GATE_CLOSED`] | raised pauses.
    gate: AtomicU64,
    /// Foreign-COW publications for the space (host, under a pause).
    cow_published: AtomicU64,
    /// Publications an EL1 broadcast invalidation covered.
    cow_covered: AtomicU64,
}

/// The table, in the shared EL1 region inside the zone.
#[repr(C, align(64))]
pub struct AddressSpaces {
    /// `TTBR0_EL1`/`TTBR1_EL1` of the carrier's maintenance root (ASID 0, the
    /// kernel hole and the EL1 region only), which a vCPU runs while it has
    /// no address space installed. 0 until the host publishes it; EL1 never
    /// switches address spaces without it.
    idle_ttbr: AtomicU64,
    entries: [SpaceEntry; ADDRESS_SPACES],
}

/// The index of a published entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpaceIndex(u16);

impl SpaceIndex {
    pub const fn index(self) -> usize {
        self.0 as usize
    }

    pub fn from_index(index: usize) -> Option<Self> {
        (index < ADDRESS_SPACES).then_some(Self(index as u16))
    }
}

/// What EL1 installs, from an entry whose gate it read open after publishing
/// its slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpaceGrant {
    pub index: SpaceIndex,
    pub ttbr0: u64,
    pub ttbr1: u64,
    /// Foreign-COW publications not yet covered by an EL1 invalidation: the
    /// installer runs `TLBI ASIDE1IS` for the space's ASID and then
    /// [`AddressSpaces::cover_cow`] with this value.
    pub cow_owed: Option<u64>,
}

impl Default for AddressSpaces {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressSpaces {
    pub const fn new() -> Self {
        Self {
            idle_ttbr: AtomicU64::new(0),
            entries: [const {
                SpaceEntry {
                    key: AtomicU64::new(0),
                    ttbr0: AtomicU64::new(0),
                    ttbr1: AtomicU64::new(0),
                    gate: AtomicU64::new(0),
                    cow_published: AtomicU64::new(0),
                    cow_covered: AtomicU64::new(0),
                }
            }; ADDRESS_SPACES],
        }
    }

    fn entry(&self, index: SpaceIndex) -> &SpaceEntry {
        &self.entries[index.index()]
    }

    /// The maintenance root a vCPU runs with no address space (0: unknown).
    pub fn idle_ttbr(&self) -> u64 {
        self.idle_ttbr.load(Ordering::Acquire)
    }

    /// Host: publish the carrier's maintenance root.
    pub fn set_idle_ttbr(&self, ttbr: u64) {
        self.idle_ttbr.store(ttbr, Ordering::Release);
    }

    /// The entry of `key`, if published (a hint for placement; EL1 decides
    /// by [`Self::grant`]).
    pub fn find(&self, key: u64) -> Option<SpaceIndex> {
        if key == 0 || key == FREED {
            return None;
        }
        let start = (key % ADDRESS_SPACES as u64) as usize;
        for probe in 0..ADDRESS_SPACES {
            let index = (start + probe) % ADDRESS_SPACES;
            match self.entries[index].key.load(Ordering::SeqCst) {
                0 => return None,
                found if found == key => return SpaceIndex::from_index(index),
                _ => {}
            }
        }
        None
    }

    /// Whether EL1 may install `key` now (a hint: published and the gate
    /// open).
    pub fn is_open(&self, key: u64) -> bool {
        self.find(key)
            .is_some_and(|index| self.entry(index).gate.load(Ordering::Acquire) == 0)
    }

    /// Host, serialized: a closed entry for `key` with its roots, or `None`
    /// when the table is full. The caller has checked `key` is not published.
    pub fn publish_closed(&self, key: u64, ttbr0: u64, ttbr1: u64) -> Option<SpaceIndex> {
        if key == 0 || key == FREED {
            return None;
        }
        let start = (key % ADDRESS_SPACES as u64) as usize;
        for probe in 0..ADDRESS_SPACES {
            let index = (start + probe) % ADDRESS_SPACES;
            let entry = &self.entries[index];
            let current = entry.key.load(Ordering::SeqCst);
            if current != 0 && current != FREED {
                continue;
            }
            entry.gate.store(GATE_CLOSED, Ordering::SeqCst);
            entry.ttbr0.store(ttbr0, Ordering::Relaxed);
            entry.ttbr1.store(ttbr1, Ordering::Relaxed);
            entry.cow_published.store(0, Ordering::Relaxed);
            entry.cow_covered.store(0, Ordering::Relaxed);
            // The key last: a reader that finds it sees the rest.
            entry.key.store(key, Ordering::SeqCst);
            return SpaceIndex::from_index(index);
        }
        None
    }

    /// Host: let EL1 install the entry (pauses raised meanwhile stay
    /// counted).
    pub fn open(&self, index: SpaceIndex) {
        self.entry(index)
            .gate
            .fetch_and(!GATE_CLOSED, Ordering::SeqCst);
    }

    /// Host: no EL1 install of the entry from now on. The caller then scans
    /// the occupancy table for vCPUs that installed it before.
    pub fn close(&self, index: SpaceIndex) {
        self.entry(index)
            .gate
            .fetch_or(GATE_CLOSED, Ordering::SeqCst);
    }

    /// Host: a page-table pause of the space began; EL1 may not install it
    /// until [`Self::lower`]. Before the pause scans the occupancy table.
    pub fn raise(&self, index: SpaceIndex) {
        self.entry(index).gate.fetch_add(1, Ordering::SeqCst);
    }

    /// Host: the pause [`Self::raise`] counted ended.
    pub fn lower(&self, index: SpaceIndex) {
        self.entry(index).gate.fetch_sub(1, Ordering::SeqCst);
    }

    /// The gate word (tests and diagnostics).
    pub fn gate(&self, index: SpaceIndex) -> u64 {
        self.entry(index).gate.load(Ordering::SeqCst)
    }

    /// The key of the entry (tests and diagnostics).
    pub fn key(&self, index: SpaceIndex) -> u64 {
        self.entry(index).key.load(Ordering::SeqCst)
    }

    /// Host: free a closed entry whose space runs nowhere.
    pub fn free(&self, index: SpaceIndex) {
        let entry = self.entry(index);
        entry.key.store(FREED, Ordering::SeqCst);
        entry.ttbr0.store(0, Ordering::Relaxed);
        entry.ttbr1.store(0, Ordering::Relaxed);
    }

    /// Host, under a pause of the space: its translations changed under a
    /// foreign COW; the next EL1 install invalidates its ASID first.
    pub fn note_cow(&self, index: SpaceIndex) {
        self.entry(index)
            .cow_published
            .fetch_add(1, Ordering::SeqCst);
    }

    /// EL1, after publishing its slot's occupancy word for `key`: the roots
    /// to install if the gate is open (read `SeqCst`, after the slot), and
    /// the entry still names `key`.
    pub fn grant(&self, index: SpaceIndex, key: u64) -> Option<SpaceGrant> {
        let entry = self.entry(index);
        if entry.gate.load(Ordering::SeqCst) != 0 {
            return None;
        }
        let ttbr0 = entry.ttbr0.load(Ordering::Acquire);
        let ttbr1 = entry.ttbr1.load(Ordering::Acquire);
        // The key after the gate: the gate read was this space's (entries
        // never move and a key is never republished once freed).
        if entry.key.load(Ordering::SeqCst) != key || ttbr0 == 0 {
            return None;
        }
        let published = entry.cow_published.load(Ordering::Acquire);
        let covered = entry.cow_covered.load(Ordering::Acquire);
        Some(SpaceGrant {
            index,
            ttbr0,
            ttbr1,
            cow_owed: (published != covered).then_some(published),
        })
    }

    /// EL1: a broadcast invalidation of the space's ASID covered the
    /// publications counted up to `published`.
    pub fn cover_cow(&self, index: SpaceIndex, published: u64) {
        self.entry(index)
            .cow_covered
            .fetch_max(published, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_published_space_is_granted_only_while_its_gate_is_open() {
        let spaces = AddressSpaces::new();
        let index = spaces.publish_closed(7, 0x1_0000, 0x1_0000).unwrap();
        assert_eq!(spaces.find(7), Some(index));
        assert!(spaces.grant(index, 7).is_none(), "closed while publishing");
        spaces.open(index);
        let grant = spaces.grant(index, 7).unwrap();
        assert_eq!(
            (grant.ttbr0, grant.ttbr1, grant.cow_owed),
            (0x1_0000, 0x1_0000, None)
        );
        spaces.raise(index);
        assert!(spaces.grant(index, 7).is_none(), "a pause holds the gate");
        spaces.raise(index);
        spaces.lower(index);
        assert!(spaces.grant(index, 7).is_none(), "one pause still raised");
        spaces.lower(index);
        assert!(spaces.grant(index, 7).is_some());
        spaces.close(index);
        assert!(spaces.grant(index, 7).is_none(), "retiring");
        assert!(spaces.grant(index, 8).is_none(), "another key");
    }

    #[test]
    fn colliding_keys_probe_and_freed_entries_are_skipped_then_reused() {
        let spaces = AddressSpaces::new();
        let n = ADDRESS_SPACES as u64;
        let a = spaces.publish_closed(5, 1, 1).unwrap();
        let b = spaces.publish_closed(5 + n, 2, 2).unwrap();
        let c = spaces.publish_closed(5 + 2 * n, 3, 3).unwrap();
        assert_ne!(a, b);
        spaces.close(a);
        spaces.free(a);
        assert_eq!(spaces.find(5), None);
        assert_eq!(
            spaces.find(5 + n),
            Some(b),
            "a freed entry does not end a probe"
        );
        assert_eq!(spaces.find(5 + 2 * n), Some(c));
        let d = spaces.publish_closed(5 + 3 * n, 4, 4).unwrap();
        assert_eq!(d, a, "a freed entry is reused");
        assert_eq!(spaces.find(5 + 3 * n), Some(d));
    }

    #[test]
    fn a_cow_publication_is_owed_until_an_install_covers_it() {
        let spaces = AddressSpaces::new();
        let index = spaces.publish_closed(3, 9, 9).unwrap();
        spaces.open(index);
        spaces.note_cow(index);
        spaces.note_cow(index);
        let grant = spaces.grant(index, 3).unwrap();
        assert_eq!(grant.cow_owed, Some(2));
        spaces.note_cow(index);
        spaces.cover_cow(index, 2);
        assert_eq!(spaces.grant(index, 3).unwrap().cow_owed, Some(3));
        spaces.cover_cow(index, 3);
        assert_eq!(spaces.grant(index, 3).unwrap().cow_owed, None);
    }
}
