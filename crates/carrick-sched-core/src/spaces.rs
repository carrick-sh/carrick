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
//! empty table. Only the host publishes/frees entries, serialized by its own
//! lock; EL1 reads them, records COW coverage, and claims the exact entry's
//! single page-table editor word before mutating live descriptors.

use core::num::NonZeroU64;
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

/// Served VMA edits one space's journal holds before EL1 must hand the next
/// one to the host instead ([`JournalFull`]).
pub const VMA_JOURNAL_ENTRIES: usize = 16;

/// One served protection edit as EL1 recorded it: `[start, end)` now has
/// `prot` (`PROT_READ`=1, `PROT_WRITE`=2, `PROT_EXEC`=4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmaEdit {
    pub start: u64,
    pub end: u64,
    pub prot: u8,
}

/// The journal has no room: the caller leaves the edit to the host (with
/// work owed) instead of recording it. An edit is never dropped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalFull;

#[repr(C)]
struct JournalSlot {
    start: AtomicU64,
    /// `end | prot`: both bounds are page aligned, so `prot` (three bits)
    /// rides in the low bits of `end`.
    end_prot: AtomicU64,
}

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
    /// The exact guest EL1 page-table editor, or zero. A host pause raises
    /// `gate` and waits for this word to clear before mutating the same tables.
    active_editor: AtomicU64,
    /// Monotonic bump cursor for anonymous private mmap allocations in the mmap arena.
    pub mmap_next: AtomicU64,
    /// Current program break for heap allocations.
    pub brk_current: AtomicU64,
    /// Edits EL1 has journaled for the space (single producer: the entry's
    /// page-table editor; its release store publishes the slot writes).
    journal_head: AtomicU64,
    /// Edits the host has applied. `head - tail` are pending.
    journal_tail: AtomicU64,
    journal: [JournalSlot; VMA_JOURNAL_ENTRIES],
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

/// Exclusive guest EL1 mutation ownership for one published address space.
/// Dropping the guard acknowledges a host pause or retirement waiting after
/// it closed the entry's gate.
pub struct SpaceEditor<'a> {
    entry: &'a SpaceEntry,
    owner: NonZeroU64,
}

/// Exclusive initialization of a published, closed fork child. This guard
/// never opens the runnable gate; task publication is a separate operation.
pub struct ClosedChildEditor<'a> {
    editor: SpaceEditor<'a>,
    grant: SpaceGrant,
}
impl ClosedChildEditor<'_> {
    pub fn grant(&self) -> SpaceGrant {
        self.grant
    }
    pub fn set_mmap_next(&self, value: u64) {
        self.editor.set_mmap_next(value);
    }
    pub fn set_brk_current(&self, value: u64) {
        self.editor.set_brk_current(value);
    }
}

/// Proof that the host has excluded the guest EL1 editor of address space
/// `key`: its gate was raised or closed and no admitted editor remained, or
/// no published entry names `key` (EL1 edits only published spaces, and a
/// freed key is never published again). Only [`AddressSpaces`] mints it, and
/// it borrows the table, so host code that must run without a concurrent
/// EL1 editor of `key` can demand one instead of trusting a comment. It is
/// valid until the matching [`AddressSpaces::lower`]; it is neither `Clone`
/// nor `Copy`, and holders use it within the exclusion that produced it.
#[derive(Debug)]
pub struct ExcludedEditor<'a> {
    key: u64,
    _spaces: core::marker::PhantomData<&'a AddressSpaces>,
}

impl ExcludedEditor<'_> {
    /// The exact address space (the host MM id) whose editor is excluded.
    pub fn key(&self) -> u64 {
        self.key
    }
}

impl<'a> SpaceEditor<'a> {
    pub fn mmap_next(&self) -> u64 {
        self.entry.mmap_next.load(Ordering::Acquire)
    }

    pub fn set_mmap_next(&self, val: u64) {
        self.entry.mmap_next.store(val, Ordering::Release);
    }

    pub fn brk_current(&self) -> u64 {
        self.entry.brk_current.load(Ordering::Acquire)
    }

    pub fn set_brk_current(&self, val: u64) {
        self.entry.brk_current.store(val, Ordering::Release);
    }

    /// Whether [`Self::journal_protect`] will succeed. The editor is the only
    /// producer and the host only frees room, so `true` stays true until this
    /// editor records: decide before editing the tables.
    pub fn journal_has_room(&self) -> bool {
        let head = self.entry.journal_head.load(Ordering::Relaxed);
        let tail = self.entry.journal_tail.load(Ordering::Acquire);
        head.wrapping_sub(tail) < VMA_JOURNAL_ENTRIES as u64
    }

    /// Record that `[start, end)` now has `prot`, for the host to apply in
    /// order before it next reads the space's VMA rows.
    pub fn journal_protect(&self, start: u64, end: u64, prot: u8) -> Result<(), JournalFull> {
        if !self.journal_has_room() {
            return Err(JournalFull);
        }
        let head = self.entry.journal_head.load(Ordering::Relaxed);
        let slot = &self.entry.journal[(head % VMA_JOURNAL_ENTRIES as u64) as usize];
        slot.start.store(start, Ordering::Relaxed);
        slot.end_prot
            .store(end | u64::from(prot & 7), Ordering::Relaxed);
        self.entry
            .journal_head
            .store(head.wrapping_add(1), Ordering::Release);
        Ok(())
    }
}

impl Drop for SpaceEditor<'_> {
    fn drop(&mut self) {
        let released = self.entry.active_editor.compare_exchange(
            self.owner.get(),
            0,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        debug_assert_eq!(released, Ok(self.owner.get()));
    }
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
                    active_editor: AtomicU64::new(0),
                    mmap_next: AtomicU64::new(0),
                    brk_current: AtomicU64::new(0),
                    journal_head: AtomicU64::new(0),
                    journal_tail: AtomicU64::new(0),
                    journal: [const {
                        JournalSlot {
                            start: AtomicU64::new(0),
                            end_prot: AtomicU64::new(0),
                        }
                    }; VMA_JOURNAL_ENTRIES],
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
        self.publish_closed_with_layout(key, ttbr0, ttbr1, 0, 0)
    }

    /// Host, serialized: a closed entry for `key` with its roots and layout hints.
    pub fn publish_closed_with_layout(
        &self,
        key: u64,
        ttbr0: u64,
        ttbr1: u64,
        brk_current: u64,
        mmap_next: u64,
    ) -> Option<SpaceIndex> {
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
            entry.active_editor.store(0, Ordering::Relaxed);
            entry.mmap_next.store(mmap_next, Ordering::Relaxed);
            entry.brk_current.store(brk_current, Ordering::Relaxed);
            entry.journal_head.store(0, Ordering::Relaxed);
            entry.journal_tail.store(0, Ordering::Relaxed);
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

    /// Host: permanently close the entry and wait for its admitted guest
    /// editor before retiring the roots or reusing the entry.
    pub fn close_and_wait_for_editor(
        &self,
        index: SpaceIndex,
        mut wait: impl FnMut(),
    ) -> ExcludedEditor<'_> {
        self.close(index);
        while self.entry(index).active_editor.load(Ordering::SeqCst) != 0 {
            wait();
        }
        self.excluded(index)
    }

    /// Host: a page-table pause of the space began; EL1 may not install it
    /// until [`Self::lower`]. Before the pause scans the occupancy table.
    pub fn raise(&self, index: SpaceIndex) {
        self.entry(index).gate.fetch_add(1, Ordering::SeqCst);
    }

    /// Host: raise the page-table gate and wait until an already admitted
    /// guest editor acknowledges completion. SeqCst ordering makes the race
    /// exhaustive: the host sees the editor, or the guest sees the gate.
    pub fn raise_and_wait_for_editor(
        &self,
        index: SpaceIndex,
        mut wait: impl FnMut(),
    ) -> ExcludedEditor<'_> {
        self.raise(index);
        while self.entry(index).active_editor.load(Ordering::SeqCst) != 0 {
            wait();
        }
        self.excluded(index)
    }

    fn excluded(&self, index: SpaceIndex) -> ExcludedEditor<'_> {
        ExcludedEditor {
            key: self.entry(index).key.load(Ordering::SeqCst),
            _spaces: core::marker::PhantomData,
        }
    }

    /// Host: proof that no EL1 editor of `key` can exist because no
    /// published entry names it. `None` while one does: raise its gate.
    pub fn unpublished(&self, key: u64) -> Option<ExcludedEditor<'_>> {
        (key != 0 && self.find(key).is_none()).then_some(ExcludedEditor {
            key,
            _spaces: core::marker::PhantomData,
        })
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
        debug_assert_eq!(entry.active_editor.load(Ordering::SeqCst), 0);
        entry.key.store(FREED, Ordering::SeqCst);
        entry.ttbr0.store(0, Ordering::Relaxed);
        entry.ttbr1.store(0, Ordering::Relaxed);
        entry.mmap_next.store(0, Ordering::Relaxed);
        entry.brk_current.store(0, Ordering::Relaxed);
    }

    pub fn mmap_next(&self, index: SpaceIndex) -> u64 {
        self.entry(index).mmap_next.load(Ordering::Acquire)
    }

    pub fn set_mmap_next(&self, index: SpaceIndex, val: u64) {
        self.entry(index).mmap_next.store(val, Ordering::Release);
    }

    pub fn brk_current(&self, index: SpaceIndex) -> u64 {
        self.entry(index).brk_current.load(Ordering::Acquire)
    }

    pub fn set_brk_current(&self, index: SpaceIndex, val: u64) {
        self.entry(index).brk_current.store(val, Ordering::Release);
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

    /// Guest EL1: try to become the only page-table editor for the exact MM.
    /// Ownership is visible before the gate is re-read, so a racing host pause
    /// either waits for this guard or makes this attempt release and fail.
    pub fn try_begin_edit(
        &self,
        index: SpaceIndex,
        key: u64,
        owner: NonZeroU64,
    ) -> Option<SpaceEditor<'_>> {
        let entry = self.entry(index);
        entry
            .active_editor
            .compare_exchange(0, owner.get(), Ordering::SeqCst, Ordering::SeqCst)
            .ok()?;
        if entry.gate.load(Ordering::SeqCst) != 0 || entry.key.load(Ordering::SeqCst) != key {
            let released = entry.active_editor.compare_exchange(
                owner.get(),
                0,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            debug_assert_eq!(released, Ok(owner.get()));
            return None;
        }
        Some(SpaceEditor { entry, owner })
    }

    /// Claim a never-runnable child while its publication gate remains closed.
    /// The exact key and gate are rechecked after acquiring its editor word.
    pub fn try_begin_closed_child_edit(
        &self,
        index: SpaceIndex,
        key: u64,
        owner: NonZeroU64,
    ) -> Option<ClosedChildEditor<'_>> {
        let entry = self.entry(index);
        entry
            .active_editor
            .compare_exchange(0, owner.get(), Ordering::SeqCst, Ordering::SeqCst)
            .ok()?;
        let editor = SpaceEditor { entry, owner };
        if key == 0
            || entry.key.load(Ordering::SeqCst) != key
            || entry.gate.load(Ordering::SeqCst) != GATE_CLOSED
        {
            return None;
        }
        let ttbr0 = entry.ttbr0.load(Ordering::Acquire);
        let ttbr1 = entry.ttbr1.load(Ordering::Acquire);
        if ttbr0 == 0 || ttbr1 == 0 {
            return None;
        }
        Some(ClosedChildEditor {
            editor,
            grant: SpaceGrant {
                index,
                ttbr0,
                ttbr1,
                cow_owed: None,
            },
        })
    }

    /// Guest EL1: [`Self::try_begin_edit`], waiting up to `spins` attempts
    /// while only another EL1 editor (a bounded critical section on another
    /// vCPU) holds the space. A raised or closed gate (the host) refuses at
    /// once: the host must not wait on a guest that waits on it.
    pub fn try_begin_edit_bounded(
        &self,
        index: SpaceIndex,
        key: u64,
        owner: NonZeroU64,
        spins: u32,
    ) -> Option<SpaceEditor<'_>> {
        let entry = self.entry(index);
        for _ in 0..spins.max(1) {
            if let Some(editor) = self.try_begin_edit(index, key, owner) {
                return Some(editor);
            }
            if entry.gate.load(Ordering::SeqCst) != 0 || entry.key.load(Ordering::SeqCst) != key {
                return None;
            }
            core::hint::spin_loop();
        }
        None
    }

    /// Host: apply the pending journaled edits of `key`'s space, oldest
    /// first, through `apply`. Each edit is released only after `apply`
    /// returned, so a slot is never reused while it is being read. The caller
    /// serializes drains of one space (the MM's `MemState` lock). Returns the
    /// number applied; 0 when `key` is not published.
    pub fn drain_vma_journal(&self, key: u64, mut apply: impl FnMut(VmaEdit)) -> usize {
        let Some(index) = self.find(key) else {
            return 0;
        };
        let entry = self.entry(index);
        let mut tail = entry.journal_tail.load(Ordering::Relaxed);
        let mut applied = 0;
        loop {
            let head = entry.journal_head.load(Ordering::Acquire);
            if tail == head {
                return applied;
            }
            let slot = &entry.journal[(tail % VMA_JOURNAL_ENTRIES as u64) as usize];
            let end_prot = slot.end_prot.load(Ordering::Relaxed);
            apply(VmaEdit {
                start: slot.start.load(Ordering::Relaxed),
                end: end_prot & !7,
                prot: (end_prot & 7) as u8,
            });
            tail = tail.wrapping_add(1);
            entry.journal_tail.store(tail, Ordering::Release);
            applied += 1;
        }
    }

    /// Journaled edits of `key`'s space the host has not applied
    /// (tests and diagnostics).
    pub fn pending_vma_edits(&self, key: u64) -> u64 {
        self.find(key).map_or(0, |index| {
            let entry = self.entry(index);
            entry
                .journal_head
                .load(Ordering::Acquire)
                .wrapping_sub(entry.journal_tail.load(Ordering::Acquire))
        })
    }

    /// Exact active guest editor (tests and diagnostics).
    pub fn active_editor(&self, index: SpaceIndex) -> Option<NonZeroU64> {
        NonZeroU64::new(self.entry(index).active_editor.load(Ordering::SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use std::sync::{Arc, mpsc};
    use std::vec::Vec;

    #[test]
    fn unpublished_fork_child_editor_keeps_the_root_closed() {
        let spaces = AddressSpaces::new();
        let child = spaces.publish_closed(71, 0x40000, 0x40000).unwrap();
        let owner = NonZeroU64::new(4).unwrap();
        let editor = spaces
            .try_begin_closed_child_edit(child, 71, owner)
            .unwrap();
        assert_eq!(editor.grant().ttbr0, 0x40000);
        assert!(spaces.grant(child, 71).is_none());
        assert!(
            spaces
                .try_begin_closed_child_edit(child, 71, owner)
                .is_none()
        );
        drop(editor);
        spaces.open(child);
        assert!(
            spaces
                .try_begin_closed_child_edit(child, 71, owner)
                .is_none()
        );
        assert!(spaces.grant(child, 71).is_some());
    }

    #[test]
    fn a_bounded_edit_waits_for_a_guest_editor_but_never_for_the_host() {
        let spaces = Arc::new(AddressSpaces::new());
        let index = spaces.publish_closed(7, 0x1_0000, 0x1_0000).unwrap();
        spaces.open(index);
        let nz = |v| NonZeroU64::new(v).unwrap();
        // Another EL1 editor holds it for a bounded section, then leaves.
        let held = spaces.try_begin_edit(index, 7, nz(1)).unwrap();
        assert!(spaces.try_begin_edit_bounded(index, 7, nz(2), 16).is_none());
        let (tx, rx) = mpsc::channel();
        let waiter = {
            let spaces = Arc::clone(&spaces);
            std::thread::spawn(move || {
                tx.send(()).unwrap();
                spaces
                    .try_begin_edit_bounded(index, 7, nz(2), u32::MAX)
                    .is_some()
            })
        };
        rx.recv().unwrap();
        drop(held);
        assert!(waiter.join().unwrap(), "the waiter gets the editor");
        // A raised gate refuses at once, however many spins are allowed.
        spaces.raise(index);
        assert!(
            spaces
                .try_begin_edit_bounded(index, 7, nz(3), u32::MAX)
                .is_none()
        );
    }

    #[test]
    fn the_journal_applies_in_order_and_backpressures_when_full() {
        let spaces = AddressSpaces::new();
        let index = spaces.publish_closed(9, 0x1_0000, 0x1_0000).unwrap();
        spaces.open(index);
        let editor = spaces
            .try_begin_edit(index, 9, NonZeroU64::new(1).unwrap())
            .unwrap();
        for n in 0..VMA_JOURNAL_ENTRIES as u64 {
            assert!(editor.journal_has_room());
            editor
                .journal_protect(n * 0x1000, n * 0x1000 + 0x1000, (n % 8) as u8)
                .unwrap();
        }
        assert!(!editor.journal_has_room());
        assert_eq!(editor.journal_protect(0, 0x1000, 1), Err(JournalFull));
        assert_eq!(spaces.pending_vma_edits(9), VMA_JOURNAL_ENTRIES as u64);
        let mut seen = Vec::new();
        let applied = spaces.drain_vma_journal(9, |edit| seen.push(edit));
        assert_eq!(applied, VMA_JOURNAL_ENTRIES);
        assert!(
            seen.iter()
                .enumerate()
                .all(|(n, e)| e.start == n as u64 * 0x1000 && u64::from(e.prot) == n as u64 % 8),
            "oldest first, nothing lost or reordered"
        );
        assert_eq!(spaces.pending_vma_edits(9), 0);
        // Room again, and the ring wraps.
        editor.journal_protect(0x9000, 0xa000, 3).unwrap();
        let mut again = Vec::new();
        assert_eq!(spaces.drain_vma_journal(9, |e| again.push(e)), 1);
        assert_eq!(
            again[0],
            VmaEdit {
                start: 0x9000,
                end: 0xa000,
                prot: 3
            }
        );
        // An unpublished key drains nothing.
        assert_eq!(spaces.drain_vma_journal(77, |_| panic!()), 0);
    }

    #[test]
    fn exclusion_proofs_name_exactly_the_excluded_space() {
        let spaces = AddressSpaces::new();
        let index = spaces.publish_closed(7, 0x1_0000, 0x1_0000).unwrap();
        spaces.open(index);
        assert!(
            spaces.unpublished(7).is_none(),
            "a published space needs its gate raised"
        );
        assert_eq!(spaces.unpublished(8).map(|proof| proof.key()), Some(8));
        assert!(spaces.unpublished(0).is_none());
        let proof = spaces.raise_and_wait_for_editor(index, || unreachable!());
        assert_eq!(proof.key(), 7);
        assert!(
            spaces
                .try_begin_edit(index, 7, NonZeroU64::new(1).unwrap())
                .is_none(),
            "no EL1 editor while the proof's gate is raised"
        );
        spaces.lower(index);
        assert_eq!(
            spaces
                .close_and_wait_for_editor(index, || unreachable!())
                .key(),
            7
        );
    }

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

    #[test]
    fn one_exact_guest_editor_owns_a_space_at_a_time() {
        let spaces = AddressSpaces::new();
        let index = spaces.publish_closed(7, 0x1_0000, 0x1_0000).unwrap();
        spaces.open(index);

        let owner = NonZeroU64::new(11).unwrap();
        let editor = spaces
            .try_begin_edit(index, 7, owner)
            .expect("open exact space admits its first editor");
        assert_eq!(spaces.active_editor(index), Some(owner));
        assert!(
            spaces
                .try_begin_edit(index, 7, NonZeroU64::new(12).unwrap())
                .is_none(),
            "a second editor cannot mutate the same live tables"
        );
        assert!(
            spaces.try_begin_edit(index, 8, owner).is_none(),
            "the editor claim is bound to the exact MM key"
        );

        drop(editor);
        assert_eq!(spaces.active_editor(index), None);
        assert!(spaces.try_begin_edit(index, 7, owner).is_some());
    }

    #[test]
    fn a_host_pause_closes_the_gate_before_waiting_for_the_guest_editor() {
        let spaces = Arc::new(AddressSpaces::new());
        let index = spaces.publish_closed(9, 0x2_0000, 0x2_0000).unwrap();
        spaces.open(index);
        let editor = spaces
            .try_begin_edit(index, 9, NonZeroU64::new(21).unwrap())
            .expect("guest editor enters before the pause");

        let (waiting_tx, waiting_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let host_spaces = Arc::clone(&spaces);
        let host = std::thread::spawn(move || {
            let mut reported = false;
            host_spaces.raise_and_wait_for_editor(index, || {
                if !reported {
                    waiting_tx.send(()).unwrap();
                    reported = true;
                }
                std::thread::yield_now();
            });
            done_tx.send(()).unwrap();
        });

        waiting_rx.recv().unwrap();
        assert_ne!(spaces.gate(index), 0, "the gate closes before the wait");
        assert!(
            spaces
                .try_begin_edit(index, 9, NonZeroU64::new(22).unwrap())
                .is_none(),
            "no editor may enter behind the raised host pause"
        );
        assert!(
            done_rx.try_recv().is_err(),
            "host still waits for the owner"
        );

        drop(editor);
        done_rx.recv().unwrap();
        host.join().unwrap();
        assert_eq!(spaces.active_editor(index), None);
        spaces.lower(index);
        assert!(
            spaces
                .try_begin_edit(index, 9, NonZeroU64::new(23).unwrap())
                .is_some(),
            "ending the pause admits the next exact editor"
        );
    }

    #[test]
    fn a_closed_space_refuses_an_editor_without_leaking_the_claim() {
        let spaces = AddressSpaces::new();
        let index = spaces.publish_closed(13, 0x3_0000, 0x3_0000).unwrap();
        let owner = NonZeroU64::new(31).unwrap();

        assert!(spaces.try_begin_edit(index, 13, owner).is_none());
        assert_eq!(spaces.active_editor(index), None);
        spaces.open(index);
        spaces.close(index);
        assert!(spaces.try_begin_edit(index, 13, owner).is_none());
        assert_eq!(spaces.active_editor(index), None);
    }
}
