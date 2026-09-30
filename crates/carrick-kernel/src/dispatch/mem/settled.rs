//! The MM's `MemState` behind the one door that settles EL1's journal.
//!
//! EL1 serves a permission-narrowing `mprotect` of resident private
//! anonymous memory without a host exit and appends it to its address
//! space's VMA journal (`carrick_sched_core::AddressSpaces`). Those edits are
//! real: `/proc/<pid>/maps`, `mincore`, `mprotect`/`munmap`/`mremap`
//! validation, the fork snapshot, exec and the core dump all read the rows
//! they change. [`SettledMem`] owns the `MemState` mutex, and its field is
//! private to this module, so the only way to reach the state is a lock that
//! first applies every pending journaled edit, in order, through the same
//! [`MemState::set_mapping_prot`] the host `mprotect` commits with. A reader
//! cannot skip the settle because it cannot name the unsettled state.

use std::sync::atomic::{AtomicU64, Ordering};

use carrick_abi::LinuxProtFlags;
use carrick_sched_core::VmaEdit;
use parking_lot::{Mutex, MutexGuard};

use super::MemState;

/// Where an MM's journal lives. Production reads the carrier's zone tables;
/// a test hands in its own table.
#[cfg(test)]
type TestSpaces = Mutex<Option<std::sync::Arc<carrick_sched_core::AddressSpaces>>>;

pub(super) struct SettledMem {
    state: Mutex<MemState>,
    /// The MM id that keys this MM's address-space entry; 0 until bound.
    key: AtomicU64,
    #[cfg(test)]
    test_spaces: TestSpaces,
}

impl SettledMem {
    pub(super) fn new(state: MemState) -> Self {
        Self {
            state: Mutex::new(state),
            key: AtomicU64::new(0),
            #[cfg(test)]
            test_spaces: Mutex::new(None),
        }
    }

    /// Name the address-space entry whose journal this MM settles.
    pub(super) fn bind(&self, key: u64) {
        self.key.store(key, Ordering::Release);
    }

    #[cfg(test)]
    pub(super) fn bind_test_spaces(
        &self,
        key: u64,
        spaces: std::sync::Arc<carrick_sched_core::AddressSpaces>,
    ) {
        *self.test_spaces.lock() = Some(spaces);
        self.bind(key);
    }

    /// Lock the state with every pending journaled edit applied.
    pub(super) fn lock(&self) -> MutexGuard<'_, MemState> {
        let mut guard = self.state.lock();
        self.settle(&mut guard);
        guard
    }

    pub(super) fn try_lock_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<MutexGuard<'_, MemState>> {
        let mut guard = self.state.try_lock_until(deadline)?;
        self.settle(&mut guard);
        Some(guard)
    }

    /// Apply EL1's journaled edits to `state`, oldest first. The state lock
    /// serializes drains of this MM's journal.
    fn settle(&self, state: &mut MemState) {
        let key = self.key.load(Ordering::Acquire);
        if key == 0 {
            return;
        }
        #[cfg(test)]
        let test_spaces = self.test_spaces.lock().clone();
        #[cfg(test)]
        let spaces: Option<&carrick_sched_core::AddressSpaces> = test_spaces
            .as_deref()
            .or_else(|| crate::el1_zone::zone().map(|zone| &zone.spaces));
        #[cfg(not(test))]
        let spaces = crate::el1_zone::zone().map(|zone| &zone.spaces);
        let Some(spaces) = spaces else {
            return;
        };
        // Deliberately NO `VmaRevision` bump. The revision is published only
        // by the host-alias dispatch protocol (`HostAliasDispatchAdmission`
        // advances it at the end of a dispatch, under the phase lock that
        // foreign-MM snapshot consumers wait on). A settle runs inside any
        // reader's lock at an arbitrary time, so a bump here would change the
        // revision under a foreign COW publication that validated its
        // snapshot against it and fail that operation (the parent's
        // concurrent mprotects answered ENOMEM under fork load). EL1's served
        // edits were outside the revision before the journal and stay so.
        spaces.drain_vma_journal(key, |edit| state.apply_journaled_edit(edit));
    }
}

impl MemState {
    /// One journaled protection edit, through the single mutation the host
    /// `mprotect` commits with.
    fn apply_journaled_edit(&mut self, edit: VmaEdit) {
        let prot = LinuxProtFlags::from_bits_truncate(u64::from(edit.prot));
        self.set_mapping_prot(edit.start, edit.end, prot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::mem::{MemAuthority, SemanticVma, VmaBackingProvenance, VmaMap};
    use carrick_sched_core::{AddressSpaces, VMA_JOURNAL_ENTRIES};
    use carrick_vfs::{ProcMapSharing, ProcMapsEntry};
    use std::num::NonZeroU64;
    use std::sync::Arc;

    const KEY: u64 = 41;
    const BASE: u64 = 0x60_0000_5000;
    const PAGE: u64 = 0x1000;
    const PAGES: u64 = 8;
    const R: u8 = 1;
    const RW: u8 = 3;

    /// An MM whose anonymous region `BASE..BASE+8 pages` is one `rw-p` row,
    /// bound to an address-space entry a test plays EL1 against.
    fn mm() -> (MemAuthority, Arc<AddressSpaces>) {
        let end = BASE + PAGES * PAGE;
        let mut state = MemState::new();
        state.dynamic_maps.push(ProcMapsEntry {
            start: BASE,
            end,
            read: true,
            write: true,
            execute: false,
            sharing: ProcMapSharing::Private,
            path: String::new(),
        });
        state.semantic_vmas = VmaMap::from_vec(vec![SemanticVma {
            start: BASE,
            end,
            read: true,
            write: true,
            execute: false,
            provenance: VmaBackingProvenance::PrivateAnonymous,
            fork_policy: carrick_abi::VmaForkPolicy::DEFAULT,
            dump_policy: carrick_abi::VmaDumpPolicy::Include,
            droppable: false,
            path: String::new(),
            file_page_offset: None,
        }]);
        let authority = MemAuthority::new(state);
        let spaces = Arc::new(AddressSpaces::new());
        let index = spaces.publish_closed(KEY, 0x1_0000, 0x1_0000).unwrap();
        spaces.open(index);
        authority.state.bind_test_spaces(KEY, Arc::clone(&spaces));
        (authority, spaces)
    }

    /// What guest EL1 does for a served `mprotect`: record it in the journal.
    fn el1_serves(spaces: &AddressSpaces, page: u64, prot: u8) {
        let index = spaces.find(KEY).unwrap();
        let editor = spaces
            .try_begin_edit(index, KEY, NonZeroU64::new(1).unwrap())
            .unwrap();
        editor
            .journal_protect(BASE + page * PAGE, BASE + (page + 1) * PAGE, prot)
            .unwrap();
    }

    fn rows(authority: &MemAuthority) -> Vec<(u64, u64, bool, bool)> {
        authority
            .lock()
            .proc_regions()
            .unwrap_or_default()
            .into_iter()
            .filter(|row| row.start >= BASE && row.start < BASE + PAGES * PAGE)
            .map(|row| (row.start, row.end, row.read, row.write))
            .collect()
    }

    #[test]
    fn a_reader_settles_the_journal_before_it_reads() {
        let (authority, spaces) = mm();
        el1_serves(&spaces, 1, R);
        assert_eq!(spaces.pending_vma_edits(KEY), 1);
        // No dispatch, no exit: the first reader applies the edit.
        assert_eq!(
            rows(&authority),
            vec![
                (BASE, BASE + PAGE, true, true),
                (BASE + PAGE, BASE + 2 * PAGE, true, false),
                (BASE + 2 * PAGE, BASE + PAGES * PAGE, true, true),
            ]
        );
        assert_eq!(spaces.pending_vma_edits(KEY), 0);
    }

    #[test]
    fn journaled_edits_apply_in_order_through_the_one_mutation_path() {
        let (authority, spaces) = mm();
        el1_serves(&spaces, 1, R);
        el1_serves(&spaces, 1, RW);
        // Narrow then restore: in order, the rows merge back to one; applied
        // in the opposite order the page would stay read-only.
        assert_eq!(
            rows(&authority),
            vec![(BASE, BASE + PAGES * PAGE, true, true)]
        );
        // Restore then narrow ends read-only: the later edit wins.
        el1_serves(&spaces, 3, RW);
        el1_serves(&spaces, 3, R);
        let page3 = rows(&authority)
            .into_iter()
            .find(|row| row.0 == BASE + 3 * PAGE)
            .expect("page 3 is its own row");
        assert_eq!((page3.1, page3.2, page3.3), (BASE + 4 * PAGE, true, false));
    }

    #[test]
    fn a_full_journal_settles_every_edit_with_none_lost() {
        let (authority, spaces) = mm();
        for n in 0..VMA_JOURNAL_ENTRIES as u64 {
            el1_serves(&spaces, n % PAGES, if n % 2 == 0 { R } else { RW });
        }
        // The last write to page 0 and 1..: pages alternate by edit parity.
        let mut expected = [RW; PAGES as usize];
        for n in 0..VMA_JOURNAL_ENTRIES as u64 {
            expected[(n % PAGES) as usize] = if n % 2 == 0 { R } else { RW };
        }
        let settled = authority.lock();
        for (page, prot) in expected.iter().enumerate() {
            let at = BASE + page as u64 * PAGE;
            let row = settled
                .dynamic_maps
                .iter()
                .find(|row| row.start <= at && at < row.end)
                .unwrap();
            assert_eq!(row.write, *prot == RW, "page {page}");
        }
    }

    #[test]
    fn a_fork_snapshot_settles_the_parents_pending_journal() {
        let (authority, spaces) = mm();
        el1_serves(&spaces, 2, R);
        let child = authority.fork_private();
        let row = child
            .lock()
            .dynamic_maps
            .iter()
            .find(|row| row.start <= BASE + 2 * PAGE && BASE + 2 * PAGE < row.end)
            .cloned()
            .unwrap();
        assert!(
            row.read && !row.write,
            "the child inherits the narrowed page"
        );
        assert_eq!((row.start, row.end), (BASE + 2 * PAGE, BASE + 3 * PAGE));
        // The parent's journal was consumed once, by the fork.
        assert_eq!(spaces.pending_vma_edits(KEY), 0);
    }

    #[test]
    fn settling_the_journal_never_advances_the_vma_revision() {
        let (authority, spaces) = mm();
        let before = authority.vma_revision();
        el1_serves(&spaces, 1, R);
        assert_eq!(rows(&authority).len(), 3, "the edit was applied");
        assert_eq!(
            authority.vma_revision(),
            before,
            "the revision is published only by the host-alias dispatch protocol"
        );
    }

    #[test]
    fn an_unbound_mm_ignores_the_journal() {
        let (authority, spaces) = mm();
        authority.state.bind(0);
        el1_serves(&spaces, 1, R);
        assert_eq!(
            rows(&authority),
            vec![(BASE, BASE + PAGES * PAGE, true, true)]
        );
        assert_eq!(spaces.pending_vma_edits(KEY), 1);
    }

    /// The `el1_sched_mm_occupancy_two_processes` shape without a VM: eight
    /// writers each narrow and restore their own pages through EL1's
    /// journal (falling back to the host commit when it is full), while the
    /// host validates that every range stays covered (Linux: mprotect of a
    /// mapped range never answers ENOMEM) and forks the MM concurrently.
    #[test]
    fn concurrent_edits_a_full_journal_and_forks_never_uncover_a_range() {
        use crate::dispatch::mem::guest_vma_covers_locked;
        const WRITERS: u64 = 8;
        let (authority, spaces) = mm();
        let authority = Arc::new(authority);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut threads = Vec::new();
        for writer in 0..WRITERS {
            let (authority, spaces) = (Arc::clone(&authority), Arc::clone(&spaces));
            threads.push(std::thread::spawn(move || {
                // One page each: `PAGES` == `WRITERS`.
                for round in 0..400u64 {
                    let prot = if round % 2 == 0 { R } else { RW };
                    let index = spaces.find(KEY).unwrap();
                    let owner = NonZeroU64::new(writer + 1).unwrap();
                    let editor = spaces
                        .try_begin_edit_bounded(index, KEY, owner, u32::MAX)
                        .unwrap();
                    let (start, end) = (BASE + writer * PAGE, BASE + (writer + 1) * PAGE);
                    if editor.journal_has_room() {
                        editor.journal_protect(start, end, prot).unwrap();
                    } else {
                        drop(editor);
                        // ReturnWithWork: the host commits the same edit.
                        authority.lock().set_mapping_prot(
                            start,
                            end,
                            LinuxProtFlags::from_bits_truncate(u64::from(prot)),
                        );
                    }
                }
            }));
        }
        let validator = {
            let (authority, stop) = (Arc::clone(&authority), Arc::clone(&stop));
            std::thread::spawn(move || {
                let mut checks = 0u64;
                while !stop.load(Ordering::Acquire) {
                    let guard = authority.lock();
                    assert!(
                        guard_covers(&guard, BASE, PAGES * PAGE),
                        "a mapped range read as a hole after {checks} checks"
                    );
                    drop(guard);
                    checks += 1;
                }
            })
        };
        let forker = {
            let (authority, stop) = (Arc::clone(&authority), Arc::clone(&stop));
            std::thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let child = authority.fork_private();
                    assert!(guard_covers(&child.lock(), BASE, PAGES * PAGE));
                }
            })
        };
        for thread in threads {
            thread.join().unwrap();
        }
        stop.store(true, Ordering::Release);
        validator.join().unwrap();
        forker.join().unwrap();
        // 400 rounds: the last edit of each writer restored RW.
        assert_eq!(
            rows(&authority),
            vec![(BASE, BASE + PAGES * PAGE, true, true)]
        );
        fn guard_covers(state: &MemState, start: u64, len: u64) -> bool {
            guest_vma_covers_locked(state, start, len)
        }
    }
}
