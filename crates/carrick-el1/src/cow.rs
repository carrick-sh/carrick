//! Guest EL1 fork-COW resolution with host-provisioned replacement frames.
//!
//! The caller holds the faulting MM's exact page-table editor. EL1 then
//! classifies the write fault ([`classify_guest_cow_write`]), takes one of
//! the MM's ready grants from the shared [`CowGrantPool`], copies the run's
//! pages from the still-shared compound into the grant through the MM's
//! two temporary copy-window aliases, repoints the run with the shared
//! descriptor executor, invalidates the MM's ASID and only then records the
//! completion for the host. Nothing here exits to the host; anything EL1
//! cannot classify, or a pool with no grant for the MM, is left to the host
//! fault path unchanged.

use carrick_el1_abi::{CowDecline, CowGrantCompletion, CowGrantPool};
use carrick_mmu_core::aarch64::SubstrateGpa;
use carrick_mmu_core::aarch64::descriptor_txn::copy_window::with_cow_copy_aliases;
use carrick_mmu_core::aarch64::descriptor_txn::guest_cow::{
    GuestCowClass, GuestCowNotArmed, classify_guest_cow_write,
};
use carrick_mmu_core::aarch64::descriptor_txn::{
    CowRepointAccess, DescriptorOp, DescriptorOutcome, InlineJournal, LiveDescriptorWords,
    TableGrants, execute_descriptor_op, plan_descriptor_op,
};

const PAGE: u64 = 4096;

/// What one guest COW attempt did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestCowOutcome {
    /// The run was copied, repointed and invalidated; the completion is the
    /// host's to settle. Retry the faulting instruction.
    Resolved(CowGrantCompletion),
    /// The leaf already permits the write; the ASID was invalidated. Retry.
    AlreadyWritable,
    /// Left to the host (counted in the pool by reason).
    Declined(CowDecline),
}

/// Where one MM's guest COW runs: its live table words and authenticated
/// root, the shared grant pool, and the MM's copy-window base.
pub struct GuestCowVenue<'a, W: ?Sized> {
    pub words: &'a W,
    pub root: SubstrateGpa,
    pub pool: &'a CowGrantPool,
    pub copy_base: u64,
}

/// Resolve one EL0 write permission fault at `far` for `mm_key` in `venue`.
/// `copy_page(source, destination)` copies one page between the two
/// copy-window aliases while both are mapped; `invalidate_asid` invalidates
/// the MM's ASID on every PE.
///
/// # Panics
///
/// When a store sequence can neither complete nor roll back (the live graph
/// is no longer the one this editor validated): continuing would run the MM
/// on unknown translations.
pub fn resolve_guest_cow<W, C, I>(
    venue: &GuestCowVenue<'_, W>,
    mm_key: u64,
    far: u64,
    mut copy_page: C,
    mut invalidate_asid: I,
) -> GuestCowOutcome
where
    W: LiveDescriptorWords + ?Sized,
    C: FnMut(u64, u64),
    I: FnMut(),
{
    let GuestCowVenue {
        words,
        root,
        pool,
        copy_base,
    } = *venue;
    let run = match classify_guest_cow_write(words, root, far) {
        Ok(run) => run,
        Err(GuestCowClass::AlreadyWritable) => {
            invalidate_asid();
            return GuestCowOutcome::AlreadyWritable;
        }
        Err(class @ (GuestCowClass::NotArmed(_) | GuestCowClass::Unreachable(_))) => {
            let reason = match class {
                GuestCowClass::NotArmed(GuestCowNotArmed::Unmapped) => CowDecline::Unmapped,
                GuestCowClass::NotArmed(GuestCowNotArmed::NotCowArmed) => CowDecline::NotCowArmed,
                GuestCowClass::NotArmed(GuestCowNotArmed::NotEl1Private) => {
                    CowDecline::NotEl1Private
                }
                GuestCowClass::NotArmed(GuestCowNotArmed::NoWriteIntent) => {
                    CowDecline::NoWriteIntent
                }
                _ => CowDecline::Unreachable,
            };
            pool.note_declined(reason);
            return GuestCowOutcome::Declined(reason);
        }
    };
    let Some(grant) = pool.claim(mm_key) else {
        pool.note_declined(CowDecline::PoolEmpty);
        return GuestCowOutcome::Declined(CowDecline::PoolEmpty);
    };
    let decline = |pool: &CowGrantPool| {
        let abandoned = pool.abandon(&grant);
        assert!(abandoned, "EL1 lost its claimed COW grant");
        pool.note_declined(CowDecline::Refused);
        GuestCowOutcome::Declined(CowDecline::Refused)
    };
    let new_ipa = grant.physical_ipa + run.compound_offset();
    let op = DescriptorOp::CowRepoint {
        access: CowRepointAccess::RecordedPrivate,
        va: run.va,
        len: run.len,
        old_ipa: run.old_ipa,
        new_ipa: SubstrateGpa(new_ipa),
        backing: grant.backing,
    };
    // Validate the whole repoint (no table split, every leaf still the
    // classified one) before copying a byte.
    match plan_descriptor_op(words, root, op) {
        Ok(plan) if plan.table_grants == 0 => {}
        _ => return decline(pool),
    }
    for offset in (0..run.len).step_by(PAGE as usize) {
        let copied = with_cow_copy_aliases(
            words,
            root,
            copy_base,
            SubstrateGpa(run.old_ipa.raw() + offset),
            SubstrateGpa(new_ipa + offset),
            &mut copy_page,
        );
        match copied {
            Ok(()) => {}
            Err(DescriptorOutcome::Indeterminate(refusal)) => {
                panic!("EL1 COW copy window could not be restored: {refusal:?}")
            }
            Err(_) => return decline(pool),
        }
    }
    let mut journal = InlineJournal::new();
    match execute_descriptor_op(words, root, op, &TableGrants::NONE, &mut journal) {
        DescriptorOutcome::Applied(applied) => {
            if applied.flush_required {
                invalidate_asid();
            }
            let completion = CowGrantCompletion {
                grant,
                span_va: run.va,
                span_len: run.len,
                old_ipa: run.old_ipa.raw(),
                new_ipa,
            };
            let recorded = pool.complete(&completion);
            assert!(recorded, "EL1 COW completion was not recordable");
            GuestCowOutcome::Resolved(completion)
        }
        DescriptorOutcome::Refused(_) => decline(pool),
        DescriptorOutcome::RolledBack(_) => {
            invalidate_asid();
            decline(pool)
        }
        DescriptorOutcome::Indeterminate(refusal) => {
            panic!("EL1 COW repoint rollback failed: {refusal:?}")
        }
    }
}

#[cfg(test)]
mod tests {
    //! The real descriptor executor and copy window over host memory: a
    //! table arena at `ROOT` (the primary arena EL1 edits through its alias)
    //! and a page-granular model of guest-physical memory that the copy
    //! window's live alias leaves select from.
    use super::*;
    use crate::fault::{
        CowResolver, GrantMailboxes, NoopPreparedResolver, PreparedFaultPath,
        dispatch_fault_with_prepared,
    };
    use carrick_el1_abi::{
        Action, COW_GRANT_SIZE, Counters, CurrentTask, EL1_COW_COPY_BASE, FrameGrantMailbox,
        TrapFrame,
    };
    use carrick_mmu_core::aarch64::descriptor_txn::{
        BackingIdentity, PrimaryTableWords, TableMaintenance,
    };
    use carrick_mmu_core::aarch64::indices;
    use carrick_sched_core::AddressSpaces;
    use core::cell::{Cell, RefCell};
    use core::num::NonZeroU64;
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::collections::BTreeMap;

    const ROOT: u64 = 0x8800_0000_0000;
    const ASID: u64 = 5 << 48;
    const MM: u64 = 77;
    const VA: u64 = 0x4000_0000;
    const OLD: u64 = 0x009b_4000_0000;
    const GRANT: u64 = 0x009d_0000_4000;
    const PA: u64 = 0x0000_FFFF_FFFF_F000;
    const AF: u64 = 1 << 10;
    const SH: u64 = 0b11 << 8;
    const AP_RO_EL0: u64 = 0b11 << 6;
    const AP_RW_EL0: u64 = 0b01 << 6;
    const NG: u64 = 1 << 11;
    const XN: u64 = (1 << 53) | (1 << 54);
    const COW: u64 = 1 << 55;
    const PRIVATE: u64 = 1 << 56;
    const MAY_WRITE: u64 = 1 << 57;

    struct Arena {
        words: Vec<AtomicU64>,
    }

    impl Arena {
        /// Tables for `VA` (L3 at +0x3000) and for the EL1 copy window
        /// (L2 at +0x4000, L3 at +0x5000) with its two idle leaves.
        fn new(window: bool) -> Self {
            let arena = Self {
                words: (0..8 * 512).map(|_| AtomicU64::new(0)).collect(),
            };
            let va = indices(VA);
            arena.set(ROOT + va[0] as u64 * 8, (ROOT + 0x1000) | 3);
            arena.set(ROOT + 0x1000 + va[1] as u64 * 8, (ROOT + 0x2000) | 3);
            arena.set(ROOT + 0x2000 + va[2] as u64 * 8, (ROOT + 0x3000) | 3);
            if window {
                let win = indices(EL1_COW_COPY_BASE);
                assert_eq!(win[0], va[0], "one L0 entry covers both");
                arena.set(ROOT + 0x1000 + win[1] as u64 * 8, (ROOT + 0x4000) | 3);
                arena.set(ROOT + 0x4000 + win[2] as u64 * 8, (ROOT + 0x5000) | 3);
                for page in 0..2 {
                    let alias = EL1_COW_COPY_BASE + page * 4096;
                    arena.set(ROOT + 0x5000 + indices(alias)[3] as u64 * 8, alias);
                }
            }
            arena
        }
        fn set(&self, pa: u64, value: u64) {
            self.words[((pa - ROOT) / 8) as usize].store(value, Ordering::Relaxed);
        }
        fn get(&self, pa: u64) -> u64 {
            self.words[((pa - ROOT) / 8) as usize].load(Ordering::Relaxed)
        }
        fn leaf_pa(va: u64) -> u64 {
            let l3 = if va >> 30 == EL1_COW_COPY_BASE >> 30 {
                ROOT + 0x5000
            } else {
                ROOT + 0x3000
            };
            l3 + indices(va)[3] as u64 * 8
        }
        fn leaf(&self, va: u64) -> u64 {
            self.get(Self::leaf_pa(va))
        }
        fn set_leaf(&self, va: u64, value: u64) {
            self.set(Self::leaf_pa(va), value);
        }
        fn words(&self) -> PrimaryTableWords<'_, Maintenance> {
            unsafe {
                PrimaryTableWords::new(
                    self.words.as_ptr().cast_mut(),
                    ROOT,
                    self.words.len() * 8,
                    &MAINTENANCE,
                )
            }
            .unwrap()
        }
        fn image(&self) -> Vec<u64> {
            self.words
                .iter()
                .map(|w| w.load(Ordering::Relaxed))
                .collect()
        }
    }

    struct Maintenance;
    static MAINTENANCE: Maintenance = Maintenance;
    impl TableMaintenance for Maintenance {
        fn publish_barrier(&self) {}
        fn invalidate_range(&self, _va: u64, _len: u64) {}
    }

    /// Guest-physical pages. Copies read the copy window's live leaves, so
    /// a copy through an unmapped or wrong alias fails the test.
    struct Memory(RefCell<BTreeMap<u64, Vec<u8>>>);

    impl Memory {
        fn page(&self, ipa: u64) -> Vec<u8> {
            self.0.borrow().get(&ipa).cloned().unwrap_or(vec![0; 4096])
        }
        fn copy_through(&self, arena: &Arena, source: u64, destination: u64) {
            let (from, to) = (arena.leaf(source), arena.leaf(destination));
            assert_ne!(from & 1, 0, "source alias not mapped during the copy");
            assert_ne!(to & 1, 0, "destination alias not mapped during the copy");
            assert_eq!(
                from & (0b11 << 6),
                0b10 << 6,
                "source alias is EL1 read-only"
            );
            assert_eq!(to & (0b11 << 6), 0, "destination alias is EL1 read-write");
            let bytes = self.page(from & PA);
            self.0.borrow_mut().insert(to & PA, bytes);
        }
    }

    fn nz(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).unwrap()
    }

    fn backing() -> BackingIdentity {
        BackingIdentity {
            frame_id: nz(11),
            mapping_id: nz(12),
            owner_generation: nz(13),
            inventory_revision: nz(14),
        }
    }

    fn armed(ipa: u64, may_write: bool) -> u64 {
        ipa | 3
            | AF
            | SH
            | AP_RO_EL0
            | NG
            | XN
            | COW
            | PRIVATE
            | if may_write { MAY_WRITE } else { 0 }
    }

    /// A forked private compound: four armed pages, lane 3 read-only in
    /// Linux, each page holding distinct bytes.
    fn forked(window: bool) -> (Arena, Memory) {
        let arena = Arena::new(window);
        let memory = Memory(RefCell::new(BTreeMap::new()));
        for lane in 0..4 {
            arena.set_leaf(VA + lane * 4096, armed(OLD + lane * 4096, lane != 3));
            memory.0.borrow_mut().insert(
                OLD + lane * 4096,
                (0..4096).map(|i| (i as u64 * 7 + lane) as u8).collect(),
            );
        }
        (arena, memory)
    }

    fn resolve(
        arena: &Arena,
        memory: &Memory,
        pool: &CowGrantPool,
        far: u64,
        invalidations: &Cell<usize>,
    ) -> GuestCowOutcome {
        resolve_guest_cow(
            &GuestCowVenue {
                words: &arena.words(),
                root: SubstrateGpa(ROOT),
                pool,
                copy_base: EL1_COW_COPY_BASE,
            },
            MM,
            far,
            |source, destination| memory.copy_through(arena, source, destination),
            || invalidations.set(invalidations.get() + 1),
        )
    }

    #[test]
    fn el1_copies_and_repoints_a_forked_compound_with_a_pool_grant() {
        let (arena, memory) = forked(true);
        let window_before = [
            arena.leaf(EL1_COW_COPY_BASE),
            arena.leaf(EL1_COW_COPY_BASE + 4096),
        ];
        let pool = CowGrantPool::new();
        let grant = pool.publish(MM, GRANT, backing()).unwrap();
        let invalidations = Cell::new(0);

        let outcome = resolve(&arena, &memory, &pool, VA + 0x1abc, &invalidations);

        let expected = CowGrantCompletion {
            grant,
            span_va: VA,
            span_len: 4 * 4096,
            old_ipa: OLD,
            new_ipa: GRANT,
        };
        assert_eq!(outcome, GuestCowOutcome::Resolved(expected));
        for lane in 0..4 {
            let leaf = arena.leaf(VA + lane * 4096);
            assert_eq!(
                leaf & PA,
                GRANT + lane * 4096,
                "lane {lane} moved to the grant"
            );
            assert_eq!(leaf & COW, 0, "lane {lane} is private now");
            let writable = leaf & (0b11 << 6) == AP_RW_EL0;
            assert_eq!(
                writable,
                lane != 3,
                "lane {lane} recovers its recorded intent"
            );
            assert_eq!(
                memory.page(GRANT + lane * 4096),
                memory.page(OLD + lane * 4096),
                "lane {lane} bytes copied"
            );
        }
        assert_eq!(
            [
                arena.leaf(EL1_COW_COPY_BASE),
                arena.leaf(EL1_COW_COPY_BASE + 4096)
            ],
            window_before,
            "the copy window is idle again"
        );
        assert!(
            invalidations.get() >= 1,
            "the MM's stale RO translations are invalidated"
        );
        let spaces = AddressSpaces::new();
        let excluded = spaces.unpublished(MM).unwrap();
        assert_eq!(
            pool.completions(&excluded).collect::<Vec<_>>(),
            vec![expected]
        );
        assert_eq!(pool.resolved(), 1);
        assert_eq!(pool.ready(MM).count(), 0);
    }

    #[test]
    fn el1_moves_only_the_run_of_the_faulting_compound() {
        let (arena, memory) = forked(true);
        // Lane 0 was already privatized by an earlier COW.
        arena.set_leaf(
            VA,
            (0x0077_0000_0000 | 3 | AF | SH | NG | XN | PRIVATE | MAY_WRITE) | AP_RW_EL0,
        );
        let pool = CowGrantPool::new();
        let grant = pool.publish(MM, GRANT, backing()).unwrap();
        let outcome = resolve(&arena, &memory, &pool, VA + 2 * 4096, &Cell::new(0));
        assert_eq!(
            outcome,
            GuestCowOutcome::Resolved(CowGrantCompletion {
                grant,
                span_va: VA + 4096,
                span_len: 3 * 4096,
                old_ipa: OLD + 4096,
                new_ipa: GRANT + 4096,
            })
        );
        assert_eq!(
            arena.leaf(VA) & PA,
            0x0077_0000_0000,
            "the private lane is untouched"
        );
    }

    #[test]
    fn an_empty_pool_or_another_mms_grant_leaves_the_fault_to_the_host() {
        let (arena, memory) = forked(true);
        let before = arena.image();
        let pool = CowGrantPool::new();
        pool.publish(MM + 1, GRANT, backing()).unwrap();
        assert_eq!(
            resolve(&arena, &memory, &pool, VA, &Cell::new(0)),
            GuestCowOutcome::Declined(CowDecline::PoolEmpty)
        );
        assert_eq!(arena.image(), before);
        assert_eq!(
            pool.ready(MM + 1).count(),
            1,
            "the other MM's grant is untouched"
        );
        assert_eq!(pool.declined()[CowDecline::PoolEmpty as usize], 1);
    }

    #[test]
    fn unclassified_writes_keep_their_grant_ready() {
        let (arena, memory) = forked(true);
        // mprotect(PROT_READ) after the fork: an armed page without write
        // intent is a SIGSEGV for the host to deliver, never a copy.
        arena.set_leaf(VA, armed(OLD, false));
        let pool = CowGrantPool::new();
        pool.publish(MM, GRANT, backing()).unwrap();
        let before = arena.image();
        assert_eq!(
            resolve(&arena, &memory, &pool, VA, &Cell::new(0)),
            GuestCowOutcome::Declined(CowDecline::NoWriteIntent)
        );
        // An untagged backend leaf.
        arena.set_leaf(VA, OLD | 3 | AF | SH | AP_RO_EL0 | NG);
        assert_eq!(
            resolve(&arena, &memory, &pool, VA, &Cell::new(0)),
            GuestCowOutcome::Declined(CowDecline::NotEl1Private)
        );
        assert_eq!(pool.ready(MM).count(), 1);
        arena.set_leaf(VA, before[((Arena::leaf_pa(VA) - ROOT) / 8) as usize]);
        assert_eq!(arena.image(), before);
    }

    #[test]
    fn a_refused_copy_returns_the_grant_and_changes_nothing() {
        // No copy window provisioned in this MM's tables.
        let (arena, memory) = forked(false);
        let before = arena.image();
        let pool = CowGrantPool::new();
        let grant = pool.publish(MM, GRANT, backing()).unwrap();
        assert_eq!(
            resolve(&arena, &memory, &pool, VA, &Cell::new(0)),
            GuestCowOutcome::Declined(CowDecline::Refused)
        );
        assert_eq!(arena.image(), before);
        assert_eq!(pool.ready(MM).collect::<Vec<_>>(), vec![grant]);
        assert!(
            memory.0.borrow().get(&GRANT).is_none(),
            "nothing was copied"
        );
    }

    #[test]
    fn an_already_writable_leaf_retries_after_invalidation() {
        let (arena, memory) = forked(true);
        arena.set_leaf(
            VA,
            (OLD | 3 | AF | SH | NG | XN | PRIVATE | MAY_WRITE) | AP_RW_EL0,
        );
        let pool = CowGrantPool::new();
        pool.publish(MM, GRANT, backing()).unwrap();
        let invalidations = Cell::new(0);
        assert_eq!(
            resolve(&arena, &memory, &pool, VA, &invalidations),
            GuestCowOutcome::AlreadyWritable
        );
        assert_eq!(invalidations.get(), 1);
        assert_eq!(pool.ready(MM).count(), 1);
    }

    /// The fault dispatcher's resolver over the model arena.
    struct ArenaResolver<'a> {
        arena: &'a Arena,
        memory: &'a Memory,
        pool: &'a CowGrantPool,
    }

    impl CowResolver for ArenaResolver<'_> {
        fn resolve_cow(&mut self, ttbr0: u64, mm_key: u64, far: u64) -> bool {
            assert_eq!(ttbr0 & PA, ROOT);
            let outcome = resolve_guest_cow(
                &GuestCowVenue {
                    words: &self.arena.words(),
                    root: SubstrateGpa(ttbr0 & PA),
                    pool: self.pool,
                    copy_base: EL1_COW_COPY_BASE,
                },
                mm_key,
                far,
                |source, destination| self.memory.copy_through(self.arena, source, destination),
                || {},
            );
            !matches!(outcome, GuestCowOutcome::Declined(_))
        }
        fn editor_busy(&mut self) {
            self.pool.note_declined(CowDecline::EditorBusy);
        }
    }

    fn dispatch(spaces: &AddressSpaces, resolver: &mut ArenaResolver<'_>) -> Action {
        let task = CurrentTask::new();
        task.zone_mm.store(MM, Ordering::Release);
        let mut frame = TrapFrame {
            esr: (0x24 << 26) | (1 << 6) | 0x0f,
            far: VA + 0x10,
            slot: 0,
            ..TrapFrame::default()
        };
        dispatch_fault_with_prepared(
            &mut frame,
            &Counters::default(),
            &[task],
            spaces,
            GrantMailboxes::own(&FrameGrantMailbox::new()),
            None::<PreparedFaultPath<'_, NoopPreparedResolver>>,
            resolver,
        )
    }

    #[test]
    fn a_guest_cow_fault_is_served_in_el1_unless_the_host_holds_the_mm() {
        let (arena, memory) = forked(true);
        let pool = CowGrantPool::new();
        pool.publish(MM, GRANT, backing()).unwrap();
        let mut resolver = ArenaResolver {
            arena: &arena,
            memory: &memory,
            pool: &pool,
        };
        // A host pause of the MM closes its gate: EL1 never edits under it.
        let closed = AddressSpaces::new();
        closed.publish_closed(MM, ROOT | ASID, ROOT | ASID).unwrap();
        let before = arena.image();
        assert_eq!(dispatch(&closed, &mut resolver), Action::Forward);
        assert_eq!(arena.image(), before);
        assert_eq!(pool.declined()[CowDecline::EditorBusy as usize], 1);
        assert_eq!(pool.ready(MM).count(), 1);

        let open = AddressSpaces::new();
        let index = open.publish_closed(MM, ROOT | ASID, ROOT | ASID).unwrap();
        open.open(index);
        assert_eq!(dispatch(&open, &mut resolver), Action::Served);
        // The host settles with the MM's editor excluded (here: unpublished).
        let host = AddressSpaces::new();
        let excluded = host.unpublished(MM).unwrap();
        assert_eq!(pool.completions(&excluded).count(), 1);
        assert_eq!(arena.leaf(VA) & PA, GRANT);
        const _: () = assert!(GRANT.is_multiple_of(COW_GRANT_SIZE));
    }
}
