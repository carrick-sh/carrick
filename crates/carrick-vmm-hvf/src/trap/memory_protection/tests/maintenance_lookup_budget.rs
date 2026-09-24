//! VM-free binding of `kernel.mm.backing-maintenance-lookup`.
//!
//! A brk shrink, an mremap onto reused arena VA and an `MREMAP_DONTUNMAP`
//! source all scrub their range before a later access can observe it. For
//! every Linux page the scrub resolves a COW source, a retained fragment, an
//! exclusive claim and a scrub target. Each of those is a question about ONE
//! page of ONE mm, so the rows it visits must be bounded by the rows relevant
//! to that page, never by how many unrelated aliases, mappings or extents are
//! live. The 2026-09-24 cpython profile found each of them walking its whole
//! table per page.
//!
//! Every fixture is adversarial rather than uniform: fork siblings holding
//! rows at the SAME guest VA in their own scopes (the fork layout), a deep
//! table of the process's own rows elsewhere, newer rows than the answer, and
//! several overlapping fragments that ARE answers. Unrelated populations run
//! at 1, 1,000 and 10,000; the per-lookup budget is `base + 0 * n`.

use super::*;

const SCALES: [u64; 3] = [1, 1_000, 10_000];

const OWN_SLOT: (u64, u64) = (0x5000_0000, 0x4000);
const PAGE: u64 = 0x1000;
const COMPOUND: u64 = 0x4000;
/// Guest VA of the live 16 KiB compound whose page is scrubbed.
const TARGET_VA: u64 = 0x7000_0000;
/// Its physical stage-2 extent.
const TARGET_PHYS: u64 = 0x20_0000_0000;

/// Alias rows visited by one lookup: the fixed answers (the compound row and
/// its four 4 KiB fragments) plus the class-window neighbours an interval
/// query may legitimately touch. Independent of the unrelated population.
const ALIAS_ROWS_BUDGET: u64 = 8;
/// Frame-inventory extents one containment lookup may visit: at most one
/// candidate per active size class plus the answer.
const FRAME_EXTENTS_BUDGET: u64 = 4;
/// Task mapping rows one scrub-target lookup may visit: the covering row and
/// its immediate neighbour.
const TASK_ROWS_BUDGET: u64 = 2;

fn own_scope() -> AliasOwnershipScope {
    AliasOwnershipScope::MmRootSlot {
        base: OWN_SLOT.0,
        size: OWN_SLOT.1,
    }
}

fn sibling_scope(index: u64) -> AliasOwnershipScope {
    AliasOwnershipScope::MmRootSlot {
        base: 0x6_0000_0000 + index * 0x4000,
        size: 0x4000,
    }
}

fn alias(
    va: u64,
    size: u64,
    ipa: u64,
    physical_ipa: u64,
    physical_size: u64,
    scope: AliasOwnershipScope,
) -> AliasBacking {
    AliasBacking {
        start: va,
        ipa,
        host_addr: 0x1_0000_0000 + ipa as usize,
        size: size as usize,
        physical_ipa,
        physical_host_addr: 0x1_0000_0000 + physical_ipa as usize,
        physical_size: physical_size as usize,
        perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
        guest_writable: true,
        sharing: GuestMappingSharing::Private,
        ownership_scope: scope,
        inventory_backing: InventoryBackingIdentity::Private(1),
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: 0,
    }
}

/// The process's live compound, its four 4 KiB fragments (pushed later, so
/// newer, with the same physical extent), and three adversarial populations
/// of `n` rows each: fork siblings at the same VA, the process's own rows
/// elsewhere, and newer own rows on other physical extents.
fn adversarial_registry(n: u64) -> (AliasRegistry, Vec<AliasBacking>) {
    let mut registry = AliasRegistry::default();
    let compound = alias(
        TARGET_VA,
        COMPOUND,
        TARGET_PHYS,
        TARGET_PHYS,
        COMPOUND,
        own_scope(),
    );
    registry.push(compound);
    let mut answers = vec![compound];
    for page in 0..4 {
        let fragment = alias(
            TARGET_VA + page * PAGE,
            PAGE,
            TARGET_PHYS + page * PAGE,
            TARGET_PHYS,
            COMPOUND,
            own_scope(),
        );
        registry.push(fragment);
        answers.push(fragment);
    }
    for index in 0..n {
        // A fork sibling's own copy of the same guest VA.
        registry.push(alias(
            TARGET_VA,
            COMPOUND,
            0x30_0000_0000 + index * COMPOUND,
            0x30_0000_0000 + index * COMPOUND,
            COMPOUND,
            sibling_scope(index),
        ));
        // The process's own deep table, away from the target.
        let elsewhere = 0x1_0000_0000 + index * 0x8000;
        registry.push(alias(
            elsewhere,
            PAGE,
            0x40_0000_0000 + index * PAGE,
            0x40_0000_0000 + index * PAGE,
            PAGE,
            own_scope(),
        ));
    }
    // Newest-first answers, as the lookups report them.
    answers.reverse();
    (registry, answers)
}

fn compound_source_predicate(alias: &AliasBacking) -> bool {
    let semantic_end = TARGET_VA + COMPOUND;
    alias.start < semantic_end
        && TARGET_VA < alias.start + alias.size as u64
        && alias.ipa.wrapping_sub(alias.start) == TARGET_PHYS.wrapping_sub(TARGET_VA)
        && TARGET_PHYS >= alias.physical_ipa
        && TARGET_PHYS + COMPOUND <= alias.physical_ipa + alias.physical_size as u64
}

#[test]
fn physical_cow_source_candidates_are_bounded_by_the_window() {
    let mut observed = Vec::new();
    for n in SCALES {
        let (registry, answers) = adversarial_registry(n);
        let before = alias_state_rows_scanned();
        let candidates = registry.process_va_overlap_candidates(
            TARGET_VA,
            COMPOUND,
            Some(OWN_SLOT),
            ContainerRootToken::ROOT,
            compound_source_predicate,
        );
        let visited = alias_state_rows_scanned() - before;
        observed.push((n, visited));
        assert_eq!(candidates, answers, "n={n}: newest-first candidate set");
    }
    for &(n, visited) in &observed {
        assert!(
            visited <= ALIAS_ROWS_BUDGET,
            "COW-source candidates visited {visited} alias rows at n={n} \
             (budget {ALIAS_ROWS_BUDGET} + 0*n); all scales: {observed:?}"
        );
    }
}

#[test]
fn containing_va_candidates_ignore_fork_siblings_at_the_same_va() {
    let probe = TARGET_VA + PAGE;
    let mut observed = Vec::new();
    for n in SCALES {
        let (registry, _) = adversarial_registry(n);
        let before = alias_state_rows_scanned();
        let candidates = registry.process_alias_containing_va_candidates(
            probe,
            Some(OWN_SLOT),
            ContainerRootToken::ROOT,
            |_| true,
        );
        let visited = alias_state_rows_scanned() - before;
        observed.push((n, visited));
        let expected: Vec<_> = registry
            .scope_rows(own_scope())
            .iter()
            .rev()
            .map(|(_, alias)| *alias)
            .filter(|alias| alias.start <= probe && probe < alias.start + alias.size as u64)
            .collect();
        assert_eq!(candidates, expected, "n={n}: containing candidates");
        assert_eq!(candidates.len(), 2, "n={n}: compound and one fragment");
    }
    for &(n, visited) in &observed {
        assert!(
            visited <= ALIAS_ROWS_BUDGET,
            "containing-VA candidates visited {visited} alias rows at n={n} \
             (budget {ALIAS_ROWS_BUDGET} + 0*n); all scales: {observed:?}"
        );
    }
}

#[test]
fn retained_reuse_fragment_is_bounded_by_the_physical_extent() {
    // The scrubbed VA was carved out of the compound by a partial munmap:
    // no live row covers it, but its invalid leaf still names the compound's
    // physical page. Fork siblings hold rows AT that VA, and the process has
    // `n` NEWER rows on other physical extents.
    let reused_va = 0x7100_0000;
    let reused_ipa = TARGET_PHYS + PAGE;
    let mut observed = Vec::new();
    for n in SCALES {
        let mut registry = AliasRegistry::default();
        let owner = alias(
            TARGET_VA,
            COMPOUND,
            TARGET_PHYS,
            TARGET_PHYS,
            COMPOUND,
            own_scope(),
        );
        registry.push(owner);
        for index in 0..n {
            registry.push(alias(
                reused_va,
                PAGE,
                0x30_0000_0000 + index * COMPOUND,
                0x30_0000_0000 + index * COMPOUND,
                COMPOUND,
                sibling_scope(index),
            ));
            registry.push(alias(
                0x1_0000_0000 + index * 0x8000,
                PAGE,
                0x40_0000_0000 + index * PAGE,
                0x40_0000_0000 + index * PAGE,
                PAGE,
                own_scope(),
            ));
        }
        let before = alias_state_rows_scanned();
        let fragment = retained_private_reuse_alias_fragment(
            &registry,
            reused_va,
            reused_ipa,
            PAGE as usize,
            Some(OWN_SLOT),
            ContainerRootToken::ROOT,
        );
        let visited = alias_state_rows_scanned() - before;
        observed.push((n, visited));
        let fragment = fragment.expect("the compound owns the retained page");
        assert_eq!(
            (
                fragment.start,
                fragment.ipa,
                fragment.physical_ipa,
                fragment.size
            ),
            (reused_va, reused_ipa, TARGET_PHYS, PAGE as usize),
            "n={n}"
        );
    }
    for &(n, visited) in &observed {
        assert!(
            visited <= ALIAS_ROWS_BUDGET,
            "retained-fragment lookup visited {visited} alias rows at n={n} \
             (budget {ALIAS_ROWS_BUDGET} + 0*n); all scales: {observed:?}"
        );
    }
}

fn extent(stage2_base: u64, stage2_length: u64, serial: u64) -> InventoryExtent {
    InventoryExtent {
        frame: carrick_hal::FrameId::from_kernel_allocation(
            std::num::NonZeroU64::new(serial).expect("nonzero"),
        ),
        mapping: carrick_hal::MappingId::from_kernel_allocation(
            std::num::NonZeroU64::new(serial).expect("nonzero"),
        ),
        backing: InventoryBackingIdentity::Private(serial),
        stage2_base,
        stage2_length,
        stage2_owner: InventoryStage2OwnerIdentity::TEST_UNOWNED,
    }
}

#[test]
fn exclusive_claim_extent_lookup_is_bounded_by_size_classes() {
    // `n` dense 16 KiB extents, one wide 2 MiB extent below them, and the
    // probed extent LAST in key order: a key-order walk visits everything.
    let base = 0x40_0000_0000_u64;
    let mut observed = Vec::new();
    for n in SCALES {
        let mut inventory = HvpatchFrameInventory::default();
        inventory.extents.insert(
            (base - 0x20_0000, 0x20_0000),
            extent(base - 0x20_0000, 0x20_0000, 1),
        );
        for index in 0..n {
            let start = base + index * 0x8000;
            inventory
                .extents
                .insert((start, COMPOUND), extent(start, COMPOUND, index + 2));
        }
        let probe_key = (base + n * 0x8000, COMPOUND);
        inventory
            .extents
            .insert(probe_key, extent(probe_key.0, COMPOUND, n + 2));
        let before = hot_path_rows_scanned(HotPathScan::FrameExtents);
        let found = inventory
            .extent_containing(probe_key.0 + PAGE)
            .map(|(key, _)| *key);
        let visited = hot_path_rows_scanned(HotPathScan::FrameExtents) - before;
        observed.push((n, visited));
        assert_eq!(found, Some(probe_key), "n={n}");
        assert_eq!(
            inventory.extent_containing(base - 1).map(|(key, _)| *key),
            Some((base - 0x20_0000, 0x20_0000)),
            "n={n}: the wide extent"
        );
        assert_eq!(
            inventory
                .extent_containing(base + COMPOUND)
                .map(|(key, _)| *key),
            None,
            "n={n}: the gap between dense extents"
        );
    }
    for &(n, visited) in &observed {
        assert!(
            visited <= FRAME_EXTENTS_BUDGET,
            "extent containment visited {visited} extents at n={n} \
             (budget {FRAME_EXTENTS_BUDGET} + 0*n); all scales: {observed:?}"
        );
    }
}

#[test]
fn scrub_target_row_is_bounded_by_the_overlapping_rows() {
    // The scrubbed page is the LOWEST row; `n` distinct rows lie above it,
    // so a newest-first whole-table walk visits every one of them first.
    let mut observed = Vec::new();
    for n in SCALES {
        let mut mappings = TaskMappingIndex::new();
        for index in 0..=n {
            let start = TARGET_VA + index * 0x8000;
            let mut row = crate::trap::thread_sibling_tests::mapped_region(
                start,
                start + COMPOUND,
                TARGET_PHYS + index * 0x8000,
            );
            // Distinct owners keep adjacent rows from coalescing.
            row.owner_generation = index + 1;
            mappings.insert(row);
        }
        let before = hot_path_rows_scanned(HotPathScan::TaskMappings);
        let row = live_ipa_mapping_row(
            &mappings,
            TARGET_VA + PAGE,
            TARGET_PHYS + PAGE,
            PAGE,
            |_| true,
        )
        .map(|row| row.start);
        let visited = hot_path_rows_scanned(HotPathScan::TaskMappings) - before;
        observed.push((n, visited));
        assert_eq!(row, Some(TARGET_VA), "n={n}");
        assert!(
            live_ipa_mapping_row(&mappings, TARGET_VA + PAGE, TARGET_PHYS, PAGE, |_| true)
                .is_none(),
            "n={n}: a VA/IPA-inconsistent projection is not a target"
        );
    }
    for &(n, visited) in &observed {
        assert!(
            visited <= TASK_ROWS_BUDGET,
            "scrub-target lookup visited {visited} task rows at n={n} \
             (budget {TASK_ROWS_BUDGET} + 0*n); all scales: {observed:?}"
        );
    }
}

/// xorshift64: deterministic, seedable, no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }
}

/// The scoped indexes answer every process-scoped query EXACTLY as the
/// carrier-wide index filtered by scope did -- same rows, same order --
/// including split fragments that share a sequence, rows rewritten in place
/// by `upsert_by_key`, several scopes at the same VAs and nested windows.
#[test]
fn scoped_alias_queries_match_the_carrier_wide_oracle() {
    let mut seeds_with_split_ties = 0;
    let scopes = [
        own_scope(),
        AliasOwnershipScope::Global,
        sibling_scope(0),
        sibling_scope(1),
    ];
    for seed in 1..=64_u64 {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ seed);
        let mut registry = AliasRegistry::default();
        for _ in 0..48 {
            let scope = scopes[rng.below(scopes.len() as u64) as usize];
            let va = TARGET_VA + rng.below(64) * PAGE;
            let size = PAGE << rng.below(5);
            let physical = 0x20_0000_0000 + rng.below(32) * COMPOUND;
            let physical_size = COMPOUND << rng.below(3);
            let mut row = alias(va, size, physical, physical, physical_size, scope);
            if rng.below(4) == 0 {
                row.sharing = GuestMappingSharing::ForkSharedAnonymous;
            }
            registry.push(row);
        }
        // Split rows into same-sequence fragments, and rewrite some in place.
        for _ in 0..4 {
            let va = TARGET_VA + rng.below(64) * PAGE;
            let _ = unregister_alias_entries(
                &mut registry,
                va,
                (PAGE * (1 + rng.below(3))) as usize,
                Some(OWN_SLOT),
                ContainerRootToken::ROOT,
            );
        }
        let own_rows: Vec<_> = registry.scope_rows(own_scope()).to_vec();
        if own_rows.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            seeds_with_split_ties += 1;
        }
        for &(_, row) in own_rows.iter().take(3) {
            let mut rewritten = row;
            rewritten.perms ^= 1;
            registry.upsert_by_key(rewritten);
        }

        let visible = |alias: &AliasBacking| {
            alias_matches_process_scope(
                alias.ownership_scope,
                Some(OWN_SLOT),
                ContainerRootToken::ROOT,
            )
        };
        for probe_page in 0..72_u64 {
            let va = TARGET_VA - 4 * PAGE + probe_page * PAGE;
            let len = PAGE << (probe_page % 3);
            let end = va + len;

            // Overlap candidates: visible bucket rows, stable newest-first.
            let mut expected: Vec<(u64, AliasBacking)> =
                AliasRegistry::process_visible_scopes(Some(OWN_SLOT), ContainerRootToken::ROOT)
                    .into_iter()
                    .flat_map(|scope| registry.scope_rows(scope).iter().copied())
                    .filter(|(_, a)| a.start < end && va < a.start + a.size as u64)
                    .collect();
            expected.sort_by_key(|(seq, _)| std::cmp::Reverse(*seq));
            let expected: Vec<_> = expected.into_iter().map(|(_, a)| a).collect();
            assert_eq!(
                registry.process_va_overlap_candidates(
                    va,
                    len,
                    Some(OWN_SLOT),
                    ContainerRootToken::ROOT,
                    |_| true
                ),
                expected,
                "seed {seed} overlap {va:#x}+{len:#x}"
            );

            // Containing candidates / newest containing: the global index
            // filtered by scope.
            let expected = registry.va_classes.containing_candidates(va, |a| {
                visible(a) && va >= a.start && va < a.start + a.size as u64
            });
            assert_eq!(
                registry.process_alias_containing_va_candidates(
                    va,
                    Some(OWN_SLOT),
                    ContainerRootToken::ROOT,
                    |_| true
                ),
                expected,
                "seed {seed} containing {va:#x}"
            );
            assert_eq!(
                registry.newest_process_alias_containing_va(
                    va,
                    Some(OWN_SLOT),
                    ContainerRootToken::ROOT,
                    |_| true
                ),
                registry.va_classes.newest_containing(va, |a| {
                    visible(a) && va >= a.start && va < a.start + a.size as u64
                }),
                "seed {seed} newest {va:#x}"
            );

            // Overlapping rows, sequence-ordered.
            let mut expected: Vec<(u64, AliasBacking)> = registry
                .va_window_rows(va, end)
                .filter(|(_, a)| visible(a) && a.start + a.size as u64 > va)
                .copied()
                .collect();
            expected.sort_by_key(|(seq, _)| *seq);
            assert_eq!(
                registry.overlapping_process_aliases(
                    va,
                    len as usize,
                    Some(OWN_SLOT),
                    ContainerRootToken::ROOT
                ),
                expected,
                "seed {seed} overlapping {va:#x}+{len:#x}"
            );
            assert_eq!(
                registry.has_live_process_alias_overlapping(
                    va,
                    end,
                    Some(OWN_SLOT),
                    ContainerRootToken::ROOT
                ),
                registry.va_window_rows(va, end).any(|(_, a)| visible(a)
                    && a.start < end
                    && a.start + a.size as u64 > va
                    && alias_backing_is_live(a.physical_host_addr)),
                "seed {seed} live overlap {va:#x}"
            );

            // Starts strictly inside a window.
            let wide_end = va + 16 * PAGE;
            let shared = |a: &AliasBacking| a.sharing == GuestMappingSharing::Private;
            assert_eq!(
                registry.first_matching_process_alias_start_between(
                    va,
                    wide_end,
                    Some(OWN_SLOT),
                    ContainerRootToken::ROOT,
                    shared
                ),
                registry
                    .va_classes
                    .first_matching_start_between(va, wide_end, |a| visible(a) && shared(a)),
                "seed {seed} first start {va:#x}"
            );
            assert_eq!(
                registry.matching_process_alias_starts_between_candidates(
                    va,
                    wide_end,
                    Some(OWN_SLOT),
                    ContainerRootToken::ROOT,
                    shared
                ),
                registry
                    .va_classes
                    .matching_starts_between_candidates(va, wide_end, |a| visible(a) && shared(a))
                    .into_iter()
                    .map(|(_, a)| a)
                    .collect::<Vec<_>>(),
                "seed {seed} starts {va:#x}"
            );

            // Existence of an exact existing projection.
            let ipa = 0x20_0000_0000 + (probe_page % 32) * PAGE;
            let exact = |a: &AliasBacking| {
                va >= a.start
                    && va + PAGE <= a.start + a.size as u64
                    && a.ipa.checked_add(va - a.start) == Some(ipa)
            };
            assert_eq!(
                registry.any_process_va_window_row(
                    va,
                    va + 1,
                    Some(OWN_SLOT),
                    ContainerRootToken::ROOT,
                    exact
                ),
                registry
                    .va_window_rows(va, va + 1)
                    .any(|(_, a)| visible(a) && exact(a)),
                "seed {seed} exists {va:#x}"
            );

            // Physical containment, newest first in reverse bucket order.
            let expected: Vec<_> = registry
                .scope_rows(own_scope())
                .iter()
                .rev()
                .map(|(_, a)| *a)
                .filter(|a| {
                    a.sharing == GuestMappingSharing::Private
                        && ipa >= a.physical_ipa
                        && ipa + PAGE <= a.physical_ipa + a.physical_size as u64
                })
                .collect();
            assert_eq!(
                registry.private_rows_containing_physical_newest_first(
                    own_scope(),
                    ipa,
                    ipa + PAGE
                ),
                expected,
                "seed {seed} physical {ipa:#x}"
            );
        }
    }
    assert!(
        seeds_with_split_ties > 0,
        "the fixture must exercise same-sequence fragments"
    );
}
