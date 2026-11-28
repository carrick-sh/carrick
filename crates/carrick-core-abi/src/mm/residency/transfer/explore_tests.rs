//! The bounded explorer of the residency transfer (#2611): every
//! combination of source rows (straddling either edge of `src`, crossing a
//! 2 MiB window, with holes), a peer MM's rows at the same addresses,
//! committed bits, a held grant-window lease, five `src` shapes and five
//! `dst` placements (an unaligned and an aligned shift, a window-crossing
//! shift, an overlap and a populated destination), each ended by a commit
//! or a cancel, on the real table. T1 to T9 are checked against an
//! independent page-level oracle before the transfer, while it is in
//! flight, and after it ends. Each seeded mutant breaks one invariant and
//! must be found.

extern crate std;

use std::boxed::Box;
use std::collections::BTreeMap;
use std::format;
use std::string::String;
use std::vec::Vec;

use super::super::{
    EL1_FRAME_GRANT_TARGET_SIZE, FrameGrantResidencyIdentity, FrameGrantResidencyTable, GRANT_LIVE,
    GRANT_PAGE_SIZE, GRANT_STATE_MASK, GRANT_WRITING,
};
use super::mutant::{self, Mutant};
use super::{ResidencyTransferRefusal, TransferRange};

const P: u64 = GRANT_PAGE_SIZE;
const W: u64 = EL1_FRAME_GRANT_TARGET_SIZE;
/// A 2 MiB window boundary: rows sit on both sides of it.
const X: u64 = 0x4000_0000;
const MM: u64 = 7;
const PEER: u64 = 9;
/// The rows a configuration chooses from, in pages relative to `X`. None
/// crosses `X`, so each lies in one window.
const ROWS: [(i64, i64); 5] = [(-4, -2), (-2, -1), (-1, 0), (0, 2), (2, 4)];
/// `src` shapes: first page relative to `X`, and length in pages.
const SOURCES: [(i64, u64); 5] = [(-3, 4), (-2, 2), (-1, 3), (-4, 8), (0, 2)];

fn table() -> Box<FrameGrantResidencyTable> {
    let layout = std::alloc::Layout::new::<FrameGrantResidencyTable>();
    // SAFETY: allocation uses the table layout and is initialized before
    // the owning Box is constructed.
    unsafe {
        let ptr = std::alloc::alloc_zeroed(layout).cast::<FrameGrantResidencyTable>();
        assert!(!ptr.is_null());
        FrameGrantResidencyTable::init_in_place(ptr);
        Box::from_raw(ptr)
    }
}

const fn at(pages: i64) -> u64 {
    X.wrapping_add_signed(pages * P as i64)
}

/// Where a page's custody lies: the frame (by IPA and the row's identity),
/// and whether its guest commit is recorded.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Custody {
    ipa: u64,
    mapping_id: u64,
    frame_id: u64,
    owner_generation: u64,
    inventory_revision: u64,
    committed: bool,
}

/// One MM's page-level view: every page a live row covers. Two live rows
/// of one MM over one page, or one frame page at two addresses, is T2.
fn view(table: &FrameGrantResidencyTable, mm: u64) -> Result<BTreeMap<u64, Custody>, String> {
    let mut pages = BTreeMap::new();
    let mut frames = BTreeMap::new();
    for record in table.slots() {
        let state = record.state.load(core::sync::atomic::Ordering::Acquire);
        if state & GRANT_STATE_MASK != GRANT_LIVE {
            continue;
        }
        let identity = record.identity();
        if identity.mm_key != mm {
            continue;
        }
        for bit in 0..(identity.len / P) as usize {
            let committed = record.committed[bit / 64].load(core::sync::atomic::Ordering::Acquire)
                & (1 << (bit % 64))
                != 0;
            let va = identity.semantic_base + bit as u64 * P;
            let custody = Custody {
                ipa: identity.physical_ipa + bit as u64 * P,
                mapping_id: identity.mapping_id,
                frame_id: identity.frame_id,
                owner_generation: identity.owner_generation,
                inventory_revision: identity.inventory_revision,
                committed,
            };
            if pages.insert(va, custody).is_some() {
                return Err(format!("T2: two live rows of mm {mm} hold {va:#x}"));
            }
            if let Some(other) = frames.insert(custody.ipa, va) {
                return Err(format!(
                    "T2: frame {:#x} of mm {mm} is held at {other:#x} and {va:#x}",
                    custody.ipa
                ));
            }
        }
    }
    Ok(pages)
}

fn writing(table: &FrameGrantResidencyTable) -> usize {
    table
        .slots()
        .filter(|record| {
            record.state.load(core::sync::atomic::Ordering::Acquire) & GRANT_STATE_MASK
                == GRANT_WRITING
        })
        .count()
}

#[derive(Clone, Copy, Debug)]
struct Config {
    rows: u8,
    source: usize,
    destination: usize,
    peer: bool,
    pinned: bool,
    commit: bool,
}

/// The five `dst` placements for a `src` at `src` of `len` bytes.
fn destination(which: usize, src: u64) -> u64 {
    match which {
        0 => src + W + P,
        1 => src - W,
        2 => src + 3 * P,
        3 => at(2),
        _ => src + 2 * W - P,
    }
}

fn publish(table: &FrameGrantResidencyTable, mm: u64, index: usize, (lo, hi): (i64, i64)) {
    let identity = FrameGrantResidencyIdentity {
        mm_key: mm,
        semantic_base: at(lo),
        physical_ipa: 0x8000_0000 + (mm << 28) + index as u64 * 0x10_0000,
        len: (hi - lo) as u64 * P,
        mapping_id: 100 + index as u64,
        frame_id: 200 + index as u64,
        owner_generation: 3,
        inventory_revision: 5,
    };
    assert!(table.publish(identity).is_some(), "setup publish");
    for page in lo..hi {
        if (page + index as i64).rem_euclid(2) == 0 {
            let token = table.lookup(mm, at(page)).expect("setup lookup");
            assert!(table.record_commit(token), "setup commit");
        }
    }
}

#[derive(Debug, Default)]
struct Stats {
    configurations: u64,
    admitted: u64,
    committed: u64,
    cancelled: u64,
    occupied: u64,
    leased: u64,
    shape_refused: u64,
    checks: u64,
}

fn run(config: Config, stats: &mut Stats) -> Result<(), String> {
    stats.configurations += 1;
    let table = table();
    for (index, row) in ROWS.into_iter().enumerate() {
        if config.rows & (1 << index) != 0 {
            publish(&table, MM, index, row);
        }
        if config.peer {
            publish(&table, PEER, index, row);
        }
    }
    let (first, pages) = SOURCES[config.source];
    let (src, len) = (at(first), pages * P);
    let dst = destination(config.destination, src);
    let before = view(&table, MM)?;
    let peer_before = view(&table, PEER)?;
    let tokens: Vec<_> = (0..pages)
        .filter_map(|page| table.lookup(MM, src + page * P))
        .collect();
    // T4's shape, independently of TransferRange::new.
    let disjoint = src + len <= dst || dst + len <= src;
    let Some(range) = TransferRange::new(MM, src, dst, len) else {
        stats.shape_refused += 1;
        return if disjoint {
            Err(format!("T4: a well-shaped range was refused: {config:?}"))
        } else {
            Ok(())
        };
    };
    if !disjoint {
        return Err(format!("T4: overlapping ranges admitted: {range:?}"));
    }
    let dst_populated = before.keys().any(|&va| va >= dst && va < dst + len);
    let pin = if config.pinned {
        tokens.first().and_then(|token| table.pin_transfer(*token))
    } else {
        None
    };
    let unchanged = |stats: &mut Stats, why: &str| -> Result<(), String> {
        stats.checks += 1;
        if view(&table, MM)? != before {
            return Err(format!("T7: {why} changed mm {MM}: {config:?}"));
        }
        if view(&table, PEER)? != peer_before {
            return Err(format!("T8: {why} changed the peer: {config:?}"));
        }
        if writing(&table) != 0 {
            return Err(format!("T7: {why} leaked a reserved slot: {config:?}"));
        }
        Ok(())
    };
    let transfer = match table.begin_transfer(range) {
        Err(ResidencyTransferRefusal::DestinationNotHole) => {
            stats.occupied += 1;
            if !dst_populated {
                return Err(format!("T4: an empty dst was refused: {config:?}"));
            }
            return unchanged(stats, "an DestinationNotHole refusal");
        }
        Err(ResidencyTransferRefusal::Leased) => {
            stats.leased += 1;
            if pin.is_none() || dst_populated {
                return Err(format!("T3: a spurious Leased: {config:?}"));
            }
            unchanged(stats, "a Leased refusal")?;
            drop(pin);
            // Reopened: every source row, not only the leased one, admits a
            // lease again.
            return if tokens
                .iter()
                .all(|token| table.pin_transfer(*token).is_some())
            {
                Ok(())
            } else {
                Err(format!(
                    "T7: a Leased refusal left a row closed: {config:?}"
                ))
            };
        }
        Err(ResidencyTransferRefusal::Capacity) => {
            return Err(format!("unexpected Capacity: {config:?}"));
        }
        Ok(transfer) => transfer,
    };
    stats.admitted += 1;
    if dst_populated {
        return Err(format!("T4: a populated dst was admitted: {config:?}"));
    }
    if pin.is_some() {
        return Err(format!("T3: a leased source row was admitted: {config:?}"));
    }
    // In flight: `src` still owns every page (T2), nothing is visible at
    // `dst` (T9), the peer is untouched (T8), no source row admits a lease
    // (T3).
    stats.checks += 1;
    for page in 0..pages {
        if table.lookup(MM, dst + page * P).is_some() {
            return Err(format!(
                "T9: dst {:#x} is visible in flight: {config:?}",
                dst + page * P
            ));
        }
    }
    if view(&table, MM)? != before {
        return Err(format!("T2: custody moved before the commit: {config:?}"));
    }
    if view(&table, PEER)? != peer_before {
        return Err(format!("T8: the peer changed in flight: {config:?}"));
    }
    if tokens
        .iter()
        .any(|token| table.pin_transfer(*token).is_some())
    {
        return Err(format!(
            "T3: a source row admitted a lease in flight: {config:?}"
        ));
    }
    if !config.commit {
        stats.cancelled += 1;
        drop(transfer);
        unchanged(stats, "a cancel")?;
        if tokens
            .iter()
            .any(|token| table.pin_transfer(*token).is_none())
        {
            return Err(format!("T7: a cancel left a source row closed: {config:?}"));
        }
        return Ok(());
    }
    stats.committed += 1;
    let Some(receipt) = transfer.commit() else {
        return Err(format!("the commit failed under exclusion: {config:?}"));
    };
    // T1, T2 and T5: the same custody, page for page, with `src` re-keyed
    // to `dst` and everything else (the parts outside `src`) in place.
    let expected: BTreeMap<u64, Custody> = before
        .iter()
        .map(|(&va, &custody)| {
            let moved = va >= src && va < src + len;
            (if moved { va - src + dst } else { va }, custody)
        })
        .collect();
    stats.checks += 1;
    let after = view(&table, MM)?;
    if after != expected {
        return Err(format!(
            "T1/T5: custody after the commit differs: {config:?}\n expected {expected:x?}\n found {after:x?}"
        ));
    }
    if view(&table, PEER)? != peer_before {
        return Err(format!("T8: the commit changed the peer: {config:?}"));
    }
    if writing(&table) != 0 {
        return Err(format!("T7: the commit leaked a reserved slot: {config:?}"));
    }
    let moved: Vec<_> = before
        .iter()
        .filter(|(va, _)| **va >= src && **va < src + len)
        .collect();
    let committed = moved
        .iter()
        .filter(|(_, custody)| custody.committed)
        .count() as u64;
    if receipt.frames_relinked != moved.len() as u64 || receipt.committed_relinked != committed {
        return Err(format!(
            "receipt {receipt:?} disagrees with {} moved pages: {config:?}",
            moved.len()
        ));
    }
    // T6: a token captured at `src` authorizes nothing now, and no live row
    // of the MM keeps a slot generation a source token names.
    for token in &tokens {
        if table.pin_transfer(*token).is_some() || table.record_commit(*token) {
            return Err(format!("T6: a source token still authorizes: {config:?}"));
        }
        let reused = table.slot(token.slot).is_some_and(|record| {
            record.state.load(core::sync::atomic::Ordering::Acquire) == token.epoch
                && record.identity().mm_key == MM
        });
        if reused {
            return Err(format!("T6: a moved row reuses a source epoch: {config:?}"));
        }
    }
    // T2's index half: the address index finds every page's owner.
    for &va in after.keys() {
        if table.lookup(MM, va).is_none() {
            return Err(format!(
                "T2: {va:#x} is held but its lookup misses: {config:?}"
            ));
        }
    }
    Ok(())
}

fn explore() -> Result<Stats, String> {
    let mut stats = Stats::default();
    for rows in 0..(1u8 << ROWS.len()) {
        for source in 0..SOURCES.len() {
            for destination in 0..5 {
                for peer in [false, true] {
                    for pinned in [false, true] {
                        for commit in [false, true] {
                            run(
                                Config {
                                    rows,
                                    source,
                                    destination,
                                    peer,
                                    pinned,
                                    commit,
                                },
                                &mut stats,
                            )?;
                        }
                    }
                }
            }
        }
    }
    Ok(stats)
}

#[test]
fn every_transfer_keeps_t1_to_t9() {
    let stats = explore().unwrap_or_else(|counterexample| panic!("{counterexample}"));
    std::println!("transfer explorer: {stats:?}");
    assert_eq!(stats.configurations, 32 * 5 * 5 * 2 * 2 * 2);
    // Every outcome is reached, so no check is vacuous.
    assert!(stats.committed > 0 && stats.cancelled > 0);
    assert!(stats.occupied > 0 && stats.leased > 0 && stats.shape_refused > 0);
}

#[test]
fn every_seeded_transfer_mutant_is_found() {
    // Each mutant must be found by its own invariant, not incidentally.
    for (which, invariant) in [
        (Mutant::TransferCopies, "T1/T5:"),
        (Mutant::KeepsSource, "T2:"),
        (Mutant::IgnoresLease, "T3:"),
        (Mutant::AdmitsOverlap, "T4:"),
        (Mutant::AdmitsPopulatedDst, "T4:"),
        (Mutant::AdmitsPopulatedTail, "T4:"),
        (Mutant::SplitDropsOutside, "T1/T5:"),
        (Mutant::DropsBits, "T1/T5:"),
        (Mutant::ReusesEpoch, "T6:"),
        (Mutant::FailDropsSource, "T7:"),
        (Mutant::MovesPeerRecord, "T8:"),
        (Mutant::ExposesEarly, "T9:"),
    ] {
        match mutant::with(which, explore) {
            Err(counterexample) if counterexample.starts_with(invariant) => {
                std::println!("mutant {which:?} found: {counterexample}")
            }
            Err(counterexample) => {
                panic!("mutant {which:?} was found, but not by {invariant}: {counterexample}")
            }
            Ok(stats) => panic!("mutant {which:?} survived {stats:?}"),
        }
    }
}

/// T7 at capacity: when the probe chain of a part the commit must publish
/// is full, the transfer is refused and the table is exactly as it was.
#[test]
fn a_transfer_without_room_changes_nothing() {
    let table = table();
    publish(&table, MM, 3, ROWS[3]);
    let (src, len) = (at(0), 2 * P);
    let dst = src + W + P;
    // Fill the 64-slot chain the moved row's slot comes from with other
    // MMs' one-page rows, found by their own chain heads.
    let class = (len / P).next_power_of_two().trailing_zeros();
    let head = FrameGrantResidencyTable::<super::super::ResidencyStorage>::first_slot(
        MM,
        dst / (P << class),
        class,
    );
    let chain: Vec<usize> = (0..64).map(|probe| (head + probe) % 4096).collect();
    // A filler lands on its chain head when the head is free, so fill the
    // lowest free slot of the chain each time.
    let free = |table: &FrameGrantResidencyTable| {
        chain.iter().copied().find(|&slot| {
            table.slot(slot).is_some_and(|record| {
                record.state.load(core::sync::atomic::Ordering::Acquire) & GRANT_STATE_MASK
                    != GRANT_LIVE
            })
        })
    };
    let mut key = 1000u64;
    let base = 0x10_0000_0000u64;
    while let Some(target) = free(&table) {
        key += 1;
        let first = FrameGrantResidencyTable::<super::super::ResidencyStorage>::first_slot(
            key,
            base / P,
            0,
        );
        if first == target {
            table
                .try_publish(FrameGrantResidencyIdentity {
                    mm_key: key,
                    semantic_base: base,
                    physical_ipa: base,
                    len: P,
                    mapping_id: 1,
                    frame_id: 1,
                    owner_generation: 1,
                    inventory_revision: 1,
                })
                .unwrap_or_else(|why| panic!("filler publish {key}: {why:?}"));
        }
    }
    let before = view(&table, MM).unwrap();
    let range = TransferRange::new(MM, src, dst, len).unwrap();
    assert!(matches!(
        table.begin_transfer(range),
        Err(ResidencyTransferRefusal::Capacity)
    ));
    assert_eq!(view(&table, MM).unwrap(), before);
    assert_eq!(writing(&table), 0);
    let token = table.lookup(MM, src).unwrap();
    assert!(
        table.pin_transfer(token).is_some(),
        "the source row reopened"
    );
}

fn writing_slots(table: &FrameGrantResidencyTable) -> Vec<usize> {
    (0..table.slot_capacity())
        .filter(|&slot| {
            table.slot(slot).is_some_and(|record| {
                record.state.load(core::sync::atomic::Ordering::Acquire) & GRANT_STATE_MASK
                    == GRANT_WRITING
            })
        })
        .collect()
}

/// Pre-review P0 1 (`94c4cf601`): a reserved slot left holding a
/// transfer's identity must never be taken for a later transfer's own
/// reservation. MM `B` shares `A`'s probe chains (keys congruent modulo the
/// segment size), so `B`'s retirement preclaim claims the tombstone `A`'s
/// cancelled transfer left, and `A`'s next transfer reserves a later slot.
#[test]
fn a_stale_reservation_marker_is_never_taken_for_a_new_one() {
    const B: u64 = MM + 4096;
    let table = table();
    publish(&table, MM, 3, ROWS[3]);
    let (src, len) = (at(0), P);
    let dst = src + W + P;
    let range = TransferRange::new(MM, src, dst, len).unwrap();
    // A reserves the slot for its one-page part at dst, then cancels.
    drop(table.begin_transfer(range).expect("first admission"));
    assert_eq!(writing(&table), 0);
    // B owns a two-page row at dst and preclaims the retirement of its
    // second page: the one-page part below it reserves on A's chain.
    table
        .publish(FrameGrantResidencyIdentity {
            mm_key: B,
            semantic_base: dst,
            physical_ipa: 0x9000_0000,
            len: 2 * P,
            mapping_id: 1,
            frame_id: 1,
            owner_generation: 1,
            inventory_revision: 1,
        })
        .expect("B's row");
    let preclaim = table
        .begin_retire_overlapping(B, dst + P, P, super::super::SplitRowCustody::Reserved)
        .expect("B's preclaim");
    let held = writing_slots(&table);
    assert_eq!(held.len(), 1, "B holds one reservation");
    // A's second transfer must commit into its own reservation.
    let receipt = table
        .begin_transfer(range)
        .expect("second admission")
        .commit()
        .expect("commit under exclusion");
    assert_eq!(receipt.frames_relinked, 1);
    assert_eq!(
        writing_slots(&table),
        held,
        "B's reservation is intact and A leaked none"
    );
    assert!(
        preclaim.commit(),
        "B's retirement commits into its own slot"
    );
    let b = view(&table, B).unwrap();
    assert_eq!(
        b.keys().copied().collect::<Vec<_>>(),
        [dst],
        "B keeps its first page"
    );
    assert!(
        view(&table, MM).unwrap().contains_key(&dst),
        "A's page moved"
    );
}
