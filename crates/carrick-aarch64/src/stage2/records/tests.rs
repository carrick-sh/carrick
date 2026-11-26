//! Witnesses for the stage-2 record table's invariants (#3056), on the
//! production type.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

const PAGE: u64 = 0x1000;
const RW: MemPerms = MemPerms {
    read: true,
    write: true,
    exec: false,
};

/// A backend lease stand-in: the table must hand the exact value back.
#[derive(Debug, Eq, PartialEq)]
struct Lease(u32);

fn spec(ipa: u64, len: u64, lease: u32) -> Stage2RecordSpec<Lease> {
    Stage2RecordSpec {
        extent: Stage2Extent::new(ipa, len).expect("test extent"),
        host_addr: 0x7000_0000_0000usize.wrapping_add(ipa as usize),
        perms: RW,
        logical_owner: None,
        backing: Lease(lease),
    }
}

fn probes(table: &Stage2RecordTable<Lease>) -> usize {
    table.probes.load(core::sync::atomic::Ordering::Relaxed)
}

fn expect_unmap(retire: Stage2Retire) -> Stage2Unmap {
    match retire {
        Stage2Retire::Unmap(unmap) => unmap,
        Stage2Retire::DeferredPinned => panic!("retirement deferred with no pin outstanding"),
    }
}

#[test]
fn a_collision_is_refused_before_a_record_exists_and_returns_the_backing() {
    let mut table = Stage2RecordTable::new();
    let first = table.register(spec(PAGE, 2 * PAGE, 1)).expect("first");

    // Overlaps the tail, the head, the whole, and the inside of `first`.
    for (ipa, len) in [
        (2 * PAGE, 2 * PAGE),
        (0, 2 * PAGE),
        (0, 8 * PAGE),
        (PAGE + 0x10, 0x10),
    ] {
        let refused = table
            .register(spec(ipa, len, 2))
            .expect_err("an overlapping extent must be refused");
        assert_eq!(
            refused.reason,
            Stage2RegisterRefusal::Collision(first),
            "{ipa:#x}+{len:#x}"
        );
        assert_eq!(
            refused.spec.backing,
            Lease(2),
            "the backing comes back whole"
        );
        assert_eq!(table.len(), 1, "no record exists for a refused extent");
    }
    // The refused extents left nothing behind: only `first` covers anything.
    assert!(table.covering(3 * PAGE, 1).is_none());
    assert!(table.covering(0, 1).is_none());
    assert_eq!(table.covering(PAGE, 2 * PAGE).unwrap().id, first);

    // Adjacent extents are not collisions.
    table.register(spec(0, PAGE, 3)).expect("adjacent below");
    table
        .register(spec(3 * PAGE, PAGE, 4))
        .expect("adjacent above");
    assert_eq!(table.teardown().len(), 3);
}

#[test]
fn a_retiring_record_keeps_its_extent_until_its_unmap_is_finished() {
    let mut table = Stage2RecordTable::new();
    let old = table.register(spec(0, 16 * PAGE, 1)).expect("wide");
    let unmap = expect_unmap(table.begin_retire(old).expect("retire"));

    // The retiring record is never found, but no record may share its IPA
    // while the backend still maps it.
    assert!(table.covering(2 * PAGE, PAGE).is_none());
    let refused = table
        .register(spec(2 * PAGE, PAGE, 2))
        .expect_err("a record over a retiring record's extent");
    assert_eq!(refused.reason, Stage2RegisterRefusal::Collision(old));

    assert_eq!(
        table.finish_retire(unmap).expect("finish").backing,
        Lease(1)
    );
    let new = table
        .register(spec(2 * PAGE, PAGE, 2))
        .expect("the extent is free once the unmap is finished");
    let found = table.covering(2 * PAGE, PAGE).expect("the new live record");
    assert_eq!(found.id, new);
    assert_eq!(found.backing, &Lease(2));
    assert!(
        table.covering(PAGE, PAGE).is_none(),
        "nothing wider survives"
    );
    assert_eq!(table.teardown().len(), 1);
}

#[test]
fn an_empty_or_overflowing_range_covers_nothing() {
    let mut table = Stage2RecordTable::new();
    table.register(spec(PAGE, PAGE, 1)).expect("record");
    assert!(table.covering(PAGE, 0).is_none());
    assert!(table.covering(PAGE + 0x80, 0).is_none());
    assert_eq!(table.pin(PAGE, 0), Err(Stage2PinRefusal::EmptyRange));
    assert!(table.covering(u64::MAX, 2).is_none());
    assert!(Stage2Extent::new(PAGE, 0).is_none());
    assert!(Stage2Extent::new(u64::MAX - 1, 2).is_none());
    assert!(Stage2Extent::new(u64::MAX - 1, 1).is_some());
    assert_eq!(table.teardown().len(), 1);
}

#[test]
fn a_range_that_runs_past_its_record_is_not_covered() {
    let mut table = Stage2RecordTable::new();
    let first = table.register(spec(0, PAGE, 1)).expect("first");
    table.register(spec(PAGE, PAGE, 2)).expect("second");
    assert_eq!(table.covering(PAGE - 1, 1).unwrap().id, first);
    assert!(
        table.covering(PAGE - 1, 2).is_none(),
        "two adjacent records never cover one range together"
    );
    assert_eq!(
        table.pin(PAGE - 1, 2),
        Err(Stage2PinRefusal::Overruns(first))
    );
    assert_eq!(table.teardown().len(), 2);
}

#[test]
fn a_covering_lookup_is_one_probe_however_many_records_there_are() {
    let mut table = Stage2RecordTable::new();
    // 4096 one-page records with one-page gaps, then one 1 GiB record above.
    for index in 0..4096u64 {
        table
            .register(spec(index * 2 * PAGE, PAGE, index as u32))
            .expect("small record");
    }
    let high = 1 << 40;
    table
        .register(spec(high, 1 << 30, 9999))
        .expect("large record");

    let before = probes(&table);
    let mut lookups = 0;
    for index in (0..4096u64).step_by(97) {
        assert!(table.covering(index * 2 * PAGE + 0x10, 0x10).is_some());
        assert!(
            table.covering(index * 2 * PAGE + PAGE, 0x10).is_none(),
            "a gap"
        );
        lookups += 2;
    }
    assert!(table.covering(high + (1 << 29), PAGE).is_some());
    assert!(table.covering(high - PAGE, PAGE).is_none());
    lookups += 2;
    assert_eq!(
        probes(&table) - before,
        lookups,
        "each lookup examines exactly one index entry"
    );
    assert_eq!(table.teardown().len(), 4097);
}

#[test]
fn a_pinned_record_owes_its_unmap_only_after_its_last_pin() {
    let mut table = Stage2RecordTable::new();
    let id = table.register(spec(4 * PAGE, 4 * PAGE, 7)).expect("record");
    let first = table.pin(5 * PAGE + 0x800, 0x10).expect("pin inside");
    assert_eq!(first.record(), id);
    assert_eq!(
        first.record_extent(),
        Stage2Extent::new(4 * PAGE, 4 * PAGE).unwrap()
    );
    assert_eq!(first.perms(), RW);
    assert_eq!(table.pinned_backing(&first), Some(&Lease(7)));
    assert_eq!(
        first.host_addr(),
        0x7000_0000_0000 + 5 * PAGE as usize + 0x800
    );
    assert_eq!(
        first.selected(),
        Stage2Extent::new(5 * PAGE + 0x800, 0x10).unwrap()
    );
    let second = table.pin(4 * PAGE, 4 * PAGE).expect("pin whole");

    assert_eq!(table.begin_retire(id), Ok(Stage2Retire::DeferredPinned));
    assert_eq!(
        table.begin_retire(id),
        Err(Stage2RetireRefused::AlreadyRetiring)
    );
    assert!(
        table.covering(4 * PAGE, PAGE).is_none(),
        "retiring is never found"
    );
    assert_eq!(
        table.pin(4 * PAGE, PAGE),
        Err(Stage2PinRefusal::NoLiveRecord),
        "retiring is never pinned"
    );

    assert_eq!(table.unpin(first), Ok(None), "a pin is still outstanding");
    let unmap = table
        .unpin(second)
        .expect("own pin")
        .expect("the last pin makes the unmap owed");
    assert_eq!(unmap.record(), id);
    assert_eq!(
        unmap.extent(),
        Stage2Extent::new(4 * PAGE, 4 * PAGE).unwrap()
    );
    assert_eq!(
        table.finish_retire(unmap).expect("finish").backing,
        Lease(7)
    );
    assert!(table.is_empty());
    assert_eq!(table.begin_retire(id), Err(Stage2RetireRefused::NotFound));
    assert!(table.teardown().is_empty());
}

#[test]
fn a_live_record_unpinned_stays_live() {
    let mut table = Stage2RecordTable::new();
    let id = table.register(spec(0, PAGE, 1)).expect("record");
    let pin = table.pin(0, PAGE).expect("pin");
    assert_eq!(table.unpin(pin), Ok(None));
    assert_eq!(table.covering(0, PAGE).unwrap().id, id);
    let unmap = expect_unmap(table.begin_retire(id).expect("retire"));
    assert_eq!(
        table.finish_retire(unmap).expect("finish").backing,
        Lease(1)
    );
    assert!(table.teardown().is_empty());
}

#[test]
fn a_token_from_another_table_is_refused_and_comes_back() {
    let mut mine = Stage2RecordTable::new();
    let mut other = Stage2RecordTable::new();
    let id = mine.register(spec(0, PAGE, 1)).expect("mine");
    let other_id = other.register(spec(0, PAGE, 2)).expect("other, same IPA");
    assert_eq!(id, other_id, "the same raw id in both tables");

    let pin = mine.pin(0, PAGE).expect("pin");
    assert_eq!(other.pinned_backing(&pin), None);
    let Err(Stage2TokenRefused(pin)) = other.unpin(pin) else {
        panic!("another table's pin must be refused");
    };
    assert_eq!(mine.begin_retire(id), Ok(Stage2Retire::DeferredPinned));
    let mine_unmap = mine
        .unpin(pin)
        .expect("the refused pin still returns to its own table")
        .expect("its last pin makes the unmap owed");

    let other_unmap = expect_unmap(other.begin_retire(other_id).expect("retire"));
    let Err(Stage2TokenRefused(other_unmap)) = mine.finish_retire(other_unmap) else {
        panic!("another table's owed unmap must be refused");
    };
    assert_eq!(
        other
            .finish_retire(other_unmap)
            .expect("its own table")
            .backing,
        Lease(2)
    );
    assert_eq!(
        mine.finish_retire(mine_unmap)
            .expect("its own table")
            .backing,
        Lease(1)
    );
    assert!(mine.teardown().is_empty());
    assert!(other.teardown().is_empty());
}

#[test]
fn a_null_or_overflowing_host_range_is_refused_before_a_record_exists() {
    let mut table = Stage2RecordTable::new();
    for host_addr in [0, usize::MAX - PAGE as usize + 1] {
        let mut wrapping = spec(0, 2 * PAGE, 1);
        wrapping.host_addr = host_addr;
        let refused = table.register(wrapping).expect_err("bad host range");
        assert_eq!(refused.reason, Stage2RegisterRefusal::HostRange);
        assert_eq!(refused.spec.backing, Lease(1));
    }
    assert!(table.is_empty());
    let mut top = spec(0, PAGE, 2);
    top.host_addr = usize::MAX - PAGE as usize;
    table
        .register(top)
        .expect("a host range ending exactly at the top");
    assert_eq!(
        table.pin(0, PAGE).map(|pin| pin.host_addr()),
        Ok(usize::MAX - PAGE as usize)
    );
    assert_eq!(table.teardown().len(), 1);
}

#[test]
fn a_range_overflowing_past_the_top_record_is_refused() {
    let mut table = Stage2RecordTable::new();
    let top = table
        .register(spec(u64::MAX - PAGE, PAGE, 1))
        .expect("record ending at u64::MAX");
    assert_eq!(table.covering(u64::MAX - 1, 1).unwrap().id, top);
    assert!(table.covering(u64::MAX - 1, 2).is_none());
    assert_eq!(
        table.pin(u64::MAX - 1, 2),
        Err(Stage2PinRefusal::EmptyRange)
    );
    assert_eq!(table.teardown().len(), 1);
}

#[test]
fn a_record_at_the_same_base_is_refused_whatever_the_old_one_is_doing() {
    let mut table = Stage2RecordTable::new();
    let live = table.register(spec(0, PAGE, 1)).expect("live");
    let pinned = table.register(spec(PAGE, PAGE, 2)).expect("to pin");
    let owed = table.register(spec(2 * PAGE, PAGE, 3)).expect("to retire");
    let pin = table.pin(PAGE, PAGE).expect("pin");
    assert_eq!(table.begin_retire(pinned), Ok(Stage2Retire::DeferredPinned));
    let unmap = expect_unmap(table.begin_retire(owed).expect("retire"));
    for (base, holder) in [(0, live), (PAGE, pinned), (2 * PAGE, owed)] {
        for len in [PAGE, 0x10] {
            let refused = table
                .register(spec(base, len, 9))
                .expect_err("same base as a live, pinned-retiring or unmap-owed record");
            assert_eq!(refused.reason, Stage2RegisterRefusal::Collision(holder));
        }
    }
    assert_eq!(table.len(), 3);
    let unmap_pinned = table.unpin(pin).expect("own pin").expect("owed now");
    table.finish_retire(unmap_pinned).expect("finish");
    table.finish_retire(unmap).expect("finish");
    assert_eq!(table.teardown().len(), 1);
}

#[test]
fn teardown_returns_every_record_with_what_it_still_owes() {
    let mut table = Stage2RecordTable::new();
    let live = table.register(spec(0, PAGE, 1)).expect("live");
    let pinned = table.register(spec(PAGE, PAGE, 2)).expect("pinned");
    let owed = table.register(spec(2 * PAGE, PAGE, 3)).expect("owed");
    let live_pin = table.pin(0, PAGE).expect("live pin");
    let retiring_pin = table.pin(PAGE, PAGE).expect("retiring pin");
    assert_eq!(table.begin_retire(pinned), Ok(Stage2Retire::DeferredPinned));
    let _owed_unmap = expect_unmap(table.begin_retire(owed).expect("retire"));

    let remnants = table.teardown();
    let states = remnants
        .iter()
        .map(|remnant| (remnant.id, remnant.state, &remnant.spec.backing))
        .collect::<Vec<_>>();
    assert_eq!(
        states,
        [
            (live, Stage2RemnantState::Live { pins: 1 }, &Lease(1)),
            (
                pinned,
                Stage2RemnantState::RetiringPinned { pins: 1 },
                &Lease(2)
            ),
            (owed, Stage2RemnantState::UnmapOwed, &Lease(3)),
        ]
    );
    drop((live_pin, retiring_pin));
}
