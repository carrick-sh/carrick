//! Interleaving witnesses for the residency table's shared reservation
//! layer (#2611): each schedule pauses one edit at a named point
//! ([`super::pause`]) and runs a peer there, on the real table.
//!
//! - A peer's reservation is never taken for another's (the claim is owned
//!   by its generation).
//! - A retirement never erases the dirty bit of the slot's next owner, on
//!   every retire path.
//! - A lock-free reader never misses a page whose custody an edit keeps, on
//!   every re-split path.

extern crate std;

use std::boxed::Box;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::format;
use std::rc::Rc;
use std::string::String;
use std::vec::Vec;

use super::pause::{self, Point};
use super::{
    EL1_FRAME_GRANT_TARGET_SIZE, FrameGrantResidencyIdentity, FrameGrantResidencyTable, GRANT_LIVE,
    GRANT_PAGE_SIZE, GRANT_STATE_MASK, GRANT_WRITING, ResidencyTransferRefusal, SplitRowCustody,
    TransferRange,
};

const P: u64 = GRANT_PAGE_SIZE;
const W: u64 = EL1_FRAME_GRANT_TARGET_SIZE;
const X: u64 = 0x4000_0000;
const A: u64 = 7;
/// Shares every probe chain with `A`: the keys are congruent modulo the
/// segment size, so the same `(base, len)` hashes to the same first slot.
const B: u64 = A + 4096;

/// A table that outlives every hook closure.
fn table() -> &'static FrameGrantResidencyTable {
    let layout = std::alloc::Layout::new::<FrameGrantResidencyTable>();
    // SAFETY: allocation uses the table layout and is initialized before
    // the reference is formed; the table is leaked for the test's life.
    unsafe {
        let ptr = std::alloc::alloc_zeroed(layout).cast::<FrameGrantResidencyTable>();
        assert!(!ptr.is_null());
        FrameGrantResidencyTable::init_in_place(ptr);
        Box::leak(Box::from_raw(ptr))
    }
}

fn row(mm: u64, base: u64, pages: u64, frame: u64) -> FrameGrantResidencyIdentity {
    FrameGrantResidencyIdentity {
        mm_key: mm,
        semantic_base: base,
        physical_ipa: 0x8000_0000 + frame * 0x10_0000,
        len: pages * P,
        mapping_id: frame,
        frame_id: frame,
        owner_generation: 1,
        inventory_revision: 1,
    }
}

/// Publish `identity` with every page committed.
fn publish_committed(
    table: &FrameGrantResidencyTable,
    identity: FrameGrantResidencyIdentity,
) -> usize {
    let slot = table.publish(identity).expect("publish");
    for page in (identity.semantic_base..identity.semantic_base + identity.len).step_by(P as usize)
    {
        assert!(table.record_commit(table.lookup(identity.mm_key, page).expect("lookup")));
    }
    slot
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

/// Every live page of `mm`, with its frame and whether it is committed.
fn pages(table: &FrameGrantResidencyTable, mm: u64) -> BTreeMap<u64, (u64, bool)> {
    let mut pages = BTreeMap::new();
    for record in table.slots() {
        if record.state.load(core::sync::atomic::Ordering::Acquire) & GRANT_STATE_MASK != GRANT_LIVE
        {
            continue;
        }
        let identity = record.identity();
        if identity.mm_key != mm {
            continue;
        }
        for page in
            (identity.semantic_base..identity.semantic_base + identity.len).step_by(P as usize)
        {
            pages.insert(
                page,
                (identity.frame_id, table.is_guest_committed(mm, page)),
            );
        }
    }
    pages
}

fn dirty_slots(table: &FrameGrantResidencyTable, mm: u64) -> Vec<usize> {
    let mut slots = Vec::new();
    let _ = table.for_each_dirty_mm::<()>(mm, |slot, _, _| {
        slots.push(slot);
        core::ops::ControlFlow::Continue(())
    });
    slots
}

/// Pre-review of `7dd713aad`, P0 1: `B` tags its reservation of a slot
/// that still holds `A`'s identity from `A`'s cancelled transfer, and is
/// paused before writing its own. `A`'s next transfer must commit into its
/// own reservation, and `B`'s must survive.
#[test]
fn a_peer_reservation_paused_before_its_identity_is_never_taken() {
    let table = table();
    let a_row = row(A, X, 1, 1);
    let b_row = row(B, X + 4 * P, 1, 2);
    table.publish(a_row).expect("A's row");
    table.publish(b_row).expect("B's row");
    let dst = X + W + P;
    let a_range = TransferRange::new(A, X, dst, P).unwrap();
    let b_range = TransferRange::new(B, X + 4 * P, dst, P).unwrap();
    // A's cancelled transfer leaves its identity in the tombstone.
    drop(table.begin_transfer(a_range).expect("A's first admission"));
    let a_commit = Rc::new(RefCell::new(None));
    let seen = Rc::new(RefCell::new(0));
    let b_commit = pause::with(
        {
            let a_commit = Rc::clone(&a_commit);
            let seen = Rc::clone(&seen);
            move |point| {
                if matches!(point, Point::Tagged { .. }) && *seen.borrow() == 0 {
                    *seen.borrow_mut() += 1;
                    let receipt = table
                        .begin_transfer(a_range)
                        .ok()
                        .and_then(|transfer| transfer.commit());
                    *a_commit.borrow_mut() = Some(receipt);
                }
            }
        },
        || {
            table
                .begin_transfer(b_range)
                .ok()
                .and_then(|transfer| transfer.commit())
        },
    );
    assert_eq!(*seen.borrow(), 1, "B paused at its reservation");
    let a_receipt = a_commit.borrow().expect("A ran at the pause");
    assert_eq!(
        a_receipt.map(|r| r.frames_relinked),
        Some(1),
        "A commits its own move"
    );
    assert_eq!(
        b_commit.map(|r| r.frames_relinked),
        Some(1),
        "B commits its own move"
    );
    assert_eq!(
        pages(table, A).get(&dst).map(|p| p.0),
        Some(1),
        "A's frame is at dst"
    );
    assert_eq!(
        pages(table, B).get(&dst).map(|p| p.0),
        Some(2),
        "B's frame is at dst"
    );
    assert_eq!(writing(table), 0, "no reservation leaked");
}

/// The retire paths of the table. Each retires `B`'s one-page row at `X`.
#[derive(Clone, Copy, Debug)]
enum RetirePath {
    /// The host's `retire`.
    Retire,
    /// A copy-on-write replacement of the row.
    Replacement,
    /// A preclaimed retirement (`begin_retire_overlapping` and commit).
    Preclaimed,
    /// A transfer of the row.
    Transfer,
}

fn retire_b(table: &FrameGrantResidencyTable, path: RetirePath, slot: usize) -> bool {
    let b_row = row(B, X, 1, 2);
    match path {
        RetirePath::Retire => table.retire(slot, b_row),
        RetirePath::Replacement => table
            .begin_replacement(row(B, X, 1, 3))
            .is_ok_and(|replacement| replacement.commit()),
        RetirePath::Preclaimed => table
            .begin_retire_overlapping(B, X, P, SplitRowCustody::Reserved)
            .is_ok_and(|retirement| retirement.commit()),
        RetirePath::Transfer => table
            .begin_transfer(TransferRange::new(B, X, X + W, P).unwrap())
            .ok()
            .and_then(|transfer| transfer.commit())
            .is_some(),
    }
}

/// Pre-review of `7dd713aad`, P0 3 (pre-existing on main for every path
/// but the transfer): `B` retires its row and is paused once the slot is
/// reusable. `A` publishes a committed row there, which sets the slot's
/// dirty bit. Resuming `B` must not clear it.
#[test]
fn a_retirement_never_erases_the_next_owners_dirty_bit() {
    let mut failures = Vec::<String>::new();
    for path in [
        RetirePath::Retire,
        RetirePath::Replacement,
        RetirePath::Preclaimed,
        RetirePath::Transfer,
    ] {
        let table = table();
        let b_slot = table.publish(row(B, X, 1, 2)).expect("B's row");
        let a_slot = Rc::new(RefCell::new(None));
        let retired = pause::with(
            {
                let a_slot = Rc::clone(&a_slot);
                move |point| {
                    if point == (Point::Retired { slot: b_slot }) && a_slot.borrow().is_none() {
                        *a_slot.borrow_mut() = Some(publish_committed(table, row(A, X, 1, 1)));
                    }
                }
            },
            || retire_b(table, path, b_slot),
        );
        assert!(retired, "{path:?}: B's retirement commits");
        let Some(a_slot) = *a_slot.borrow() else {
            panic!("{path:?}: B never paused with its slot reusable");
        };
        assert_eq!(a_slot, b_slot, "{path:?}: A reuses B's slot");
        if !dirty_slots(table, A).contains(&a_slot) {
            failures.push(format!(
                "{path:?}: A's dirty bit on slot {a_slot} was erased"
            ));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The re-split paths: each changes the middle page of `A`'s committed
/// three-page row at `X` and keeps its other two pages' custody.
#[derive(Clone, Copy, Debug)]
enum ResplitPath {
    Replacement,
    Preclaimed,
    Transfer,
}

/// Pre-review of `7dd713aad`, P0 2 (pre-existing on main for the
/// replacement and the retirement): at every pause point inside the edit, a
/// lock-free reader must still find the two kept pages, live and
/// committed, and must find the moved or replaced page at one of its
/// addresses.
#[test]
fn a_lock_free_reader_never_misses_a_kept_page_mid_resplit() {
    let mut failures = Vec::<String>::new();
    for path in [
        ResplitPath::Replacement,
        ResplitPath::Preclaimed,
        ResplitPath::Transfer,
    ] {
        let table = table();
        publish_committed(table, row(A, X, 3, 1));
        let dst = X + W;
        let points = Rc::new(RefCell::new(0usize));
        let seen = Rc::new(RefCell::new(Vec::<String>::new()));
        let committed = pause::with(
            {
                let points = Rc::clone(&points);
                let seen = Rc::clone(&seen);
                move |point| {
                    *points.borrow_mut() += 1;
                    for kept in [X, X + 2 * P] {
                        if !table.is_guest_committed(A, kept) {
                            seen.borrow_mut()
                                .push(format!("{path:?} at {point:?}: kept page {kept:#x} missed"));
                        }
                    }
                    let middle = table.lookup(A, X + P).is_some();
                    let moved = table.lookup(A, dst).is_some();
                    match path {
                        ResplitPath::Replacement if !middle => seen
                            .borrow_mut()
                            .push(format!("{path:?} at {point:?}: replaced page missed")),
                        ResplitPath::Transfer if !middle && !moved => seen
                            .borrow_mut()
                            .push(format!("{path:?} at {point:?}: moved page missed")),
                        _ => {}
                    }
                }
            },
            || match path {
                ResplitPath::Replacement => table
                    .begin_replacement(row(A, X + P, 1, 9))
                    .is_ok_and(|replacement| replacement.commit()),
                ResplitPath::Preclaimed => table
                    .begin_retire_overlapping(A, X + P, P, SplitRowCustody::Reserved)
                    .is_ok_and(|retirement| retirement.commit()),
                ResplitPath::Transfer => table
                    .begin_transfer(TransferRange::new(A, X + P, dst, P).unwrap())
                    .ok()
                    .and_then(|transfer| transfer.commit())
                    .is_some(),
            },
        );
        assert!(committed, "{path:?}: the edit commits");
        assert!(
            *points.borrow() >= 3,
            "{path:?}: the edit passed its points"
        );
        for kept in [X, X + 2 * P] {
            assert!(
                table.is_guest_committed(A, kept),
                "{path:?}: kept page after"
            );
        }
        failures.extend(seen.borrow().iter().cloned());
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Ruling 4 on #2611: a held lease is "not now". The refusal carries the
/// release count it observed; once the lease drops, the one probe reports
/// the release and the rerun is admitted and commits.
#[test]
fn a_leased_transfer_is_admitted_once_the_lease_drops() {
    let table = table();
    publish_committed(table, row(A, X, 2, 1));
    let range = TransferRange::new(A, X, X + W, 2 * P).unwrap();
    let pin = table
        .pin_transfer(table.lookup(A, X + P).unwrap())
        .expect("lease");
    let Err(ResidencyTransferRefusal::Leased(release)) = table.begin_transfer(range) else {
        panic!("a held lease refuses the transfer as Leased");
    };
    assert!(!table.lease_released(release), "no release yet");
    assert_eq!(writing(table), 0, "the refusal changed nothing");
    // The lease drops before the refused caller enrols: the probe after
    // enrolling still sees it, so the wake cannot be missed.
    drop(pin);
    assert!(table.lease_released(release), "the probe sees the release");
    let receipt = table
        .begin_transfer(range)
        .expect("the rerun is admitted")
        .commit()
        .expect("and commits");
    assert_eq!(receipt.frames_relinked, 2);
    assert!(table.is_guest_committed(A, X + W + P));
}

/// Pre-review of `7dd713aad`, P0 4: `A`'s admission reads its live source
/// row and pauses before closing it. The row is retired (by a path that
/// ignores `A`'s editor) and `B` reuses the slot and leases its own row.
/// `A` must not report `B`'s lease as its contention, must not close `B`'s
/// row, and moves nothing: a source that disappeared was retired, not
/// moved.
#[test]
fn a_recycled_source_slot_is_neither_closed_nor_contention() {
    let table = table();
    let a_row = row(A, X, 1, 1);
    let a_slot = table.publish(a_row).expect("A's row");
    let b_row = row(B, X, 1, 2);
    let b_pin = Rc::new(RefCell::new(None));
    let admitted = pause::with(
        {
            let b_pin = Rc::clone(&b_pin);
            move |point| {
                if point == (Point::SourceRead { slot: a_slot }) && b_pin.borrow().is_none() {
                    assert!(table.retire(a_slot, a_row), "A's row retires");
                    let b_slot = table.publish(b_row).expect("B's row");
                    assert_eq!(b_slot, a_slot, "B reuses A's slot");
                    let pin = table
                        .pin_transfer(table.lookup(B, X).unwrap())
                        .expect("B's lease");
                    *b_pin.borrow_mut() = Some(pin);
                }
            }
        },
        || {
            table
                .begin_transfer(TransferRange::new(A, X, X + W, P).unwrap())
                .map(|transfer| transfer.commit())
        },
    );
    assert!(b_pin.borrow().is_some(), "A paused at its source read");
    let receipt = admitted.expect("B's lease is not A's contention");
    assert_eq!(receipt.map(|r| r.rows_rekeyed), Some(0), "nothing moved");
    drop(b_pin.borrow_mut().take());
    assert!(
        table
            .begin_retire_overlapping(B, X, P, SplitRowCustody::Reserved)
            .is_ok(),
        "B's row is open: A never closed it"
    );
    assert_eq!(pages(table, B).get(&X).map(|p| p.0), Some(2));
}
