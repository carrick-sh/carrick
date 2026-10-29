extern crate std;
use super::tests::{identity, table};
use super::*;
use crate::{ReservationIncarnation, ReservationProtection};
use carrick_guest_arch::{ContextGeneration, MmGeneration, UserVa};
use core::num::NonZeroU64;

fn owner(mm: u64, root: u64) -> StockResidencyOwner {
    StockResidencyOwner {
        mm: MmGeneration::new(NonZeroU64::new(mm).unwrap()),
        root: ContextGeneration::new(NonZeroU64::new(root).unwrap()),
    }
}
fn publish(
    table: &FrameGrantResidencyTable,
    owner: StockResidencyOwner,
) -> FrameGrantResidencyIdentity {
    let identity = FrameGrantResidencyIdentity {
        mm_key: owner.mm.raw().get(),
        len: crate::COW_GRANT_SIZE,
        ..identity()
    };
    table
        .reserve_stock(
            owner,
            &[StockChunkReservation {
                base: UserVa::new(identity.semantic_base),
                retained: StockPageMask::ALL,
            }],
        )
        .unwrap()
        .publish(owner, &[identity])
        .unwrap();
    identity
}
fn page(mapping: u64, protection: ReservationProtection) -> StockPageAdoption {
    StockPageAdoption {
        mapping: ReservationIncarnation::new(mapping).unwrap(),
        protection,
    }
}
fn stage<'a>(
    table: &'a FrameGrantResidencyTable,
    owner: StockResidencyOwner,
    identity: FrameGrantResidencyIdentity,
    pages: [Option<StockPageAdoption>; 4],
) -> StockAdoptionTransaction<'a> {
    table.begin_stock_adoption(owner, identity, pages).unwrap()
}

#[test]
fn stock_adoption_mixed_access_and_none_have_distinct_page_owners() {
    let table = table();
    let who = owner(7, 1);
    let id = publish(&table, who);
    let peer = owner(8, 3);
    let peer_id = publish(&table, peer);
    let peer_before = table.stock_adoptions(peer, peer_id).unwrap();
    let pages = [
        Some(page(11, ReservationProtection::READ)),
        Some(page(12, ReservationProtection::READ_WRITE)),
        Some(page(13, ReservationProtection::from_bits(5).unwrap())),
        Some(page(14, ReservationProtection::NONE)),
    ];
    let mut pending = stage(&table, who, id, pages);
    assert!(table.stock_adoptions(who, id).is_none());
    assert_eq!(table.stock_adoptions(peer, peer_id), Some(peer_before));
    let result = pending.commit().unwrap();
    assert_eq!(result.pages, pages);
    assert_eq!(result.retained, StockPageMask::ALL);
    assert_eq!(result.committed.bits(), 0);
    assert_eq!(table.stock_adoptions(who, id), Some(result));
    assert_eq!(table.stock_record_count(), 2);
}

#[test]
fn stock_adoption_explicit_rollback_restores_complete_preimage() {
    let table = table();
    let who = owner(7, 1);
    let id = publish(&table, who);
    stage(
        &table,
        who,
        id,
        [
            Some(page(11, ReservationProtection::READ)),
            None,
            None,
            None,
        ],
    )
    .commit()
    .unwrap();
    let token = table.lookup(id.mm_key, id.semantic_base).unwrap();
    assert!(table.record_commit(token));
    let before = table.stock_adoptions(who, id).unwrap();
    let dirty_before = table.dirty[token.slot / 64].load(Ordering::Acquire);
    let mut pending = stage(
        &table,
        who,
        id,
        [
            Some(page(11, ReservationProtection::READ_WRITE)),
            Some(page(12, ReservationProtection::NONE)),
            None,
            None,
        ],
    );
    assert!(!table.record_commit(token));
    assert!(table.pin_transfer(token).is_none());
    assert!(
        table
            .begin_retire_overlapping(id.mm_key, id.semantic_base, id.len)
            .is_none()
    );
    pending.rollback().unwrap();
    assert_eq!(table.stock_adoptions(who, id), Some(before));
    assert_eq!(
        table.dirty[token.slot / 64].load(Ordering::Acquire),
        dirty_before
    );
    assert!(table.pin_transfer(token).is_some());
}

#[test]
fn stock_adoption_validates_all_pages_before_claiming_or_editing() {
    let table = table();
    let who = owner(7, 1);
    let id = publish(&table, who);
    stage(
        &table,
        who,
        id,
        [
            None,
            None,
            None,
            Some(page(14, ReservationProtection::READ)),
        ],
    )
    .commit()
    .unwrap();
    let before = table.stock_adoptions(who, id).unwrap();
    assert!(
        table
            .begin_stock_adoption(
                who,
                id,
                [
                    Some(page(11, ReservationProtection::READ_WRITE)),
                    None,
                    None,
                    Some(page(99, ReservationProtection::READ))
                ]
            )
            .is_none()
    );
    assert_eq!(table.stock_adoptions(who, id), Some(before));
    assert!(table.begin_stock_adoption(who, id, [None; 4]).is_none());
    let token = table.lookup(id.mm_key, id.semantic_base).unwrap();
    let pin = table.pin_transfer(token).unwrap();
    assert!(
        table
            .begin_stock_adoption(
                who,
                id,
                [
                    Some(page(11, ReservationProtection::READ)),
                    None,
                    None,
                    None
                ]
            )
            .is_none()
    );
    assert_eq!(table.stock_adoptions(who, id), Some(before));
    drop(pin);
}

#[test]
fn stock_adoption_owner_root_and_physical_identity_are_exact() {
    let table = table();
    let who = owner(7, 1);
    let id = publish(&table, who);
    let peer = owner(8, 2);
    let peer_id = publish(&table, peer);
    let before = table.stock_adoptions(who, id).unwrap();
    for foreign in [peer, owner(7, 2)] {
        assert!(
            table
                .begin_stock_adoption(
                    foreign,
                    id,
                    [Some(page(1, ReservationProtection::READ)), None, None, None]
                )
                .is_none()
        );
        assert!(table.stock_adoptions(foreign, id).is_none());
    }
    for changed in [
        FrameGrantResidencyIdentity {
            owner_generation: id.owner_generation + 1,
            ..id
        },
        FrameGrantResidencyIdentity {
            inventory_revision: id.inventory_revision + 1,
            ..id
        },
        FrameGrantResidencyIdentity {
            frame_id: id.frame_id + 1,
            ..id
        },
        FrameGrantResidencyIdentity {
            mapping_id: id.mapping_id + 1,
            ..id
        },
        FrameGrantResidencyIdentity {
            physical_ipa: id.physical_ipa + crate::COW_GRANT_SIZE,
            ..id
        },
    ] {
        assert!(
            table
                .begin_stock_adoption(
                    who,
                    changed,
                    [Some(page(1, ReservationProtection::READ)), None, None, None]
                )
                .is_none()
        );
    }
    assert_eq!(table.stock_adoptions(who, id), Some(before));
    assert!(table.stock_adoptions(peer, peer_id).is_some());
}

#[test]
fn stock_adoption_retirement_clears_only_returned_page_overlay() {
    let table = table();
    let who = owner(7, 1);
    let id = publish(&table, who);
    let pages =
        core::array::from_fn(|i| Some(page(i as u64 + 1, ReservationProtection::READ_WRITE)));
    stage(&table, who, id, pages).commit().unwrap();
    assert!(table.retire_small_span(
        id.mm_key,
        id.semantic_base + GRANT_PAGE_SIZE,
        GRANT_PAGE_SIZE
    ));
    let snapshot = table.stock_adoptions(who, id).unwrap();
    assert_eq!(snapshot.retained.bits(), 13);
    assert_eq!(snapshot.pages, [pages[0], None, pages[2], pages[3]]);
    let before = snapshot;
    assert!(
        table
            .begin_stock_adoption(
                who,
                id,
                [
                    Some(page(1, ReservationProtection::READ)),
                    Some(page(99, ReservationProtection::READ)),
                    None,
                    None
                ]
            )
            .is_none()
    );
    assert_eq!(table.stock_adoptions(who, id), Some(before));
    assert!(
        table
            .publish(FrameGrantResidencyIdentity {
                semantic_base: id.semantic_base + GRANT_PAGE_SIZE,
                physical_ipa: 0x800_0000,
                len: GRANT_PAGE_SIZE,
                ..id
            })
            .is_some()
    );
    assert!(table.retire_small_span(id.mm_key, id.semantic_base, id.len));
    assert_eq!(table.stock_record_count(), 0);
    assert!(table.stock_adoptions(who, id).is_none());
}

#[test]
fn stock_adoption_drop_retains_quarantined_row_and_peer_stays_live() {
    let table = table();
    let who = owner(7, 1);
    let id = publish(&table, who);
    let peer = owner(8, 2);
    let peer_id = publish(&table, peer);
    let peer_before = table.stock_adoptions(peer, peer_id).unwrap();
    let pending = stage(
        &table,
        who,
        id,
        [
            Some(page(1, ReservationProtection::READ_WRITE)),
            None,
            None,
            None,
        ],
    );
    drop(pending); // No proof of descriptor undo: retain, never reopen.
    assert!(table.stock_adoption_quarantined(who, id));
    assert!(table.stock_adoptions(who, id).is_none());
    let token = table.lookup(id.mm_key, id.semantic_base).unwrap();
    assert!(!table.record_commit(token));
    assert!(table.pin_transfer(token).is_none());
    assert!(!table.retire_small_span(id.mm_key, id.semantic_base, id.len));
    assert!(
        table
            .begin_stock_adoption(
                who,
                id,
                [Some(page(1, ReservationProtection::READ)), None, None, None]
            )
            .is_none()
    );
    assert_eq!(table.stock_record_count(), 2);
    assert_eq!(table.stock_adoptions(peer, peer_id), Some(peer_before));
}

#[test]
fn stock_adoption_permission_directions_do_not_widen_a_peer_page() {
    let table = table();
    let who = owner(7, 1);
    let id = publish(&table, who);
    stage(
        &table,
        who,
        id,
        [
            Some(page(1, ReservationProtection::READ)),
            Some(page(2, ReservationProtection::READ_WRITE)),
            None,
            None,
        ],
    )
    .commit()
    .unwrap();
    let after = stage(
        &table,
        who,
        id,
        [
            Some(page(1, ReservationProtection::READ_WRITE)),
            Some(page(2, ReservationProtection::from_bits(5).unwrap())),
            None,
            None,
        ],
    )
    .commit()
    .unwrap();
    assert_eq!(
        after.pages[0],
        Some(page(1, ReservationProtection::READ_WRITE))
    );
    assert_eq!(
        after.pages[1],
        Some(page(2, ReservationProtection::from_bits(5).unwrap()))
    );
    assert!(
        !after.pages[1]
            .unwrap()
            .protection
            .permits(ReservationProtection::WRITE)
    );
    assert_eq!(after.pages[2..], [None, None]);
    let after = stage(
        &table,
        who,
        id,
        [Some(page(1, ReservationProtection::NONE)), None, None, None],
    )
    .commit()
    .unwrap();
    assert_eq!(after.pages[0], Some(page(1, ReservationProtection::NONE)));
    assert_eq!(
        after.pages[1],
        Some(page(2, ReservationProtection::from_bits(5).unwrap()))
    );
}

#[test]
fn stock_adoption_failed_settlement_returns_custody_without_reopening_row() {
    let table = table();
    let who = owner(7, 1);
    let id = publish(&table, who);
    let mut pending = stage(
        &table,
        who,
        id,
        [Some(page(1, ReservationProtection::READ)), None, None, None],
    );
    // Inject damage after staging, analogous to an unverified external undo.
    // Neither settlement may release the claim on a mismatched preimage.
    let slot = table.lookup(id.mm_key, id.semantic_base).unwrap().slot;
    table.slots[slot].stock_mappings[0].store(99, Ordering::Release);
    assert_eq!(
        pending.rollback(),
        Err(StockAdoptionRefusal::PreimageChanged)
    );
    assert!(table.stock_adoptions(who, id).is_none());
    assert_eq!(pending.commit(), Err(StockAdoptionRefusal::PreimageChanged));
    assert!(table.stock_adoptions(who, id).is_none());
    drop(pending);
    assert!(table.stock_adoption_quarantined(who, id));
    assert_eq!(table.stock_record_count(), 1);
    assert!(!table.retire_small_span(id.mm_key, id.semantic_base, id.len));
}

#[test]
fn stock_adoption_base_page_retirement_and_record_reuse_are_not_authority() {
    let table = table();
    let who = owner(7, 1);
    let id = publish(&table, who);
    stage(
        &table,
        who,
        id,
        [None, Some(page(2, ReservationProtection::READ)), None, None],
    )
    .commit()
    .unwrap();
    assert!(table.retire_small_span(id.mm_key, id.semantic_base, GRANT_PAGE_SIZE));
    let before = table.stock_adoptions(who, id).unwrap();
    assert_eq!(before.retained.bits(), 14);
    stage(
        &table,
        who,
        id,
        [
            None,
            Some(page(2, ReservationProtection::READ_WRITE)),
            None,
            None,
        ],
    )
    .rollback()
    .unwrap();
    assert_eq!(table.stock_adoptions(who, id), Some(before));
    assert!(table.retire_small_span(id.mm_key, id.semantic_base, id.len));
    let successor = owner(7, 2);
    let fresh = FrameGrantResidencyIdentity {
        owner_generation: id.owner_generation + 1,
        ..id
    };
    table
        .reserve_stock(
            successor,
            &[StockChunkReservation {
                base: UserVa::new(fresh.semantic_base),
                retained: StockPageMask::ALL,
            }],
        )
        .unwrap()
        .publish(successor, &[fresh])
        .unwrap();
    assert!(table.stock_adoptions(who, id).is_none());
    let snapshot = table.stock_adoptions(successor, fresh).unwrap();
    assert_eq!(snapshot.pages, [None; 4]);
    assert_eq!(snapshot.committed.bits(), 0);
}

#[test]
fn stock_adoption_quarantine_latch_blocks_even_a_damaged_pin_claim() {
    let table = table();
    let who = owner(7, 1);
    let id = publish(&table, who);
    let token = table.lookup(id.mm_key, id.semantic_base).unwrap();
    stage(
        &table,
        who,
        id,
        [Some(page(1, ReservationProtection::READ)), None, None, None],
    )
    .commit()
    .unwrap();
    let mut pending = stage(
        &table,
        who,
        id,
        [
            Some(page(1, ReservationProtection::READ_WRITE)),
            None,
            None,
            None,
        ],
    );
    table.slots[token.slot]
        .transfer_pins
        .store(0, Ordering::Release);
    assert_eq!(
        pending.rollback(),
        Err(StockAdoptionRefusal::PreimageChanged)
    );
    drop(pending);
    assert!(table.stock_adoption_quarantined(who, id));
    assert!(!table.record_commit(token));
    assert!(table.pin_transfer(token).is_none());
    assert!(!table.ack_dirty(token.slot, id));
    assert!(!table.retire(token.slot, id));
    assert!(
        table
            .begin_retire_overlapping(id.mm_key, id.semantic_base, id.len)
            .is_none()
    );
    assert!(!table.retire_overlapping(id.mm_key, id.semantic_base, id.len));
    assert!(!table.retire_small_span(id.mm_key, id.semantic_base, id.len));
    let mut visited = 0;
    table.for_each_dirty_mm(id.mm_key, |_, _, _| visited += 1);
    assert_eq!(visited, 0);
    assert_eq!(table.stock_record_count(), 1);
}
