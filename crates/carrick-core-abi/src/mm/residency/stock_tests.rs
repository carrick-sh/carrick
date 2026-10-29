extern crate std;
use super::tests::{identity, table};
use super::*;

fn chunk() -> FrameGrantResidencyIdentity {
    FrameGrantResidencyIdentity {
        len: crate::COW_GRANT_SIZE,
        ..identity()
    }
}

fn fill_other_slots(table: &FrameGrantResidencyTable, occupied: usize) {
    // Class-zero buckets permute all 4096 first slots. Publish real live
    // grants for a simultaneously live peer, not synthetic state flags.
    for bucket in 0..FRAME_GRANT_RESIDENCY_SLOTS as u64 {
        let va = 0x40_0000 + bucket * GRANT_PAGE_SIZE;
        let first = FrameGrantResidencyTable::first_slot(8, va / GRANT_PAGE_SIZE, 0);
        if first == occupied {
            continue;
        }
        assert!(
            table
                .publish(FrameGrantResidencyIdentity {
                    mm_key: 8,
                    semantic_base: va,
                    physical_ipa: 0x800_0000 + bucket * GRANT_PAGE_SIZE,
                    len: GRANT_PAGE_SIZE,
                    ..identity()
                })
                .is_some()
        );
    }
}

#[test]
fn saturated_chunk_retirement_preserves_surviving_pages() {
    let table = table();
    let identity = chunk();
    let slot = publish_stock(&table, owner(7, 1), identity);
    for page in 0..4 {
        assert!(
            table.record_commit(
                table
                    .lookup(
                        identity.mm_key,
                        identity.semantic_base + page * GRANT_PAGE_SIZE
                    )
                    .unwrap()
            )
        );
    }
    fill_other_slots(&table, slot);
    assert!(table.retire_small_span(
        identity.mm_key,
        identity.semantic_base + GRANT_PAGE_SIZE,
        GRANT_PAGE_SIZE
    ));
    assert!(
        table.is_guest_committed(identity.mm_key, identity.semantic_base),
        "chunk retirement must preserve the committed prefix under slot pressure"
    );
    assert!(
        table.is_guest_committed(
            identity.mm_key,
            identity.semantic_base + 3 * GRANT_PAGE_SIZE
        ),
        "chunk retirement must preserve the committed suffix under slot pressure"
    );
}

fn owner(mm: u64, root: u64) -> StockResidencyOwner {
    use carrick_guest_arch::{ContextGeneration, MmGeneration};
    StockResidencyOwner {
        mm: MmGeneration::new(core::num::NonZeroU64::new(mm).unwrap()),
        root: ContextGeneration::new(core::num::NonZeroU64::new(root).unwrap()),
    }
}
fn request(base: u64) -> StockChunkReservation {
    StockChunkReservation {
        base: carrick_guest_arch::UserVa::new(base),
        retained: StockPageMask::ALL,
    }
}
fn publish_stock(
    table: &FrameGrantResidencyTable,
    owner: StockResidencyOwner,
    identity: FrameGrantResidencyIdentity,
) -> usize {
    table
        .reserve_stock(owner, &[request(identity.semantic_base)])
        .unwrap()
        .publish(owner, &[identity])
        .unwrap()[0]
}

#[test]
fn concrete_claims_are_invisible_exclude_overlaps_and_cancel_as_a_batch() {
    let table = table();
    let who = owner(7, 1);
    let id = chunk();
    let claims = [
        request(id.semantic_base),
        request(id.semantic_base + crate::COW_GRANT_SIZE),
    ];
    let lease = table.reserve_stock(who, &claims).unwrap();
    assert_eq!(lease.len(), 2);
    assert!(!lease.is_empty());
    assert_eq!(table.stock_record_count(), 2);
    assert!(table.lookup(7, id.semantic_base).is_none());
    assert!(
        table.publish(id).is_none(),
        "reserved occupancy must block ordinary publication"
    );
    assert!(table.reserve_stock(who, &claims[..1]).is_none());
    // The same VA in a second live MM remains independent.
    let peer = FrameGrantResidencyIdentity {
        mm_key: 8,
        physical_ipa: 0x400_0000,
        ..id
    };
    let peer_slot = publish_stock(&table, owner(8, 1), peer);
    drop(lease);
    assert_eq!(table.stock_record_count(), 1);
    assert!(table.lookup(7, id.semantic_base).is_none());
    assert_eq!(table.lookup(8, peer.semantic_base).unwrap().slot, peer_slot);
    let own_slot = publish_stock(&table, who, id);
    assert_ne!(own_slot, peer_slot);
    assert_eq!(table.stock_record_count(), 2);
}

#[test]
fn batch_validation_rejects_foreign_owner_and_bad_last_identity_before_any_publication() {
    let table = table();
    let who = owner(7, 1);
    let id = chunk();
    let claims = [
        request(id.semantic_base),
        request(id.semantic_base + crate::COW_GRANT_SIZE),
    ];
    let next = FrameGrantResidencyIdentity {
        semantic_base: claims[1].base.raw(),
        physical_ipa: id.physical_ipa + crate::COW_GRANT_SIZE,
        frame_id: 23,
        mapping_id: 24,
        ..id
    };
    for bad in [
        FrameGrantResidencyIdentity {
            frame_id: 0,
            ..next
        },
        FrameGrantResidencyIdentity { mm_key: 8, ..next },
        FrameGrantResidencyIdentity {
            physical_ipa: next.physical_ipa + GRANT_PAGE_SIZE,
            ..next
        },
    ] {
        assert!(
            table
                .reserve_stock(who, &claims)
                .unwrap()
                .publish(who, &[id, bad])
                .is_err()
        );
        assert_eq!(table.stock_record_count(), 0);
        assert!(table.lookup(7, id.semantic_base).is_none());
    }
    for foreign in [owner(8, 1), owner(7, 2)] {
        assert!(
            table
                .reserve_stock(who, &claims)
                .unwrap()
                .publish(foreign, &[id, next])
                .is_err()
        );
        assert_eq!(table.stock_record_count(), 0);
    }
    let slots = table
        .reserve_stock(who, &claims)
        .unwrap()
        .publish(who, &[id, next])
        .unwrap();
    assert_eq!(slots.len(), 2);
    assert_eq!(
        table.stock_record(who, claims[1].base).unwrap().identity,
        next
    );
    assert!(table.stock_record(owner(7, 2), claims[1].base).is_none());
    assert!(
        table
            .reserve_stock(owner(7, 2), &[request(0x200_0000)])
            .is_none(),
        "recycled root cannot acquire old stock entitlement"
    );
    assert!(table.retire_overlapping(7, id.semantic_base, 2 * crate::COW_GRANT_SIZE));
    assert_eq!(table.stock_record_count(), 0);
    assert!(table.reserve_stock(owner(7, 2), &claims).is_some());
}

fn peer_at_first_slot(slot: usize) -> FrameGrantResidencyIdentity {
    let bucket = (0..FRAME_GRANT_RESIDENCY_SLOTS as u64)
        .find(|bucket| FrameGrantResidencyTable::first_slot(8, 0x400 + bucket, 0) == slot)
        .unwrap();
    FrameGrantResidencyIdentity {
        mm_key: 8,
        semantic_base: (0x400 + bucket) * GRANT_PAGE_SIZE,
        physical_ipa: 0x800_0000 + bucket * GRANT_PAGE_SIZE,
        len: GRANT_PAGE_SIZE,
        ..identity()
    }
}

#[test]
fn collision_full_probe_set_refuses_even_with_global_free_slots_and_undoes_earlier_claims() {
    let table = table();
    let id = chunk();
    let first =
        FrameGrantResidencyTable::first_slot(7, id.semantic_base / crate::COW_GRANT_SIZE, 2);
    let mut peers = alloc::vec::Vec::new();
    for offset in 0..GRANT_PROBES {
        let slot = (first + offset) % FRAME_GRANT_RESIDENCY_SLOTS;
        let peer = peer_at_first_slot(slot);
        assert_eq!(table.publish(peer), Some(slot));
        peers.push(peer);
    }
    assert_eq!(peers.len(), 64);
    let requests = [
        request(id.semantic_base + crate::COW_GRANT_SIZE),
        request(id.semantic_base),
    ];
    assert!(table.reserve_stock(owner(7, 1), &requests).is_none());
    assert_eq!(
        table.stock_record_count(),
        0,
        "earlier concrete claims must cancel"
    );
    for peer in peers {
        assert_eq!(
            table
                .lookup(peer.mm_key, peer.semantic_base)
                .unwrap()
                .identity,
            peer
        );
    }
    // An unrelated probe set is still serviceable. A free-count admission
    // would have falsely promised the colliding request above.
    assert!(table.reserve_stock(owner(7, 1), &requests[..1]).is_some());
}

#[test]
fn canceled_empty_slot_keeps_peer_probe_chain_reachable() {
    let table = table();
    let id = chunk();
    let lease = table
        .reserve_stock(owner(7, 1), &[request(id.semantic_base)])
        .unwrap();
    let first =
        FrameGrantResidencyTable::first_slot(7, id.semantic_base / crate::COW_GRANT_SIZE, 2);
    let peer = peer_at_first_slot(first);
    let peer_slot = table.publish(peer).unwrap();
    assert_ne!(peer_slot, first);
    drop(lease);
    assert_eq!(table.stock_record_count(), 0);
    assert_eq!(
        table.lookup(8, peer.semantic_base).unwrap().slot,
        peer_slot,
        "cancellation cannot restore EMPTY in front of another MM's insertion"
    );
}

#[test]
fn masked_returns_preserve_commits_reject_stale_tokens_and_allow_new_grants_in_holes() {
    let table = table();
    let who = owner(7, 1);
    let id = chunk();
    let slot = publish_stock(&table, who, id);
    let old: alloc::vec::Vec<_> = (0..4)
        .map(|bit| {
            table
                .lookup(7, id.semantic_base + bit * GRANT_PAGE_SIZE)
                .unwrap()
        })
        .collect();
    for page in &old {
        assert!(table.record_commit(*page));
    }
    let peer = FrameGrantResidencyIdentity {
        mm_key: 8,
        physical_ipa: 0x400_0000,
        ..id
    };
    let peer_slot = publish_stock(&table, owner(8, 2), peer);
    for bit in [1, 3] {
        assert!(table.retire_small_span(
            7,
            id.semantic_base + bit * GRANT_PAGE_SIZE,
            GRANT_PAGE_SIZE
        ));
        assert!(!table.record_commit(old[bit as usize]));
        assert!(table.pin_transfer(old[bit as usize]).is_none());
    }
    let record = table
        .stock_record(who, carrick_guest_arch::UserVa::new(id.semantic_base))
        .unwrap();
    assert_eq!(record.retained.bits(), 0b0101);
    assert_eq!(record.identity, id);
    assert_eq!(
        table.stock_record_count(),
        2,
        "fragmentation consumes no replacement rows"
    );
    for bit in [0, 2] {
        let page = table
            .lookup(7, id.semantic_base + bit * GRANT_PAGE_SIZE)
            .unwrap();
        assert_eq!(page.slot, slot);
        assert!(table.is_guest_committed(7, id.semantic_base + bit * GRANT_PAGE_SIZE));
        assert_eq!(page.retained_span().unwrap().len().raw(), GRANT_PAGE_SIZE);
    }
    let mut spans = alloc::vec::Vec::new();
    table.live_spans_overlapping(7, id.semantic_base, id.len, |start, end| {
        spans.push((start, end))
    });
    assert_eq!(
        spans,
        [
            (id.semantic_base, id.semantic_base + GRANT_PAGE_SIZE),
            (
                id.semantic_base + 2 * GRANT_PAGE_SIZE,
                id.semantic_base + 3 * GRANT_PAGE_SIZE
            )
        ]
    );
    let replacement = FrameGrantResidencyIdentity {
        semantic_base: id.semantic_base + GRANT_PAGE_SIZE,
        physical_ipa: 0x600_0000,
        len: GRANT_PAGE_SIZE,
        mapping_id: 101,
        frame_id: 102,
        ..id
    };
    let replacement_slot = table.publish(replacement).unwrap();
    assert_ne!(replacement_slot, slot);
    assert!(table.record_commit(table.lookup(7, replacement.semantic_base).unwrap()));
    assert!(!table.record_commit(old[1]));
    assert_eq!(table.lookup(8, peer.semantic_base).unwrap().slot, peer_slot);
    assert_eq!(
        table
            .stock_record(
                owner(8, 2),
                carrick_guest_arch::UserVa::new(peer.semantic_base)
            )
            .unwrap()
            .retained,
        StockPageMask::ALL
    );
}

#[test]
fn claimed_retirement_cancels_exactly_and_pins_refuse_before_mutation() {
    let table = table();
    let id = chunk();
    let who = owner(7, 1);
    publish_stock(&table, who, id);
    let page = table.lookup(7, id.semantic_base).unwrap();
    assert!(table.record_commit(page));
    let pin = table.pin_transfer(page).unwrap();
    assert!(
        table
            .begin_retire_overlapping(7, id.semantic_base, GRANT_PAGE_SIZE)
            .is_none()
    );
    assert_eq!(
        table
            .stock_record(who, carrick_guest_arch::UserVa::new(id.semantic_base))
            .unwrap()
            .retained,
        StockPageMask::ALL
    );
    drop(pin);
    let claim = table
        .begin_retire_overlapping(7, id.semantic_base, GRANT_PAGE_SIZE)
        .unwrap();
    assert!(table.pin_transfer(page).is_none());
    drop(claim);
    assert!(table.is_guest_committed(7, id.semantic_base));
    assert!(table.pin_transfer(page).is_some());
    assert!(
        table
            .begin_retire_overlapping(7, id.semantic_base, GRANT_PAGE_SIZE)
            .unwrap()
            .commit()
    );
    assert!(table.lookup(7, id.semantic_base).is_none());
    assert!(table.pin_transfer(page).is_none());
    assert_eq!(table.stock_record_count(), 1);
    assert!(
        table
            .begin_retire_overlapping(7, id.semantic_base, id.len)
            .unwrap()
            .commit()
    );
    assert_eq!(table.stock_record_count(), 0);
}

fn many_chunks(
    table: &FrameGrantResidencyTable,
    who: StockResidencyOwner,
    base: u64,
    count: usize,
) {
    for batch in 0..count / STOCK_CHUNKS_PER_REFILL {
        let ids: alloc::vec::Vec<_> = (0..STOCK_CHUNKS_PER_REFILL)
            .map(|index| {
                let va =
                    base + (batch * STOCK_CHUNKS_PER_REFILL + index) as u64 * crate::COW_GRANT_SIZE;
                FrameGrantResidencyIdentity {
                    mm_key: who.mm.raw().get(),
                    semantic_base: va,
                    physical_ipa: 0x4000_0000 + va,
                    mapping_id: va / GRANT_PAGE_SIZE + 1,
                    frame_id: va / GRANT_PAGE_SIZE + 2,
                    ..chunk()
                }
            })
            .collect();
        let requests: alloc::vec::Vec<_> = ids.iter().map(|id| request(id.semantic_base)).collect();
        assert_eq!(
            table
                .reserve_stock(who, &requests)
                .unwrap()
                .publish(who, &ids)
                .unwrap()
                .len(),
            64
        );
    }
}

#[test]
fn pending_and_live_rows_share_mm_and_carrier_quotas_with_room_for_ordinary_grants() {
    let table = table();
    let a = owner(7, 1);
    let b = owner(8, 2);
    let base = 0x200_0000;
    many_chunks(
        &table,
        a,
        base,
        STOCK_CHUNKS_PER_MM - STOCK_CHUNKS_PER_REFILL,
    );
    let requests: alloc::vec::Vec<_> = (0..64)
        .map(|i| request(base + (960 + i) * crate::COW_GRANT_SIZE))
        .collect();
    let pending = table.reserve_stock(a, &requests).unwrap();
    assert_eq!(table.stock_record_count(), 1024);
    assert!(
        table
            .reserve_stock(a, &[request(base + 0x200_0000)])
            .is_none()
    );
    drop(pending);
    assert_eq!(table.stock_record_count(), 960);
    many_chunks(&table, a, requests[0].base.raw(), 64);
    many_chunks(&table, b, base, STOCK_CHUNKS_PER_MM);
    assert_eq!(table.stock_record_count(), STOCK_CHUNKS_PER_CARRIER);
    assert!(table.reserve_stock(owner(9, 3), &[request(base)]).is_none());
    let ordinary = FrameGrantResidencyIdentity {
        mm_key: 9,
        semantic_base: 0x500_0000,
        physical_ipa: 0x600_0000,
        len: GRANT_PAGE_SIZE,
        ..identity()
    };
    assert!(
        table.publish(ordinary).is_some(),
        "stock quota leaves capacity for other consumers"
    );
    assert!(table.retire_overlapping(7, base, 16 * 1024 * 1024));
    assert_eq!(table.stock_record_count(), 1024);
    assert!(table.lookup(8, base).is_some());
    assert!(table.lookup(9, ordinary.semantic_base).is_some());
    assert!(table.retire_overlapping(8, base, 16 * 1024 * 1024));
    assert_eq!(table.stock_record_count(), 0);
}

#[test]
fn concurrent_live_mms_cannot_overclaim_the_shared_stock_quota() {
    let table = table();
    let base = 0x200_0000;
    many_chunks(&table, owner(7, 1), base, 1024);
    many_chunks(&table, owner(8, 2), base, 960);
    let barrier = std::sync::Barrier::new(3);
    std::thread::scope(|scope| {
        let attempt = |who| {
            let requests: alloc::vec::Vec<_> = (0..64)
                .map(|i| request(base + (960 + i) * crate::COW_GRANT_SIZE))
                .collect();
            barrier.wait();
            table.reserve_stock(who, &requests)
        };
        let a = scope.spawn(move || attempt(owner(8, 2)));
        let b = scope.spawn(move || attempt(owner(9, 3)));
        barrier.wait();
        let claims = [a.join().unwrap(), b.join().unwrap()];
        let admitted = claims.iter().filter(|claim| claim.is_some()).count();
        assert!(admitted <= 1);
        assert_eq!(table.stock_record_count(), 1984 + admitted as u64 * 64);
        assert!(table.stock_record_count() <= STOCK_CHUNKS_PER_CARRIER);
        drop(claims);
    });
    assert_eq!(table.stock_record_count(), 1984);
    assert!(table.lookup(7, base).is_some());
    assert!(table.lookup(8, base).is_some());
}

#[test]
fn malformed_or_excessive_refills_claim_nothing() {
    let table = table();
    let who = owner(7, 1);
    let base = chunk().semantic_base;
    assert!(table.reserve_stock(who, &[]).is_none());
    assert!(table.reserve_stock(who, &[request(base); 65]).is_none());
    assert!(
        table
            .reserve_stock(who, &[request(base + GRANT_PAGE_SIZE)])
            .is_none()
    );
    let empty = StockChunkReservation {
        base: carrick_guest_arch::UserVa::new(base),
        retained: StockPageMask::new(0).unwrap(),
    };
    assert!(
        table
            .reserve_stock(who, &[request(base + crate::COW_GRANT_SIZE), empty])
            .is_none()
    );
    assert!(StockPageMask::new(16).is_none());
    assert_eq!(table.stock_record_count(), 0);
    assert!(table.publish(chunk()).is_some());
}

#[test]
fn publication_refusal_returns_claim_custody_until_the_physical_owner_cancels() {
    let table = table();
    let who = owner(7, 1);
    let id = chunk();
    let claim = table
        .reserve_stock(who, &[request(id.semantic_base)])
        .unwrap();
    let retained = claim.publish(owner(7, 2), &[id]).unwrap_err();
    assert_eq!(table.stock_record_count(), 1);
    assert!(
        table.publish(id).is_none(),
        "unknown physical rollback must keep capacity excluded"
    );
    assert!(table.lookup(7, id.semantic_base).is_none());
    drop(retained); // Encompassing owner has now verified physical cancellation.
    assert_eq!(table.stock_record_count(), 0);
    assert!(table.publish(id).is_some());
}

#[test]
fn a_pinned_survivor_does_not_block_retirement_inside_a_masked_hole() {
    let table = table();
    let who = owner(7, 1);
    let id = chunk();
    publish_stock(&table, who, id);
    let hole = id.semantic_base + GRANT_PAGE_SIZE;
    assert!(table.retire_small_span(7, hole, GRANT_PAGE_SIZE));
    let survivor = table.lookup(7, id.semantic_base).unwrap();
    let pin = table.pin_transfer(survivor).unwrap();
    let replacement = FrameGrantResidencyIdentity {
        semantic_base: hole,
        physical_ipa: 0x700_0000,
        len: GRANT_PAGE_SIZE,
        frame_id: 40,
        mapping_id: 41,
        ..id
    };
    assert!(table.publish(replacement).is_some());
    let retirement = table
        .begin_retire_overlapping(7, hole, GRANT_PAGE_SIZE)
        .expect("a stock row's retired hole must not reserve its pinned survivor");
    assert!(retirement.commit());
    assert!(table.lookup(7, hole).is_none());
    assert_eq!(table.lookup(7, id.semantic_base).unwrap().identity, id);
    assert_eq!(
        table
            .stock_record(who, carrick_guest_arch::UserVa::new(id.semantic_base))
            .unwrap()
            .retained
            .bits(),
        0b1101
    );
    drop(pin);
}
