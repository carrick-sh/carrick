use super::*;
use alloc::vec::Vec;
use carrick_guest_arch::FrameGpa;

fn nz(raw: u64) -> NonZeroU64 {
    NonZeroU64::new(raw).unwrap()
}

const RW: EditPermissions = EditPermissions {
    readable: true,
    writable: true,
    executable: false,
    user: true,
};
const RO: EditPermissions = EditPermissions {
    readable: true,
    writable: false,
    executable: false,
    user: true,
};

fn shape(kind: PublicationKind) -> PublicationShape {
    PublicationShape {
        kind,
        outcome: PublicationOutcome::Applied,
        drain: PublicationDrain::ArmBroadcastAsid,
        isa: GuestIsa::Aarch64,
        permissions: RW,
        table_grants: TableGrantCount(1),
    }
}

fn identity(counter: u64) -> PublicationIdentity {
    PublicationIdentity {
        mm: PublicationMm::new(nz(7)),
        incarnation: MmIncarnation::new(nz(3)),
        counter: PublicationCounter::new(nz(counter)),
        edit_sequence: EditSequence::new(nz(counter + 100)),
        root: RootGpa::page_aligned(FrameGpa::new(0x4000_0000)).unwrap(),
    }
}

fn span(start: u64, len: u64) -> UserRange {
    UserRange::checked(UserVa::new(start), GuestLen::new(len)).unwrap()
}

fn output(address: u64, leaf: EditLeafSize, access: ExtentAccess) -> PublishedOutput {
    PublishedOutput {
        address: Stage1Ipa::new(address),
        leaf,
        ticket: TicketId::new(nz(11)),
        owner_generation: OwnerGeneration::new(nz(13)),
        access,
        inventory_revision: InventoryRevision::new(nz(14)),
    }
}

fn prior(address: u64) -> PublishedPrior {
    PublishedPrior {
        address: Stage1Ipa::new(address),
        leaf: EditLeafSize::Page,
        owner_generation: OwnerGeneration::new(nz(5)),
    }
}

fn map_view(counter: u64) -> PublicationView {
    PublicationView::checked(
        shape(PublicationKind::Map),
        identity(counter),
        span(0x40_0000, 0x2000),
        Some(output(
            0x8000_0000,
            EditLeafSize::Page,
            ExtentAccess::Edge(EdgeGeneration::new(nz(9))),
        )),
        None,
    )
    .unwrap()
}

#[test]
fn layout_is_literal() {
    assert_eq!(core::mem::size_of::<MmPublication>(), MmPublication::SIZE);
    // Exhaustive pattern: a new field must update the offset guards.
    let _ = |MmPublication {
                 revision: _,
                 kind: _,
                 outcome: _,
                 drain: _,
                 isa: _,
                 permissions: _,
                 leaves: _,
                 table_grants: _,
                 mm: _,
                 incarnation: _,
                 counter: _,
                 edit_sequence: _,
                 root: _,
                 span_va: _,
                 span_len: _,
                 output: _,
                 prior_output: _,
                 ticket: _,
                 owner_generation: _,
                 prior_owner_generation: _,
                 edge_generation: _,
                 inventory_revision: _,
                 digest: _,
             }: MmPublication| {};
}

#[test]
fn round_trip_preserves_every_domain() {
    let view = map_view(5);
    assert_eq!(MmPublication::encode(&view).decode(), Ok(view));
    let repoint = PublicationView::checked(
        PublicationShape {
            permissions: RO,
            table_grants: TableGrantCount(0),
            ..shape(PublicationKind::CowRepoint)
        },
        identity(6),
        span(0x40_0000, 0x1000),
        Some(output(0x8000_1000, EditLeafSize::Page, ExtentAccess::Owner)),
        Some(prior(0x9000_0000)),
    )
    .unwrap();
    assert_eq!(MmPublication::encode(&repoint).decode(), Ok(repoint));
}

#[test]
fn indeterminate_outcome_is_not_decodable() {
    let mut record = MmPublication::encode(&map_view(5));
    for raw in [0, 4] {
        record.outcome = raw;
        record.digest = digest_words(&record.words());
        assert_eq!(record.decode(), Err(PublicationDecodeError::Outcome));
    }
}

#[test]
fn torn_record_fails_digest() {
    let mut record = MmPublication::encode(&map_view(5));
    record.owner_generation ^= 1;
    assert_eq!(record.decode(), Err(PublicationDecodeError::Digest));
}

#[test]
fn drain_claim_must_match_isa() {
    let x86_asid = PublicationShape {
        isa: GuestIsa::X86_64,
        ..shape(PublicationKind::Unmap)
    };
    assert_eq!(
        PublicationView::checked(
            x86_asid,
            identity(1),
            span(0x40_0000, 0x1000),
            None,
            Some(prior(0x9000_0000)),
        ),
        Err(PublicationDecodeError::Drain)
    );
    let refused_broadcast = PublicationShape {
        outcome: PublicationOutcome::Refused,
        table_grants: TableGrantCount(0),
        ..shape(PublicationKind::Unmap)
    };
    assert_eq!(
        PublicationView::checked(
            refused_broadcast,
            identity(1),
            span(0x40_0000, 0x1000),
            None,
            Some(prior(0x9000_0000)),
        ),
        Err(PublicationDecodeError::Drain)
    );
}

#[test]
fn unmap_requires_prior_and_writable_protect_names_one() {
    let unmap = PublicationShape {
        table_grants: TableGrantCount(0),
        ..shape(PublicationKind::Unmap)
    };
    assert_eq!(
        PublicationView::checked(unmap, identity(1), span(0x40_0000, 0x1000), None, None),
        Err(PublicationDecodeError::Prior)
    );
    let protect = PublicationShape {
        table_grants: TableGrantCount(0),
        ..shape(PublicationKind::Protect)
    };
    assert_eq!(
        PublicationView::checked(protect, identity(1), span(0x40_0000, 0x1000), None, None),
        Err(PublicationDecodeError::Prior)
    );
    let read_only = PublicationShape {
        permissions: RO,
        ..protect
    };
    assert!(
        PublicationView::checked(read_only, identity(1), span(0x40_0000, 0x1000), None, None)
            .is_ok()
    );
    // A prior names exactly one alias covering the span.
    assert_eq!(
        PublicationView::checked(
            protect,
            identity(1),
            span(0x40_0000, 0x2000),
            None,
            Some(prior(0x9000_0000)),
        ),
        Err(PublicationDecodeError::Prior)
    );
}

#[test]
fn block_and_coalesce_need_parent_alignment() {
    let block = |out: u64, start: u64, kind: PublicationKind, len: u64| {
        PublicationView::checked(
            shape(kind),
            identity(1),
            span(start, len),
            Some(output(out, EditLeafSize::Block2M, ExtentAccess::Owner)),
            None,
        )
    };
    let two_m = 2 << 20;
    assert!(block(0x8000_0000, 0x4000_0000, PublicationKind::Map, two_m).is_ok());
    // Contiguous but unaligned output: masking would map the wrong bytes.
    assert_eq!(
        block(0x8000_1000, 0x4000_0000, PublicationKind::Map, two_m),
        Err(PublicationDecodeError::Output)
    );
    assert_eq!(
        block(0x8000_0000, 0x4000_1000, PublicationKind::Coalesce, two_m),
        Err(PublicationDecodeError::Output)
    );
    assert_eq!(
        block(
            0x8000_0000,
            0x4000_0000,
            PublicationKind::Coalesce,
            2 * two_m
        ),
        Err(PublicationDecodeError::Output)
    );
}

#[test]
fn table_grants_only_under_a_ticket() {
    assert_eq!(
        PublicationView::checked(
            shape(PublicationKind::Unmap),
            identity(1),
            span(0x40_0000, 0x1000),
            None,
            Some(prior(0x9000_0000)),
        ),
        Err(PublicationDecodeError::TableGrants)
    );
}

#[test]
fn ring_is_bounded_and_signals_watermark() {
    let mut ring = PublicationRing::<4>::new(3).unwrap();
    let (mut producer, mut consumer) = ring.split();
    let records: [MmPublication; 5] =
        core::array::from_fn(|i| MmPublication::encode(&map_view(i as u64 + 1)));
    assert_eq!(producer.push(&records[0]), Ok(RingPressure::Below));
    assert_eq!(producer.push(&records[1]), Ok(RingPressure::Below));
    assert_eq!(producer.push(&records[2]), Ok(RingPressure::AtWatermark));
    assert_eq!(producer.push(&records[3]), Ok(RingPressure::AtWatermark));
    assert_eq!(producer.push(&records[4]), Err(RingFull));
    assert_eq!(consumer.pop(), Ok(Some(records[0])));
    assert_eq!(producer.push(&records[4]), Ok(RingPressure::AtWatermark));
    let mut drained = Vec::new();
    assert_eq!(consumer.drain_into(&mut drained), Ok(4));
    assert_eq!(drained, records[1..].to_vec());
    assert_eq!(consumer.pop(), Ok(None));
}

#[test]
fn ring_clamps_a_corrupt_head() {
    let mut ring = PublicationRing::<4>::new(2).unwrap();
    let (_, mut consumer) = ring.split();
    consumer.corrupt_head(5);
    assert_eq!(consumer.pop(), Err(RingCorrupt));
}

#[test]
fn ring_rejects_invalid_geometry() {
    assert!(PublicationRing::<4>::new(0).is_none());
    assert!(PublicationRing::<4>::new(5).is_none());
    assert!(PublicationRing::<0>::new(1).is_none());
    assert!(PublicationRing::<3>::new(1).is_none());
}

#[test]
fn drain_is_bounded_by_one_head_snapshot() {
    let mut ring = PublicationRing::<4>::new(4).unwrap();
    let records: [MmPublication; 2] =
        core::array::from_fn(|i| MmPublication::encode(&map_view(i as u64 + 1)));
    let (mut producer, mut consumer) = ring.split();
    for record in &records {
        producer.push(record).unwrap();
    }
    // The producer refills one slot after every pop; the drain still ends
    // after the two records visible at its snapshot.
    let mut drained = Vec::new();
    let mut refills = 0;
    let count = consumer
        .drain_with(&mut drained, |_| {
            // Bounded so the unbounded (old) drain terminates and fails.
            if refills < 8 {
                refills += 1;
                producer.push(&records[0]).unwrap();
            }
        })
        .unwrap();
    assert_eq!((count, refills), (2, 2));
    assert_eq!(drained, records.to_vec());
    assert_eq!(consumer.pop(), Ok(Some(records[0])));
}

#[test]
fn executable_protect_names_a_prior() {
    let protect = PublicationShape {
        permissions: EditPermissions {
            executable: true,
            ..RO
        },
        table_grants: TableGrantCount(0),
        ..shape(PublicationKind::Protect)
    };
    assert_eq!(
        PublicationView::checked(protect, identity(1), span(0x40_0000, 0x1000), None, None),
        Err(PublicationDecodeError::Prior)
    );
}
