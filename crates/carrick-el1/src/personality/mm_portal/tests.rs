use super::test_support::*;
use super::*;
use crate::fault::{NoopCowResolver, NoopPreparedResolver};
use carrick_el1_abi::{
    FrameGrantMailbox, FrameGrantResidencyTable, ReservationProtection, ReservationRange,
};
use carrick_mmu_core::aarch64::descriptor_txn::CallerInvalidatesAsid;
use carrick_sched_core::AddressSpaces;
use core::sync::atomic::Ordering;
#[test]
fn transfer_revalidates_exact_mm_before_copy() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 2, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let tables = Tables::new(ROOT, IPA, 2);
    let maintenance = CallerInvalidatesAsid;
    let words = tables.live(&maintenance);
    let mut transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(VA),
            8192,
            TransferIntent::UserWrite,
            0,
        )
        .unwrap();
    let first = selected(select(&portal, &transfer, &tables));
    portal
        .revalidate(&transfer, first, &words, 0)
        .unwrap()
        .unwrap()
        .complete(&mut transfer)
        .unwrap();
    let second = selected(select(&portal, &transfer, &tables));
    let index = spaces.find(mm.raw()).unwrap();
    {
        let _editor = spaces
            .try_begin_edit(index, mm.raw(), NonZeroU64::new(2).unwrap())
            .unwrap();
        tables.words[1537].store((IPA + 0x20000) | RW, Ordering::Release);
    }
    assert!(
        portal
            .revalidate(&transfer, second, &words, 0)
            .unwrap()
            .is_none()
    );
    assert_eq!(transfer.offset(), 4096);
    assert_eq!(
        selected(select(&portal, &transfer, &tables)).ipa,
        IPA + 0x20000
    );
}

#[test]
fn transfer_fence_bounds_remap_to_one_chunk() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 2, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let tables = Tables::new(ROOT, IPA, 2);
    let maintenance = CallerInvalidatesAsid;
    let words = tables.live(&maintenance);
    let mut transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(VA),
            8192,
            TransferIntent::UserWrite,
            0,
        )
        .unwrap();
    let chunk = selected(select(&portal, &transfer, &tables));
    let fence = portal
        .revalidate(&transfer, chunk, &words, 0)
        .unwrap()
        .unwrap();
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                assert!(
                    spaces
                        .try_begin_edit(
                            spaces.find(mm.raw()).unwrap(),
                            mm.raw(),
                            NonZeroU64::new(2).unwrap()
                        )
                        .is_none()
                )
            })
            .join()
            .unwrap();
    });
    assert_eq!(fence.selected().len, 4096); // Copy occurs before remap can acquire.
    fence.complete(&mut transfer).unwrap();
    let _editor = spaces
        .try_begin_edit(
            spaces.find(mm.raw()).unwrap(),
            mm.raw(),
            NonZeroU64::new(2).unwrap(),
        )
        .unwrap();
    assert_eq!(transfer.offset(), 4096);
}

#[test]
fn stopped_target_uses_open_mm_without_el0_entry() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let tables = Tables::new(ROOT, IPA, 1);
    let transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(VA),
            4096,
            TransferIntent::UserRead,
            0,
        )
        .unwrap();
    assert_eq!(selected(select(&portal, &transfer, &tables)).ipa, IPA);
}

#[test]
fn closed_target_gate_suspends_owned_position() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let tables = Tables::new(ROOT, IPA, 1);
    let transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(VA),
            4096,
            TransferIntent::UserRead,
            0,
        )
        .unwrap();
    let index = spaces.find(mm.raw()).unwrap();
    spaces.close(index);
    assert_eq!(select(&portal, &transfer, &tables), TransferStep::Suspended);
    assert_eq!(transfer.offset(), 0);
    spaces.open(index);
    assert!(matches!(
        select(&portal, &transfer, &tables),
        TransferStep::Selected(_)
    ));
}

#[test]
fn stopped_lazy_transfer_reuses_fault_grant_mailbox() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let tables = Tables::new(ROOT, IPA, 1);
    tables.words[1536].store(0, Ordering::Release);
    let transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(VA),
            4096,
            TransferIntent::UserRead,
            0,
        )
        .unwrap();
    let mailbox = FrameGrantMailbox::new();
    let maintenance = CallerInvalidatesAsid;
    assert!(matches!(
        portal
            .select(
                &transfer,
                &tables.live(&maintenance),
                &mut NoopPreparedResolver,
                &mut NoopCowResolver,
                &residency(),
                &mailbox,
                0
            )
            .unwrap(),
        TransferStep::Supply(_)
    ));
    assert_eq!(transfer.offset(), 0);
    // Simulate the existing host supply publishing the leaf, not a second allocator.
    tables.words[1536].store(IPA | RW, Ordering::Release);
    assert_eq!(selected(select(&portal, &transfer, &tables)).ipa, IPA);
}

#[test]
fn internal_reads_cannot_name_arbitrary_user_windows() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let handle = portal.admitted_handle(mm, 0).unwrap();
    let tables = Tables::new(ROOT, IPA, 1);
    let maintenance = CallerInvalidatesAsid;
    let transfer = portal
        .begin(
            handle,
            GuestVa::new(VA),
            1,
            TransferIntent::CarrickInternalRead,
            0,
        )
        .unwrap();
    assert!(matches!(
        portal.select(
            &transfer,
            &tables.live(&maintenance),
            &mut NoopPreparedResolver,
            &mut NoopCowResolver,
            &residency(),
            &FrameGrantMailbox::new(),
            0
        ),
        Err(MmError::Fault)
    ));
}

#[test]
fn owner_allocates_distinct_transfer_sequences() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let handle = portal.admitted_handle(mm, 0).unwrap();
    let tables = Tables::new(ROOT, IPA, 1);
    let a = portal
        .begin(handle, GuestVa::new(VA), 1, TransferIntent::UserRead, 0)
        .unwrap();
    let b = portal
        .begin(handle, GuestVa::new(VA), 1, TransferIntent::UserRead, 0)
        .unwrap();
    assert_ne!(
        selected(select(&portal, &a, &tables)),
        selected(select(&portal, &b, &tables))
    );
}

#[test]
fn kernel_only_leaf_does_not_trigger_anonymous_supply() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let tables = Tables::new(ROOT, IPA, 1);
    tables.words[1536].store(IPA | 3 | (1 << 10), Ordering::Release);
    let transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(VA),
            1,
            TransferIntent::UserRead,
            0,
        )
        .unwrap();
    let maintenance = CallerInvalidatesAsid;
    assert!(matches!(
        portal.select(
            &transfer,
            &tables.live(&maintenance),
            &mut NoopPreparedResolver,
            &mut NoopCowResolver,
            &residency(),
            &FrameGrantMailbox::new(),
            0
        ),
        Err(MmError::Fault)
    ));
}

fn retained() -> carrick_el1_abi::PortalRetainedData {
    carrick_el1_abi::PortalRetainedData {
        record: NonZeroU64::new(7).unwrap(),
        vm_generation: NonZeroU64::new(9).unwrap(),
        owner: Some((NonZeroU64::new(12).unwrap(), NonZeroU64::new(13).unwrap())),
    }
}

#[test]
fn service_copies_real_bytes_under_editor_and_refuses_remapped_selection() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 2, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let tables = Tables::new(ROOT, IPA, 2);
    let maintenance = CallerInvalidatesAsid;
    let words = tables.live(&maintenance);
    let mut transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(VA),
            8192,
            TransferIntent::UserWrite,
            0,
        )
        .unwrap();
    let first = selected(select(&portal, &transfer, &tables));
    let slot = carrick_el1_abi::PortalTransferSlot::new();
    let mut ticket = slot
        .submit(
            first
                .request(TransferIntent::UserWrite, retained())
                .unwrap(),
        )
        .unwrap();
    let mut old = vec![0u8; 8192];
    let index = spaces.find(mm.raw()).unwrap();
    serve_transfer(&portal, slot.claim().unwrap(), &words, 0, || {
        assert!(region.table().el1_slot_holding(0).is_none());
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    assert!(
                        spaces
                            .try_begin_edit(index, mm.raw(), NonZeroU64::new(2).unwrap())
                            .is_none()
                    );
                })
                .join()
                .unwrap()
        });
        assert!(ticket.copy_requested(|authorization| {
            assert_eq!(authorization.request().retained, retained());
            old[..4096].copy_from_slice(&vec![0x37; 4096]);
            true
        }));
    })
    .unwrap();
    let receipt = ticket.take_completion().unwrap();
    assert_eq!(receipt.completed, 4096);
    assert!(old[..4096].iter().all(|byte| *byte == 0x37));
    assert!(old[4096..].iter().all(|byte| *byte == 0));
    // The host continuation advances only after the exact completion receipt.
    transfer
        .settle(
            first
                .request(TransferIntent::UserWrite, retained())
                .unwrap(),
            receipt,
        )
        .unwrap();
    let second = selected(select(&portal, &transfer, &tables));
    let mut stale = slot
        .submit(
            second
                .request(TransferIntent::UserWrite, retained())
                .unwrap(),
        )
        .unwrap();
    {
        let _editor = spaces
            .try_begin_edit(index, mm.raw(), NonZeroU64::new(2).unwrap())
            .unwrap();
        tables.words[1537].store((IPA + 0x20000) | RW, Ordering::Release);
    }
    serve_transfer(&portal, slot.claim().unwrap(), &words, 0, || {
        panic!("stale selection copied")
    })
    .unwrap();
    assert_eq!(stale.take_completion().unwrap().errno, 11);
    assert!(old[4096..].iter().all(|byte| *byte == 0));
    assert_eq!(transfer.offset(), 4096);
    let next = selected(select(&portal, &transfer, &tables));
    let mut next_ticket = slot
        .submit(next.request(TransferIntent::UserWrite, retained()).unwrap())
        .unwrap();
    let mut replacement = [0; 4096];
    serve_transfer(&portal, slot.claim().unwrap(), &words, 0, || {
        assert!(next_ticket.copy_requested(|_| {
            replacement.fill(0x72);
            true
        }));
    })
    .unwrap();
    assert_eq!(next_ticket.take_completion().unwrap().completed, 4096);
    assert_eq!(replacement, [0x72; 4096]);
    assert!(old[4096..].iter().all(|byte| *byte == 0));
}

#[test]
fn service_cancellation_resumes_and_releases_exact_editor() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let tables = Tables::new(ROOT, IPA, 1);
    let maintenance = CallerInvalidatesAsid;
    let transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(VA),
            1,
            TransferIntent::UserWrite,
            0,
        )
        .unwrap();
    let request = selected(select(&portal, &transfer, &tables))
        .request(TransferIntent::UserWrite, retained())
        .unwrap();
    let slot = carrick_el1_abi::PortalTransferSlot::new();
    let mut ticket = slot.submit(request).unwrap();
    serve_transfer(
        &portal,
        slot.claim().unwrap(),
        &tables.live(&maintenance),
        0,
        || {
            assert!(ticket.copy_requested(|_| false));
        },
    )
    .unwrap();
    let receipt = ticket.take_completion().unwrap();
    assert_eq!((receipt.completed, receipt.errno), (0, 125));
    assert!(
        spaces
            .try_begin_edit(
                spaces.find(mm.raw()).unwrap(),
                mm.raw(),
                NonZeroU64::new(2).unwrap()
            )
            .is_some()
    );
}

#[test]
fn internal_read_accepts_only_actual_immutable_image_header() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let base = carrick_el1_abi::EL1_REGION_BASE + carrick_el1_abi::EL1_IMAGE_OFFSET;
    let tables = Tables::new(ROOT, IPA, 0);
    tables.words[((base >> 39) & 511) as usize].store((ROOT + 4096) | 3, Ordering::Relaxed);
    tables.words[512 + ((base >> 30) & 511) as usize].store((ROOT + 8192) | 3, Ordering::Relaxed);
    tables.words[1024 + ((base >> 21) & 511) as usize].store((ROOT + 12288) | 3, Ordering::Relaxed);
    tables.words[1536 + ((base >> 12) & 511) as usize]
        .store(IPA | 3 | (1 << 10) | (1 << 7), Ordering::Relaxed);
    let transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(base + 4),
            4,
            TransferIntent::CarrickInternalRead,
            0,
        )
        .unwrap();
    let chunk = selected(select(&portal, &transfer, &tables));
    assert_eq!(chunk.ipa, IPA + 4);
    let slot = carrick_el1_abi::PortalTransferSlot::new();
    let mut ticket = slot
        .submit(
            chunk
                .request(TransferIntent::CarrickInternalRead, retained())
                .unwrap(),
        )
        .unwrap();
    let maintenance = CallerInvalidatesAsid;
    let mut image_header = [0u8; 32];
    image_header[..4].copy_from_slice(&carrick_el1_abi::IMAGE_MAGIC);
    image_header[4..8].copy_from_slice(&carrick_el1_abi::IMAGE_VERSION.to_le_bytes());
    assert_eq!(
        carrick_el1_abi::ImageHeader::read_from_prefix(&image_header)
            .unwrap()
            .version,
        carrick_el1_abi::IMAGE_VERSION
    );
    let mut result = [0; 4];
    serve_transfer(
        &portal,
        slot.claim().unwrap(),
        &tables.live(&maintenance),
        0,
        || {
            assert!(ticket.copy_requested(|_| {
                result.copy_from_slice(&image_header[4..8]);
                true
            }));
        },
    )
    .unwrap();
    assert_eq!(ticket.take_completion().unwrap().errno, 0);
    assert_eq!(result, carrick_el1_abi::IMAGE_VERSION.to_le_bytes());
}

#[test]
fn stopped_target_untouched_transfer_prepares_only_exact_owner_window() {
    use carrick_mmu_core::aarch64::descriptor_txn::{
        BackingIdentity, DescriptorOp, DescriptorOutcome, DescriptorTxn, DescriptorTxnId, PageSpan,
        TableGrants,
    };
    use carrick_mmu_core::aarch64::{GuestLeafPublication, SubstrateGpa};
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 16, 0);
    let other = admit(&region, &spaces, 78, ROOT + 0x100000, 16, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let tables = Tables::new(ROOT, IPA, 0);
    let maintenance = CallerInvalidatesAsid;
    let words = tables.live(&maintenance);
    let residency = residency();
    let mailbox = FrameGrantMailbox::new();
    let transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(VA + 7),
            4,
            TransferIntent::UserWrite,
            0,
        )
        .unwrap();
    let TransferStep::Supply(window) = portal
        .select(
            &transfer,
            &words,
            &mut NoopPreparedResolver,
            &mut NoopCowResolver,
            &residency,
            &mailbox,
            0,
        )
        .unwrap()
    else {
        panic!("missing lazy owner receipt");
    };
    assert_eq!(window.operation.mm, mm);
    assert_ne!(window.operation.mm, other);
    assert_eq!(transfer.offset(), 0);
    let nz = |n| NonZeroU64::new(n).unwrap();
    let txn = DescriptorTxn {
        id: DescriptorTxnId {
            mm_key: nz(mm.raw()),
            generation: nz(1),
        },
        root: SubstrateGpa(ROOT),
        op: DescriptorOp::Prepare {
            publication: GuestLeafPublication {
                va: window.range.start(),
                ipa: IPA,
                len: window.range.len(),
                writable: true,
                executable: false,
            },
            resident: PageSpan::new(VA, 4096),
            backing: BackingIdentity {
                frame_id: nz(2),
                mapping_id: nz(3),
                owner_generation: nz(4),
                inventory_revision: nz(5),
            },
        },
        tables: TableGrants::new(&[]).unwrap(),
    };
    let slot = carrick_el1_abi::PortalGrantSlot::new();
    assert!(slot.submit(window, &txn));
    let receipt = serve_grant(&portal, &slot, &words, &residency, 0, || {}).unwrap();
    assert!(
        matches!(receipt.outcome, DescriptorOutcome::Applied(_)),
        "{receipt:?}"
    );
    assert!(slot.take_receipt(window, &txn).is_some());
    assert_eq!(transfer.offset(), 0);
    let chunk = selected(
        portal
            .select(
                &transfer,
                &words,
                &mut NoopPreparedResolver,
                &mut NoopCowResolver,
                &residency,
                &mailbox,
                0,
            )
            .unwrap(),
    );
    assert_eq!(chunk.ipa, IPA + 7);
    assert_eq!(chunk.len, 4);
    let request = chunk
        .request(TransferIntent::UserWrite, retained())
        .unwrap();
    let copy = carrick_el1_abi::PortalTransferSlot::new();
    let mut ticket = copy.submit(request).unwrap();
    let mut bytes = [0; 4096];
    serve_transfer(&portal, copy.claim().unwrap(), &words, 0, || {
        assert!(ticket.copy_requested(|_| {
            bytes[7..11].copy_from_slice(b"lazy");
            true
        }));
    })
    .unwrap();
    assert_eq!(ticket.take_completion().unwrap().completed, 4);
    assert_eq!(&bytes[7..11], b"lazy");
    // A fresh receipt cannot replace an already committed predecessor.
    assert!(slot.submit(window, &txn));
    let refused = serve_grant(&portal, &slot, &words, &residency, 0, || {}).unwrap();
    assert!(matches!(refused.outcome, DescriptorOutcome::Refused(_)));
}

#[test]
fn partial_retired_compound_replacement_preserves_live_neighbor() {
    use carrick_mmu_core::aarch64::descriptor_txn::{
        BackingIdentity, DescriptorOp, DescriptorOutcome, DescriptorTxn, DescriptorTxnId, PageSpan,
        TableGrants,
    };
    use carrick_mmu_core::aarch64::{GuestLeafPublication, SubstrateGpa};
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 2, 0);
    let other = admit(&region, &spaces, 78, ROOT + 0x100000, 16, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let tables = Tables::new(ROOT, IPA, 2);
    // Both pages start in the same dirty physical compound. Retire just the
    // first leaf through the production executor, then complete the matching
    // reservation unmap and fresh anonymous remap receipts.
    for page in 0..2 {
        tables.words[1536 + page].fetch_or(1 << 56 | 1 << 57, Ordering::Relaxed);
    }
    let old_neighbor = tables.words[1537].load(Ordering::Relaxed);
    let old_bytes = [0x5a; 16384];
    let mut fresh_bytes = [0; 16384];
    let maintenance = CallerInvalidatesAsid;
    let words = tables.live(&maintenance);
    let retired = carrick_mmu_core::aarch64::descriptor_txn::execute_descriptor_txn(
        &words,
        SubstrateGpa(ROOT),
        &DescriptorTxn {
            id: DescriptorTxnId {
                mm_key: NonZeroU64::new(mm.raw()).unwrap(),
                generation: NonZeroU64::new(1).unwrap(),
            },
            root: SubstrateGpa(ROOT),
            op: DescriptorOp::Retire(PageSpan::new(VA, 4096)),
            tables: TableGrants::new(&[]).unwrap(),
        },
        &mut carrick_mmu_core::aarch64::descriptor_txn::InlineJournal::new(),
    );
    assert!(matches!(retired.outcome, DescriptorOutcome::Applied(_)));
    {
        use crate::memory::reservations::{Decision, Placement};
        let mut owner = region
            .table()
            .lock_el1_resolved(spaces.find(mm.raw()).unwrap().index(), mm, &view, 0)
            .unwrap();
        for remap in [false, true] {
            let decision = if remap {
                owner
                    .mmap(
                        Placement::Fixed(VA),
                        4096,
                        ReservationProtection::READ_WRITE,
                    )
                    .unwrap()
            } else {
                owner
                    .munmap(ReservationRange::new(VA, VA + 4096).unwrap())
                    .unwrap()
            };
            let Decision::Work(request) = decision else {
                panic!()
            };
            let receipt = unsafe {
                carrick_el1_abi::ReservationCompletion::after_descriptor_and_backing_commit(
                    request,
                    carrick_el1_abi::ReservationBackingReceipt {
                        receipt: request.sequence.raw(),
                        granted_bytes: 0,
                        returned_bytes: 0,
                    },
                )
            }
            .unwrap();
            owner.complete(receipt).unwrap();
        }
    }
    let residency = residency();
    let mailbox = FrameGrantMailbox::new();
    let transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(VA + 7),
            4,
            TransferIntent::UserWrite,
            0,
        )
        .unwrap();
    let TransferStep::Supply(window) = portal
        .select(
            &transfer,
            &words,
            &mut NoopPreparedResolver,
            &mut NoopCowResolver,
            &residency,
            &mailbox,
            0,
        )
        .unwrap()
    else {
        panic!("missing lazy owner receipt");
    };
    assert_eq!(window.operation.mm, mm);
    assert_ne!(window.operation.mm, other);
    assert_eq!(transfer.offset(), 0);
    let nz = |n| NonZeroU64::new(n).unwrap();
    let txn = DescriptorTxn {
        id: DescriptorTxnId {
            mm_key: nz(mm.raw()),
            generation: nz(1),
        },
        root: SubstrateGpa(ROOT),
        op: DescriptorOp::Prepare {
            publication: GuestLeafPublication {
                va: window.range.start(),
                ipa: IPA + 0x10000,
                len: window.range.len(),
                writable: true,
                executable: false,
            },
            resident: PageSpan::new(VA, 4096),
            backing: BackingIdentity {
                frame_id: nz(2),
                mapping_id: nz(3),
                owner_generation: nz(4),
                inventory_revision: nz(5),
            },
        },
        tables: TableGrants::new(&[]).unwrap(),
    };
    let slot = carrick_el1_abi::PortalGrantSlot::new();
    assert!(slot.submit(window, &txn));
    let receipt = serve_grant(&portal, &slot, &words, &residency, 0, || {}).unwrap();
    assert!(
        matches!(receipt.outcome, DescriptorOutcome::Applied(_)),
        "{receipt:?}"
    );
    assert!(slot.take_receipt(window, &txn).is_some());
    assert_eq!(transfer.offset(), 0);
    let chunk = selected(
        portal
            .select(
                &transfer,
                &words,
                &mut NoopPreparedResolver,
                &mut NoopCowResolver,
                &residency,
                &mailbox,
                0,
            )
            .unwrap(),
    );
    assert_eq!(chunk.ipa, IPA + 0x10000 + 7);
    assert_eq!(chunk.len, 4);
    let request = chunk
        .request(TransferIntent::UserWrite, retained())
        .unwrap();
    let copy = carrick_el1_abi::PortalTransferSlot::new();
    let mut ticket = copy.submit(request).unwrap();
    assert_eq!(fresh_bytes, [0; 16384]);
    serve_transfer(&portal, copy.claim().unwrap(), &words, 0, || {
        assert!(ticket.copy_requested(|_| {
            fresh_bytes[7..11].copy_from_slice(b"lazy");
            true
        }));
    })
    .unwrap();
    assert_eq!(ticket.take_completion().unwrap().completed, 4);
    assert_eq!(&fresh_bytes[7..11], b"lazy");
    assert_eq!(tables.words[1537].load(Ordering::Acquire), old_neighbor);
    assert_eq!(&old_bytes[4096..8192], &[0x5a; 4096]);
    assert!(
        fresh_bytes[..7]
            .iter()
            .chain(&fresh_bytes[11..4096])
            .all(|byte| *byte == 0)
    );
    // A fresh receipt cannot replace an already committed predecessor.
    assert!(slot.submit(window, &txn));
    let refused = serve_grant(&portal, &slot, &words, &residency, 0, || {}).unwrap();
    assert!(matches!(refused.outcome, DescriptorOutcome::Refused(_)));
}

#[test]
fn kernel_only_write_denial_is_a_fault_without_supply() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let tables = Tables::new(ROOT, IPA, 1);
    tables.words[1536].store(IPA | 3 | (1 << 10) | (1 << 7), Ordering::Release);
    let transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(VA),
            4,
            TransferIntent::UserWrite,
            0,
        )
        .unwrap();
    let mailbox = FrameGrantMailbox::new();
    let result = portal.select(
        &transfer,
        &tables.live(&CallerInvalidatesAsid),
        &mut NoopPreparedResolver,
        &mut NoopCowResolver,
        &residency(),
        &mailbox,
        0,
    );
    assert!(matches!(result, Err(MmError::Fault)), "{result:?}");
    assert!(mailbox.claim_request().is_none());
}

#[test]
fn cow_without_publication_capability_refuses_exec_and_instruction_reads_work() {
    use crate::memory::reservations::Decision;
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    {
        let mut owner = region
            .table()
            .lock_el1_resolved(spaces.find(mm.raw()).unwrap().index(), mm, &view, 0)
            .unwrap();
        let Decision::Work(request) = owner
            .mprotect(
                ReservationRange::new(VA, VA + 4096).unwrap(),
                ReservationProtection::from_bits(7).unwrap(),
            )
            .unwrap()
        else {
            panic!()
        };
        let receipt = unsafe {
            carrick_el1_abi::ReservationCompletion::after_descriptor_and_backing_commit(
                request,
                carrick_el1_abi::ReservationBackingReceipt {
                    receipt: request.sequence.raw(),
                    granted_bytes: 0,
                    returned_bytes: 0,
                },
            )
        }
        .unwrap();
        owner.complete(receipt).unwrap();
    }
    let tables = Tables::new(ROOT, IPA, 1);
    // COW armed, private, writable ceiling, user-readable and executable.
    let rule = carrick_mmu_core::aarch64::TerminalRule::Pt {
        op: Some(carrick_mmu_core::aarch64::PtOp::ReadWrite { exec: true }),
        reset_retired: false,
        deny_host_buffers: false,
        fork_arm: true,
        adopt_private: true,
    };
    let words = tables.live(&CallerInvalidatesAsid);
    use carrick_mmu_core::aarch64::descriptor_txn::{
        DescriptorOp, DescriptorOutcome, InlineJournal, PageSpan, TableGrants, TerminalEdit,
        execute_descriptor_op,
    };
    let outcome = execute_descriptor_op(
        &words,
        carrick_mmu_core::aarch64::SubstrateGpa(ROOT),
        DescriptorOp::Terminal {
            span: PageSpan::new(VA, 4096),
            edit: TerminalEdit {
                rule,
                asid_scoped: true,
                excluded_ipa: 0,
                excluded_len: 0,
                reclaim_budget: 0,
            },
        },
        &TableGrants::new(&[]).unwrap(),
        &mut InlineJournal::new(),
    );
    assert!(matches!(outcome, DescriptorOutcome::Applied(_)));
    let write = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(VA),
            4,
            TransferIntent::UserWrite,
            0,
        )
        .unwrap();
    let mailbox = FrameGrantMailbox::new();
    assert_eq!(
        portal.select(
            &write,
            &tables.live(&CallerInvalidatesAsid),
            &mut NoopPreparedResolver,
            &mut NoopCowResolver,
            &residency(),
            &mailbox,
            0
        ),
        Err(MmError::UnsupportedExecutableCow)
    );
    assert_eq!(MmError::UnsupportedExecutableCow.errno(), 95);
    assert!(mailbox.claim_request().is_none());
    let instruction = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(VA),
            4,
            TransferIntent::ReadInstruction,
            0,
        )
        .unwrap();
    assert_eq!(selected(select(&portal, &instruction, &tables)).ipa, IPA);
    tables.words[1536].store(0, Ordering::Release);
    assert!(matches!(
        portal
            .select(
                &instruction,
                &tables.live(&CallerInvalidatesAsid),
                &mut NoopPreparedResolver,
                &mut NoopCowResolver,
                &residency(),
                &mailbox,
                0
            )
            .unwrap(),
        TransferStep::Supply(_)
    ));
    let request = mailbox.claim_request().unwrap();
    assert_eq!(request.access, 4);
}

#[test]
fn imported_private_empty_cow_pool_returns_owned_exact_target_supply() {
    struct EmptyCow<'a>(
        &'a Tables,
        &'a carrick_el1_abi::CowGrantPool,
        &'a FrameGrantResidencyTable,
    );
    impl crate::fault::CowResolver for EmptyCow<'_> {
        fn resolve_cow(&mut self, _: u64, _: u64, _: u64) -> bool {
            panic!("typed outcome required")
        }
        fn resolve_cow_outcome(
            &mut self,
            ttbr: u64,
            mm: u64,
            va: u64,
        ) -> crate::fault::CowResolution {
            let result = crate::cow::resolve_guest_cow(
                &crate::cow::GuestCowVenue {
                    words: &self.0.live(&CallerInvalidatesAsid),
                    root: carrick_mmu_core::aarch64::SubstrateGpa(ttbr),
                    pool: self.1,
                    residency: self.2,
                    copy_base: carrick_el1_abi::EL1_COW_COPY_BASE,
                    publish_executable: None,
                },
                mm,
                va,
                |_, _| panic!("empty pool must not copy"),
                || {},
            );
            assert_eq!(
                result,
                crate::cow::GuestCowOutcome::Declined(carrick_el1_abi::CowDecline::PoolEmpty)
            );
            crate::fault::CowResolution::NeedsSupply
        }
    }
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit_kind(&region, &spaces, 77, ROOT, 1, 0, false);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let tables = Tables::new(ROOT, IPA, 1);
    tables.words[1536].store(
        IPA | RW | (3 << 6) | (1 << 55) | (1 << 56) | (1 << 57),
        Ordering::Release,
    );
    let transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(VA),
            4,
            TransferIntent::UserWrite,
            0,
        )
        .unwrap();
    let pool = carrick_el1_abi::CowGrantPool::new();
    let resident = residency();
    let mailbox = FrameGrantMailbox::new();
    let TransferStep::CowSupply(window) = portal
        .select(
            &transfer,
            &tables.live(&CallerInvalidatesAsid),
            &mut NoopPreparedResolver,
            &mut EmptyCow(&tables, &pool, &resident),
            &resident,
            &mailbox,
            0,
        )
        .unwrap()
    else {
        panic!("owned COW supply required")
    };
    assert_eq!(window.operation.mm, mm);
    assert_eq!(window.range.len(), 4096);
    assert_eq!(transfer.offset(), 0);
    assert!(
        mailbox.claim_request().is_none(),
        "private file COW never asks anonymous zero supply"
    );
    assert!(
        spaces
            .try_begin_edit(
                spaces.find(mm.raw()).unwrap(),
                mm.raw(),
                NonZeroU64::new(2).unwrap()
            )
            .is_some()
    );
}

#[test]
fn reservation_policy_readonly_none_and_retire_refuse_exact_mm() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let a = admit(&region, &spaces, 77, ROOT, 1, 0);
    let b = admit(&region, &spaces, 78, ROOT + 0x100_000, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let a_tables = Tables::new(ROOT, IPA, 1);
    let b_tables = Tables::new(ROOT + 0x100_000, IPA + 0x100_000, 1);
    for protection in [
        Some(ReservationProtection::from_bits(1).unwrap()),
        Some(ReservationProtection::from_bits(0).unwrap()),
        None,
    ] {
        change_policy(&region, &spaces, a, &a_tables, protection);
        for intent in [TransferIntent::UserRead, TransferIntent::UserWrite] {
            for (mm, tables) in [(a, &a_tables), (b, &b_tables)] {
                let transfer = portal
                    .begin(
                        portal.admitted_handle(mm, 0).unwrap(),
                        GuestVa::new(VA),
                        4,
                        intent,
                        0,
                    )
                    .unwrap();
                let mailbox = FrameGrantMailbox::new();
                let result = portal.select(
                    &transfer,
                    &tables.live(&CallerInvalidatesAsid),
                    &mut NoopPreparedResolver,
                    &mut NoopCowResolver,
                    &residency(),
                    &mailbox,
                    0,
                );
                let allowed = mm == b
                    || (intent == TransferIntent::UserRead
                        && protection.is_some_and(|p| p.bits() == 1));
                if allowed {
                    assert!(matches!(result, Ok(TransferStep::Selected(_))));
                } else {
                    assert_eq!(result.unwrap_err().errno(), 14);
                }
                assert!(mailbox.claim_request().is_none());
            }
        }
    }
}
