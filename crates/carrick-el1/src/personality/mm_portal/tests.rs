use super::test_support::*;
use super::*;
use crate::fault::{NoopCowResolver, NoopPreparedResolver};
use carrick_el1_abi::{
    FrameGrantMailbox, FrameGrantResidencyTable, ReservationNodeFlags, ReservationProtection,
    ReservationRange,
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
fn owner_lazy_selection_keeps_supply_owned_when_fault_mailbox_is_occupied() {
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
    assert!(crate::fault::request_lazy_frames(&mailbox, 99, VA, 1));
    let result = portal
        .select(
            &transfer,
            &tables.live(&CallerInvalidatesAsid),
            &mut NoopPreparedResolver,
            &mut NoopCowResolver,
            &residency(),
            0,
        )
        .unwrap();
    assert!(
        matches!(result, TransferStep::Supply(window) if window.operation.mm == mm),
        "owner selection must retain its supply receipt independently of fault transport occupancy"
    );
    assert_eq!(mailbox.claim_request().unwrap().mm_key, 99);
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
    let maintenance = CallerInvalidatesAsid;
    assert!(matches!(
        portal
            .select(
                &transfer,
                &tables.live(&maintenance),
                &mut NoopPreparedResolver,
                &mut NoopCowResolver,
                &residency(),
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
fn internal_read_selects_identity_control_from_exact_live_mm() {
    // Frozen host-buffer failure: identity shim-enabled word, not image header.
    let address = 0x2d_001e_4004;
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let tables = Tables::new(ROOT, IPA, 0);
    tables.words[512 + 1].store(0, Ordering::Relaxed);
    tables.words[512 + ((address >> 30) & 511) as usize]
        .store((ROOT + 8192) | 3, Ordering::Relaxed);
    tables.words[1024 + ((address >> 21) & 511) as usize]
        .store((ROOT + 12288) | 3, Ordering::Relaxed);
    tables.words[1536 + ((address >> 12) & 511) as usize]
        .store(IPA | (RW & !(1 << 6)), Ordering::Relaxed);
    let transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(address),
            4,
            TransferIntent::CarrickInternalRead,
            0,
        )
        .unwrap();
    let chunk = selected(select(&portal, &transfer, &tables));
    assert_eq!(chunk.ipa, IPA + 4);
    assert_eq!(chunk.len, 4);
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
    for (address, len) in [
        (VA, 1),
        (carrick_el1_abi::CARRICK_IDENTITY_PAGE_BASE - 1, 2),
        (
            carrick_el1_abi::CARRICK_IDENTITY_PAGE_BASE
                + carrick_el1_abi::CARRICK_IDENTITY_PAGE_SIZE
                - 1,
            2,
        ),
        (carrick_el1_abi::EL1_REGION_BASE + 4095, 2),
    ] {
        let transfer = portal
            .begin(
                handle,
                GuestVa::new(address),
                len,
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
                0
            ),
            Err(MmError::Fault)
        ));
    }
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
fn service_copies_real_bytes_under_permit_and_refuses_remapped_selection() {
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
                            .is_some()
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
    assert_eq!(
        stale.take_prepare_suspension(),
        Some(carrick_el1_abi::PortalPrepareSuspension::SelectionChanged)
    );
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
    let result = portal.select(
        &transfer,
        &tables.live(&CallerInvalidatesAsid),
        &mut NoopPreparedResolver,
        &mut NoopCowResolver,
        &residency(),
        0,
    );
    assert!(matches!(result, Err(MmError::Fault)), "{result:?}");
}

#[test]
fn untouched_private_file_selects_only_owner_retained_source() {
    use crate::memory::reservations::Layout;
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = ReservationMm::new(77).unwrap();
    let index = spaces.publish_closed(mm.raw(), ROOT, ROOT).unwrap();
    region
        .table()
        .publish(
            index.index(),
            mm,
            Layout {
                heap: ReservationRange::new(4096, VA).unwrap(),
                arena: ReservationRange::new(VA, VA + 0x1000_0000).unwrap(),
                brk: 4096,
                address_limit: u64::MAX,
                data_limit: u64::MAX,
                external_address_bytes: 0,
                external_data_bytes: 0,
            },
        )
        .unwrap();
    let view = nodes(&region);
    let source = carrick_el1_abi::HostBackingIdentity::new(
        NonZeroU64::new(71).unwrap(),
        NonZeroU64::new(4).unwrap(),
        8192,
    );
    let mut root = region
        .table()
        .lock_el1_resolved(index.index(), mm, &view, 0)
        .unwrap();
    root.import_with_backing(
        ReservationRange::new(VA, VA + 8192).unwrap(),
        ReservationProtection::READ_WRITE,
        carrick_el1_abi::ReservationNodeFlags::PRIVATE,
        source,
    )
    .unwrap();
    root.finish_import().unwrap();
    drop(root);
    spaces.open(index);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(VA + 4096),
            4,
            TransferIntent::UserRead,
            0,
        )
        .unwrap();
    let tables = Tables::new(ROOT, IPA, 0);
    let TransferStep::Supply(window) = select(&portal, &transfer, &tables) else {
        panic!("no retained file supply")
    };
    assert_eq!(window.host_backing, source.advance(4096));
    assert_eq!(
        window.range,
        ReservationRange::new(VA + 4096, VA + 8192).unwrap()
    );
    let mut root = region
        .table()
        .lock_el1_resolved(index.index(), mm, &view, 0)
        .unwrap();
    let plan = crate::memory::reservations::ReservationFaultPlan {
        mm,
        generation: window.generation,
        range: window.range,
        protection: window.protection,
        fault_page: window.fault_page,
    };
    assert!(root.authenticate_transfer_fault(plan, window.host_backing));
    let wrong = carrick_el1_abi::HostBackingIdentity::new(
        source.handle(),
        NonZeroU64::new(5).unwrap(),
        source.offset(),
    );
    assert!(!root.authenticate_transfer_fault(plan, Some(wrong)));
    assert!(!root.authenticate_transfer_fault(plan, None));
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
    assert_eq!(
        portal.select(
            &write,
            &tables.live(&CallerInvalidatesAsid),
            &mut NoopPreparedResolver,
            &mut NoopCowResolver,
            &residency(),
            0
        ),
        Err(MmError::UnsupportedExecutableCow)
    );
    assert_eq!(MmError::UnsupportedExecutableCow.errno(), 95);
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
                0
            )
            .unwrap(),
        TransferStep::Supply(window) if window.protection.permits(ReservationProtection::from_bits(4).unwrap())
    ));
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
                    copy_window: crate::cow::CowCopyWindow::target(
                        &self.0.live(&CallerInvalidatesAsid),
                        carrick_mmu_core::aarch64::SubstrateGpa(ttbr),
                    ),
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
    let TransferStep::CowSupply(window) = portal
        .select(
            &transfer,
            &tables.live(&CallerInvalidatesAsid),
            &mut NoopPreparedResolver,
            &mut EmptyCow(&tables, &pool, &resident),
            &resident,
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
        change_policy(
            &region,
            carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
            a,
            &a_tables,
            protection,
        );
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
                let result = portal.select(
                    &transfer,
                    &tables.live(&CallerInvalidatesAsid),
                    &mut NoopPreparedResolver,
                    &mut NoopCowResolver,
                    &residency(),
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
            }
        }
    }
}

struct ForkWords<'a> {
    arenas: &'a [&'a Tables],
    loads: core::cell::Cell<usize>,
}
impl carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords for ForkWords<'_> {
    fn load(
        &self,
        pa: u64,
    ) -> Result<u64, carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal> {
        self.loads.set(self.loads.get() + 1);
        let word = self
            .arenas
            .iter()
            .find_map(|table| {
                pa.checked_sub(table.base)
                    .filter(|offset| offset.is_multiple_of(8))
                    .and_then(|offset| table.words.get(offset as usize / 8))
            })
            .ok_or(
                carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal::TableOutsidePrimary,
            )?;
        Ok(word.load(Ordering::Acquire))
    }
    fn compare_exchange(
        &self,
        pa: u64,
        before: u64,
        after: u64,
    ) -> Result<bool, carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal> {
        let word = self
            .arenas
            .iter()
            .find_map(|table| {
                pa.checked_sub(table.base)
                    .filter(|offset| offset.is_multiple_of(8))
                    .and_then(|offset| table.words.get(offset as usize / 8))
            })
            .ok_or(
                carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal::TableOutsidePrimary,
            )?;
        Ok(word
            .compare_exchange(before, after, Ordering::AcqRel, Ordering::Acquire)
            .is_ok())
    }
    fn store_unlinked(
        &self,
        pa: u64,
        value: u64,
    ) -> Result<(), carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal> {
        let word = self
            .arenas
            .iter()
            .find_map(|table| {
                pa.checked_sub(table.base)
                    .filter(|offset| offset.is_multiple_of(8))
                    .and_then(|offset| table.words.get(offset as usize / 8))
            })
            .ok_or(
                carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal::TableOutsidePrimary,
            )?;
        word.store(value, Ordering::Release);
        Ok(())
    }
    fn publish_barrier(&self) {}
    fn invalidate_range(&self, _: u64, _: u64) {}
}
fn fork_request(
    region: &Region,
    spaces: &AddressSpaces,
    parent: ReservationMm,
    child_mm: u64,
    child: &Tables,
    supply: &Tables,
) -> carrick_el1_abi::PortalForkRequest {
    let index = spaces
        .publish_closed(child_mm, child.base, child.base)
        .unwrap();
    let view = nodes(region);
    let mut parent_root = region
        .table()
        .lock_el1_resolved(spaces.find(parent.raw()).unwrap().index(), parent, &view, 0)
        .unwrap();
    let operation = carrick_el1_abi::PortalOperation {
        carrier: NonZeroU64::new(1).unwrap(),
        mm: parent,
        incarnation: NonZeroU64::new(parent_root.incarnation().raw()).unwrap(),
        sequence: parent_root.next_transfer_sequence().unwrap(),
    };
    let generation = parent_root.generation();
    let layout = parent_root.layout();
    drop(parent_root);
    let child_mm = ReservationMm::new(child_mm).unwrap();
    region
        .table()
        .publish(index.index(), child_mm, layout)
        .unwrap();
    carrick_el1_abi::PortalForkRequest {
        operation,
        parent_generation: generation,
        child_mm,
        child_tables: carrick_el1_abi::PortalForkTableArena::new(
            child.base,
            child.words.len() as u64 * 8,
        )
        .unwrap(),
        parent_tables: carrick_el1_abi::PortalForkTableArena::new(
            supply.base,
            supply.words.len() as u64 * 8,
        )
        .unwrap(),
        kernel_control_ipa: 0xa000_0000,
    }
}

#[test]
pub(crate) fn owner_fork_child_has_live_private_cow_and_parent_stays_unchanged_on_abort() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let parent = admit(&region, &spaces, 77, ROOT, 2, 128);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let parent_tables = Tables::new(ROOT, IPA, 2);
    let child = Tables::new(ROOT + 0x100000, 0, 0);
    let supply = Tables::new(ROOT + 0x200000, 0, 0);
    let request = fork_request(&region, &spaces, parent, 78, &child, &supply);
    let arenas = [&parent_tables, &child, &supply];
    let words = ForkWords {
        arenas: &arenas,
        loads: core::cell::Cell::new(0),
    };
    let plan = portal
        .prepare_fork(
            request,
            ForkScratch::new(request, portal.fork_mapping_count(parent, 0).unwrap()).unwrap(),
            &words,
            0,
        )
        .unwrap();
    assert_eq!(
        plan.custody()
            .iter()
            .filter(|item| matches!(item, carrick_el1_abi::PortalForkCustody::Frame { .. }))
            .count(),
        2
    );
    let original = parent_tables.words[1536].load(Ordering::Acquire);
    let mut unpublished = portal.publish_fork(plan, &words, 0).unwrap();
    assert!(carrick_mmu_core::aarch64::terminal_descriptor_is_fork_cow(
        parent_tables.words[1536].load(Ordering::Acquire)
    ));
    assert!(carrick_mmu_core::aarch64::terminal_descriptor_is_fork_cow(
        child.words[1536].load(Ordering::Acquire)
    ));
    assert!(spaces.grant(spaces.find(78).unwrap(), 78).is_none());
    assert!(
        portal
            .begin(
                portal.admitted_handle(parent, 0).unwrap(),
                GuestVa::new(VA),
                1,
                TransferIntent::UserRead,
                0
            )
            .is_err()
    );
    assert!(
        words.loads.get() <= 4 * 512 * 2,
        "fork must walk only own live tables"
    );
    unpublished.abort(&portal, &words, 0).unwrap();
    assert_eq!(parent_tables.words[1536].load(Ordering::Acquire), original);
    assert!(
        !region
            .table()
            .admitted(spaces.find(78).unwrap().index(), request.child_mm)
    );
}

#[test]
fn owner_fork_refuses_stale_unchanged_shared_leaf_during_custody() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let parent = admit_kind(&region, &spaces, 77, ROOT, 1, 0, false);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let parent_tables = Tables::new(ROOT, IPA, 1);
    let child = Tables::new(ROOT + 0x100000, 0, 0);
    let supply = Tables::new(ROOT + 0x200000, 0, 0);
    let request = fork_request(&region, &spaces, parent, 78, &child, &supply);
    let arenas = [&parent_tables, &child, &supply];
    let words = ForkWords {
        arenas: &arenas,
        loads: core::cell::Cell::new(0),
    };
    let plan = portal
        .prepare_fork(
            request,
            ForkScratch::new(request, portal.fork_mapping_count(parent, 0).unwrap()).unwrap(),
            &words,
            0,
        )
        .unwrap();
    parent_tables.words[1536].store((IPA + 4096) | RW, Ordering::Release);
    assert!(matches!(
        portal.publish_fork(plan, &words, 0),
        Err(MmError::Stale)
    ));
    assert!(
        !region
            .table()
            .admitted(spaces.find(78).unwrap().index(), request.child_mm)
    );
}

#[test]
fn owner_fork_refuses_outstanding_copy_and_keeps_peer_same_va_separate() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let parent = admit(&region, &spaces, 77, ROOT, 1, 0);
    let peer = admit(&region, &spaces, 79, ROOT + 0x300000, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let parent_tables = Tables::new(ROOT, IPA, 1);
    let peer_tables = Tables::new(ROOT + 0x300000, IPA + 0x300000, 1);
    let child = Tables::new(ROOT + 0x100000, 0, 0);
    let supply = Tables::new(ROOT + 0x200000, 0, 0);
    let request = fork_request(&region, &spaces, parent, 78, &child, &supply);
    let mut transfer = portal
        .begin(
            portal.admitted_handle(parent, 0).unwrap(),
            GuestVa::new(VA),
            4,
            TransferIntent::UserRead,
            0,
        )
        .unwrap();
    let selected_chunk = selected(select(&portal, &transfer, &parent_tables));
    let arenas = [&parent_tables, &child, &supply, &peer_tables];
    let words = ForkWords {
        arenas: &arenas,
        loads: core::cell::Cell::new(0),
    };
    let fence = portal
        .revalidate(&transfer, selected_chunk, &words, 0)
        .unwrap()
        .unwrap();
    assert!(matches!(
        portal.prepare_fork(
            request,
            ForkScratch::new(request, portal.fork_mapping_count(parent, 0).unwrap()).unwrap(),
            &words,
            1
        ),
        Err(MmError::Busy)
    ));
    fence.complete(&mut transfer).unwrap();
    let peer_copy = portal
        .begin(
            portal.admitted_handle(peer, 0).unwrap(),
            GuestVa::new(VA),
            4,
            TransferIntent::UserRead,
            0,
        )
        .unwrap();
    assert_eq!(
        selected(select(&portal, &peer_copy, &peer_tables)).ipa,
        IPA + 0x300000
    );
}

#[test]
fn owner_fork_untouched_private_file_reads_source_and_child_write_stays_private() {
    use carrick_mmu_core::aarch64::descriptor_txn::{
        BackingIdentity, DescriptorOp, DescriptorOutcome, DescriptorTxn, DescriptorTxnId, PageSpan,
        TableGrants,
    };
    use carrick_mmu_core::aarch64::{GuestLeafPublication, SubstrateGpa};
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let parent = admit_kind(&region, &spaces, 77, ROOT, 1, 0, false);
    let view = nodes(&region);
    let source = carrick_el1_abi::HostBackingIdentity::new(
        NonZeroU64::new(71).unwrap(),
        NonZeroU64::new(4).unwrap(),
        4096,
    );
    {
        let mut root = region
            .table()
            .lock_el1_resolved(spaces.find(77).unwrap().index(), parent, &view, 0)
            .unwrap();
        root.retire_opaque(ReservationRange::new(VA, VA + 4096).unwrap())
            .unwrap();
        root.insert_opaque_backed(
            ReservationRange::new(VA, VA + 4096).unwrap(),
            ReservationProtection::READ_WRITE,
            carrick_el1_abi::ReservationNodeFlags::PRIVATE,
            Some(source),
        )
        .unwrap();
    }
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let parent_tables = Tables::new(ROOT, IPA, 0);
    let child = Tables::new(ROOT + 0x100000, 0, 0);
    let supply = Tables::new(ROOT + 0x200000, 0, 0);
    let request = fork_request(&region, &spaces, parent, 78, &child, &supply);
    let arenas = [&parent_tables, &child, &supply];
    let words = ForkWords {
        arenas: &arenas,
        loads: core::cell::Cell::new(0),
    };
    let plan = portal
        .prepare_fork(
            request,
            ForkScratch::new(request, portal.fork_mapping_count(parent, 0).unwrap()).unwrap(),
            &words,
            0,
        )
        .unwrap();
    assert_eq!(
        plan.custody(),
        &[carrick_el1_abi::PortalForkCustody::HostBacking {
            handle: source.handle(),
            generation: source.generation()
        }]
    );
    let completion = portal
        .publish_fork(plan, &words, 0)
        .unwrap()
        .commit(&portal, 0)
        .unwrap();
    spaces.open(spaces.find(78).unwrap());
    let fault_slots = Box::new(carrick_el1_abi::MmPortalSlots::new());
    assert!(fault_slots.bind_carrier(NonZeroU64::new(1).unwrap()));
    let fault_mailbox = FrameGrantMailbox::new();
    assert!(
        (crate::fault::FileFaultVenue {
            roots: region.table(),
            spaces: carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
            slots: &fault_slots,
            worker: 0,
            mailbox: &fault_mailbox
        })
        .publish(78, VA, 1)
    );
    let fault_request = fault_mailbox.claim_request().unwrap();
    let fault_window = fault_slots
        .grant(0)
        .unwrap()
        .fault_selection(78, fault_request.request_generation)
        .unwrap();
    assert_eq!(fault_window.host_backing, Some(source));
    assert!(fault_slots.has_outstanding_transfer(request.child_mm));
    assert!(
        fault_slots
            .grant(0)
            .unwrap()
            .cancel_fault_selection(fault_window, fault_request.request_generation)
    );
    let transfer = portal
        .begin(
            completion.child,
            GuestVa::new(VA),
            4,
            TransferIntent::UserRead,
            0,
        )
        .unwrap();
    let residency = residency();
    let TransferStep::Supply(window) = portal
        .select(
            &transfer,
            &words,
            &mut NoopPreparedResolver,
            &mut NoopCowResolver,
            &residency,
            0,
        )
        .unwrap()
    else {
        panic!("untouched file must use retained owner source");
    };
    assert_eq!(window.host_backing, Some(source));
    let file_bytes = [0x5a; 4096];
    let mut child_bytes = file_bytes;
    let nz = |value| NonZeroU64::new(value).unwrap();
    let txn = DescriptorTxn {
        id: DescriptorTxnId {
            mm_key: nz(78),
            generation: nz(1),
        },
        root: SubstrateGpa(child.base),
        op: DescriptorOp::Prepare {
            publication: GuestLeafPublication {
                va: VA,
                ipa: IPA + 0x100000,
                len: 4096,
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
        tables: TableGrants::NONE,
    };
    let grant_slot = carrick_el1_abi::PortalGrantSlot::new();
    assert!(grant_slot.submit(window, &txn));
    let receipt = serve_grant(&portal, &grant_slot, &words, &residency, 0, || {}).unwrap();
    assert!(matches!(receipt.outcome, DescriptorOutcome::Applied(_)));
    assert!(grant_slot.take_receipt(window, &txn).is_some());
    let chunk = selected(
        portal
            .select(
                &transfer,
                &words,
                &mut NoopPreparedResolver,
                &mut NoopCowResolver,
                &residency,
                0,
            )
            .unwrap(),
    );
    assert_eq!(
        &child_bytes[(chunk.ipa - (IPA + 0x100000)) as usize..][..4],
        &[0x5a; 4]
    );
    let write = portal
        .begin(
            completion.child,
            GuestVa::new(VA),
            4,
            TransferIntent::UserWrite,
            0,
        )
        .unwrap();
    let selected_write = selected(
        portal
            .select(
                &write,
                &words,
                &mut NoopPreparedResolver,
                &mut NoopCowResolver,
                &residency,
                0,
            )
            .unwrap(),
    );
    let copy = carrick_el1_abi::PortalTransferSlot::new();
    let mut ticket = copy
        .submit(
            selected_write
                .request(TransferIntent::UserWrite, retained())
                .unwrap(),
        )
        .unwrap();
    serve_transfer(&portal, copy.claim().unwrap(), &words, 0, || {
        assert!(ticket.copy_requested(|_| {
            child_bytes[..4].copy_from_slice(b"fork");
            true
        }));
    })
    .unwrap();
    assert_eq!(ticket.take_completion().unwrap().completed, 4);
    assert_eq!(&child_bytes[..4], b"fork");
    assert_eq!(file_bytes, [0x5a; 4096]);
    assert_eq!(
        parent_tables.words[1536].load(Ordering::Acquire),
        0,
        "parent remains untouched"
    );
    assert_eq!(
        region
            .table()
            .lock_el1_resolved(spaces.find(77).unwrap().index(), parent, &view, 0)
            .unwrap()
            .mapping(VA)
            .unwrap()
            .host_backing,
        Some(source)
    );
}

fn fork_translate<W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords>(
    words: &W,
    root: u64,
    va: u64,
) -> u64 {
    let mut table = root;
    for (level, shift) in [39, 30, 21, 12].into_iter().enumerate() {
        let descriptor = words.load(table + ((va >> shift) & 511) * 8).unwrap();
        if level == 3 || descriptor & 3 != 3 {
            let span = 1u64 << shift;
            return (descriptor & 0x0000_ffff_ffff_f000 & !(span - 1)) + (va & (span - 1));
        }
        table = descriptor & 0x0000_ffff_ffff_f000;
    }
    unreachable!()
}

#[test]
fn owner_fork_resident_child_cow_copies_with_production_classifier() {
    use carrick_mmu_core::aarch64::descriptor_txn::BackingIdentity;
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let parent = admit(&region, &spaces, 77, ROOT, 2, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let parent_tables = Tables::new(ROOT, IPA, 2);
    let child = Tables::new(ROOT + 0x100000, 0, 0);
    let supply = Tables::new(ROOT + 0x200000, 0, 0);
    let copy_base = carrick_el1_abi::EL1_COW_COPY_BASE;
    let indices = carrick_mmu_core::aarch64::indices(copy_base);
    parent_tables.words[512 + indices[1]].store((ROOT + 0x4000) | 3, Ordering::Release);
    parent_tables.words[2048 + indices[2]].store((ROOT + 0x5000) | 3, Ordering::Release);
    for page in 0..2 {
        parent_tables.words[2560 + indices[3] + page]
            .store(copy_base + page as u64 * 4096, Ordering::Release);
    }
    let request = fork_request(&region, &spaces, parent, 78, &child, &supply);
    let arenas = [&parent_tables, &child, &supply];
    let words = ForkWords {
        arenas: &arenas,
        loads: core::cell::Cell::new(0),
    };
    let plan = portal
        .prepare_fork(
            request,
            ForkScratch::new(request, portal.fork_mapping_count(parent, 0).unwrap()).unwrap(),
            &words,
            0,
        )
        .unwrap();
    let receipt = portal
        .publish_fork(plan, &words, 0)
        .unwrap()
        .commit(&portal, 0)
        .unwrap();
    spaces.open(spaces.find(78).unwrap());
    let original = [0x5a; 8192];
    let replacement = core::cell::RefCell::new([0; 16384]);
    let pool = carrick_el1_abi::CowGrantPool::new();
    let nz = |v| NonZeroU64::new(v).unwrap();
    let replacement_ipa = IPA + 0x100000;
    pool.publish(
        78,
        replacement_ipa,
        BackingIdentity {
            frame_id: nz(11),
            mapping_id: nz(12),
            owner_generation: nz(13),
            inventory_revision: nz(14),
        },
    )
    .unwrap();
    let residency = residency();
    let _editor = spaces
        .try_begin_edit(spaces.find(78).unwrap(), 78, nz(2))
        .unwrap();
    let outcome = crate::cow::resolve_guest_cow(
        &crate::cow::GuestCowVenue {
            words: &words,
            root: carrick_mmu_core::aarch64::SubstrateGpa(child.base),
            pool: &pool,
            residency: &residency,
            copy_window: crate::cow::CowCopyWindow::target(
                &words,
                carrick_mmu_core::aarch64::SubstrateGpa(child.base),
            ),
            publish_executable: None,
        },
        receipt.child.mm().raw(),
        VA,
        |source, target| {
            let source = fork_translate(&words, child.base, source) - IPA;
            let target = fork_translate(&words, child.base, target) - replacement_ipa;
            replacement.borrow_mut()[target as usize..target as usize + 4096]
                .copy_from_slice(&original[source as usize..source as usize + 4096]);
        },
        || {},
    );
    assert!(
        matches!(outcome, crate::cow::GuestCowOutcome::Resolved(_)),
        "{outcome:?}"
    );
    replacement.borrow_mut()[..4].copy_from_slice(b"fork");
    assert_eq!(original, [0x5a; 8192]);
    assert_eq!(fork_translate(&words, ROOT, VA), IPA);
    assert_eq!(fork_translate(&words, child.base, VA), replacement_ipa);
    assert_eq!(&replacement.borrow()[..4], b"fork");
}

struct FailingForkWords<'a> {
    inner: ForkWords<'a>,
    live_cas: core::cell::Cell<usize>,
    fail_at: usize,
}
impl carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords for FailingForkWords<'_> {
    fn load(
        &self,
        pa: u64,
    ) -> Result<u64, carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal> {
        self.inner.load(pa)
    }
    fn compare_exchange(
        &self,
        pa: u64,
        before: u64,
        after: u64,
    ) -> Result<bool, carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal> {
        let count = self.live_cas.get() + 1;
        self.live_cas.set(count);
        if count == self.fail_at {
            return Err(
                carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal::TableOutsidePrimary,
            );
        }
        self.inner.compare_exchange(pa, before, after)
    }
    fn store_unlinked(
        &self,
        pa: u64,
        value: u64,
    ) -> Result<(), carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal> {
        self.inner.store_unlinked(pa, value)
    }
    fn publish_barrier(&self) {
        self.inner.publish_barrier()
    }
    fn invalidate_range(&self, va: u64, len: u64) {
        self.inner.invalidate_range(va, len)
    }
}

#[test]
fn owner_fork_live_store_failure_restores_parent_and_refuses_child() {
    for block in [false, true] {
        let region = Region::new();
        let spaces = AddressSpaces::new();
        let parent = admit(&region, &spaces, 77, ROOT, 2, 0);
        let view = nodes(&region);
        let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
        let parent_tables = Tables::new(ROOT, IPA, 2);
        let child = Tables::new(ROOT + 0x100000, 0, 0);
        let supply = Tables::new(ROOT + 0x200000, 0, 0);
        if block {
            parent_tables.words[1024].store((IPA & !0x1fffff) | (RW & !2), Ordering::Release);
        }
        let before = parent_tables
            .words
            .iter()
            .map(|word| word.load(Ordering::Acquire))
            .collect::<Vec<_>>();
        let request = fork_request(&region, &spaces, parent, 78, &child, &supply);
        let arenas = [&parent_tables, &child, &supply];
        let words = FailingForkWords {
            inner: ForkWords {
                arenas: &arenas,
                loads: core::cell::Cell::new(0),
            },
            live_cas: core::cell::Cell::new(0),
            fail_at: 2,
        };
        let plan = portal
            .prepare_fork(
                request,
                ForkScratch::new(request, portal.fork_mapping_count(parent, 0).unwrap()).unwrap(),
                &words,
                0,
            )
            .unwrap();
        assert!(matches!(
            portal.publish_fork(plan, &words, 0),
            Err(MmError::Core)
        ));
        let after = parent_tables
            .words
            .iter()
            .map(|word| word.load(Ordering::Acquire))
            .collect::<Vec<_>>();
        assert_eq!(
            after, before,
            "block={block}: physical failure lost the parent preimage"
        );
        assert!(
            !region
                .table()
                .admitted(spaces.find(78).unwrap().index(), request.child_mm)
        );
        assert!(!portal.root(parent, 0).unwrap().fork_pending());
    }
}

#[test]
fn owner_fork_parent_copyout_cow_reconciles_exact_pending_rollback() {
    owner_parent_copyout_rollback(false);
}
#[test]
fn owner_fork_parent_copyout_abort_retains_live_split_arena() {
    owner_parent_copyout_rollback(true);
}
fn owner_parent_copyout_rollback(mixed_block: bool) {
    use carrick_mmu_core::aarch64::descriptor_txn::BackingIdentity;
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let parent = admit(&region, &spaces, 77, ROOT, 2, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let parent_tables = Tables::new(ROOT, IPA, 2);
    let child = Tables::new(ROOT + 0x100000, 0, 0);
    let supply = Tables::new(ROOT + 0x200000, 0, 0);
    let copy_base = carrick_el1_abi::EL1_COW_COPY_BASE;
    let indices = carrick_mmu_core::aarch64::indices(copy_base);
    parent_tables.words[512 + indices[1]].store((ROOT + 0x4000) | 3, Ordering::Release);
    parent_tables.words[2048 + indices[2]].store((ROOT + 0x5000) | 3, Ordering::Release);
    for page in 0..2 {
        parent_tables.words[2560 + indices[3] + page]
            .store(copy_base + page as u64 * 4096, Ordering::Release);
    }
    if mixed_block {
        parent_tables.words[1024].store(IPA | (RW & !2), Ordering::Release);
    }
    let request = fork_request(&region, &spaces, parent, 78, &child, &supply);
    let arenas = [&parent_tables, &child, &supply];
    let words = ForkWords {
        arenas: &arenas,
        loads: core::cell::Cell::new(0),
    };
    let plan = portal
        .prepare_fork(
            request,
            ForkScratch::new(request, portal.fork_mapping_count(parent, 0).unwrap()).unwrap(),
            &words,
            0,
        )
        .unwrap();
    let mut pending = portal.publish_fork(plan, &words, 0).unwrap();
    let handle = portal.admitted_handle(parent, 0).unwrap();
    assert!(matches!(
        portal.begin(handle, GuestVa::new(VA), 4, TransferIntent::UserWrite, 0),
        Err(MmError::Busy)
    ));
    let scoped = portal
        .begin_fork_parent_write(
            handle,
            GuestVa::new(VA),
            4,
            TransferIntent::UserWrite,
            request.operation.sequence,
            0,
        )
        .unwrap();
    assert_eq!(scoped.offset(), 0);
    assert!(
        portal
            .begin_fork_parent_write(
                handle,
                GuestVa::new(VA),
                4,
                TransferIntent::UserWrite,
                NonZeroU64::new(request.operation.sequence.get() + 10).unwrap(),
                0
            )
            .is_err()
    );
    let original = [0x5a; 8192];
    let replacement = core::cell::RefCell::new([0; 16384]);
    let pool = carrick_el1_abi::CowGrantPool::new();
    let nz = |v| NonZeroU64::new(v).unwrap();
    let replacement_ipa = IPA + 0x100000;
    pool.publish(
        77,
        replacement_ipa,
        BackingIdentity {
            frame_id: nz(11),
            mapping_id: nz(12),
            owner_generation: nz(13),
            inventory_revision: nz(14),
        },
    )
    .unwrap();
    let residency = residency();
    let _editor = spaces
        .try_begin_edit(spaces.find(77).unwrap(), 77, nz(2))
        .unwrap();
    let outcome = crate::cow::resolve_guest_cow(
        &crate::cow::GuestCowVenue {
            words: &words,
            root: carrick_mmu_core::aarch64::SubstrateGpa(ROOT),
            pool: &pool,
            residency: &residency,
            copy_window: crate::cow::CowCopyWindow::target(
                &words,
                carrick_mmu_core::aarch64::SubstrateGpa(ROOT),
            ),
            publish_executable: None,
        },
        parent.raw(),
        VA,
        |source, target| {
            let source = fork_translate(&words, ROOT, source) - IPA;
            let target = fork_translate(&words, ROOT, target) - replacement_ipa;
            replacement.borrow_mut()[target as usize..target as usize + 4096]
                .copy_from_slice(&original[source as usize..source as usize + 4096]);
        },
        || {},
    );
    assert!(
        matches!(outcome, crate::cow::GuestCowOutcome::Resolved(_)),
        "{outcome:?}"
    );
    drop(_editor);
    let crate::cow::GuestCowOutcome::Resolved(completion) = outcome else {
        panic!("owner COW receipt missing")
    };
    pending.reconcile_parent_write(&words, completion).unwrap();
    replacement.borrow_mut()[..4].copy_from_slice(b"ptid");
    assert_eq!(fork_translate(&words, child.base, VA), IPA);
    pending.abort(&portal, &words, 0).unwrap();
    assert_eq!(fork_translate(&words, ROOT, VA), replacement_ipa);
    assert_eq!(pending.completion().parent_tables_used != 0, mixed_block);
    assert_eq!(pending.completion().child_tables_used, 0);
    assert!(
        !region
            .table()
            .admitted(spaces.find(78).unwrap().index(), request.child_mm)
    );
    assert_eq!(&replacement.borrow()[..4], b"ptid");
}

#[test]
fn owner_fork_dontfork_omits_and_wipeonfork_retains_zero_reservation() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let parent = admit(&region, &spaces, 77, ROOT, 2, 0);
    let view = nodes(&region);
    {
        let mut root = region
            .table()
            .lock_resolved(
                spaces.find(77).unwrap().index(),
                parent,
                &view,
                &crate::memory::reservations::NoRootWait,
            )
            .unwrap();
        root.set_flags(
            ReservationRange::new(VA, VA + 4096).unwrap(),
            ReservationNodeFlags::DONTFORK,
            ReservationNodeFlags::EMPTY,
        )
        .unwrap();
        root.set_flags(
            ReservationRange::new(VA + 4096, VA + 8192).unwrap(),
            ReservationNodeFlags::WIPEONFORK,
            ReservationNodeFlags::EMPTY,
        )
        .unwrap();
    }
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let parent_tables = Tables::new(ROOT, IPA, 2);
    let child = Tables::new(ROOT + 0x100000, 0, 0);
    let supply = Tables::new(ROOT + 0x200000, 0, 0);
    let request = fork_request(&region, &spaces, parent, 78, &child, &supply);
    let arenas = [&parent_tables, &child, &supply];
    let words = ForkWords {
        arenas: &arenas,
        loads: core::cell::Cell::new(0),
    };
    let before = [
        parent_tables.words[1536].load(Ordering::Acquire),
        parent_tables.words[1537].load(Ordering::Acquire),
    ];
    let plan = portal
        .prepare_fork(
            request,
            ForkScratch::new(request, portal.fork_mapping_count(parent, 0).unwrap()).unwrap(),
            &words,
            0,
        )
        .unwrap();
    assert!(plan.custody().is_empty());
    portal
        .publish_fork(plan, &words, 0)
        .unwrap()
        .commit(&portal, 0)
        .unwrap();
    let mut child_root = region
        .table()
        .lock_el1_resolved(spaces.find(78).unwrap().index(), request.child_mm, &view, 0)
        .unwrap();
    assert!(child_root.mapping(VA).is_none());
    assert!(
        child_root
            .mapping(VA + 4096)
            .unwrap()
            .flags
            .contains(ReservationNodeFlags::WIPEONFORK)
    );
    assert_eq!(child.words[1536].load(Ordering::Acquire), 0);
    assert_eq!(child.words[1537].load(Ordering::Acquire), 0);
    assert_eq!(
        [
            parent_tables.words[1536].load(Ordering::Acquire),
            parent_tables.words[1537].load(Ordering::Acquire)
        ],
        before
    );
}

#[test]
fn owner_fork_preserves_parent_owed_return_and_omits_retired_child_leaf() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let parent = admit(&region, &spaces, 77, ROOT, 2, 0);
    let view = nodes(&region);
    let retired_range = ReservationRange::new(VA, VA + 4096).unwrap();
    let sequence;
    {
        let mut root = region
            .table()
            .lock_el1_resolved(spaces.find(77).unwrap().index(), parent, &view, 0)
            .unwrap();
        let crate::memory::reservations::Decision::Work(request) =
            root.munmap(retired_range).unwrap()
        else {
            panic!()
        };
        sequence = request.sequence;
        let slot = root.reserve_return(retired_range).unwrap();
        let completion = unsafe {
            carrick_el1_abi::ReservationCompletion::after_descriptor_and_backing_commit(
                request,
                carrick_el1_abi::ReservationBackingReceipt {
                    receipt: sequence.raw(),
                    granted_bytes: 0,
                    returned_bytes: 0,
                },
            )
        }
        .unwrap();
        root.complete_deferring_return(completion, slot).unwrap();
        assert!(root.fork_ready());
        assert!(!root.fork_settled());
    }
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let parent_tables = Tables::new(ROOT, IPA, 2);
    // The retired owner terminal retains its physical address until the
    // parent's physical acknowledgement; Fork must not inherit it.
    parent_tables.words[1536].store(IPA | (1 << 56) | (1 << 55), Ordering::Release);
    let child = Tables::new(ROOT + 0x100000, 0, 0);
    let supply = Tables::new(ROOT + 0x200000, 0, 0);
    let request = fork_request(&region, &spaces, parent, 78, &child, &supply);
    let arenas = [&parent_tables, &child, &supply];
    let words = ForkWords {
        arenas: &arenas,
        loads: core::cell::Cell::new(0),
    };
    let plan = portal
        .prepare_fork(
            request,
            ForkScratch::new(request, portal.fork_mapping_count(parent, 0).unwrap()).unwrap(),
            &words,
            0,
        )
        .unwrap();
    portal
        .publish_fork(plan, &words, 0)
        .unwrap()
        .commit(&portal, 0)
        .unwrap();
    assert_eq!(child.words[1536].load(Ordering::Acquire), 0);
    {
        let mut child_root = region
            .table()
            .lock_el1_resolved(spaces.find(78).unwrap().index(), request.child_mm, &view, 0)
            .unwrap();
        assert!(child_root.authenticate_fork_origin(request));
        let mut wrong = request;
        wrong.operation.carrier = NonZeroU64::new(99).unwrap();
        assert!(!child_root.authenticate_fork_origin(wrong));
        let handle = unsafe {
            El1MmHandle::from_admitted_owner(
                request.operation.carrier,
                request.child_mm,
                NonZeroU64::new(child_root.incarnation().raw()).unwrap(),
            )
        };
        assert!(child_root.authenticate_fork_handle(handle));
        let wrong = unsafe {
            El1MmHandle::from_admitted_owner(
                NonZeroU64::new(99).unwrap(),
                handle.mm(),
                handle.incarnation(),
            )
        };
        assert!(!child_root.authenticate_fork_handle(wrong));
    }
    let mut parent_root = region
        .table()
        .lock_el1_resolved(spaces.find(77).unwrap().index(), parent, &view, 0)
        .unwrap();
    let mut owed = Vec::new();
    parent_root.observe_deferred_returns(&mut |row| owed.push(row));
    assert_eq!(owed.len(), 1);
    assert_eq!(owed[0].range, retired_range);
    assert_eq!(owed[0].sequence, sequence);
    let child_root = region
        .table()
        .lock_el1_resolved(spaces.find(78).unwrap().index(), request.child_mm, &view, 0)
        .unwrap();
    child_root.observe_deferred_returns(&mut |_| panic!("parent return leaked into child"));
    assert_eq!(
        parent_root.acknowledge_deferred_returns(sequence).unwrap(),
        1
    );
    assert_eq!(
        parent_root.acknowledge_deferred_returns(sequence).unwrap(),
        0
    );
}

#[test]
fn owner_fork_census_allocates_for_live_graph_not_physical_arena_capacity() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let parent = admit(&region, &spaces, 77, ROOT, 2, 128);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let parent_tables = Tables::new(ROOT, IPA, 2);
    let child = Tables::new(ROOT + 0x100000, 0, 0);
    let supply = Tables::new(ROOT + 0x200000, 0, 0);
    let mut request = fork_request(&region, &spaces, parent, 78, &child, &supply);
    let arenas = [&parent_tables, &child, &supply];
    let words = ForkWords {
        arenas: &arenas,
        loads: core::cell::Cell::new(0),
    };
    request.child_tables.len = 0x20_0000;
    request.parent_tables.len = 0x20_0000;
    // Keep physical supplies disjoint when expanding the unused capacity.
    request.parent_tables.base = ROOT + 0x400000;
    let scratch = portal.census_fork(request, &words, 0).unwrap();
    assert_eq!(scratch.allocation_counts(), (2048, 0, 2048, 2));
    let plan = portal.prepare_fork(request, scratch, &words, 0).unwrap();
    assert_eq!(
        plan.custody()
            .iter()
            .filter(|item| matches!(item, carrick_el1_abi::PortalForkCustody::Frame { .. }))
            .count(),
        2
    );
    let original = parent_tables.words[1536].load(Ordering::Acquire);
    let mut unpublished = portal.publish_fork(plan, &words, 0).unwrap();
    assert!(carrick_mmu_core::aarch64::terminal_descriptor_is_fork_cow(
        parent_tables.words[1536].load(Ordering::Acquire)
    ));
    assert!(carrick_mmu_core::aarch64::terminal_descriptor_is_fork_cow(
        child.words[1536].load(Ordering::Acquire)
    ));
    assert!(spaces.grant(spaces.find(78).unwrap(), 78).is_none());
    assert!(
        portal
            .begin(
                portal.admitted_handle(parent, 0).unwrap(),
                GuestVa::new(VA),
                1,
                TransferIntent::UserRead,
                0
            )
            .is_err()
    );
    assert!(
        words.loads.get() <= 3 * 4 * 512,
        "fork must walk only own live tables"
    );
    unpublished.abort(&portal, &words, 0).unwrap();
    assert_eq!(parent_tables.words[1536].load(Ordering::Acquire), original);
    assert!(
        !region
            .table()
            .admitted(spaces.find(78).unwrap().index(), request.child_mm)
    );
}

// Contract kernel.mm.prepared-copy: ready-source effects must retain semantic
// range admission without monopolizing the MM descriptor editor.
#[test]
fn prepared_copy_overlapping_munmap_waits_before_any_mutation() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 2, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let tables = Tables::new(ROOT, IPA, 2);
    let maintenance = CallerInvalidatesAsid;
    let transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(VA),
            4096,
            TransferIntent::UserWrite,
            0,
        )
        .unwrap();
    let chunk = selected(select(&portal, &transfer, &tables));
    let request = chunk
        .request(TransferIntent::UserWrite, retained())
        .unwrap();
    let permit = prepare_transfer(&portal, request, &tables.live(&maintenance), 0)
        .unwrap()
        .unwrap();
    let mut root = portal.root(mm, 1).unwrap();
    assert!(
        matches!(
            root.munmap(ReservationRange::new(VA, VA + 4096).unwrap()),
            Err(crate::memory::reservations::Refusal::PreparedConflict)
        ),
        "overlapping munmap must wait before proposing mutation"
    );
    drop(root);
    portal.cancel_prepared(permit, request, 0).unwrap();
    assert!(
        portal
            .root(mm, 1)
            .unwrap()
            .munmap(ReservationRange::new(VA, VA + 4096).unwrap())
            .is_ok()
    );
}
#[test]
fn prepared_copy_releases_editor_for_unrelated_edit() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 2, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let tables = Tables::new(ROOT, IPA, 2);
    let maintenance = CallerInvalidatesAsid;
    let transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(VA),
            4096,
            TransferIntent::UserWrite,
            0,
        )
        .unwrap();
    let chunk = selected(select(&portal, &transfer, &tables));
    let request = chunk
        .request(TransferIntent::UserWrite, retained())
        .unwrap();
    let permit = prepare_transfer(&portal, request, &tables.live(&maintenance), 0)
        .unwrap()
        .unwrap();
    assert!(
        spaces
            .try_begin_edit(
                spaces.find(mm.raw()).unwrap(),
                mm.raw(),
                NonZeroU64::new(2).unwrap()
            )
            .is_some(),
        "ready consumption must not hold descriptor editor"
    );
    portal.cancel_prepared(permit, request, 0).unwrap();
}

#[test]
fn prepared_copy_commit_and_cancel_never_acquire_held_root_or_editor() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 2, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
    let tables = Tables::new(ROOT, IPA, 2);
    let maintenance = CallerInvalidatesAsid;
    let transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(VA),
            4096,
            TransferIntent::UserWrite,
            0,
        )
        .unwrap();
    let request = selected(select(&portal, &transfer, &tables))
        .request(TransferIntent::UserWrite, retained())
        .unwrap();
    let slot = carrick_el1_abi::PortalTransferSlot::new();
    let mut ticket = slot.submit_prepare(request).unwrap();
    serve_transfer(
        &portal,
        slot.claim().unwrap(),
        &tables.live(&maintenance),
        0,
        || panic!("prepare must not copy"),
    )
    .unwrap();
    let permit = ticket.take_prepared().unwrap();
    // A non-overlapping committed edit changes the MM generation, preserving
    // this permit's own generation and exact semantic admission.
    let mut root = portal.root(mm, 1).unwrap();
    let decision = root
        .mprotect(
            ReservationRange::new(VA + 4096, VA + 8192).unwrap(),
            ReservationProtection::from_bits(1).unwrap(),
        )
        .unwrap();
    if let crate::memory::reservations::Decision::Work(request) = decision {
        root.complete(unsafe {
            carrick_el1_abi::ReservationCompletion::after_descriptor_and_backing_commit(
                request,
                carrick_el1_abi::ReservationBackingReceipt {
                    receipt: 1,
                    granted_bytes: 0,
                    returned_bytes: 0,
                },
            )
            .unwrap()
        })
        .unwrap();
    }
    let _editor = spaces
        .try_begin_edit(
            spaces.find(mm.raw()).unwrap(),
            mm.raw(),
            NonZeroU64::new(2).unwrap(),
        )
        .unwrap();
    let mut commit = slot.submit_commit(request, permit, 23).unwrap();
    serve_transfer(
        &portal,
        slot.claim().unwrap(),
        &tables.live(&maintenance),
        0,
        || {
            assert!(commit.copy_requested(|authorization| {
                assert_eq!(authorization.request().range.len(), 23);
                true
            }));
        },
    )
    .unwrap();
    assert_eq!(commit.take_completion().unwrap().completed, 23);
    assert!(
        root.has_prepared_copy(),
        "settled metadata remains queued until the root holder reaps it"
    );
    // A stale generation cannot copy or cancel a successor, even at same VA.
    drop(_editor);
    drop(root);
    let successor_request = selected(select(&portal, &transfer, &tables))
        .request(TransferIntent::UserWrite, retained())
        .unwrap();
    let successor = prepare_transfer(&portal, successor_request, &tables.live(&maintenance), 0)
        .unwrap()
        .unwrap();
    assert_ne!(permit.generation, successor.generation);
    assert!(portal.cancel_prepared(permit, request, 0).is_err());
    let mut stale_commit = slot.submit_commit(request, permit, 4096).unwrap();
    assert_eq!(
        serve_transfer(
            &portal,
            slot.claim().unwrap(),
            &tables.live(&maintenance),
            0,
            || panic!("stale prepared COMMIT must never copy")
        ),
        Err(MmError::Stale)
    );
    assert_eq!(stale_commit.take_completion().unwrap().completed, 0);
    assert!(
        portal
            .cancel_prepared(successor, successor_request, u32::MAX)
            .is_err()
    );
    let foreign_carrier =
        MmPortal::new(NonZeroU64::new(99).unwrap(), region.table(), &spaces, &view);
    assert!(
        foreign_carrier
            .cancel_prepared(successor, successor_request, 0)
            .is_err()
    );
    let held_root = portal.root(mm, 1).unwrap();
    let held_editor = spaces
        .try_begin_edit(
            spaces.find(mm.raw()).unwrap(),
            mm.raw(),
            NonZeroU64::new(2).unwrap(),
        )
        .unwrap();
    portal
        .cancel_prepared(successor, successor_request, 0)
        .unwrap();
    assert!(
        held_root.has_prepared_copy(),
        "atomic cancellation does not reacquire the held root"
    );
    drop(held_editor);
}

#[test]
fn prepared_copy_el1_edit_parks_then_commit_or_cancel_wakes_exact_saved_syscall() {
    use crate::substrate::sched::{FakeCpu, HardwareUserWord, Sched, Served, ThreadCpu};
    use carrick_el1_abi::{Counters, CurrentTask, El1TaskId, SlotId, TrapFrame};
    for cancel in [false, true] {
        for nr in [215, 226, 216] {
            let region = Region::new();
            let zone = region.zone();
            let mm = admit_notified(&region, 77, ROOT, 2, 0);
            let view = nodes(&region);
            let portal = MmPortal::new(
                NonZeroU64::new(1).unwrap(),
                region.table(),
                &zone.spaces,
                &view,
            )
            .with_zone(zone)
            .unwrap();
            let tables = Tables::new(ROOT, IPA, 2);
            let maintenance = CallerInvalidatesAsid;
            let transfer = portal
                .begin(
                    portal.admitted_handle(mm, 0).unwrap(),
                    GuestVa::new(VA),
                    4096,
                    TransferIntent::UserWrite,
                    0,
                )
                .unwrap();
            let request = selected(select(&portal, &transfer, &tables))
                .request(TransferIntent::UserWrite, retained())
                .unwrap();
            let permit = prepare_transfer(&portal, request, &tables.live(&maintenance), 0)
                .unwrap()
                .unwrap();
            let slot = SlotId::from_index(0).unwrap();
            zone.drive(slot, 1);
            zone.publish_slot(slot, mm.raw(), None, 0);
            assert!(zone.occupancy.replace(
                carrick_sched_core::ExecutionSlot::zone(slot),
                0,
                mm.raw()
            ));
            zone.enter_guest(slot);
            let task = CurrentTask::new();
            task.set(El1TaskId::from_linux_tid(101), 1, 5);
            task.zone_mm.store(mm.raw(), Ordering::Release);
            task.thread_serial.store(1101, Ordering::Release);
            task.mark_pending_host_work(); // deterministic leave, no WFI.
            let counters = Counters::default();
            let mut cpu = FakeCpu::default();
            let mut frame = TrapFrame::default();
            frame.x[8] = nr;
            frame.x[0] = VA;
            frame.x[1] = 4096;
            frame.x[2] = if nr == 216 { 4096 } else { 1 };
            if nr == 216 {
                frame.x[1] = 8192;
            }
            frame.elr = 0x1004;
            let original = frame.x;
            let key = portal.prepared_wait_key(transfer.handle).unwrap();
            let mut sched = Sched {
                zone,
                slot,
                task: &task,
                cpu: &mut cpu,
                user: &HardwareUserWord,
                counters: &counters,
            };
            assert!(matches!(
                park_prepared_edit(&mut sched, &mut frame, region.table()),
                Some(Served::Idle)
            ));
            assert_eq!(zone.object_queue_census(key.index()).unwrap().waiters, 1);
            assert_eq!(counters.forwarded[nr as usize].load(Ordering::Relaxed), 0);
            assert_eq!(
                portal
                    .root(mm, 1)
                    .unwrap()
                    .mapping(VA)
                    .unwrap()
                    .range
                    .start(),
                VA
            );
            let delivered = core::cell::Cell::new(false);
            let completion =
                |owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>| {
                    assert!(!zone.object_queue_census(key.index()).unwrap().locked);
                    let (_, effects) = owned.deliver_handbacks(&mut |_| panic!("available slot"));
                    assert!(effects.queued_own);
                    delivered.set(true);
                };
            let held_queue = zone
                .object_wait_with_completion(key, &carrick_sched_core::BoundedSpin(0), &completion)
                .unwrap();
            if cancel {
                portal.cancel_prepared(permit, request, 0).unwrap();
            } else {
                let wire = carrick_el1_abi::PortalTransferSlot::new();
                let mut ticket = wire.submit_commit(request, permit, 4096).unwrap();
                serve_transfer(
                    &portal,
                    wire.claim().unwrap(),
                    &tables.live(&maintenance),
                    0,
                    || {
                        assert!(ticket.copy_requested(|_| true));
                    },
                )
                .unwrap();
                assert_eq!(ticket.take_completion().unwrap().completed, 4096);
            }
            assert!(
                !delivered.get(),
                "commit/cancel must return before the queue holder unlocks"
            );
            assert_eq!(zone.object_queue_census(key.index()).unwrap().waiters, 1);
            drop(held_queue);
            assert!(delivered.get(), "the holder owns eventual wake delivery");
            assert_eq!(zone.object_queue_census(key.index()).unwrap().waiters, 0);
            let switched = zone
                .switch_in_full(slot)
                .expect("settlement must queue waiter");
            // SAFETY: switch_in_full assigned the exact context to this slot.
            let context = unsafe { zone.record(switched.record).ctx_mut() };
            assert_eq!(context.x, original);
            assert_eq!(context.pc, 0x1000);
            sched.cpu.load(&mut frame, context);
            assert!(park_prepared_edit(&mut sched, &mut frame, region.table()).is_none());
            let mut root = portal.root(mm, 1).unwrap();
            let range = ReservationRange::new(VA, VA + 4096).unwrap();
            let decision = match nr {
                215 => root.munmap(range),
                226 => root.mprotect(range, ReservationProtection::from_bits(1).unwrap()),
                _ => root.mremap(
                    ReservationRange::new(VA, VA + 8192).unwrap(),
                    4096,
                    crate::memory::reservations::MoveTarget::InPlace,
                ),
            }
            .unwrap();
            let crate::memory::reservations::Decision::Work(edit) = decision else {
                panic!("resumed edit must apply");
            };
            root.complete(unsafe {
                carrick_el1_abi::ReservationCompletion::after_descriptor_and_backing_commit(
                    edit,
                    carrick_el1_abi::ReservationBackingReceipt {
                        receipt: 1,
                        granted_bytes: 0,
                        returned_bytes: 0,
                    },
                )
                .unwrap()
            })
            .unwrap();
            match nr {
                215 => assert!(root.mapping(VA).is_none()),
                226 => assert_eq!(root.mapping(VA).unwrap().protection.bits(), 1),
                _ => assert!(root.mapping(VA + 4096).is_none()),
            }
            assert_eq!(zone.counters.el1_parks.load(Ordering::Relaxed), 1);
        }
    }
}

#[test]
fn prepared_copy_elastic_aggregate_prepare_and_settlement_have_linear_work() {
    for count in [16usize, 64, 256, 320] {
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
                TransferIntent::UserWrite,
                0,
            )
            .unwrap();
        let request = selected(select(&portal, &transfer, &tables))
            .request(TransferIntent::UserWrite, retained())
            .unwrap();
        let mut root = portal.root(mm, 1).unwrap();
        let mut permits = Vec::with_capacity(count);
        root.work = 0;
        for _ in 0..count {
            permits.push(root.prepare_copy(request, None).unwrap());
        }
        assert_eq!(
            root.work, count,
            "preparation must not visit already active record pages"
        );
        assert!(root.has_prepared_copy());
        for permit in permits {
            assert!(
                region
                    .table()
                    .claim_prepared(Some(&view), permit, request)
                    .unwrap()
                    .release()
            );
        }
        root.reap_prepared();
        assert_eq!(
            root.work,
            count * 2,
            "each settlement unlinks one owned record directly"
        );
        assert!(!root.has_prepared_copy());
        root.work = 0;
        root.reap_prepared();
        assert_eq!(root.work, 0, "settled history must not accumulate");
    }
}

#[test]
fn prepared_copy_rejected_tuple_cannot_overwrite_concurrent_claim() {
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
            TransferIntent::UserWrite,
            0,
        )
        .unwrap();
    let request = selected(select(&portal, &transfer, &tables))
        .request(TransferIntent::UserWrite, retained())
        .unwrap();
    let permit = prepare_transfer(&portal, request, &tables.live(&CallerInvalidatesAsid), 0)
        .unwrap()
        .unwrap();
    let mut rejected = request;
    rejected.selected.offset += 1;
    let paused = std::sync::Barrier::new(2);
    let resume = std::sync::Barrier::new(2);
    let owner = region.table();
    std::thread::scope(|scope| {
        let rejecting = scope.spawn(|| {
            assert!(
                owner
                    .claim_prepared_with_rejection::<NoPin>(None, permit, rejected, || {
                        paused.wait();
                        resume.wait();
                    })
                    .is_err()
            );
        });
        paused.wait();
        // Old code releases early here; fixed code keeps rejection custody
        // until its sole rollback. Both paths must preserve the next claimant.
        let early = owner.claim_prepared::<NoPin>(None, permit, request).ok();
        resume.wait();
        rejecting.join().unwrap();
        let legitimate = early.unwrap_or_else(|| {
            owner
                .claim_prepared::<NoPin>(None, permit, request)
                .unwrap()
        });
        assert!(
            owner
                .claim_prepared::<NoPin>(None, permit, request)
                .is_err(),
            "rejection rollback must not make a legitimate COPYING claim stealable"
        );
        assert!(
            legitimate.release(),
            "legitimate claimant must settle successfully"
        );
    });
}

fn schedulerless_settlement_preserves_prepared_permit(cancel: bool) {
    use crate::substrate::sched::{FakeCpu, HardwareUserWord, Sched, Served};
    use carrick_el1_abi::{Counters, CurrentTask, El1TaskId, SlotId, TrapFrame};
    let region = Region::new();
    let zone = region.zone();
    let mm = admit_notified(&region, 77, ROOT, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(
        NonZeroU64::new(1).unwrap(),
        region.table(),
        &zone.spaces,
        &view,
    )
    .with_zone(zone)
    .unwrap();
    let plain = MmPortal::new(
        NonZeroU64::new(1).unwrap(),
        region.table(),
        &zone.spaces,
        &view,
    );
    let tables = Tables::new(ROOT, IPA, 1);
    let transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(VA),
            4096,
            TransferIntent::UserWrite,
            0,
        )
        .unwrap();
    let request = selected(select(&portal, &transfer, &tables))
        .request(TransferIntent::UserWrite, retained())
        .unwrap();
    let permit = prepare_transfer(&portal, request, &tables.live(&CallerInvalidatesAsid), 0)
        .unwrap()
        .unwrap();
    let slot = SlotId::from_index(0).unwrap();
    zone.drive(slot, 1);
    zone.publish_slot(slot, mm.raw(), None, 0);
    assert!(
        zone.occupancy
            .replace(carrick_sched_core::ExecutionSlot::zone(slot), 0, mm.raw())
    );
    zone.enter_guest(slot);
    let task = CurrentTask::new();
    task.set(El1TaskId::from_linux_tid(101), 1, 5);
    task.zone_mm.store(mm.raw(), Ordering::Release);
    task.thread_serial.store(1101, Ordering::Release);
    task.mark_pending_host_work();
    let counters = Counters::default();
    let mut cpu = FakeCpu::default();
    let mut frame = TrapFrame::default();
    frame.x[8] = 215;
    frame.x[0] = VA;
    frame.x[1] = 4096;
    frame.elr = 0x1004;
    let original = frame.x;
    let mut sched = Sched {
        zone,
        slot,
        task: &task,
        cpu: &mut cpu,
        user: &HardwareUserWord,
        counters: &counters,
    };
    assert!(matches!(
        park_prepared_edit(&mut sched, &mut frame, region.table()),
        Some(Served::Idle)
    ));
    let key = portal.prepared_wait_key(transfer.handle).unwrap();
    assert_eq!(zone.object_queue_census(key.index()).unwrap().waiters, 1);
    if cancel {
        assert_eq!(
            plain.cancel_prepared(permit, request, 0),
            Err(MmError::Core)
        );
    } else {
        let wire = carrick_el1_abi::PortalTransferSlot::new();
        let mut ticket = wire.submit_commit(request, permit, 4096).unwrap();
        let copied = core::cell::Cell::new(false);
        assert_eq!(
            serve_transfer(
                &plain,
                wire.claim().unwrap(),
                &tables.live(&CallerInvalidatesAsid),
                0,
                || {
                    copied.set(true);
                    assert!(ticket.copy_requested(|_| true));
                }
            ),
            Err(MmError::Core)
        );
        assert!(
            !copied.get(),
            "delivery authentication must precede any copy effect"
        );
        assert_eq!(
            ticket.take_completion().unwrap().errno,
            MmError::Core.errno()
        );
    }
    assert_eq!(zone.object_queue_census(key.index()).unwrap().waiters, 1);
    portal
        .cancel_prepared(permit, request, 0)
        .expect("delivery refusal must preserve rightful cancellation custody");
    assert_eq!(zone.object_queue_census(key.index()).unwrap().waiters, 0);
    let switched = zone
        .switch_in_full(slot)
        .expect("correct cancellation must wake enrolled edit");
    let context = unsafe { zone.record(switched.record).ctx_mut() };
    assert_eq!(context.x, original);
    assert_eq!(context.pc, 0x1000);
}

#[test]
fn prepared_copy_schedulerless_cancel_preserves_rightful_wake() {
    schedulerless_settlement_preserves_prepared_permit(true);
}

#[test]
fn prepared_copy_schedulerless_commit_refuses_before_copy_and_preserves_rightful_wake() {
    schedulerless_settlement_preserves_prepared_permit(false);
}

#[test]
fn prepared_copy_metadata_capacity_suspends_before_source_and_recovers_after_cancel() {
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
            4096,
            TransferIntent::UserWrite,
            0,
        )
        .unwrap();
    let request = selected(select(&portal, &transfer, &tables))
        .request(TransferIntent::UserWrite, retained())
        .unwrap();
    let mut permits = Vec::new();
    {
        let mut root = portal.root(mm, 1).unwrap();
        loop {
            match root.prepare_copy(request, None) {
                Ok(permit) => permits.push(permit),
                Err(crate::memory::reservations::Refusal::MetadataRequired) => break,
                other => panic!("unexpected admission {other:?}"),
            }
        }
    }
    assert!(
        permits.len() > 256,
        "record capacity follows elastic metadata authority, not a guessed slot cap"
    );
    let wire = carrick_el1_abi::PortalTransferSlot::new();
    let mut ticket = wire.submit_prepare(request).unwrap();
    serve_transfer(
        &portal,
        wire.claim().unwrap(),
        &tables.live(&maintenance),
        0,
        || panic!("capacity suspension must precede source consumption"),
    )
    .unwrap();
    assert_eq!(
        ticket.take_prepare_suspension(),
        Some(carrick_el1_abi::PortalPrepareSuspension::ReservationMetadata)
    );
    for permit in permits {
        portal.cancel_prepared(permit, request, 0).unwrap();
    }
    let recovered = prepare_transfer(&portal, request, &tables.live(&maintenance), 0)
        .unwrap()
        .unwrap();
    portal.cancel_prepared(recovered, request, 0).unwrap();
}

#[test]
fn prepared_copy_hardware_settlement_seam_needs_no_live_grant_or_descriptor_words() {
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
            4096,
            TransferIntent::UserWrite,
            0,
        )
        .unwrap();
    let request = selected(select(&portal, &transfer, &tables))
        .request(TransferIntent::UserWrite, retained())
        .unwrap();
    let permit = prepare_transfer(&portal, request, &tables.live(&maintenance), 0)
        .unwrap()
        .unwrap();
    spaces.close(spaces.find(mm.raw()).unwrap());
    assert!(
        spaces
            .grant(spaces.find(mm.raw()).unwrap(), mm.raw())
            .is_none()
    );
    let wire = carrick_el1_abi::PortalTransferSlot::new();
    let mut ticket = wire.submit_commit(request, permit, 4096).unwrap();
    let root = portal.root(mm, 1).unwrap();
    // This is the exact hardware phase seam. It has no descriptor words or
    // SpaceGrant parameter; target-table lookup follows only the other phases.
    production::settle_prepared_service(&portal, wire.claim().unwrap(), permit, 0, || {
        assert!(ticket.copy_requested(|_| true))
    })
    .unwrap();
    assert_eq!(ticket.take_completion().unwrap().completed, 4096);
    drop(root);
}

fn prepare_reports_exact_release_cause(cause: carrick_el1_abi::PortalWaitCause) {
    use carrick_el1_abi::{PortalOwnerWait, PortalPrepareSuspension, PortalWaitCause};
    use carrick_sched_core::spaces::notification::SpaceWaitCause;
    let region = Region::new();
    let zone = region.zone();
    let mm = admit_notified(&region, 77, ROOT, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(
        NonZeroU64::new(1).unwrap(),
        region.table(),
        &zone.spaces,
        &view,
    )
    .with_zone(zone)
    .unwrap();
    let tables = Tables::new(ROOT, IPA, 1);
    let handle = portal.admitted_handle(mm, 0).unwrap();
    let transfer = portal
        .begin(handle, GuestVa::new(VA), 4096, TransferIntent::UserWrite, 0)
        .unwrap();
    let request = selected(select(&portal, &transfer, &tables))
        .request(TransferIntent::UserWrite, retained())
        .unwrap();
    let entry = zone
        .space_entry(NonZeroU64::new(mm.raw()).unwrap())
        .unwrap();
    let source = entry.notifications(handle.incarnation()).unwrap();
    let space_cause = match cause {
        PortalWaitCause::Editor => SpaceWaitCause::Editor,
        PortalWaitCause::Reservations => SpaceWaitCause::Reservations,
        PortalWaitCause::Gate => SpaceWaitCause::Gate,
        _ => unreachable!(),
    };
    let access = portal.space_access(1).unwrap();
    let editor = (cause == PortalWaitCause::Editor).then(|| {
        access
            .try_begin_edit(entry.index(), mm.raw(), NonZeroU64::new(2).unwrap())
            .unwrap()
    });
    let root = (cause == PortalWaitCause::Reservations).then(|| portal.root(mm, 1).unwrap());
    if cause == PortalWaitCause::Gate {
        access.raise(entry.index());
    }
    let revision = source.observe(space_cause).revision();
    let wire = carrick_el1_abi::PortalTransferSlot::new();
    let mut ticket = wire.submit_prepare(request).unwrap();
    let result = serve_transfer(
        &portal,
        wire.claim().unwrap(),
        &tables.live(&CallerInvalidatesAsid),
        0,
        || panic!("PREPARE suspension must precede source consumption"),
    );
    let actual = ticket.take_prepare_suspension();
    // Clean up before assertions, including the historical completed-error path.
    let _ = ticket.take_completion();
    drop(root);
    drop(editor);
    if cause == PortalWaitCause::Gate {
        access.lower(entry.index());
    }
    assert_eq!(result, Ok(()));
    assert_eq!(
        actual,
        Some(PortalPrepareSuspension::Owner(unsafe {
            PortalOwnerWait::from_owner(handle, cause, revision)
        }))
    );
}
#[test]
fn prepare_reports_editor_release_cause() {
    prepare_reports_exact_release_cause(carrick_el1_abi::PortalWaitCause::Editor);
}
#[test]
fn prepare_reports_root_release_cause() {
    prepare_reports_exact_release_cause(carrick_el1_abi::PortalWaitCause::Reservations);
}
#[test]
fn prepare_reports_gate_release_cause() {
    prepare_reports_exact_release_cause(carrick_el1_abi::PortalWaitCause::Gate);
}

fn owner_wait_enrollment_follows_only_its_real_release(
    cause: carrick_el1_abi::PortalWaitCause,
    before: bool,
) {
    use carrick_el1_abi::{PortalPrepareSuspension, PortalWaitCause};
    use carrick_sched_core::object_wait::{
        ObjectWaitError, OperationToken, OwnedObjectWakeEffects,
    };
    use carrick_sched_core::{BoundedSpin, Claim, ThreadIdentity};
    let region = Region::new();
    let zone = region.zone();
    let mm = admit_notified(&region, 77, ROOT, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(
        NonZeroU64::new(1).unwrap(),
        region.table(),
        &zone.spaces,
        &view,
    )
    .with_zone(zone)
    .unwrap();
    let tables = Tables::new(ROOT, IPA, 1);
    let handle = portal.admitted_handle(mm, 0).unwrap();
    let transfer = portal
        .begin(handle, GuestVa::new(VA), 4096, TransferIntent::UserWrite, 0)
        .unwrap();
    let request = selected(select(&portal, &transfer, &tables))
        .request(TransferIntent::UserWrite, retained())
        .unwrap();
    let entry = zone
        .space_entry(NonZeroU64::new(mm.raw()).unwrap())
        .unwrap();
    let access = portal.space_access(1).unwrap();
    let mut editor = (cause == PortalWaitCause::Editor).then(|| {
        access
            .try_begin_edit(entry.index(), mm.raw(), NonZeroU64::new(2).unwrap())
            .unwrap()
    });
    let mut root = (cause == PortalWaitCause::Reservations).then(|| portal.root(mm, 1).unwrap());
    if cause == PortalWaitCause::Gate {
        access.raise(entry.index());
    }
    let pending = if cause == PortalWaitCause::PendingEdit {
        let mut root = portal.root(mm, 1).unwrap();
        let crate::memory::reservations::Decision::Work(request) = root
            .mprotect(
                ReservationRange::new(VA, VA + 4096).unwrap(),
                ReservationProtection::from_bits(1).unwrap(),
            )
            .unwrap()
        else {
            panic!("fixture needs pending proposal");
        };
        Some(request)
    } else {
        None
    };
    let wire = carrick_el1_abi::PortalTransferSlot::new();
    let mut ticket = wire.submit_prepare(request).unwrap();
    serve_transfer(
        &portal,
        wire.claim().unwrap(),
        &tables.live(&CallerInvalidatesAsid),
        0,
        || panic!("no consuming effect"),
    )
    .unwrap();
    let Some(PortalPrepareSuspension::Owner(receipt)) = ticket.take_prepare_suspension() else {
        panic!("exact owner wait required");
    };
    assert_eq!(receipt.cause(), cause);
    let slots = region.portal_slots();
    assert!(slots.bind_carrier(handle.carrier()));
    let enrollment = slots.authenticate_wait(zone, receipt).unwrap();
    let other = Region::new();
    assert!(
        slots.authenticate_wait(other.zone(), receipt).is_err(),
        "same numeric identity cannot cross carrier regions"
    );
    let record = zone
        .alloc_record(ThreadIdentity {
            tid: 101,
            serial: 1001,
            mm: mm.raw(),
            file_table: 1,
            generation: 1,
            affinity: 0,
            lifecycle_page: 0,
            control_slot: 0,
        })
        .unwrap();
    let operation = OperationToken::new(701, 11).unwrap();
    let complete = |owned: OwnedObjectWakeEffects<'_>| {
        let _ = owned.defer_handbacks();
    };
    let release = |editor: &mut Option<_>, root: &mut Option<_>| {
        drop(root.take());
        drop(editor.take());
        if cause == PortalWaitCause::Gate {
            access.lower(entry.index());
        }
        if let Some(request) = pending {
            portal.root(mm, 1).unwrap().refuse(request).unwrap();
        }
    };
    if before {
        release(&mut editor, &mut root);
        let (error, returned) = enrollment
            .park_host(record, operation, &complete)
            .unwrap_err();
        assert_eq!(error, ObjectWaitError::Changed);
        assert_eq!(returned.index(), 701);
        assert!(!zone.record(record).has_object_operation());
    } else {
        enrollment.park_host(record, operation, &complete).unwrap();
        // A real, unrelated root/editor release must neither consume nor reschedule this operation.
        if cause != PortalWaitCause::Reservations {
            drop(portal.root(mm, 2).unwrap());
        } else {
            drop(
                access
                    .try_begin_edit(entry.index(), mm.raw(), NonZeroU64::new(3).unwrap())
                    .unwrap(),
            );
        }
        assert!(matches!(zone.record(record).claim(), Claim::Parked { .. }));
        release(&mut editor, &mut root);
        let mut delivered = Vec::new();
        zone.take_completion_handbacks(&BoundedSpin(0), &mut |record| delivered.push(record));
        assert_eq!(delivered, [zone.record_ref(record)]);
        assert!(zone.record(record).object_host_continuation());
        assert_eq!(
            unsafe { zone.record(record).take_object_operation() }
                .unwrap()
                .index(),
            701
        );
        zone.take_completion_handbacks(&BoundedSpin(0), &mut |_| panic!("duplicate completion"));
    }
    zone.free_record(record);
}
#[test]
fn owner_wait_release_before_enrollment_never_parks_a_lost_edge() {
    use carrick_el1_abi::PortalWaitCause::*;
    for cause in [Editor, Reservations, Gate, PendingEdit] {
        owner_wait_enrollment_follows_only_its_real_release(cause, true);
    }
}
#[test]
fn owner_wait_unrelated_release_cannot_reschedule_and_real_release_delivers_once() {
    use carrick_el1_abi::PortalWaitCause::*;
    for cause in [Editor, Reservations, Gate, PendingEdit] {
        owner_wait_enrollment_follows_only_its_real_release(cause, false);
    }
}

#[test]
fn owner_wait_queue_admission_busy_retains_owned_handback_until_unlock() {
    use carrick_el1_abi::{PortalOwnerWait, PortalWaitCause};
    use carrick_sched_core::object_wait::{OperationToken, OwnedObjectWakeEffects};
    use carrick_sched_core::spaces::notification::SpaceWaitCause;
    use carrick_sched_core::{BoundedSpin, ThreadIdentity};
    let region = Region::new();
    let zone = region.zone();
    let mm = admit_notified(&region, 77, ROOT, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(
        NonZeroU64::new(1).unwrap(),
        region.table(),
        &zone.spaces,
        &view,
    )
    .with_zone(zone)
    .unwrap();
    let handle = portal.admitted_handle(mm, 0).unwrap();
    let entry = zone
        .space_entry(NonZeroU64::new(mm.raw()).unwrap())
        .unwrap();
    let source = entry.notifications(handle.incarnation()).unwrap();
    let revision = source.observe(SpaceWaitCause::Editor).revision();
    let editor = portal
        .space_access(1)
        .unwrap()
        .try_begin_edit(entry.index(), mm.raw(), NonZeroU64::new(2).unwrap())
        .unwrap();
    assert!(
        portal
            .space_access(0)
            .unwrap()
            .try_begin_edit(entry.index(), mm.raw(), NonZeroU64::new(1).unwrap())
            .is_none()
    );
    let receipt = unsafe { PortalOwnerWait::from_owner(handle, PortalWaitCause::Editor, revision) };
    let slots = region.portal_slots();
    assert!(slots.bind_carrier(handle.carrier()));
    let enrollment = slots.authenticate_wait(zone, receipt).unwrap();
    let delivered = core::cell::RefCell::new(Vec::new());
    let complete = |owned: OwnedObjectWakeEffects<'_>| {
        let _ = owned.deliver_handbacks(&mut |r| delivered.borrow_mut().push(r));
    };
    let queue = zone
        .object_wait_with_completion(
            source.key(SpaceWaitCause::Editor),
            &BoundedSpin(0),
            &complete,
        )
        .unwrap();
    let record = zone
        .alloc_record(ThreadIdentity {
            tid: 101,
            serial: 1001,
            mm: mm.raw(),
            file_table: 1,
            generation: 1,
            affinity: 0,
            lifecycle_page: 0,
            control_slot: 0,
        })
        .unwrap();
    let result = enrollment.park_host(record, OperationToken::new(701, 11).unwrap(), &complete);
    assert!(
        delivered.borrow().is_empty(),
        "queue release is the admission producer"
    );
    drop(queue);
    let actual = delivered.borrow().clone();
    let expected = zone.record_ref(record);
    let operation = unsafe { zone.record(record).take_object_operation() };
    zone.free_record(record);
    drop(editor);
    assert_eq!(
        source.observe(SpaceWaitCause::Editor).revision(),
        revision + 1,
        "admission does not manufacture resource revisions"
    );
    assert!(
        result.is_ok(),
        "Busy must retain an owned admission handback: {result:?}"
    );
    assert_eq!(actual, [expected]);
    assert_eq!(operation.unwrap().index(), 701);
}

#[test]
fn selected_data_retains_exact_pre_selection_reservation_observation() {
    use carrick_sched_core::spaces::notification::SpaceWaitCause;
    let region = Region::new();
    let zone = region.zone();
    let mm = admit_notified(&region, 77, ROOT, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(
        NonZeroU64::new(1).unwrap(),
        region.table(),
        &zone.spaces,
        &view,
    )
    .with_zone(zone)
    .unwrap();
    let handle = portal.admitted_handle(mm, 0).unwrap();
    let transfer = portal
        .begin(handle, GuestVa::new(VA), 4, TransferIntent::UserRead, 0)
        .unwrap();
    let entry = zone
        .space_entry(NonZeroU64::new(mm.raw()).unwrap())
        .unwrap();
    let source = entry.notifications(handle.incarnation()).unwrap();
    let revision = source.observe(SpaceWaitCause::Reservations).revision();
    let tables = Tables::new(ROOT, IPA, 1);
    let chosen = selected(select(&portal, &transfer, &tables));
    let wait = chosen.retry.unwrap();
    assert_eq!(wait.handle(), handle);
    assert_eq!(wait.cause(), carrick_el1_abi::PortalWaitCause::Reservations);
    assert_eq!(wait.revision(), revision);
    assert_ne!(
        source.observe(SpaceWaitCause::Reservations).revision(),
        revision
    );
}
