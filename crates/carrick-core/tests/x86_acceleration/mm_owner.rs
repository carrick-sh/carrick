//! Original ARM AM assertions moved with the transaction owner.
use carrick_core::mm::transaction::*;
use carrick_core::mm::transfer::*;
use carrick_core_abi::{
    PortalTransferIntent as TransferIntent, ReservationProtection, ReservationRange,
};
use carrick_el1::memory::reservations::NativeReservationGeometry;
use carrick_el1::personality::mm_portal::NativeOwnerVenue;
use carrick_el1::personality::mm_portal::test_support::*;
use carrick_mmu_core::aarch64::descriptor_txn::CallerInvalidatesAsid;
use carrick_personality_linux::mm::LinuxReservationPolicy;
use carrick_sched_core::AddressSpaces;
use core::num::NonZeroU64;
use core::sync::atomic::Ordering;

type FixturePortal<'a> =
    MmPortal<'a, NoPin, LinuxReservationPolicy, NativeReservationGeometry, NativeOwnerVenue>;

fn retained() -> carrick_core_abi::PortalRetainedData {
    carrick_core_abi::PortalRetainedData {
        record: NonZeroU64::new(7).unwrap(),
        vm_generation: NonZeroU64::new(1).unwrap(),
        owner: Some((NonZeroU64::new(3).unwrap(), NonZeroU64::new(1).unwrap())),
    }
}

#[test]
pub(super) fn transfer_revalidates_exact_mm_before_copy() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 2, 0);
    let view = nodes(&region);
    let portal = FixturePortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
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
pub(super) fn prepared_copy_commit_and_cancel_never_acquire_held_root_or_editor() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 2, 0);
    let view = nodes(&region);
    let portal = FixturePortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view);
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
    let slot = carrick_core_abi::PortalTransferSlot::new();
    let mut ticket = slot.submit_prepare(request).unwrap();
    let admission = admit_transfer_service(&portal, &slot).unwrap().unwrap();
    let TransferServiceAdmission::NeedsWords { service, grant } = admission else {
        panic!("prepare must authenticate its live root")
    };
    assert_eq!(grant.ttbr0, ROOT);
    serve_transfer(&portal, service, &tables.live(&maintenance), 0, || {
        panic!("prepare must not copy")
    })
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
    if let carrick_core::mm::reservation::Decision::Work(request) = decision {
        root.complete(unsafe {
            carrick_core_abi::ReservationCompletion::after_descriptor_and_backing_commit(
                request,
                carrick_core_abi::ReservationBackingReceipt {
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
        FixturePortal::new(NonZeroU64::new(99).unwrap(), region.table(), &spaces, &view);
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
fn arm_unbound_carrier_transfer_has_exact_esrch_completion() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 1, 0);
    let view = nodes(&region);
    let portal = FixturePortal::new(NonZeroU64::MIN, region.table(), &spaces, &view);
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
    let slots = carrick_el1_abi::MmPortalSlots::new();
    let slot = slots.slot(0).unwrap();
    let mut ticket = slot.submit_prepare(request).unwrap();
    // The facade must settle before accessing the unrelated empty zone/root:
    // missing carrier authority has exactly the former ESRCH outcome.
    let layout = std::alloc::Layout::new::<carrick_sched_core::ZoneTables>();
    let zone = unsafe {
        let ptr = std::alloc::alloc_zeroed(layout).cast::<carrick_sched_core::ZoneTables>();
        assert!(!ptr.is_null());
        Box::from_raw(ptr)
    };
    let _ = carrick_el1::personality::mm_portal::production::admit_transfer_hw(
        &slots,
        &zone,
        region.table(),
        slot,
    );
    let outcome = ticket
        .take_completion()
        .expect("unbound production ARM slot must complete rather than remain unsettled");
    assert_eq!(outcome.operation, request.operation);
    assert_eq!(outcome.retained, request.retained);
    assert_eq!(outcome.completed, 0);
    assert_eq!(outcome.errno, 3);
    assert!(ticket.take_completion().is_none());
}
