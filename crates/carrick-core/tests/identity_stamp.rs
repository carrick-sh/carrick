//! The same closed control-write owner through x86 hardware projection.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use carrick_core::mm::transaction::MmError;
use carrick_core::mm::transaction::{MmPortal, TransferStep};
use carrick_core::mm::transfer::resolver::{NoopCowResolver, NoopPreparedResolver};
use carrick_core::mm::transfer::{GuestVa, SelectedChunk, TransferContinuation};
use carrick_core_abi::PortalTransferIntent as TransferIntent;
use carrick_el1::personality::mm_portal::NativeOwnerVenue;
use carrick_el1::personality::mm_portal::test_support::*;
use carrick_mmu_core::aarch64::descriptor_txn::CallerInvalidatesAsid;
use carrick_mmu_core::x86::owner_mmu::X86Mmu;
use carrick_sched_core::AddressSpaces;
use core::num::NonZeroU64;
use core::sync::atomic::Ordering;
fn selected(step: TransferStep) -> SelectedChunk {
    match step {
        TransferStep::Selected(chunk) => chunk,
        other => panic!("control stamp did not select physical bytes: {other:?}"),
    }
}
#[test]
fn x86_identity_stamp_selects_private_control_in_two_live_mms() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let first = admit(&region, &spaces, 77, ROOT, 1, 0);
    let second = admit(&region, &spaces, 78, ROOT + 0x100000, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::<_, _, _, NativeOwnerVenue>::new(
        NonZeroU64::new(1).unwrap(),
        region.table(),
        &spaces,
        &view,
    )
    .with_mmu(X86Mmu);
    let first_tables = Tables::new(ROOT, IPA, 0);
    let second_tables = Tables::new(ROOT + 0x100000, IPA + 0x4000, 0);
    let word = carrick_el1_abi::CarrickIdentityWrite::ShimGate(0);
    let address = word.address(
        carrick_core_abi::IdentityControlBase::new(carrick_el1_abi::CARRICK_IDENTITY_PAGE_BASE)
            .unwrap(),
    );
    for (mm, tables, ipa) in [
        (first, &first_tables, IPA),
        (second, &second_tables, IPA + 0x4000),
    ] {
        tables.words[512 + ((address >> 30) & 511) as usize]
            .store((tables.base + 8192) | 3, Ordering::Relaxed);
        tables.words[1024 + ((address >> 21) & 511) as usize]
            .store((tables.base + 12288) | 3, Ordering::Relaxed);
        tables.words[1536 + ((address >> 12) & 511) as usize]
            .store(ipa | 3 | (1 << 63), Ordering::Relaxed);
        let handle = portal.admitted_handle(mm, 0).unwrap();
        let user = portal
            .begin(
                handle,
                GuestVa::new(address),
                4,
                TransferIntent::UserWrite,
                0,
            )
            .unwrap();
        let select_control = |transfer: &TransferContinuation| {
            portal.select(
                transfer,
                &tables.live(&CallerInvalidatesAsid),
                carrick_core::mm::transaction::SelectionVenues {
                    prepared: &mut NoopPreparedResolver,
                    cow: &mut NoopCowResolver,
                    residency: &residency(),
                    slot: 0,
                },
            )
        };
        assert!(matches!(select_control(&user), Err(MmError::Fault)));
        let stamp = portal
            .begin(
                handle,
                GuestVa::new(address),
                4,
                TransferIntent::CarrickIdentityWrite,
                0,
            )
            .unwrap();
        let chunk = selected(
            select_control(&stamp).expect("private control stamp must select through its owner"),
        );
        assert_eq!(chunk.ipa, ipa + word.offset());
        assert!(!chunk.executable);
        assert_eq!(
            tables.words[1536 + ((address >> 12) & 511) as usize].load(Ordering::Acquire)
                & (1 << 2),
            0
        );
        assert!(
            portal
                .revalidate(&stamp, chunk, &tables.live(&CallerInvalidatesAsid), 0)
                .unwrap()
                .is_some()
        );
        let leaf = &tables.words[1536 + ((address >> 12) & 511) as usize];
        let original = leaf.load(Ordering::Acquire);
        leaf.store(original + 0x10000, Ordering::Release);
        assert!(
            portal
                .revalidate(&stamp, chunk, &tables.live(&CallerInvalidatesAsid), 0)
                .unwrap()
                .is_none(),
            "same generation cannot authorize a changed physical output"
        );
        leaf.store(original, Ordering::Release);
        for word in [
            carrick_el1_abi::CarrickIdentityWrite::Pid(701),
            carrick_el1_abi::CarrickIdentityWrite::SyscallCount(0),
            carrick_el1_abi::CarrickIdentityWrite::ClockGate(1),
        ] {
            let transfer = portal
                .begin(
                    handle,
                    GuestVa::new(
                        word.address(
                            carrick_core_abi::IdentityControlBase::new(
                                carrick_el1_abi::CARRICK_IDENTITY_PAGE_BASE,
                            )
                            .unwrap(),
                        ),
                    ),
                    word.len() as u64,
                    TransferIntent::CarrickIdentityWrite,
                    0,
                )
                .unwrap();
            let chunk = selected(select_control(&transfer).unwrap());
            assert_eq!(chunk.ipa, ipa + word.offset());
            assert_eq!(chunk.len, word.len() as u64);
        }
        for (address, len) in [
            (address - 4, 8),
            (address + 16, 4),
            (VA, 4),
            (
                carrick_el1_abi::EL1_REGION_BASE + carrick_el1_abi::EL1_IMAGE_OFFSET,
                4,
            ),
        ] {
            let transfer = portal
                .begin(
                    handle,
                    GuestVa::new(address),
                    len,
                    TransferIntent::CarrickIdentityWrite,
                    0,
                )
                .unwrap();
            assert!(matches!(select_control(&transfer), Err(MmError::Fault)));
        }
        for bad in [
            0,
            original | (1 << 2),
            original & !(1 << 1),
            original & !(1 << 63),
        ] {
            leaf.store(bad, Ordering::Release);
            assert!(
                matches!(select_control(&stamp), Err(MmError::Fault)),
                "missing, user-accessible, readonly or executable control cannot supply a stamp"
            );
        }
        leaf.store(original, Ordering::Release);
    }
}
