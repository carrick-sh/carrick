//! The production reservation/permit owner, exercised over x86 descriptors.
use super::test_support::*;
use super::*;
use crate::fault::{NoopCowResolver, NoopPreparedResolver};
use carrick_mmu_core::aarch64::descriptor_txn::CallerInvalidatesAsid;
use carrick_mmu_core::x86::descriptor_txn::{NX, PRESENT, USER, WRITE};
use carrick_sched_core::AddressSpaces;
use core::sync::atomic::Ordering;

fn transfer_fixture(pages: usize, unrelated: usize) {
    let region = Region::new();
    region.add_bank();
    let spaces = AddressSpaces::new();
    let mms = [
        admit(&region, &spaces, 1, ROOT, pages, unrelated),
        admit(&region, &spaces, 2, ROOT + 0x10000, pages, 512),
    ];
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view)
        .with_mmu(carrick_mmu_core::x86::owner_mmu::X86Mmu);
    for (index, mm) in mms.into_iter().enumerate() {
        let tables = Tables::new(
            ROOT + index as u64 * 0x10000,
            IPA + index as u64 * 0x1000000,
            pages,
        );
        for (entry, offset) in [(0, 4096), (513, 8192), (1024, 12288)] {
            tables.words[entry].store(
                (tables.base + offset) | PRESENT | WRITE | USER,
                Ordering::Relaxed,
            );
        }
        for page in 0..pages {
            tables.words[1536 + page].store(
                (IPA + index as u64 * 0x1000000 + page as u64 * 4096) | PRESENT | WRITE | USER | NX,
                Ordering::Relaxed,
            );
        }
        let maintenance = CallerInvalidatesAsid;
        let live = tables.live(&maintenance);
        let words = CountWords {
            words: &live,
            loads: core::cell::Cell::new(0),
        };
        let mut transfer = portal
            .begin(
                portal.admitted_handle(mm, 0).unwrap(),
                GuestVa::new(VA),
                pages as u64 * 4096,
                TransferIntent::UserWrite,
                0,
            )
            .unwrap();
        for page in 0..pages {
            let step = portal
                .select(
                    &transfer,
                    &words,
                    carrick_core::mm::transaction::SelectionVenues {
                        prepared: &mut NoopPreparedResolver,
                        cow: &mut NoopCowResolver,
                        residency: &residency(),
                        slot: 0,
                    },
                )
                .unwrap();
            let TransferStep::Selected(selected) = step else {
                panic!("resident x86 owner page must be selected: {step:?}")
            };
            assert_eq!(
                selected.ipa,
                IPA + index as u64 * 0x1000000 + page as u64 * 4096
            );
            assert!(!selected.executable);
            portal
                .revalidate(&transfer, selected, &words, 0)
                .unwrap()
                .unwrap()
                .complete(&mut transfer)
                .unwrap();
        }
        assert!(transfer.is_complete());
        assert_eq!(
            words.loads.get(),
            8 * pages,
            "two four-level walks per touched page; unrelated reservations add no descriptor work"
        );
    }
}

#[test]
fn x86_transfer_16_pages() {
    transfer_fixture(16, 16);
}
#[test]
fn x86_transfer_64_pages() {
    transfer_fixture(64, 16);
}
#[test]
fn x86_transfer_256_pages() {
    transfer_fixture(256, 16);
}

#[test]
fn x86_wrong_output_pin_refuses_before_preparing_copy() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mms = [
        admit(&region, &spaces, 1, ROOT, 1, 16),
        admit(&region, &spaces, 2, ROOT + 0x10000, 1, 16),
    ];
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view)
        .with_mmu(carrick_mmu_core::x86::owner_mmu::X86Mmu);
    let tables = Tables::new(ROOT, IPA, 1);
    for (entry, offset) in [(0, 4096), (513, 8192), (1024, 12288)] {
        tables.words[entry].store((ROOT + offset) | PRESENT | WRITE | USER, Ordering::Relaxed);
    }
    tables.words[1536].store(IPA | PRESENT | WRITE | USER | NX, Ordering::Relaxed);
    let maintenance = CallerInvalidatesAsid;
    let words = tables.live(&maintenance);
    let transfer = portal
        .begin(
            portal.admitted_handle(mms[0], 0).unwrap(),
            GuestVa::new(VA),
            4096,
            TransferIntent::UserWrite,
            0,
        )
        .unwrap();
    let TransferStep::Selected(selected) = portal
        .select(
            &transfer,
            &words,
            carrick_core::mm::transaction::SelectionVenues {
                prepared: &mut NoopPreparedResolver,
                cow: &mut NoopCowResolver,
                residency: &residency(),
                slot: 0,
            },
        )
        .unwrap()
    else {
        panic!("resident page must select")
    };
    let mut request = selected
        .request(
            TransferIntent::UserWrite,
            carrick_el1_abi::PortalRetainedData {
                record: NonZeroU64::new(7).unwrap(),
                vm_generation: NonZeroU64::new(1).unwrap(),
                owner: Some((NonZeroU64::new(3).unwrap(), NonZeroU64::new(1).unwrap())),
            },
        )
        .unwrap();
    request.selected.ipa += 0x1000000; // same VA, peer physical output
    assert!(
        prepare_transfer(&portal, request, &words, 0)
            .unwrap()
            .is_none()
    );
    assert!(
        !region
            .table()
            .lock(spaces.find(mms[0].raw()).unwrap().index(), mms[0])
            .unwrap()
            .has_prepared_copy()
    );
}
