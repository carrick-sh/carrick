//! The production reservation/permit owner, exercised over x86 descriptors.
use super::test_support::*;
use super::*;
use crate::fault::{NoopCowResolver, NoopPreparedResolver};
use carrick_mmu_core::aarch64::descriptor_txn::CallerInvalidatesAsid;
use carrick_mmu_core::x86::descriptor_txn::{NX, PRESENT, USER, WRITE};
use carrick_sched_core::AddressSpaces;
use core::sync::atomic::Ordering;

#[test]
fn x86_owner_transfer_scales_with_touched_pages_and_preserves_two_mm_identity() {
    for pages in [16, 64, 256] {
        let mut region = Region::new();
        region.add_bank();
        let spaces = AddressSpaces::new();
        let mms = [
            admit(&region, &spaces, 1, ROOT, pages, 0),
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
                    (IPA + index as u64 * 0x1000000 + page as u64 * 4096)
                        | PRESENT
                        | WRITE
                        | USER
                        | NX,
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
                        &mut NoopPreparedResolver,
                        &mut NoopCowResolver,
                        &residency(),
                        0,
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
}
