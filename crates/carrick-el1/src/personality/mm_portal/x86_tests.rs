//! The production reservation/permit owner, exercised over x86 descriptors.
use super::test_support::*;
use super::*;
use crate::fault::{NoopCowResolver, NoopPreparedResolver};
use carrick_mmu_core::aarch64::descriptor_txn::CallerInvalidatesAsid;
use carrick_mmu_core::x86::descriptor_txn::{NX, PRESENT, USER, WRITE};
use carrick_sched_core::AddressSpaces;
use core::sync::atomic::Ordering;

struct X86ForkWords<'a> {
    arenas: &'a [&'a Tables],
}
impl X86ForkWords<'_> {
    fn word(
        &self,
        pa: u64,
    ) -> Result<
        &core::sync::atomic::AtomicU64,
        carrick_mmu_core::descriptor_refusal::DescriptorRefusal,
    > {
        self.arenas
            .iter()
            .find_map(|arena| {
                pa.checked_sub(arena.base)
                    .filter(|offset| offset.is_multiple_of(8))
                    .and_then(|offset| arena.words.get(offset as usize / 8))
            })
            .ok_or(carrick_mmu_core::descriptor_refusal::DescriptorRefusal::TableOutsidePrimary)
    }
}
impl carrick_mmu_core::x86::descriptor_txn::LiveDescriptorWords for X86ForkWords<'_> {
    fn load(
        &self,
        pa: u64,
    ) -> Result<u64, carrick_mmu_core::descriptor_refusal::DescriptorRefusal> {
        Ok(self.word(pa)?.load(Ordering::Acquire))
    }
    fn compare_exchange(
        &self,
        pa: u64,
        before: u64,
        after: u64,
    ) -> Result<bool, carrick_mmu_core::descriptor_refusal::DescriptorRefusal> {
        Ok(self
            .word(pa)?
            .compare_exchange(before, after, Ordering::AcqRel, Ordering::Acquire)
            .is_ok())
    }
    fn store_unlinked(
        &self,
        pa: u64,
        value: u64,
    ) -> Result<(), carrick_mmu_core::descriptor_refusal::DescriptorRefusal> {
        self.word(pa)?.store(value, Ordering::Release);
        Ok(())
    }
    fn publish_barrier(&self) {}
    fn invalidate_range(&self, _: u64, _: u64) {}
}

#[test]
fn x86_maintenance_reads_only_an_invalid_retired_leaf() {
    use carrick_mmu_core::aarch64::SubstrateGpa;
    use carrick_mmu_core::x86::descriptor_txn::{ADDRESS, PREPARED, RETIRED};
    let tables = Tables::new(ROOT, 0, 0);
    for (entry, offset) in [(0, 4096), (512, 8192), (1024, 12288)] {
        tables.words[entry].store((ROOT + offset) | PRESENT | WRITE | USER, Ordering::Release);
    }
    tables.words[1536].store(IPA | RETIRED | USER, Ordering::Release);
    let arenas = [&tables];
    let words = X86ForkWords { arenas: &arenas };
    assert_eq!(
        super::maintenance::retired_page_x86(&words, SubstrateGpa(ROOT), 0, 4096).unwrap(),
        (Some(IPA & ADDRESS), 4096)
    );
    tables.words[1536].store(IPA | PREPARED | USER, Ordering::Release);
    assert_eq!(
        super::maintenance::retired_page_x86(&words, SubstrateGpa(ROOT), 0, 4096),
        Err(MmError::Fault)
    );
}

#[test]
fn x86_owner_fork_arms_private_parent_and_restores_on_abort() {
    use carrick_el1_abi::{
        PortalForkRequest, PortalForkTableArena, PortalOperation, ReservationMm,
    };
    use carrick_mmu_core::x86::descriptor_txn::{COW, MAY_WRITE, NX};
    let mut region = Region::new();
    region.add_bank();
    let spaces = AddressSpaces::new();
    let parent = admit(&region, &spaces, 77, ROOT, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::MIN, region.table(), &spaces, &view)
        .with_mmu(carrick_mmu_core::x86::owner_mmu::X86Mmu);
    let parent_tables = Tables::new(ROOT, IPA, 1);
    for (entry, offset) in [(0, 4096), (513, 8192), (1024, 12288)] {
        parent_tables.words[entry]
            .store((ROOT + offset) | PRESENT | WRITE | USER, Ordering::Release);
    }
    let original = IPA | PRESENT | WRITE | USER | MAY_WRITE | NX;
    parent_tables.words[1536].store(original, Ordering::Release);
    let child = Tables::new(ROOT + 0x100000, 0, 0);
    let supply = Tables::new(ROOT + 0x200000, 0, 0);
    for arena in [&child, &supply] {
        for word in arena.words.iter() {
            word.store(0, Ordering::Release);
        }
    }
    let child_index = spaces.publish_closed(78, child.base, child.base).unwrap();
    let mut root = region
        .table()
        .lock_el1_resolved(spaces.find(parent.raw()).unwrap().index(), parent, &view, 0)
        .unwrap();
    let request = PortalForkRequest {
        operation: PortalOperation {
            carrier: NonZeroU64::MIN,
            mm: parent,
            incarnation: NonZeroU64::new(root.incarnation().raw()).unwrap(),
            sequence: root.next_transfer_sequence().unwrap(),
        },
        parent_generation: root.generation(),
        child_mm: ReservationMm::new(78).unwrap(),
        child_tables: PortalForkTableArena::new(child.base, child.words.len() as u64 * 8).unwrap(),
        parent_tables: PortalForkTableArena::new(supply.base, supply.words.len() as u64 * 8)
            .unwrap(),
        kernel_control_ipa: 0xa000_0000,
    };
    let layout = root.layout();
    drop(root);
    region
        .table()
        .publish(child_index.index(), request.child_mm, layout)
        .unwrap();
    let arenas = [&parent_tables, &child, &supply];
    let words = X86ForkWords { arenas: &arenas };
    let scratch = ForkScratch::new(request, portal.fork_mapping_count(parent, 0).unwrap()).unwrap();
    let plan = portal.prepare_fork(request, scratch, &words, 0).unwrap();
    let mut unpublished = portal.publish_fork(plan, &words, 0).unwrap();
    let parent_leaf = parent_tables.words[1536].load(Ordering::Acquire);
    let child_leaf = child.words[1536].load(Ordering::Acquire);
    assert_eq!(parent_leaf & (COW | MAY_WRITE | WRITE), COW | MAY_WRITE);
    assert_eq!(child_leaf & (COW | MAY_WRITE | WRITE), COW | MAY_WRITE);
    assert!(spaces.grant(child_index, 78).is_none());
    unpublished.abort(&portal, &words, 0).unwrap();
    assert_eq!(parent_tables.words[1536].load(Ordering::Acquire), original);
    assert!(
        !region
            .table()
            .admitted(child_index.index(), request.child_mm)
    );
}

#[test]
fn x86_portal_grant_publishes_only_its_resident_page() {
    use carrick_mmu_core::aarch64::descriptor_txn::{
        BackingIdentity, DescriptorOp, DescriptorOutcome, DescriptorTxn, DescriptorTxnId, PageSpan,
        TableGrants,
    };
    use carrick_mmu_core::aarch64::{GuestLeafPublication, SubstrateGpa};
    let mut region = Region::new();
    region.add_bank();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 1, ROOT, 2, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::MIN, region.table(), &spaces, &view)
        .with_mmu(carrick_mmu_core::x86::owner_mmu::X86Mmu);
    let tables = Tables::new(ROOT, IPA, 2);
    for (entry, offset) in [(0, 4096), (513, 8192), (1024, 12288)] {
        tables.words[entry].store((ROOT + offset) | PRESENT | WRITE | USER, Ordering::Relaxed);
    }
    tables.words[1536].store(0, Ordering::Relaxed);
    tables.words[1537].store(0, Ordering::Relaxed);
    let maintenance = CallerInvalidatesAsid;
    let words = tables.live(&maintenance);
    let residency = residency();
    let transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(VA),
            4096,
            TransferIntent::UserRead,
            0,
        )
        .unwrap();
    let TransferStep::Supply(window) = portal
        .select(
            &transfer,
            &words,
            carrick_core::mm::transaction::SelectionVenues {
                prepared: &mut NoopPreparedResolver,
                cow: &mut NoopCowResolver,
                residency: &residency,
                slot: 0,
            },
        )
        .unwrap()
    else {
        panic!("unmapped x86 owner page must request backing");
    };
    let one = NonZeroU64::MIN;
    let txn = DescriptorTxn {
        id: DescriptorTxnId {
            mm_key: one,
            generation: one,
        },
        root: SubstrateGpa(ROOT),
        op: DescriptorOp::Prepare {
            publication: GuestLeafPublication {
                va: VA,
                ipa: IPA,
                len: 8192,
                writable: true,
                executable: false,
            },
            resident: PageSpan::new(VA, 4096),
            backing: BackingIdentity {
                frame_id: one,
                mapping_id: one,
                owner_generation: one,
                inventory_revision: one,
            },
        },
        tables: TableGrants::NONE,
    };
    let slot = carrick_el1_abi::PortalGrantSlot::new();
    assert!(slot.submit(window, &txn));
    let receipt = serve_grant(&portal, &slot, &words, &residency, 0, || {})
        .unwrap()
        .unwrap();
    assert!(matches!(receipt.outcome, DescriptorOutcome::Applied(_)));
    assert!(slot.take_receipt(window, &txn).is_some());
    let resident = carrick_mmu_core::x86::descriptor_txn::translate_leaf(
        &words,
        carrick_guest_arch::RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(ROOT)).unwrap(),
        carrick_guest_arch::UserVa::new(VA),
        carrick_mmu_core::x86::descriptor_txn::Access::Read,
        true,
    )
    .unwrap();
    assert_eq!(resident.output.raw(), IPA);
    assert!(matches!(
        carrick_mmu_core::x86::descriptor_txn::translate_leaf(
            &words,
            carrick_guest_arch::RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(ROOT))
                .unwrap(),
            carrick_guest_arch::UserVa::new(VA + 4096),
            carrick_mmu_core::x86::descriptor_txn::Access::Read,
            true,
        ),
        Err(carrick_mmu_core::x86::descriptor_txn::FaultClass::NotPresent)
    ));
}

fn transfer_fixture(pages: usize, unrelated: usize) {
    let mut region = Region::new();
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
