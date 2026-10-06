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

struct X86RetiredOwner;
impl carrick_core::mm::cow::OwnerCowMmu for X86RetiredOwner {
    const CARRIER_MAINT_ROOT_BASE: u64 = 0;
    const DEFAULT_COW_COPY_BASE: u64 = 0;

    fn classify_cow_write<
        W: carrick_mmu_core::x86::descriptor_txn::LiveDescriptorWords + ?Sized,
    >(
        _: &W,
        _: u64,
        _: u64,
        _: bool,
    ) -> carrick_core::mm::cow::CowClassifyOutcome {
        carrick_core::mm::cow::CowClassifyOutcome::Declined(carrick_el1_abi::CowDecline::Unmapped)
    }

    fn plan_cow_repoint<W: carrick_mmu_core::x86::descriptor_txn::LiveDescriptorWords + ?Sized>(
        words: &W,
        root: u64,
        op: carrick_core::mm::cow::CowRepointOp,
    ) -> bool {
        use carrick_guest_arch::{FrameGpa, RootGpa};
        use carrick_mmu_core::x86::descriptor_txn::{
            DescriptorOp, DescriptorTxn, DescriptorTxnId, PageSpan, plan_descriptor_txn,
        };
        let root = RootGpa::page_aligned(FrameGpa::new(root)).unwrap();
        let txn = DescriptorTxn {
            id: DescriptorTxnId {
                mm_key: NonZeroU64::new(op.mm_key).unwrap(),
                generation: NonZeroU64::new(op.grant_epoch).unwrap(),
            },
            root,
            op: DescriptorOp::CowRepoint {
                span: PageSpan::new(op.va, op.len),
                old: FrameGpa::new(op.old_ipa),
                new: FrameGpa::new(op.new_ipa),
                backing: op.backing,
            },
            tables: &[],
        };
        plan_descriptor_txn(words, &txn, root).is_ok()
    }

    fn with_copy_aliases<
        W: carrick_mmu_core::x86::descriptor_txn::LiveDescriptorWords + ?Sized,
        F: FnMut(u64, u64),
    >(
        _: &W,
        _: u64,
        _: u64,
        source: u64,
        destination: u64,
        effect: &mut F,
    ) -> Result<(), carrick_core::mm::cow::CowRepointOutcome> {
        effect(source, destination);
        Ok(())
    }

    fn execute_cow_repoint<
        W: carrick_mmu_core::x86::descriptor_txn::LiveDescriptorWords + ?Sized,
    >(
        words: &W,
        root: u64,
        op: carrick_core::mm::cow::CowRepointOp,
    ) -> carrick_core::mm::cow::CowRepointOutcome {
        use carrick_core::mm::cow::CowRepointOutcome;
        use carrick_guest_arch::{FrameGpa, RootGpa};
        use carrick_mmu_core::x86::descriptor_txn::{
            DescriptorOp, DescriptorOutcome, DescriptorTxn, DescriptorTxnId, InlineJournal,
            PageSpan, execute_descriptor_txn,
        };
        let root = RootGpa::page_aligned(FrameGpa::new(root)).unwrap();
        let txn = DescriptorTxn {
            id: DescriptorTxnId {
                mm_key: NonZeroU64::new(op.mm_key).unwrap(),
                generation: NonZeroU64::new(op.grant_epoch).unwrap(),
            },
            root,
            op: DescriptorOp::CowRepoint {
                span: PageSpan::new(op.va, op.len),
                old: FrameGpa::new(op.old_ipa),
                new: FrameGpa::new(op.new_ipa),
                backing: op.backing,
            },
            tables: &[],
        };
        match execute_descriptor_txn(words, &txn, root, &mut InlineJournal::new()).outcome {
            DescriptorOutcome::Applied { .. } => CowRepointOutcome::Applied {
                flush_required: false,
            },
            DescriptorOutcome::Refused(_) => CowRepointOutcome::Refused,
            DescriptorOutcome::RolledBack(_) => CowRepointOutcome::RolledBack,
            DescriptorOutcome::Indeterminate(_) => CowRepointOutcome::Indeterminate,
        }
    }
}

#[test]
fn x86_pending_brk_maintenance_scrubs_private_grant_and_keeps_leaf_invalid() {
    use crate::memory::reservations::{Decision, RootReleaseVenue};
    use carrick_core::mm::cow::{CowCopyWindow, GuestCowVenue};
    use carrick_el1_abi::{
        PortalBackingMaintenance, ReservationBackingReceipt, ReservationCompletion,
    };
    use carrick_mmu_core::aarch64::SubstrateGpa;
    use carrick_mmu_core::x86::descriptor_txn::{ADDRESS, RETIRED};
    let region = Region::new();
    let zone = region.zone();
    let mm = admit_notified(&region, 77, ROOT, 1, 0);
    let peer_mm = admit_notified(&region, 78, ROOT + 0x100000, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::MIN, region.table(), &zone.spaces, &view)
        .with_zone(zone)
        .unwrap()
        .with_mmu(carrick_mmu_core::x86::owner_mmu::X86Mmu);
    let handle = portal.admitted_handle(mm, 0).unwrap();
    let tables = Tables::new(ROOT, IPA, 0);
    for (entry, offset) in [(0, 4096), (512, 8192), (1024, 12288)] {
        tables.words[entry].store((ROOT + offset) | PRESENT | WRITE | USER, Ordering::Release);
    }
    tables.words[1538].store(IPA | RETIRED | USER, Ordering::Release);
    let peer_tables = Tables::new(ROOT + 0x100000, IPA, 0);
    for (entry, offset) in [(0, 4096), (512, 8192), (1024, 12288)] {
        peer_tables.words[entry].store(
            (peer_tables.base + offset) | PRESENT | WRITE | USER,
            Ordering::Release,
        );
    }
    peer_tables.words[1538].store(IPA | PRESENT | USER, Ordering::Release);
    {
        let mut root = portal.root(mm, 1).unwrap();
        let Decision::Work(grow) = root.brk(0x3000).unwrap() else {
            panic!("heap growth proposal");
        };
        // SAFETY: the fixture has installed the owned backing under this root.
        root.complete(unsafe {
            ReservationCompletion::after_descriptor_and_backing_commit(
                grow,
                ReservationBackingReceipt {
                    receipt: 1,
                    granted_bytes: 8192,
                    returned_bytes: 0,
                },
            )
            .unwrap()
        })
        .unwrap();
    }
    let index = zone.spaces.find(mm.raw()).unwrap();
    let access = portal.space_access(1).unwrap();
    access.raise(index);
    let pending = {
        let venue = RootReleaseVenue::new(region.table(), access.venue().unwrap()).unwrap();
        let mut root = venue
            .lock_resolved(
                index.index(),
                mm,
                &view,
                &crate::memory::reservations::NoRootWait,
            )
            .unwrap();
        root.begin_host_proposal().unwrap();
        let Decision::Work(shrink) = root.brk(0x2000).unwrap() else {
            panic!("pending shrink proposal");
        };
        shrink
    };
    let request = PortalBackingMaintenance::new(handle, pending, 0x2000).unwrap();
    let arenas = [&tables];
    let words = X86ForkWords { arenas: &arenas };
    let pool = carrick_el1_abi::CowGrantPool::new();
    let resident = residency();
    let venue = GuestCowVenue::<X86RetiredOwner, _> {
        words: &words,
        root: SubstrateGpa(ROOT),
        pool: &pool,
        residency: &resident,
        copy_window: CowCopyWindow::target(&words, SubstrateGpa(ROOT)),
        publish_executable: None,
    };
    assert_eq!(
        portal
            .begin_backing_maintenance(request, 0)
            .unwrap()
            .scrub_retired_x86(
                &venue,
                |_, _| panic!("no grant must not copy"),
                || panic!("fatal")
            )
            .unwrap(),
        BackingMaintenanceProgress::Supply
    );
    let nz = |value| NonZeroU64::new(value).unwrap();
    let aliased = pool
        .publish(
            mm.raw(),
            IPA,
            carrick_mmu_core::aarch64::descriptor_txn::BackingIdentity {
                frame_id: nz(20),
                mapping_id: nz(21),
                owner_generation: nz(22),
                inventory_revision: nz(23),
            },
        )
        .unwrap();
    assert!(
        portal
            .begin_backing_maintenance(request, 0)
            .unwrap()
            .scrub_retired_x86(
                &venue,
                |_, _| panic!("shared predecessor must not be zeroed"),
                || panic!("fatal"),
            )
            .is_err()
    );
    {
        let excluded = access.raise_and_wait_for_editor(index, || panic!("editor did not drain"));
        assert!(pool.revoke(&excluded, &aliased));
    }
    access.lower(index);
    let grant = pool
        .publish(
            mm.raw(),
            IPA + 0x100000,
            carrick_mmu_core::aarch64::descriptor_txn::BackingIdentity {
                frame_id: nz(10),
                mapping_id: nz(11),
                owner_generation: nz(12),
                inventory_revision: nz(13),
            },
        )
        .unwrap();
    let predecessor = [0xa5u8; 4096];
    let mut replacement = [0xcdu8; 4096];
    assert_eq!(
        portal
            .begin_backing_maintenance(request, 0)
            .unwrap()
            .scrub_retired_x86(
                &venue,
                |source, destination| {
                    assert_eq!((source, destination), (IPA, grant.physical_ipa));
                    assert_eq!(tables.words[1538].load(Ordering::Acquire) & PRESENT, 0);
                    replacement.fill(0);
                },
                || panic!("fatal"),
            )
            .unwrap(),
        BackingMaintenanceProgress::Complete { next: 0x3000 }
    );
    assert_eq!(
        tables.words[1538].load(Ordering::Acquire) & ADDRESS,
        grant.physical_ipa
    );
    assert_eq!(tables.words[1538].load(Ordering::Acquire) & PRESENT, 0);
    assert_eq!(predecessor, [0xa5; 4096]);
    assert_eq!(replacement, [0; 4096]);
    assert_eq!(
        peer_tables.words[1538].load(Ordering::Acquire) & (ADDRESS | PRESENT),
        IPA | PRESENT,
        "the other live MM retains the predecessor"
    );
    assert!(zone.spaces.find(peer_mm.raw()).is_some());
    let completions: Vec<_> = {
        let excluded = access.raise_and_wait_for_editor(index, || panic!("editor did not drain"));
        pool.completions(&excluded).collect()
    };
    assert_eq!(completions.len(), 1);
    assert_eq!(
        completions[0].purpose,
        carrick_el1_abi::CowGrantPurpose::RetiredBacking
    );
    assert_eq!(completions[0].old_ipa, IPA);
    assert_eq!(completions[0].new_ipa, grant.physical_ipa);
    portal
        .root(mm, 1)
        .unwrap()
        // SAFETY: the invalid retained leaf has been privately zeroed and
        // repointed under the exact admitted maintenance editor above.
        .complete(unsafe {
            ReservationCompletion::after_descriptor_and_backing_commit(
                pending,
                ReservationBackingReceipt {
                    receipt: 2,
                    granted_bytes: 4096,
                    returned_bytes: 4096,
                },
            )
            .unwrap()
        })
        .unwrap();
    assert!(portal.begin_backing_maintenance(request, 0).is_err());
    access.lower(index);
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
