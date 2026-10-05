//! The production reservation/permit owner, exercised over x86 descriptors.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "x86_acceleration/mm_owner.rs"]
mod mm_owner;
use carrick_core::mm::transaction::{admit_service_root, serve_transfer};
use carrick_core::mm::transfer::resolver::{NoopCowResolver, NoopPreparedResolver};
use carrick_core_abi::{PortalRetainedData, PortalTransferSlot};
use carrick_el1::personality::mm_portal::test_support::*;
use carrick_el1::personality::mm_portal::*;
use carrick_mmu_core::aarch64::descriptor_txn::CallerInvalidatesAsid;
use carrick_mmu_core::x86::descriptor_txn::{NX, PRESENT, USER, WRITE};
use carrick_sched_core::AddressSpaces;
use core::num::NonZeroU64;
use core::sync::atomic::Ordering;

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
    // Stable, separately owned byte buffers stand in for physical custody in
    // this VM-free test. Hardware pin/retirement acceptance is a separate gate.
    let mut backing = [vec![0u8; pages * 4096], vec![0u8; pages * 4096]];
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
            let identity = PortalRetainedData {
                record: NonZeroU64::new((page + 1) as u64).unwrap(),
                vm_generation: NonZeroU64::new(1).unwrap(),
                owner: Some((
                    NonZeroU64::new(mm.raw()).unwrap(),
                    NonZeroU64::new(1).unwrap(),
                )),
            };
            let request = selected
                .request(TransferIntent::UserWrite, identity)
                .unwrap();
            let slot = PortalTransferSlot::new();
            let mut ticket = slot.submit(request).unwrap();
            let (service, grant) = admit_service_root(&portal, slot.claim().unwrap()).unwrap();
            assert_eq!(grant.ttbr0, tables.base);
            serve_transfer(&portal, service, &words, 0, || {
                // PREPARE has released both MM locks before host bytes move.
                assert!(region.table().el1_slot_holding(0).is_none());
                let other_editor = spaces
                    .try_begin_edit(
                        spaces.find(mm.raw()).unwrap(),
                        mm.raw(),
                        NonZeroU64::new(2).unwrap(),
                    )
                    .unwrap();
                let root = portal.root(mm, 1).unwrap();
                assert!(root.has_prepared_copy());
                drop(root);
                drop(other_editor);
                assert!(ticket.copy_requested(|copy| {
                    let authorized = copy.request();
                    assert_eq!(authorized.retained, identity);
                    assert_eq!(authorized.selected.ipa, selected.ipa);
                    let start =
                        (authorized.selected.ipa - (IPA + index as u64 * 0x1000000)) as usize;
                    let end = start + authorized.range.len() as usize;
                    backing[index][start..end].fill(0x31 + index as u8);
                    true
                }));
            })
            .unwrap();
            transfer
                .settle(request, ticket.take_completion().unwrap())
                .unwrap();
            let mut root = portal.root(mm, 0).unwrap();
            root.reap_prepared();
            assert!(!root.has_prepared_copy());
        }
        assert!(transfer.is_complete());
        assert_eq!(
            words.loads.get(),
            8 * pages,
            "two four-level walks per touched page; unrelated reservations add no descriptor work"
        );
    }
    assert!(backing[0].iter().all(|byte| *byte == 0x31));
    assert!(backing[1].iter().all(|byte| *byte == 0x32));
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
            carrick_core_abi::PortalRetainedData {
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

/// VM-free order-1 witness. CPL0 execution remains a separate integration gate.
#[test]
fn x1_shared_mm_owner() {
    mm_owner::transfer_revalidates_exact_mm_before_copy();
    mm_owner::prepared_copy_commit_and_cancel_never_acquire_held_root_or_editor();
    transfer_fixture(16, 16);
    transfer_fixture(64, 16);
    transfer_fixture(256, 16);
    x86_wrong_output_pin_refuses_before_preparing_copy();
}

#[path = "x86_acceleration/fork_cow.rs"]
mod fork_cow;
struct FailGrantStore<'a, W> {
    words: &'a W,
    stores: core::cell::Cell<usize>,
}
impl<W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords>
    carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords for FailGrantStore<'_, W>
{
    fn load(
        &self,
        pa: u64,
    ) -> Result<u64, carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal> {
        self.words.load(pa)
    }
    fn compare_exchange(
        &self,
        pa: u64,
        old: u64,
        new: u64,
    ) -> Result<bool, carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal> {
        let stores = self.stores.get() + 1;
        self.stores.set(stores);
        if stores == 2 {
            Ok(false)
        } else {
            self.words.compare_exchange(pa, old, new)
        }
    }
    fn store_unlinked(
        &self,
        pa: u64,
        value: u64,
    ) -> Result<(), carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal> {
        self.words.store_unlinked(pa, value)
    }
    fn publish_barrier(&self) {
        self.words.publish_barrier()
    }
    fn invalidate_range(&self, va: u64, len: u64) {
        self.words.invalidate_range(va, len)
    }
}

fn grant_fixture<B: carrick_mmu_core::owner_mmu::OwnerGrantMmu>(
    pages: usize,
    x86: bool,
    backend: B,
) {
    use carrick_core::mm::frames::serve_grant;
    use carrick_core_abi::PortalGrantSlot;
    use carrick_mmu_core::aarch64::descriptor_txn::{
        BackingIdentity, DescriptorOp, DescriptorOutcome, DescriptorTxn, DescriptorTxnId, PageSpan,
        TableGrants,
    };
    use carrick_mmu_core::aarch64::{GuestLeafPublication, SubstrateGpa};
    let mut region = Region::new();
    region.add_bank();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 11, ROOT, pages, 16);
    let other = admit(&region, &spaces, 12, ROOT + 0x10000, pages, 512);
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::MIN, region.table(), &spaces, &view).with_mmu(backend);
    let tables = Tables::new(ROOT, IPA, 0);
    if x86 {
        for (entry, offset) in [(0, 4096), (513, 8192), (1024, 12288)] {
            tables.words[entry].store((ROOT + offset) | PRESENT | WRITE | USER, Ordering::Release);
        }
    }
    let live = tables.live(&CallerInvalidatesAsid);
    let residency = residency();
    let transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(VA),
            1,
            TransferIntent::UserWrite,
            0,
        )
        .unwrap();
    let TransferStep::Supply(window) = portal
        .select(
            &transfer,
            &live,
            carrick_core::mm::transaction::SelectionVenues {
                prepared: &mut NoopPreparedResolver,
                cow: &mut NoopCowResolver,
                residency: &residency,
                slot: 0,
            },
        )
        .unwrap()
    else {
        panic!("missing grant selection");
    };
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
                frame_id: nz(1),
                mapping_id: nz(2),
                owner_generation: nz(3),
                inventory_revision: nz(4),
            },
        },
        tables: TableGrants::new(&[]).unwrap(),
    };
    let wire = PortalGrantSlot::new();
    for stale in [
        carrick_core_abi::PortalGrantWindow {
            generation: carrick_core_abi::ReservationGeneration::new(window.generation.raw() + 1)
                .unwrap(),
            ..window
        },
        carrick_core_abi::PortalGrantWindow {
            protection: carrick_core_abi::ReservationProtection::from_bits(1).unwrap(),
            ..window
        },
    ] {
        assert!(wire.submit(stale, &txn));
        let receipt = serve_grant(&portal, &wire, &live, &residency, 0, || {})
            .unwrap()
            .unwrap();
        assert!(matches!(receipt.outcome, DescriptorOutcome::Refused(_)));
        assert!(wire.take_receipt(stale, &txn).is_some());
        assert_eq!(tables.words[1536].load(Ordering::Acquire), 0);
        assert!(residency.lookup(mm.raw(), VA).is_none());
    }
    // A failure after one live store must undo the complete owner publication,
    // retire its logical residency and invalidate before any receipt is visible.
    assert!(wire.submit(window, &txn));
    let failed = FailGrantStore {
        words: &live,
        stores: core::cell::Cell::new(0),
    };
    let rollback_invalidated = core::cell::Cell::new(false);
    let rollback = serve_grant(&portal, &wire, &failed, &residency, 0, || {
        rollback_invalidated.set(true)
    })
    .unwrap()
    .unwrap();
    assert!(
        matches!(rollback.outcome, DescriptorOutcome::RolledBack(_)),
        "grant was not rolled back: {:?}",
        rollback.outcome
    );
    assert!(
        rollback_invalidated.get(),
        "rollback receipt preceded invalidation"
    );
    assert!(wire.take_receipt(window, &txn).is_some());
    assert!(residency.lookup(mm.raw(), VA).is_none());
    assert!((0..pages).all(|page| tables.words[1536 + page].load(Ordering::Acquire) == 0));
    let counted = CountWords {
        words: &live,
        loads: core::cell::Cell::new(0),
    };
    assert!(wire.submit(window, &txn));
    let invalidated = core::cell::Cell::new(false);
    let receipt = serve_grant(&portal, &wire, &counted, &residency, 0, || {
        assert!(
            spaces
                .try_begin_edit(spaces.find(mm.raw()).unwrap(), mm.raw(), nz(9))
                .is_none()
        );
        invalidated.set(true);
    })
    .unwrap()
    .unwrap();
    assert!(
        counted.loads.get() <= pages * 9,
        "grant work {} exceeded {}",
        counted.loads.get(),
        pages * 9
    );
    txn.verify_receipt(&receipt).unwrap();
    assert_eq!(
        invalidated.get(),
        carrick_mmu_core::aarch64::descriptor_txn::outcome_requires_invalidation(&receipt.outcome),
        "receipt did not honor required invalidation"
    );
    assert!(wire.take_receipt(window, &txn).is_some());
    assert!(residency.is_guest_committed(mm.raw(), VA));
    assert!(residency.lookup(other.raw(), VA).is_none());
    if pages > 1 {
        assert!(!residency.is_guest_committed(mm.raw(), VA + 4096));
        assert_eq!(
            tables.words[1537].load(Ordering::Acquire) & 1,
            0,
            "bulk neighbor became resident"
        );
    }
}

#[test]
fn x3_shared_protocol() {
    retirement_fixture(12);
    retirement_fixture(14);
    pin_retirement_fixture(12);
    pin_retirement_fixture(14);
    retirement_receipt_fixture();
    for pages in [16, 64, 256] {
        grant_fixture::<carrick_mmu_core::owner_mmu::Aarch64Mmu>(
            pages,
            false,
            carrick_mmu_core::owner_mmu::Aarch64Mmu,
        );
        grant_fixture::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(
            pages,
            true,
            carrick_mmu_core::x86::owner_mmu::X86Mmu,
        );
    }
}

#[derive(Clone, Debug, Default)]
struct RetirementVenue {
    state: std::sync::Arc<parking_lot::Mutex<carrick_core::mm::retirement::ResidencyState>>,
    settled: std::sync::Arc<parking_lot::Condvar>,
}
// SAFETY: every clone uses the same mutex and condition variable.
unsafe impl carrick_core::mm::retirement::ResidencyVenue for RetirementVenue {
    type Guard<'a> = parking_lot::MutexGuard<'a, carrick_core::mm::retirement::ResidencyState>;
    fn lock(&self) -> Self::Guard<'_> {
        self.state.lock()
    }
    fn wait(&self, guard: &mut Self::Guard<'_>) {
        self.settled.wait(guard);
    }
    fn notify_all(&self) {
        self.settled.notify_all();
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FixtureRoot {
    base: u64,
    size: u64,
}
impl carrick_core::mm::retirement::RootSlot for FixtureRoot {
    fn base(self) -> u64 {
        self.base
    }
    fn size(self) -> u64 {
        self.size
    }
}
struct Invalidation(u64);
// SAFETY: fixture CPU translations are invalidated by this exact generation.
unsafe impl carrick_core::mm::retirement::InvalidationProof<u64> for Invalidation {
    fn generation(&self) -> u64 {
        self.0
    }
}
struct TerminalRoot(FixtureRoot);
// SAFETY: fixture backing has no host mappings or pins at terminal completion.
unsafe impl carrick_core::mm::retirement::TerminalRootProof for TerminalRoot {
    fn base(&self) -> u64 {
        self.0.base
    }
    fn size(&self) -> u64 {
        self.0.size
    }
}

fn retirement_fixture(page_shift: u32) {
    let mut gate = carrick_core::mm::retirement::LeaseGate::default();
    assert!(gate.prepare());
    assert!(!gate.is_live());
    assert!(!gate.prepare());
    gate.rollback();
    assert!(gate.is_live());
    assert!(gate.prepare());
    gate.commit();
    gate.rollback();
    assert!(!gate.is_live());
    use carrick_core::mm::retirement::{
        AddressResidency, ResidencyError, RootQuarantine, RootRetirementError,
    };
    let root = FixtureRoot {
        base: 0x200000,
        size: 1 << page_shift,
    };
    let current = AddressResidency::<RetirementVenue, u64>::new(11);
    let peer = AddressResidency::<RetirementVenue, u64>::new(12);
    let peer_load = peer.begin_load().unwrap();
    let prepared = current.prepare_retirement().unwrap();
    assert!(matches!(
        current.begin_load(),
        Err(ResidencyError::Retiring)
    ));
    drop(prepared);
    let mut load = current.begin_load().unwrap();
    load.arm_hardware_dirty().unwrap();
    let retired = current.begin_retirement().unwrap();
    assert!(matches!(
        current.begin_load(),
        Err(ResidencyError::Retiring)
    ));
    assert_eq!(
        retired.acknowledge(Invalidation(12)),
        Err(ResidencyError::StaleGeneration)
    );
    assert_eq!(
        retired.acknowledge(Invalidation(11)),
        Err(ResidencyError::ExecutorStillLoading)
    );
    assert!(!retired.is_complete());
    drop(load);
    retired.wait_for_admitted_loads();
    // A cancelled dirty install still owes all-venue invalidation.
    assert!(retired.needs_invalidation());
    let mut gate = RootQuarantine::reserve(Some(root)).unwrap();
    let ticket = gate.take_ticket().unwrap().unwrap();
    assert!(matches!(
        gate.take_ticket(),
        Err(RootRetirementError::TicketAlreadyIssued)
    ));
    let receipt = ticket.redeem(TerminalRoot(root)).unwrap();
    assert_eq!(
        retired.complete_root(gate, Some(receipt)),
        Err(RootRetirementError::Incomplete)
    );
    retired.acknowledge(Invalidation(11)).unwrap();

    // The same coordinates in a later admission cannot accept an old nonce.
    let mut stale_gate = RootQuarantine::reserve(Some(root)).unwrap();
    let stale = stale_gate
        .take_ticket()
        .unwrap()
        .unwrap()
        .redeem(TerminalRoot(root))
        .unwrap();
    let gate = RootQuarantine::reserve(Some(root)).unwrap();
    assert!(matches!(
        retired.complete_root(gate, Some(stale)),
        Err(RootRetirementError::Mismatch { .. })
    ));
    let mut gate = RootQuarantine::reserve(Some(root)).unwrap();
    let ticket = gate.take_ticket().unwrap().unwrap();
    let wrong = FixtureRoot {
        base: root.base + root.size,
        size: root.size,
    };
    assert!(matches!(
        ticket.redeem(TerminalRoot(wrong)),
        Err(RootRetirementError::Mismatch { .. })
    ));
    let gate = RootQuarantine::reserve(Some(root)).unwrap();
    assert_eq!(
        retired.complete_root(gate, None),
        Err(RootRetirementError::ReceiptMissing)
    );
    let mut gate = RootQuarantine::reserve(Some(root)).unwrap();
    let receipt = gate
        .take_ticket()
        .unwrap()
        .unwrap()
        .redeem(TerminalRoot(root))
        .unwrap();
    assert_eq!(
        retired.complete_root(gate, Some(receipt)).unwrap(),
        Some(root)
    );
    assert!(!peer.is_retiring());
    peer_load.mark_resident().unwrap();
}

#[derive(Debug)]
struct PinFixture(
    std::rc::Rc<std::cell::RefCell<carrick_core::mm::retirement::CarrierStage2Record>>,
);
impl carrick_core::mm::retirement::RecordPinVenue for PinFixture {
    fn release_pin(&self, identity: carrick_core::mm::retirement::CarrierStage2RecordIdentity) {
        carrick_core::mm::retirement::release_record_pin(&mut self.0.borrow_mut(), identity);
    }
}
fn pin_retirement_fixture(page_shift: u32) {
    use carrick_core::mm::frames::{FrameReferences, ReferenceRetirement};
    use carrick_core::mm::retirement::*;
    let identity = CarrierStage2RecordIdentity {
        record_id: CarrierStage2RecordId(41),
        vm_generation: CarrierVmGeneration(7),
        logical_owner: Some(CarrierLogicalOwner {
            id: 11,
            generation: 1,
        }),
    };
    let make_record = |identity: CarrierStage2RecordIdentity| CarrierStage2Record {
        snapshot: CarrierStage2RecordSnapshot {
            record_id: identity.record_id,
            vm_generation: identity.vm_generation,
            logical_owner: identity.logical_owner,
            ipa: 0x800000,
            len: 1 << page_shift,
            host_addr: 0,
            mapped: true,
            backend_map_installed: true,
            release_ipa: true,
            perms: 3,
            pin_count: 0,
            retirement_requested: false,
            retry_eligible: false,
            retry_pending: None,
            terminalized_by_vm_destroy: false,
            superseded_by_rebind: false,
            release_in_flight: false,
            release_retry_pending: false,
        },
        unmap_in_flight: false,
    };
    let record = std::rc::Rc::new(std::cell::RefCell::new(make_record(identity)));
    let peer_identity = CarrierStage2RecordIdentity {
        record_id: CarrierStage2RecordId(42),
        logical_owner: Some(CarrierLogicalOwner {
            id: 12,
            generation: 1,
        }),
        ..identity
    };
    let peer = make_record(peer_identity);
    let pin = pin_record(
        &mut record.borrow_mut(),
        identity,
        PinFixture(record.clone()),
    )
    .unwrap();
    assert_eq!(pin.identity(), identity);
    for wrong in [
        peer_identity,
        CarrierStage2RecordIdentity {
            vm_generation: CarrierVmGeneration(8),
            ..identity
        },
        CarrierStage2RecordIdentity {
            logical_owner: Some(CarrierLogicalOwner {
                id: 11,
                generation: 2,
            }),
            ..identity
        },
    ] {
        let before = *record.borrow();
        assert!(pin_record(&mut record.borrow_mut(), wrong, PinFixture(record.clone())).is_err());
        assert!(!release_record_pin(&mut record.borrow_mut(), wrong));
        assert_eq!(*record.borrow(), before);
    }
    // Four 4 KiB leaves may share one 16 KiB physical backing. Retiring one
    // leaf retains its live neighbors; even the last leaf cannot drop a pin.
    let mut refs = FrameReferences::default();
    let leaves = 1 << (page_shift - 12);
    for _ in 0..leaves {
        refs.retain().unwrap();
    }
    assert_eq!(refs.request_retirement(), ReferenceRetirement::Deferred);
    for index in 0..leaves {
        assert_eq!(refs.unmap().unwrap(), index == leaves - 1);
    }
    assert_eq!(
        request_record_retirement(&mut record.borrow_mut(), identity),
        CarrierStage2RetireOutcome::DeferredActivePins
    );
    assert_eq!(
        prepare_record_retirement(&mut record.borrow_mut(), identity),
        RecordRetirement::Complete(CarrierStage2RetireOutcome::DeferredActivePins)
    );
    assert!(record.borrow().snapshot.mapped);
    assert!(
        pin_record(
            &mut record.borrow_mut(),
            identity,
            PinFixture(record.clone())
        )
        .is_err()
    );
    drop(pin);
    assert_eq!(record.borrow().snapshot.pin_count, 0);
    assert!(record.borrow().snapshot.retry_eligible);
    assert!(matches!(
        prepare_record_retirement(&mut record.borrow_mut(), identity),
        RecordRetirement::Unmap { .. }
    ));
    assert_eq!(
        prepare_record_retirement(&mut record.borrow_mut(), identity),
        RecordRetirement::Complete(CarrierStage2RetireOutcome::RetryPending(
            CarrierStage2BackendError::ConcurrentRetirement
        ))
    );
    assert_eq!(
        settle_record_retirement(
            &mut record.borrow_mut(),
            identity,
            Err(CarrierStage2BackendError::HvReturn(7))
        ),
        CarrierStage2RetireOutcome::RetryPending(CarrierStage2BackendError::HvReturn(7))
    );
    assert!(record.borrow().snapshot.mapped);
    assert!(matches!(
        prepare_record_retirement(&mut record.borrow_mut(), identity),
        RecordRetirement::Unmap { .. }
    ));
    assert_eq!(
        settle_record_retirement(&mut record.borrow_mut(), identity, Ok(())),
        CarrierStage2RetireOutcome::RetiredUnmapped
    );
    assert!(!record.borrow().snapshot.mapped);
    assert_eq!(
        peer,
        make_record(peer_identity),
        "retirement changed the second MM"
    );

    let mut destroyed = make_record(identity);
    let pin = pin_record(&mut destroyed, identity, PinFixture(record.clone()))
        .unwrap()
        .into_transferred_identity();
    destroyed.snapshot.superseded_by_rebind = true;
    terminalize_record(&mut destroyed);
    assert!(release_record_pin(&mut destroyed, pin));
    assert_eq!(destroyed.snapshot.pin_count, 0);
    assert_eq!(
        prepare_record_retirement(&mut destroyed, identity),
        RecordRetirement::Complete(CarrierStage2RetireOutcome::TerminalizedByVmDestroy)
    );
}

#[derive(Clone, Copy)]
struct PendingReference(carrick_core_abi::MappingId, carrick_core_abi::FrameId);
impl carrick_core::mm::retirement::PendingRetirementReference for PendingReference {
    fn child_mapping(&self) -> carrick_core_abi::MappingId {
        self.0
    }
    fn frame(&self) -> carrick_core_abi::FrameId {
        self.1
    }
}
fn retirement_receipt_fixture() {
    use carrick_core_abi::*;
    let nz = |n| NonZeroU64::new(n).unwrap();
    let pairs: Vec<_> = (1..=20_000)
        .map(|n| {
            (
                MappingId::from_kernel_allocation(nz(n)),
                FrameId::from_kernel_allocation(nz(n % 501 + 1)),
            )
        })
        .collect();
    let provenance = FrameInventoryProvenance::from_kernel_entropy([7; 32]);
    let transaction = KernelTransactionId::from_kernel_allocation(nz(97));
    let receipt = FrameInventoryRetirementReceipt::from_kernel_authority(
        FrameInventoryApplyReceipt::from_kernel_authority(
            provenance,
            transaction,
            nz(11),
            12,
            pairs.clone(),
        ),
        true,
    );
    assert!(
        FrameInventoryReceiptChallenge::from_kernel_authority(provenance, transaction)
            .authenticate_retirement(&receipt, nz(11))
    );
    assert!(
        !FrameInventoryReceiptChallenge::from_kernel_authority(provenance, transaction)
            .authenticate_retirement(&receipt, nz(12))
    );
    let mut pending: Vec<_> = pairs
        .iter()
        .map(|&(mapping, frame)| PendingReference(mapping, frame))
        .collect();
    // A superseded fork inheritance no longer appears in the live set.
    pending.push(PendingReference(
        MappingId::from_kernel_allocation(nz(30_000)),
        FrameId::from_kernel_allocation(nz(9)),
    ));
    assert!(
        carrick_core::mm::retirement::authenticate_pending_retirement(&pairs, &pending, &receipt)
            .ok()
    );
    pending[10_000].1 = FrameId::from_kernel_allocation(nz(99_999));
    assert!(
        !carrick_core::mm::retirement::authenticate_pending_retirement(&pairs, &pending, &receipt)
            .ok()
    );
    let mut arenas = vec![0x200000, 0x400000, 0x600000];
    let mut calls = 0;
    let result =
        carrick_core::mm::retirement::retire_table_arenas(&mut arenas, Some(0x200000), |_| {
            calls += 1;
            if calls == 2 { Err(()) } else { Ok(()) }
        });
    assert_eq!(result, Err(()));
    assert_eq!(calls, 2);
    assert_eq!(arenas, vec![0x200000, 0x600000]);
    carrick_core::mm::retirement::retire_table_arenas(&mut arenas, Some(0x200000), |_| {
        Ok::<_, ()>(())
    })
    .unwrap();
    assert_eq!(arenas, vec![0x200000]);
}
