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

mod fork_cow {
    use carrick_core::mm::fork::{
        ForkChildRoot, ForkError, ForkParentRoot, ForkReceiptError, ForkScratch, ForkTableCursor,
        Mapping, PreparedOwnerFork, copy_table, validate_fork_completion,
    };
    use carrick_el1_abi::{
        CowGrant, CowGrantCompletion, CowGrantPurpose, El1MmHandle, PortalForkCompletion,
        PortalForkCustody, PortalForkRequest, PortalForkTableArena, PortalOperation,
        ReservationGeneration, ReservationMm, ReservationNodeFlags, ReservationProtection,
        ReservationRange,
    };
    use carrick_mmu_core::aarch64::descriptor_txn::{
        BackingIdentity, DescriptorRefusal, LiveDescriptorWords,
    };
    use carrick_guest_arch::{FrameGpa, RootGpa, UserVa};
    use carrick_mmu_core::owner_mmu::{Aarch64Mmu, OwnerMmuRefusal, OwnerTranslation};
    use carrick_mmu_core::x86::descriptor_txn::{
        COW, HUGE, MAY_WRITE, NX, PREPARED, PRESENT, USER, WRITE,
    };
    use carrick_mmu_core::x86::owner_mmu::X86Mmu;
    use core::num::NonZeroU64;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    struct TestMemory {
        words: Mutex<BTreeMap<u64, u64>>,
    }

    impl TestMemory {
        fn new() -> Self {
            Self {
                words: Mutex::new(BTreeMap::new()),
            }
        }

        fn store(&self, addr: u64, val: u64) {
            self.words.lock().unwrap().insert(addr, val);
        }
    }

    #[derive(Clone)]
    struct TestChildRoot {
        incarnation: u64,
        admitted: bool,
        authorized: bool,
        origin: Option<PortalForkRequest>,
        finished: bool,
        retired: Arc<AtomicBool>,
    }

    impl ForkChildRoot for TestChildRoot {
        fn incarnation(&self) -> u64 {
            self.incarnation
        }
        fn is_admitted(&self) -> bool {
            self.admitted
        }
        fn fork_write_authorized(&mut self, _sequence: Option<NonZeroU64>) -> bool {
            self.authorized
        }
        fn authenticate_fork_origin(&mut self, request: PortalForkRequest) -> bool {
            self.origin.is_some_and(|o| o == request)
        }
        fn set_fork_origin(&mut self, request: PortalForkRequest) -> Result<(), ForkError> {
            self.origin = Some(request);
            Ok(())
        }
        fn clear_fork_origin(&mut self) {
            self.origin = None;
        }
        fn publish_fork_child(&mut self, _request: PortalForkRequest) -> Result<(), ForkError> {
        Ok(())
    }
        fn finish_fork_publication(&mut self, _operation: PortalOperation) -> Result<(), ForkError> {
            self.finished = true;
            Ok(())
        }
        fn retire(self) -> Result<(), ForkError> {
            self.retired.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Clone)]
    struct TestParentRoot {
        incarnation: u64,
        generation: ReservationGeneration,
        sequence: u64,
        ready: bool,
        authorized: bool,
        finished: bool,
    }

    impl ForkParentRoot<TestChildRoot> for TestParentRoot {
        fn incarnation(&self) -> u64 {
            self.incarnation
        }
        fn generation(&self) -> ReservationGeneration {
            self.generation
        }
        fn operation_sequence(&self) -> u64 {
            self.sequence
        }
        fn fork_ready(&mut self) -> bool {
            self.ready
        }
        fn fork_write_authorized(&mut self, _sequence: Option<NonZeroU64>) -> bool {
            self.authorized
        }
        fn reserve_fork_certificate(&mut self, _request: PortalForkRequest) -> Result<(), ForkError> {
            Ok(())
        }
        fn clone_into(&mut self, _child: &mut TestChildRoot) -> Result<(), ForkError> {
            Ok(())
        }
        fn publish_fork_parent(&mut self, _request: PortalForkRequest) -> Result<ReservationGeneration, ForkError> {
            Ok(self.generation)
        }
        fn finish_fork_publication(&mut self, _operation: PortalOperation) -> Result<(), ForkError> {
            self.finished = true;
            Ok(())
        }
        fn commit_fork_generation(&mut self) -> Result<ReservationGeneration, ForkError> {
            let next = ReservationGeneration::new(self.generation.raw() + 1).unwrap();
            self.generation = next;
            Ok(next)
        }
    }

    struct LinuxForkPolicy;

    impl carrick_core::mm::fork::MappingInheritancePolicy for LinuxForkPolicy {
        fn inheritance_policy(&self, mapping: &Mapping) -> carrick_core::mm::fork::Policy {
            if mapping.flags.contains(ReservationNodeFlags::DONTFORK) {
                carrick_core::mm::fork::Policy::Omit
            } else if mapping.flags.contains(ReservationNodeFlags::WIPEONFORK) {
                carrick_core::mm::fork::Policy::Wipe
            } else if mapping.flags.contains(ReservationNodeFlags::PRIVATE) {
                carrick_core::mm::fork::Policy::Private
            } else {
                carrick_core::mm::fork::Policy::Keep
            }
        }

        fn is_shared(&self, mapping: &Mapping) -> bool {
            !mapping.flags.contains(ReservationNodeFlags::PRIVATE)
        }
    }

    impl LiveDescriptorWords for TestMemory {
        fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
            Ok(self.words.lock().unwrap().get(&pa).copied().unwrap_or(0))
        }

        fn compare_exchange(
            &self,
            pa: u64,
            before: u64,
            after: u64,
        ) -> Result<bool, DescriptorRefusal> {
            let mut map = self.words.lock().unwrap();
            let val = map.entry(pa).or_insert(0);
            if *val == before {
                *val = after;
                Ok(true)
            } else {
                Ok(false)
            }
        }

        fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal> {
            self.store(pa, value);
            Ok(())
        }

        fn publish_barrier(&self) {}
        fn invalidate_range(&self, _va: u64, _len: u64) {}
    }

    fn sample_request(parent_gen: u64) -> PortalForkRequest {
        PortalForkRequest {
            operation: PortalOperation {
                carrier: NonZeroU64::new(1).unwrap(),
                mm: ReservationMm::new(10).unwrap(),
                incarnation: NonZeroU64::new(1).unwrap(),
                sequence: NonZeroU64::new(1).unwrap(),
            },
            parent_generation: ReservationGeneration::new(parent_gen).unwrap(),
            child_mm: ReservationMm::new(20).unwrap(),
            child_tables: PortalForkTableArena::new(0x20_0000, 0x1_0000).unwrap(),
            parent_tables: PortalForkTableArena::new(0x30_0000, 0x1_0000).unwrap(),
            kernel_control_ipa: 0x40_0000,
        }
    }

    fn sample_child_handle(mm: u64) -> El1MmHandle {
        unsafe {
            El1MmHandle::from_admitted_owner(
                NonZeroU64::new(1).unwrap(),
                ReservationMm::new(mm).unwrap(),
                NonZeroU64::new(1).unwrap(),
            )
        }
    }

    #[test]
    fn x2_shared_fork_cow() {
        let req = sample_request(5);
        let child_handle = sample_child_handle(20);
        let initial_completion = PortalForkCompletion {
            request: req,
            child: child_handle,
            parent_generation: ReservationGeneration::new(5).unwrap(),
            child_tables_used: 4096,
            parent_tables_used: 0,
        };

        // 1. Receipt validation defect witnesses
        // Injected defect: Stale child
        let stale_child_completion = PortalForkCompletion {
            child: sample_child_handle(99),
            ..initial_completion
        };
        assert_eq!(
            validate_fork_completion(
                req,
                child_handle,
                initial_completion,
                Ok(stale_child_completion),
                true,
            ),
            Err(ForkReceiptError::StaleChild),
            "validate_fork_completion must reject stale or mismatched child handle"
        );

        // Injected defect: Abort without incrementing parent generation
        let unincremented_abort_completion = PortalForkCompletion {
            parent_generation: ReservationGeneration::new(5).unwrap(),
            child_tables_used: 0,
            ..initial_completion
        };
        assert_eq!(
            validate_fork_completion(
                req,
                child_handle,
                initial_completion,
                Ok(unincremented_abort_completion),
                false,
            ),
            Err(ForkReceiptError::InvalidAbortParentGeneration),
            "validate_fork_completion must reject abort without parent generation increment"
        );

        // Injected defect: Abort with nonzero child tables used
        let nonzero_child_abort_completion = PortalForkCompletion {
            parent_generation: ReservationGeneration::new(6).unwrap(),
            child_tables_used: 4096,
            ..initial_completion
        };
        assert_eq!(
            validate_fork_completion(
                req,
                child_handle,
                initial_completion,
                Ok(nonzero_child_abort_completion),
                false,
            ),
            Err(ForkReceiptError::InvalidAbortChildTables),
            "validate_fork_completion must reject abort with nonzero child tables retained"
        );

        // Valid commit validation
        assert_eq!(
            validate_fork_completion(
                req,
                child_handle,
                initial_completion,
                Ok(initial_completion),
                true,
            ),
            Ok(initial_completion),
            "valid commit receipt must pass"
        );

        // Valid abort validation
        let valid_abort_completion = PortalForkCompletion {
            parent_generation: ReservationGeneration::new(6).unwrap(),
            child_tables_used: 0,
            ..initial_completion
        };
        assert_eq!(
            validate_fork_completion(
                req,
                child_handle,
                initial_completion,
                Ok(valid_abort_completion),
                false,
            ),
            Ok(valid_abort_completion),
            "valid abort receipt must pass"
        );

        // 2. Fork and COW execution with X86Mmu
        let mem = TestMemory::new();
        let root_pa = 0x10_0000;
        let l3_pa = 0x10_1000;
        let l2_pa = 0x10_2000;
        let l1_pa = 0x10_3000;
        let leaf_pa = 0x10_4000;

        // Build 4-level page table for VA 0x0000_0000_0000_0000
        // PML4 -> PDPT -> PD -> PT -> 4KiB page (writable, user, present)
        mem.store(root_pa, l3_pa | PRESENT | WRITE | USER);
        mem.store(l3_pa, l2_pa | PRESENT | WRITE | USER);
        mem.store(l2_pa, l1_pa | PRESENT | WRITE | USER);
        let original_leaf = leaf_pa | PRESENT | WRITE | USER;
        mem.store(l1_pa, original_leaf);

        let mappings = vec![Mapping {
            range: ReservationRange::new(0, 0x0000_8000_0000_0000).unwrap(),
            protection: ReservationProtection::READ_WRITE,
            anonymous: true,
            flags: ReservationNodeFlags::PRIVATE,
            generation: ReservationGeneration::new(1).unwrap(),
            host_backing: None,
        }];

        let mut scratch = ForkScratch::bounded(req, 1, 512 * 4, 512 * 4, 512 * 4, 512).unwrap();
        scratch.mappings = mappings;

        copy_table::<X86Mmu, _, _>(
            &LinuxForkPolicy,
            &mem,
            req,
            &mut scratch,
            ForkTableCursor {
                table: root_pa,
                level: 0,
                base: 0,
                child_offset: 0,
            },
        )
        .unwrap();

        // Check that parent leaf was armed for COW: WRITE removed, COW | MAY_WRITE added
        let (parent_edit_before, parent_edit_after) = {
            let parent_edit = scratch.edits.iter().find(|e| e.pa == l1_pa).unwrap();
            (parent_edit.before, parent_edit.after)
        };
        assert_eq!(parent_edit_before, original_leaf);
        assert_eq!(parent_edit_after & WRITE, 0, "parent write bit cleared");
        assert_eq!(
            parent_edit_after & (COW | MAY_WRITE),
            COW | MAY_WRITE,
            "parent armed with COW | MAY_WRITE"
        );

        // Retained custody check
        let prepared = PreparedOwnerFork::<X86Mmu>::new(req, root_pa, scratch);
        assert_eq!(prepared.custody().len(), 1);
        assert!(
            matches!(prepared.custody()[0], PortalForkCustody::Frame { ipa, .. } if ipa == leaf_pa),
            "prepared fork must retain custody of private frame"
        );

        // Publish fork child transaction
        let child_retired = Arc::new(AtomicBool::new(false));
        let child_root = TestChildRoot {
            incarnation: 1,
            admitted: false,
            authorized: true,
            origin: None,
            finished: false,
            retired: child_retired.clone(),
        };
        let parent_root = TestParentRoot {
            incarnation: 1,
            generation: ReservationGeneration::new(5).unwrap(),
            sequence: 1,
            ready: true,
            authorized: true,
            finished: false,
        };
        let mut unpublished = prepared
            .publish(&mem, parent_root.clone(), child_root.clone(), child_handle)
            .unwrap();

        // Verify publish applied the COW edits to live memory
        assert_eq!(
            mem.load(l1_pa).unwrap(),
            parent_edit_after,
            "publish applied descriptor edits to live table"
        );

        // Stale-child control defect witness: abort and commit must reject an unauthenticated child
        let unauthenticated_child = TestChildRoot {
            origin: None,
            ..child_root.clone()
        };
        let mut stale_attempt = unpublished.clone();
        assert_eq!(
            stale_attempt.abort(&mem, parent_root.clone(), unauthenticated_child.clone()),
            Err(ForkError::Stale),
            "abort must fail with Stale when child does not authenticate origin"
        );
        assert_eq!(
            stale_attempt.commit(parent_root.clone(), unauthenticated_child),
            Err(ForkError::Stale),
            "commit must fail with Stale when child does not authenticate origin"
        );

        // Simulate parent write fault: parent resolves COW write to new page (0x50_0000)
        let new_ipa = 0x50_0000;
        let new_leaf = new_ipa | PRESENT | WRITE | USER | MAY_WRITE;
        mem.store(l1_pa, new_leaf);

        // Injected defect: Calling abort before reconciliation must fail
        // Rollback will detect live memory modified by un-reconciled write
        let mut unreconciled_child = unpublished.clone();
        let unrec_child_root = TestChildRoot {
            origin: Some(req),
            ..child_root.clone()
        };
        assert_eq!(
            unreconciled_child.abort(&mem, parent_root.clone(), unrec_child_root),
            Err(ForkError::Core),
            "abort before parent write reconciliation must fail with ForkError::Core due to rollback failure"
        );

        // Reconcile parent write with COW grant completion
        let cow_completion = CowGrantCompletion {
            purpose: CowGrantPurpose::UserWrite,
            grant: CowGrant {
                slot: 0,
                epoch: 8,
                mm_key: req.operation.mm.raw(),
                physical_ipa: new_ipa,
                backing: BackingIdentity {
                    frame_id: NonZeroU64::new(1).unwrap(),
                    mapping_id: NonZeroU64::new(1).unwrap(),
                    owner_generation: NonZeroU64::new(1).unwrap(),
                    inventory_revision: NonZeroU64::new(1).unwrap(),
                },
            },
            span_va: 0,
            span_len: 4096,
            old_ipa: leaf_pa,
            new_ipa,
        };
        assert!(cow_completion.is_well_formed());
        unpublished
            .reconcile_parent_write(&mem, cow_completion)
            .unwrap();

        // Abort after reconciliation: must succeed, retain the parent write, and retire the child
        let valid_abort_child = TestChildRoot {
            origin: Some(req),
            retired: child_retired.clone(),
            ..child_root
        };
        unpublished
            .abort(&mem, parent_root, valid_abort_child)
            .unwrap();

        // Verify parent's write was preserved in live memory
        assert_eq!(
            mem.load(l1_pa).unwrap(),
            new_leaf,
            "reconciled parent write must be preserved on abort"
        );
        // Verify child retirement
        assert!(
            child_retired.load(Ordering::SeqCst),
            "abort must retire child root"
        );
        // Verify completion status
        assert_eq!(
            unpublished.completion().child_tables_used,
            0,
            "abort clears child_tables_used"
        );
        assert_eq!(
            unpublished.completion().parent_generation,
            ReservationGeneration::new(6).unwrap(),
            "abort commits next parent generation"
        );

        // 3. Verify the same copy_table runs against Aarch64Mmu
        let arm_mem = TestMemory::new();
        let arm_root = 0x80_0000;
        let arm_l3 = 0x80_1000;
        let arm_l2 = 0x80_2000;
        let arm_l1 = 0x80_3000;
        let arm_leaf = 0x80_4000 | 3 | (1 << 6); // table descriptor / user leaf
        arm_mem.store(arm_root, arm_l3 | 3);
        arm_mem.store(arm_l3, arm_l2 | 3);
        arm_mem.store(arm_l2, arm_l1 | 3);
        arm_mem.store(arm_l1, arm_leaf);

        let mut arm_scratch = ForkScratch::bounded(req, 1, 512 * 4, 512 * 4, 512 * 4, 512).unwrap();
        arm_scratch.mappings = vec![Mapping {
            range: ReservationRange::new(0, 0x0000_8000_0000_0000).unwrap(),
            protection: ReservationProtection::READ_WRITE,
            anonymous: true,
            flags: ReservationNodeFlags::PRIVATE,
            generation: ReservationGeneration::new(1).unwrap(),
            host_backing: None,
        }];

        copy_table::<Aarch64Mmu, _, _>(
            &LinuxForkPolicy,
            &arm_mem,
            req,
            &mut arm_scratch,
            ForkTableCursor {
                table: arm_root,
                level: 0,
                base: 0,
                child_offset: 0,
            },
        )
        .unwrap();
        assert!(
            !arm_scratch.edits.is_empty(),
            "AArch64 copy_table runs using the exact same generic capsule"
        );

        // 4. Red-first witness: x86 table-descriptor cloning must preserve ancestor
        // permissions (NX, read-only, supervisor), never synthesize PRESENT|WRITE|USER.
        let perms_mem = TestMemory::new();
        let root_pa = 0x10_0000;
        let l3_pa = 0x10_1000;
        let l2_pa = 0x10_2000;
        let l1_pa = 0x10_3000;
        let leaf_pa = 0x10_4000;

        // L4 entry: points to L3 with NX set
        perms_mem.store(root_pa, l3_pa | PRESENT | WRITE | USER | NX);
        // L3 entry: points to L2 with read-only (WRITE cleared)
        perms_mem.store(l3_pa, l2_pa | PRESENT | USER);
        // L2 entry: points to L1 with supervisor (USER cleared)
        perms_mem.store(l2_pa, l1_pa | PRESENT | WRITE);
        // L1 entry: points to leaf
        perms_mem.store(l1_pa, leaf_pa | PRESENT | WRITE | USER);

        let mut perms_scratch = ForkScratch::bounded(req, 1, 512 * 8, 512 * 8, 512 * 8, 512).unwrap();
        perms_scratch.mappings = vec![Mapping {
            range: ReservationRange::new(0, 0x0000_8000_0000_0000).unwrap(),
            protection: ReservationProtection::READ_WRITE,
            anonymous: true,
            flags: ReservationNodeFlags::PRIVATE,
            generation: ReservationGeneration::new(1).unwrap(),
            host_backing: None,
        }];

        copy_table::<X86Mmu, _, _>(
            &LinuxForkPolicy,
            &perms_mem,
            req,
            &mut perms_scratch,
            ForkTableCursor {
                table: root_pa,
                level: 0,
                base: 0,
                child_offset: 0,
            },
        )
        .unwrap();

        // Check the child table descriptors created in perms_scratch.child
        // Index 0 in child root table (offset 0) points to child L3 table.
        let child_l3_desc = perms_scratch.child[0];
        assert_ne!(
            child_l3_desc & NX,
            0,
            "child table descriptor must preserve NX from parent ancestor"
        );

        // Child L3 table (offset 512) index 0 points to child L2 table.
        let child_l2_desc = perms_scratch.child[512];
        assert_eq!(
            child_l2_desc & WRITE,
            0,
            "child table descriptor must preserve read-only (no WRITE) from parent ancestor"
        );

        // Child L2 table (offset 1024) index 0 points to child L1 table.
        let child_l1_desc = perms_scratch.child[1024];
        assert_eq!(
            child_l1_desc & USER,
            0,
            "child table descriptor must preserve supervisor (no USER) from parent ancestor"
        );

        // 5. Witness: uncovered x86 descriptors must use B::is_user, not ARM bit 6.
        let clean_user = 0x1000 | PRESENT | WRITE | USER;
        let pol_user =
            carrick_core::mm::fork::policy::<X86Mmu, _>(&LinuxForkPolicy, &[], 0, 4096, clean_user)
                .unwrap();
        assert_eq!(
            pol_user,
            carrick_core::mm::fork::Policy::Omit,
            "uncovered clean x86 user leaf must be omitted"
        );

        let dirty_supervisor = 0x2000 | PRESENT | WRITE | (1 << 6);
        let pol_sup = carrick_core::mm::fork::policy::<X86Mmu, _>(
            &LinuxForkPolicy,
            &[],
            0,
            4096,
            dirty_supervisor,
        )
        .unwrap();
        assert_eq!(
            pol_sup,
            carrick_core::mm::fork::Policy::Keep,
            "uncovered dirty x86 supervisor leaf must be kept"
        );

        // 6. Red-first witness: split a 2 MiB huge leaf spanning PRIVATE and DONTFORK.
        // The newly created parent and child table entries must point to tables
        // (HUGE / PS bit clear), carrying only non-terminal permission bits (P, RW, US, NX).
        let huge_mem = TestMemory::new();
        let root_pa = 0x20_0000;
        let l3_pa = 0x20_1000;
        let l2_pa = 0x20_2000;
        let huge_leaf_2m_pa = 0x40_0000; // 2 MiB aligned

        // L4 entry points to L3
        huge_mem.store(root_pa, l3_pa | PRESENT | WRITE | USER);
        // L3 entry points to L2
        huge_mem.store(l3_pa, l2_pa | PRESENT | WRITE | USER);
        // L2 entry is a 2 MiB huge leaf spanning [0..2 MiB)
        let huge_leaf = huge_leaf_2m_pa | PRESENT | WRITE | USER | HUGE | NX;
        huge_mem.store(l2_pa, huge_leaf);

        let mut huge_scratch = ForkScratch::bounded(req, 1, 512 * 8, 512 * 8, 512 * 8, 512).unwrap();
        // [0..1 MiB): PRIVATE
        // [1..2 MiB): DONTFORK
        huge_scratch.mappings = vec![
            Mapping {
                range: ReservationRange::new(0, 0x10_0000).unwrap(),
                protection: ReservationProtection::READ_WRITE,
                anonymous: true,
                flags: ReservationNodeFlags::PRIVATE,
                generation: ReservationGeneration::new(1).unwrap(),
                host_backing: None,
            },
            Mapping {
                range: ReservationRange::new(0x10_0000, 0x20_0000).unwrap(),
                protection: ReservationProtection::READ_WRITE,
                anonymous: true,
                flags: ReservationNodeFlags::DONTFORK,
                generation: ReservationGeneration::new(1).unwrap(),
                host_backing: None,
            },
        ];

        copy_table::<X86Mmu, _, _>(
            &LinuxForkPolicy,
            &huge_mem,
            req,
            &mut huge_scratch,
            ForkTableCursor {
                table: root_pa,
                level: 0,
                base: 0,
                child_offset: 0,
            },
        )
        .unwrap();

        // The parent's L2 entry must be updated to a table pointer pointing to the new parent L1 table.
        let parent_edit = huge_scratch
            .edits
            .iter()
            .find(|e| e.pa == l2_pa)
            .expect("parent L2 entry must be edited when huge leaf is split");
        assert_eq!(
            parent_edit.after & HUGE,
            0,
            "parent split entry must be a table pointer with HUGE (PS) bit clear"
        );
        assert_ne!(
            parent_edit.after & PRESENT,
            0,
            "parent split entry must have PRESENT set"
        );
        assert_ne!(
            parent_edit.after & WRITE,
            0,
            "parent split entry must preserve WRITE permission"
        );
        assert_ne!(
            parent_edit.after & USER,
            0,
            "parent split entry must preserve USER permission"
        );
        assert_ne!(
            parent_edit.after & NX,
            0,
            "parent split entry must preserve NX permission"
        );
        assert_eq!(
            parent_edit.after & (COW | MAY_WRITE | PREPARED),
            0,
            "parent split table entry must not carry leaf-only metadata bits"
        );

        // The child's L2 entry must also be a table pointer with HUGE cleared.
        // Child L4 is at child offset 0. Index 0 points to child L3 table.
        // Child L3 table is at offset 512. Index 0 points to child L2 table.
        // Child L2 table is at offset 1024. Index 0 is the split table pointer.
        let child_l2_desc = huge_scratch.child[1024];
        assert_eq!(
            child_l2_desc & HUGE,
            0,
            "child split entry must be a table pointer with HUGE (PS) bit clear"
        );
        assert_ne!(
            child_l2_desc & PRESENT,
            0,
            "child split entry must have PRESENT set"
        );
        assert_ne!(
            child_l2_desc & WRITE,
            0,
            "child split entry must preserve WRITE permission"
        );
        assert_ne!(
            child_l2_desc & USER,
            0,
            "child split entry must preserve USER permission"
        );
        assert_ne!(
            child_l2_desc & NX,
            0,
            "child split entry must preserve NX permission"
        );
        assert_eq!(
            child_l2_desc & (COW | MAY_WRITE | PREPARED),
            0,
            "child split table entry must not carry leaf-only metadata bits"
        );
    }

    // A test ISA with an unrelated control window and a deliberately different
    // copy layout. Shared fork must use its capabilities rather than ARM addresses.
    struct RelocatedControlMmu;
    const TEST_CONTROL_BASE: u64 = 0x80_0000;
    const TEST_ALIAS_BASE: u64 = TEST_CONTROL_BASE + 0x3000;

    impl carrick_mmu_core::owner_mmu::OwnerMmu for RelocatedControlMmu {
        fn root(register: u64) -> Result<RootGpa, OwnerMmuRefusal> {
            X86Mmu::root(register)
        }
        fn translate<W: LiveDescriptorWords + ?Sized>(
            words: &W,
            root: RootGpa,
            va: UserVa,
            access: carrick_mmu_core::aarch64::LeafAccess,
            user: bool,
        ) -> Result<Option<OwnerTranslation>, OwnerMmuRefusal> {
            X86Mmu::translate(words, root, va, access, user)
        }
        fn classify_cow<W: LiveDescriptorWords + ?Sized>(
            words: &W,
            root: RootGpa,
            va: UserVa,
            executable_publication: bool,
        ) -> Result<(), OwnerMmuRefusal> {
            X86Mmu::classify_cow(words, root, va, executable_publication)
        }
    }

    impl carrick_mmu_core::owner_mmu::OwnerForkMmu for RelocatedControlMmu {
        const ADDRESS_MASK: u64 = X86Mmu::ADDRESS_MASK;
        fn control_window() -> Option<(UserVa, UserVa)> {
            Some((
                UserVa::new(TEST_CONTROL_BASE),
                UserVa::new(TEST_CONTROL_BASE + 0x20_0000),
            ))
        }
        fn is_control_alias(va: UserVa) -> bool {
            (TEST_ALIAS_BASE..TEST_ALIAS_BASE + 8192).contains(&va.raw())
        }
        fn control_alias_destination(
            va: UserVa,
            child_tables: FrameGpa,
        ) -> Result<FrameGpa, OwnerMmuRefusal> {
            if !Self::is_control_alias(va) {
                return Err(OwnerMmuRefusal::Unreachable);
            }
            Ok(FrameGpa::new(
                child_tables.raw() + va.raw() - TEST_ALIAS_BASE,
            ))
        }
        fn control_copy_destination(
            va: UserVa,
            child_control: FrameGpa,
        ) -> Result<FrameGpa, OwnerMmuRefusal> {
            if !(TEST_CONTROL_BASE..TEST_CONTROL_BASE + 0x20_0000).contains(&va.raw()) {
                return Err(OwnerMmuRefusal::Unreachable);
            }
            Ok(FrameGpa::new(
                child_control.raw() + 0x1_0000 + 2 * (va.raw() - TEST_CONTROL_BASE),
            ))
        }
        fn is_table(word: u64, level: usize) -> bool {
            X86Mmu::is_table(word, level)
        }
        fn table_word(output: FrameGpa, inherited: Option<u64>) -> u64 {
            X86Mmu::table_word(output, inherited)
        }
        fn is_user(word: u64) -> bool {
            X86Mmu::is_user(word)
        }
        fn is_retired(word: u64) -> bool {
            X86Mmu::is_retired(word)
        }
        fn is_absent_unowned(word: u64) -> bool {
            X86Mmu::is_absent_unowned(word)
        }
        fn is_owned_resident(word: u64) -> bool {
            X86Mmu::is_owned_resident(word)
        }
        fn is_writable_user(word: u64) -> bool {
            X86Mmu::is_writable_user(word)
        }
        fn is_executable_control(word: u64) -> bool {
            X86Mmu::is_executable_control(word)
        }
        fn control_needs_copy(va: UserVa, word: u64) -> bool {
            !Self::is_control_alias(va) && word & WRITE != 0
        }
        fn split(word: u64, level: usize, index: usize) -> Result<u64, OwnerMmuRefusal> {
            X86Mmu::split(word, level, index)
        }
        fn arm_private(word: u64, level: usize, va: UserVa) -> Result<u64, OwnerMmuRefusal> {
            X86Mmu::arm_private(word, level, va)
        }
        fn needs_break_before_make(before: u64, after: u64, level: usize) -> bool {
            X86Mmu::needs_break_before_make(before, after, level)
        }
    }

    #[test]
    fn x2_fork_control_window_census_uses_adapter_bounds_and_aliases() {
        let mut count = carrick_core::mm::fork::ForkCensus {
            child: 0,
            parent: 0,
            live: 0,
            custody: 0,
        };
        carrick_core::mm::fork::census_entry::<RelocatedControlMmu, _, _>(
            &LinuxForkPolicy,
            &TestMemory::new(),
            &[],
            0x100_0000 | PRESENT | WRITE | HUGE | NX,
            2,
            TEST_CONTROL_BASE,
            &mut count,
        )
        .unwrap();
        assert_eq!(
            count.child, 512,
            "control block splits into one child table"
        );
        assert_eq!(count.parent, 0, "structural split leaves parent unchanged");
        assert_eq!(count.custody, 510, "two alias pages need no custody");
        assert_eq!(
            count.live, 0,
            "splitting a terminal needs no live table scan"
        );
    }

    #[test]
    fn x2_fork_control_alias_destination_comes_from_adapter() {
        let request = sample_request(5);
        let mut scratch = ForkScratch::new(request, 0).unwrap();
        let descriptor = 0x100_0000 | PRESENT | WRITE | NX;
        let (parent, child) = carrick_core::mm::fork::copy_entry::<RelocatedControlMmu, _, _>(
            &LinuxForkPolicy,
            &TestMemory::new(),
            request,
            &mut scratch,
            descriptor,
            3,
            TEST_ALIAS_BASE + 4096,
        )
        .unwrap();
        assert_eq!(parent, descriptor);
        assert_eq!(
            child,
            (request.child_tables.base + 4096) | PRESENT | WRITE | NX
        );
        assert!(scratch.custody.is_empty());

        let short_request = PortalForkRequest {
            child_tables: PortalForkTableArena::new(request.child_tables.base, 4096).unwrap(),
            ..request
        };
        assert_eq!(
            carrick_core::mm::fork::copy_entry::<RelocatedControlMmu, _, _>(
                &LinuxForkPolicy,
                &TestMemory::new(),
                short_request,
                &mut scratch,
                descriptor,
                3,
                TEST_ALIAS_BASE + 4096,
            ),
            Err(ForkError::NoMemory)
        );
    }

    #[test]
    fn x2_fork_structural_copy_destination_comes_from_adapter() {
        let request = sample_request(5);
        let mut scratch = ForkScratch::bounded(request, 0, 1024, 0, 0, 512).unwrap();
        let descriptor = 0x100_0000 | PRESENT | WRITE | HUGE | NX;
        let (parent, child) = carrick_core::mm::fork::copy_entry::<RelocatedControlMmu, _, _>(
            &LinuxForkPolicy,
            &TestMemory::new(),
            request,
            &mut scratch,
            descriptor,
            2,
            TEST_CONTROL_BASE,
        )
        .unwrap();
        assert_eq!(parent, descriptor);
        assert_eq!(
            child,
            (request.child_tables.base + 4096) | PRESENT | WRITE | NX
        );
        assert_eq!(scratch.child_used, 1024);
        assert_eq!(scratch.parent_used, 0);
        assert_eq!(scratch.custody.len(), 510);
        for index in 0..512 {
            let destination = if (3..5).contains(&index) {
                request.child_tables.base + (index - 3) * 4096
            } else {
                request.kernel_control_ipa + 0x1_0000 + index * 8192
            };
            assert_eq!(
                scratch.child[512 + index as usize],
                destination | PRESENT | WRITE | NX
            );
        }
        for (index, custody) in (0..512)
            .filter(|i| !(3..5).contains(i))
            .zip(&scratch.custody)
        {
            assert_eq!(
                *custody,
                PortalForkCustody::StructuralCopy {
                    source_ipa: 0x100_0000 + index * 4096,
                    destination_ipa: request.kernel_control_ipa + 0x1_0000 + index * 8192,
                    len: 4096,
                    executable: false,
                }
            );
        }
        assert!(scratch.edits.is_empty());
        assert!(scratch.reads.is_empty());
    }
}

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
