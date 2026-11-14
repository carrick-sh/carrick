//! VM-free HVF production exclusion/reclaim witness for #1482 P0-1.
use super::*;
use carrick_el1::memory::reservations::{Decision, Layout, Placement, SharedReservations};
use carrick_el1_abi::{
    ReservationBackingReceipt, ReservationCompletion, ReservationProtection, ReservationRange,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Debug)]
struct Tables;
impl carrick_hal::fork_stock::NativeForkTableReservation for Tables {
    fn arenas(&self) -> &[RootGpa] {
        &[]
    }
}
struct Inventory(AtomicUsize);
impl carrick_hal::PhysicalFrameInventory for Inventory {
    fn bind(&self, _: carrick_hal::GuestFrameOwner) -> Arc<dyn carrick_hal::FrameCowAuthority> {
        panic!("this fixture releases retired MMs; it never binds a live MM")
    }
    fn allocate_backing_ids(
        &self,
    ) -> Result<
        (carrick_hal::FrameId, carrick_hal::MappingId),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Err("no frame allocation in the reclaim fixture".into())
    }
    fn retire_mm(
        &self,
        _: MmGeneration,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(0)
    }
}
struct RestoreRegion(usize);
impl Drop for RestoreRegion {
    fn drop(&mut self) {
        carrick_el1_abi::record_el1_region_host_ptr(self.0);
    }
}
fn completion(request: carrick_el1_abi::ReservationRequest) -> ReservationCompletion {
    // SAFETY: VM-free model of descriptor retirement; no live descriptor is
    // created, and only the production whole-MM release frees the owed slots.
    unsafe {
        ReservationCompletion::after_descriptor_and_backing_commit(
            request,
            ReservationBackingReceipt {
                receipt: request.sequence.raw(),
                granted_bytes: 0,
                returned_bytes: 0,
            },
        )
    }
    .unwrap()
}

#[test]
fn native_exclusion_reclaims_a_full_table_of_exited_fork_holders() {
    let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
    let previous_region = carrick_el1_abi::get_el1_region_host_ptr();
    let custody = Arc::new(CarrierVmCustody::new());
    let generation = custody.begin_create().unwrap();
    custody.commit_create(generation).unwrap();
    let mut region = carrick_test_support::TestEl1Region::zeroed();
    let region_ptr = region.as_mut_ptr();
    carrick_el1_abi::record_el1_region_host_ptr(region_ptr as usize);
    // Restore the global pointer before the owned region can be freed.
    let _restore = RestoreRegion(previous_region);
    // SAFETY: aligned zero-valid ABI records in owned TestEl1Region storage.
    let zone = unsafe {
        &*region_ptr
            .add(carrick_el1_abi::EL1_ZONE_OFFSET as usize)
            .cast::<carrick_el1_abi::ZoneTables>()
    };
    // SAFETY: disjoint aligned zero-valid reservation storage in the owned region.
    let returns = unsafe {
        &*region_ptr
            .add(carrick_el1_abi::EL1_RESERVATIONS_OFFSET as usize)
            .cast::<SharedReservations>()
    };
    let mut physical = carrick_test_support::TestEl1Region::zeroed();
    let stock_base = carrick_el1_abi::AARCH64_STAGE1_TABLE_POOL_BASE;
    for (ipa, len, offset, id) in [
        (stock_base, 0x10000, 0usize, 1),
        (
            carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE,
            0x40000,
            0x10000,
            2,
        ),
    ] {
        assert!(offset + len <= carrick_el1_abi::EL1_REGION_SIZE as usize);
        // SAFETY: each complete mapped span is within the retained fixture storage.
        let host_addr = unsafe { physical.as_mut_ptr().add(offset) } as usize;
        custody
            .publish_stage2_record_using(
                crate::trap::CarrierStage2RecordSpec {
                    vm_generation: generation,
                    ipa,
                    len,
                    host_addr,
                    mapped: true,
                    backend_map_installed: true,
                    release_ipa: false,
                    perms: 3,
                    logical_owner: Some(crate::trap::CarrierLogicalOwner { id, generation: 1 }),
                },
                |_| 0,
            )
            .unwrap();
    }
    let inventory = Arc::new(Inventory(AtomicUsize::new(0)));
    let mut stock = custody.fork_stock.lock();
    stock.backing = Some(NativeForkBacking {
        _arenas: Vec::new(),
        resources: carrick_hal::fork_stock::NativeForkStockResources {
            tables: Arc::new(Tables),
            inventory: inventory.clone(),
        },
    });
    stock.owner.set_carrier(custody.transfer_carrier);
    stock
        .owner
        .install(
            (0..16).map(|i| page(stock_base + i * 4096)).collect(),
            (0..8)
                .map(|i| {
                    ForkLifecycleLoan::new(
                        KernelVa::new(ForkLifecycleLoan::ARM_DEFAULT.page.raw() + i * 0x4000),
                        KernelVa::new(ForkLifecycleLoan::ARM_DEFAULT.controls.raw() + i * 0x4000),
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap();
    for index in 0..8 {
        stock
            .owner
            .provide_arm_control_capacity(0x5000_0000 + index * 0x10000)
            .unwrap();
        let parent = test_execution(41, 0, 301);
        let child_mm = 302 + index;
        let mut request = test_request(parent, child_mm, 1, 1);
        request.operation.carrier = custody.transfer_carrier;
        let mut exchange = ForkStockExchange::new(request).unwrap();
        let mut ledger = fork_table_accounting(&custody);
        let loan = stock
            .owner
            .loan(&mut ledger, parent, &mut exchange, |_| true)
            .unwrap();
        let done = carrick_el1_abi::PortalForkCompletion {
            request: loan.request,
            // SAFETY: exact admitted loan identity in the VM-free fixture.
            child: unsafe {
                carrick_el1_abi::El1MmHandle::from_admitted_owner(
                    custody.transfer_carrier,
                    loan.request.child_mm,
                    NonZeroU64::MIN,
                )
            },
            parent_generation: ReservationGeneration::INITIAL,
            child_tables_used: 4096,
            parent_tables_used: 0,
        };
        let mut reserve =
            carrick_el1_abi::ForkStockSettlement::reserve(loan, done, KernelVa::new(0x1000), 0)
                .unwrap();
        stock
            .owner
            .reserve_custody(
                parent,
                &mut reserve,
                |_| true,
                |_| true,
                |_, _, _| Ok(NativeChildPhysical::default()),
            )
            .unwrap();
        let mut commit = carrick_el1_abi::ForkStockSettlement::commit_reserved(loan, done).unwrap();
        stock
            .owner
            .settle(
                &mut ledger,
                parent,
                &mut commit,
                |_| true,
                |_| true,
                |_| true,
            )
            .unwrap();
        let mut child = test_execution(42 + index, 1, child_mm);
        child.context.root = page(loan.request.child_tables.base);
        let mut retire =
            carrick_el1_abi::NativeChildRetire::new(child.binding, child.context).unwrap();
        stock.owner.retire_child(child, &mut retire).unwrap();

        let mm = ReservationMm::new(child_mm).unwrap();
        returns
            .publish(
                index as usize,
                mm,
                Layout {
                    heap: ReservationRange::new(0x1000, 0x100000).unwrap(),
                    arena: ReservationRange::new(0x100000, 0x1000000).unwrap(),
                    brk: 0x1000,
                    address_limit: u64::MAX,
                    data_limit: u64::MAX,
                    external_address_bytes: 0,
                    external_data_bytes: 0,
                },
            )
            .unwrap();
        let mut root = returns.lock(index as usize, mm).unwrap();
        root.finish_import().unwrap();
        for extent in 0..8 {
            let start = 0x100000 + extent * 8192;
            let Decision::Work(map) = root
                .mmap(
                    Placement::Fixed(start),
                    4096,
                    ReservationProtection::READ_WRITE,
                )
                .unwrap()
            else {
                panic!("map")
            };
            root.complete(completion(map)).unwrap();
            let Decision::Work(unmap) = root
                .munmap(ReservationRange::new(start, start + 4096).unwrap())
                .unwrap()
            else {
                panic!("unmap")
            };
            let slot = root.reserve_return(unmap.range).unwrap();
            root.complete_deferring_return(completion(unmap), slot)
                .unwrap();
        }
        assert_eq!(root.retire_final().unwrap(), 8);
    }
    assert!(returns.owed_return_table_full());
    drop(stock);
    // This is the same entry invoked by HVF's production doorbell. No later
    // fork or terminal reclaim crossing is issued by this fixture.
    let excluded = zone.spaces.unpublished(301).unwrap();
    crate::metadata_grant::settle_native_exclusion_in(&custody, None, &excluded).unwrap();
    assert!(
        !returns.owed_return_table_full(),
        "the production exclusion must reclaim exited holders"
    );
    assert_eq!(inventory.0.load(Ordering::SeqCst), 8);
    assert!(!custody.fork_stock.lock().owner.has_quarantine());
}
