//! Fork Reserve retains the byte sources a native parent holds (#1522).
use super::*;

/// A byte source that answers only its identity: Reserve retains it by
/// identity and never reads it.
struct IdentitySource(carrick_el1_abi::HostBackingIdentity);
impl carrick_hal::fork_stock::HostBackingRetention for IdentitySource {
    fn identity(&self) -> carrick_el1_abi::HostBackingIdentity {
        self.0
    }
    fn read(
        &self,
        _: carrick_hal::fork_stock::HostBackingRead,
    ) -> Result<Vec<u8>, carrick_hal::fork_stock::HostBackingReadError> {
        Err(carrick_hal::fork_stock::HostBackingReadError::Unavailable)
    }
}

/// A native process that maps a byte source after its birth (an exec
/// successor's own image, a native private file mapping) holds it in its
/// committed custody's `sources`, not in the rows its own fork inherited.
/// Its fork selects that source as a `HostBacking` row, and Reserve must
/// retain it from the parent's custody. Every signed generic probe that
/// forks from the probe process (an exec successor of probeinit) got
/// `Inventory` here, so `fork` returned EAGAIN (`signalexit`,
/// `mprotectexec`).
#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn native_fork_reserve_retains_a_source_the_parent_acquired_after_birth() {
    let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
    let custody = std::sync::Arc::new(CarrierVmCustody::new());
    let generation = custody.begin_create().unwrap();
    custody.commit_create(generation).unwrap();
    let mut region = carrick_test_support::TestEl1Region::zeroed();
    let region_ptr = region.as_mut_ptr();
    let mut physical = carrick_test_support::TestEl1Region::zeroed();
    let physical_ptr = physical.as_mut_ptr();
    let slot = carrick_guest_arch::SlotId::new(0);
    // SAFETY: exclusively owned, aligned initialized ABI fixture storage.
    let zone = unsafe {
        &*region_ptr
            .add(carrick_el1_abi::EL1_ZONE_OFFSET as usize)
            .cast::<carrick_el1_abi::ZoneTables>()
    };
    // SAFETY: this stopped CPU's CurrentTask belongs to the fixture.
    let task = unsafe {
        &*region_ptr
            .add(carrick_el1_abi::EL1_CURRENT_TASKS_OFFSET as usize)
            .cast::<carrick_el1_abi::CurrentTask>()
    };
    // Run `tid` of `mm` on CPU 0 with `root`, as the stopped lane the
    // crossing authenticates.
    let run_on_cpu0 = |tid: i32, mm: u64, root: u64, asid: u64| {
        let ttbr0 = (asid << 48) | root;
        let space = zone.spaces.publish_closed(mm, ttbr0, ttbr0).unwrap();
        zone.spaces.open(space);
        zone.drive(slot, mm);
        zone.publish_slot(slot, mm, Some(0), 1);
        zone.enter_guest(slot);
        zone.install_space(slot, mm).unwrap();
        task.set(
            carrick_el1_abi::El1TaskId::from_linux_tid(tid),
            carrick_el1_abi::SnapshotGeneration::from_raw(11),
            1,
        );
        task.mm.key.store(mm, core::sync::atomic::Ordering::Release);
        task.mm
            .thread_generation
            .store(101, core::sync::atomic::Ordering::Release);
        task.publish_root_generation(ContextGeneration::new(NonZeroU64::MIN));
        ttbr0
    };
    let mut parent = test_execution(41, 0, 301);
    parent.context.root = page(carrick_el1_abi::AARCH64_STAGE1_TABLE_POOL_BASE);
    let ttbr0 = run_on_cpu0(41, 301, parent.context.root.address().raw(), 1);
    let stock_base = carrick_el1_abi::AARCH64_STAGE1_TABLE_POOL_BASE + 0x20_0000;
    for (ipa, len, offset, id) in [
        (stock_base, 0x8000, 0usize, 1),
        (
            carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE,
            0x10000,
            0x10000,
            2,
        ),
    ] {
        custody
            .publish_stage2_record_using(
                crate::trap::CarrierStage2RecordSpec {
                    vm_generation: generation,
                    ipa,
                    len,
                    host_addr: unsafe { physical_ptr.add(offset) } as usize,
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
    let second_lifecycle = ForkLifecycleLoan::new(
        KernelVa::new(ForkLifecycleLoan::ARM_DEFAULT.page.raw() + 0x4000),
        KernelVa::new(ForkLifecycleLoan::ARM_DEFAULT.controls.raw() + 0x4000),
    )
    .unwrap();
    {
        let mut stock = custody.fork_stock.lock();
        stock.owner.set_carrier(custody.transfer_carrier);
        stock
            .owner
            .install(
                (0..8)
                    .map(|index| page(stock_base + index * 4096))
                    .collect(),
                vec![second_lifecycle, ForkLifecycleLoan::ARM_DEFAULT],
            )
            .unwrap();
        // One control capacity per fork: neither is reclaimed here.
        for base in [0x5000_0000, 0x6000_0000] {
            stock.owner.provide_arm_control_capacity(base).unwrap();
        }
    }
    let address = KernelVa::new(carrick_el1_abi::stack_slot_usable_base(0));
    let offset = (address.raw() - carrick_el1_abi::EL1_REGION_BASE) as usize;
    // SAFETY: aligned complete records on this CPU's retained fixture stack.
    let record = unsafe { region_ptr.add(offset).cast::<ForkStockExchange>() };
    let settlement = record.cast::<carrick_el1_abi::ForkStockSettlement>();
    let bytes = unsafe {
        crate::metadata_grant::RetainedAbiRegion::new(
            region_ptr,
            carrick_el1_abi::EL1_REGION_SIZE as usize,
        )
        .unwrap()
    };
    let custody_va = KernelVa::new(
        carrick_el1_abi::EL1_REGION_BASE + carrick_el1_abi::EL1_BOOTSTRAP_METADATA_OFFSET as u64,
    );
    // SAFETY: the bootstrap metadata row array belongs to the fixture.
    let custody_rows = unsafe {
        region_ptr
            .add(carrick_el1_abi::EL1_BOOTSTRAP_METADATA_OFFSET as usize)
            .cast::<[u64; 4]>()
    };
    let cross = |ttbr0: u64| {
        crate::metadata_grant::service_native_fork_stock(
            &custody,
            Some(generation),
            CpuId::new(0),
            address,
            0,
            ttbr0,
            bytes,
        )
        .unwrap()[0]
    };
    // Loan, Reserve `rows` and (when Reserve succeeds) commit one fork.
    let fork = |exec: GrantExecution,
                ttbr0: u64,
                child_mm: u64,
                rows: &[[u64; 4]]|
     -> Result<(), carrick_el1_abi::ForkStockRefusal> {
        let mut request = test_request(exec, child_mm, 1, 1);
        request.operation.carrier = custody.transfer_carrier;
        unsafe {
            record.write(ForkStockExchange::new(request).unwrap());
        }
        let loaned = cross(ttbr0);
        let loan = unsafe { &mut *record }.take(request);
        assert_eq!(
            (loaned, loan.map(|loan| loan.map(|_| ()))),
            (carrick_el1_abi::METADATA_GRANT_SUCCESS, Some(Ok(()))),
            "the stock loans fork tables to the live lane: {:?}",
            custody.fork_stock.lock().owner.admission_refusal()
        );
        let loan = loan.unwrap().unwrap();
        let completion = carrick_el1_abi::PortalForkCompletion {
            request: loan.request,
            // SAFETY: this receipt names the exact stock loan above.
            child: unsafe {
                carrick_el1_abi::El1MmHandle::from_admitted_owner(
                    custody.transfer_carrier,
                    loan.request.child_mm,
                    NonZeroU64::MIN,
                )
            },
            parent_generation: ReservationGeneration::new(2).unwrap(),
            child_tables_used: 4096,
            parent_tables_used: 4096,
        };
        for (index, row) in rows.iter().enumerate() {
            unsafe { custody_rows.add(index).write(*row) };
        }
        unsafe {
            settlement.write(
                carrick_el1_abi::ForkStockSettlement::reserve(
                    loan,
                    completion,
                    custody_va,
                    rows.len() as u64,
                )
                .unwrap(),
            );
        }
        cross(ttbr0);
        if let Some(Err(refusal)) = unsafe { &mut *settlement }.take(loan) {
            unsafe { settlement.write(carrick_el1_abi::ForkStockSettlement::abort(loan)) };
            assert_eq!(cross(ttbr0), carrick_el1_abi::METADATA_GRANT_SUCCESS);
            return Err(refusal);
        }
        unsafe {
            settlement.write(
                carrick_el1_abi::ForkStockSettlement::commit_reserved_with_child_identity(
                    loan, completion, 42, 102,
                )
                .unwrap(),
            );
        }
        assert_eq!(cross(ttbr0), carrick_el1_abi::METADATA_GRANT_SUCCESS);
        assert_eq!(unsafe { &mut *settlement }.take(loan), Some(Ok(())));
        Ok(())
    };

    // The first native process is a committed child with no rows.
    fork(parent, ttbr0, 302, &[]).unwrap();
    // After birth it maps a byte source, recorded where exec
    // (`execve_rebuild`) and native private file mappings
    // (`with_native_sources_of`) record it.
    let source = carrick_el1_abi::HostBackingIdentity::new(
        NonZeroU64::new(2).unwrap(),
        NonZeroU64::new(1).unwrap(),
        0,
    );
    let child_root = {
        let mut stock = custody.fork_stock.lock();
        let mm = ReservationMm::new(302).unwrap();
        let root = stock.owner.child_root(mm).unwrap();
        stock
            .owner
            .child_physical_mut(mm, root)
            .unwrap()
            .sources
            .inherit(std::sync::Arc::new(IdentitySource(source)));
        root
    };
    // That process forks, selecting its own source.
    let mut native = test_execution(42, 0, 302);
    native.context.root = child_root;
    let native_ttbr0 = run_on_cpu0(42, 302, child_root.address().raw(), 2);
    let row = carrick_el1_abi::PortalForkCustody::HostBacking {
        handle: source.handle(),
        generation: source.generation(),
    }
    .words();
    assert_eq!(
        fork(native, native_ttbr0, 303, &[row]),
        Ok(()),
        "a fork must retain a source its parent acquired after birth"
    );
    assert_eq!(custody.fork_stock.lock().owner.live_children(), 2);
}
