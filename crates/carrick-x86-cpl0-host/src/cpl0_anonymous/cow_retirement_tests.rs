use super::*;
use crate::carrier_memory::{BackingExtent, CarrierMemoryIo, CarrierMemoryRegion, PreparedBacking};
use carrick_mmu_core::x86::descriptor_txn::BackingIdentity;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Default)]
struct TestIo(Mutex<HashMap<u32, CarrierMemoryRegion>>);

impl CarrierMemoryIo for TestIo {
    fn carrier_slot_limit(&self) -> Result<u32, carrick_hal::OsError> {
        Ok(2048)
    }

    unsafe fn set_user_memory_region(
        &self,
        region: CarrierMemoryRegion,
    ) -> Result<(), carrick_hal::OsError> {
        let mut regions = self.0.lock().unwrap();
        if region.memory_size == 0 {
            regions.remove(&region.slot);
        } else {
            regions.insert(region.slot, region);
        }
        Ok(())
    }

    fn signal_msi(&self, _: u32, _: u32) -> Result<(), carrick_hal::OsError> {
        Err(carrick_hal::OsError::new("unused test MSI"))
    }
}

#[test]
#[ignore = "#1733: red witness"]
fn retired_fork_children_release_cow_pool_grants_across_pool_capacity() {
    let nz = |n| NonZeroU64::new(n).unwrap();
    let mut memory = CarrierMemory::new(TestIo::default()).unwrap();
    let region_len = carrick_el1_abi::EL1_REGION_SIZE as usize;
    memory
        .install(&[PreparedBacking {
            extent: Arc::new(
                BackingExtent::private(FrameGpa::new(KERNEL_REGION_GPA), region_len).unwrap(),
            ),
            identity: BackingIdentity {
                frame_id: nz(1),
                mapping_id: nz(1),
                owner_generation: nz(1),
                inventory_revision: nz(1),
            },
        }])
        .unwrap();
    let root_arena_gpa = 0x4000_0000u64;
    memory
        .install(&[PreparedBacking {
            extent: Arc::new(BackingExtent::private(FrameGpa::new(root_arena_gpa), 4096).unwrap()),
            identity: BackingIdentity {
                frame_id: nz(2),
                mapping_id: nz(2),
                owner_generation: nz(2),
                inventory_revision: nz(2),
            },
        }])
        .unwrap();
    let inventory = Arc::new(carrick_kernel::kernel::FrameInventoryAuthority::new())
        .physical_projection(Arc::new(carrick_kernel::kernel::ObjectIdRegistry::new()));
    // SAFETY: zero-initialized retained carrier region owns these aligned tables.
    unsafe {
        let residency = memory
            .retained_record::<carrick_el1_abi::FrameGrantResidencyTable>(FrameGpa::new(
                KERNEL_REGION_GPA + carrick_el1_abi::EL1_FRAME_GRANT_RESIDENCY_OFFSET,
            ))
            .unwrap();
        carrick_el1_abi::FrameGrantResidencyTable::init_in_place(
            (&raw const *residency).cast_mut(),
        );
        let pool = memory
            .retained_record::<carrick_el1_abi::CowGrantPool>(FrameGpa::new(
                KERNEL_REGION_GPA + carrick_el1_abi::EL1_COW_GRANT_POOL_OFFSET,
            ))
            .unwrap();
        (&raw const *pool)
            .cast_mut()
            .write(carrick_el1_abi::CowGrantPool::new());
    }
    let cycles = carrick_core_abi::mm::cow_pool::COW_GRANT_POOL_SLOTS as u64 + 8;
    for cycle in 0..cycles {
        let mm_raw = 500 + cycle;
        let child_mm = ReservationMm::new(mm_raw).unwrap();
        let root_gpa = RootGpa::page_aligned(FrameGpa::new(root_arena_gpa)).unwrap();
        memory
            .install_root(
                nz(mm_raw),
                AddressContext {
                    root: root_gpa,
                    mm: MmGeneration::new(nz(mm_raw)),
                    generation: ContextGeneration::new(nz(10 + cycle)),
                },
            )
            .unwrap();
        // SAFETY: initialized above inside the retained carrier region.
        let pool = unsafe {
            memory
                .retained_record::<carrick_el1_abi::CowGrantPool>(FrameGpa::new(
                    KERNEL_REGION_GPA + carrick_el1_abi::EL1_COW_GRANT_POOL_OFFSET,
                ))
                .unwrap()
        };
        assert!(
            pool.publish(
                mm_raw,
                0x8000_0000 + cycle * 0x4000,
                carrick_mmu_core::aarch64::descriptor_txn::BackingIdentity {
                    frame_id: nz(200 + cycle),
                    mapping_id: nz(200 + cycle),
                    owner_generation: nz(1),
                    inventory_revision: nz(1),
                },
            )
            .is_some(),
            "COW grant pool exhausted at fork/exit cycle {cycle}: retired children leaked grants"
        );
        assert_eq!(pool.ready(mm_raw).count(), 1);
        let absence = SlotAbsence::scan(child_mm, [1u64].into_iter()).unwrap();
        release_retired_child(&mut memory, &*inventory, &absence).unwrap();
    }
    // SAFETY: initialized above inside the retained carrier region.
    let pool = unsafe {
        memory
            .retained_record::<carrick_el1_abi::CowGrantPool>(FrameGpa::new(
                KERNEL_REGION_GPA + carrick_el1_abi::EL1_COW_GRANT_POOL_OFFSET,
            ))
            .unwrap()
    };
    for cycle in 0..cycles {
        let mm_raw = 500 + cycle;
        assert_eq!(
            pool.ready(mm_raw).count(),
            0,
            "retired child MM {mm_raw} retained READY COW grant after release_retired_child"
        );
    }
}
