//! HVF physical adapters for the shared HAL fork-stock owner.
//!
//! Wire records are kernel virtual addresses on the stopped CPU's retained
//! ABI stack. Only table frames are resolved through physical inventory.
use carrick_guest_arch::{FrameGpa, RootGpa};
use carrick_hal::asid::{AsidAllocator, AsidGeneration};
pub use carrick_hal::fork_stock::{ForkStockServiceError, GrantExecution, take_fork_table_stock};
use core::num::NonZeroU64;
pub type PendingForkLoan = carrick_hal::fork_stock::PendingForkLoan<AsidGeneration>;
use crate::trap::{CarrierVmCustody, El1FrameGrantLedger, El1FrameGrantMm};
use carrick_hal::fork_stock::{ForkStock, ForkTableLedger};

#[derive(Debug)]
pub struct ForkStockHostCustody {
    pub(crate) owner: ForkStock<AsidAllocator>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    backing: Option<NativeForkBacking>,
    run_failure: carrick_core_abi::NativeRunFailureConsumer,
}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
struct NativeForkBacking {
    _arenas: Vec<std::sync::Arc<crate::trap::StructuralBackingOwner>>,
    resources: carrick_hal::fork_stock::NativeForkStockResources,
}

impl ForkStockHostCustody {
    pub fn new(carrier: NonZeroU64) -> Self {
        Self::with_asids(carrier, AsidAllocator::new())
    }
    pub fn with_asids(carrier: NonZeroU64, asids: AsidAllocator) -> Self {
        Self {
            owner: ForkStock::new(
                carrier,
                carrick_mem::memory::LINUX_KERNEL_REGION_BASE,
                asids,
            ),
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            backing: None,
            run_failure: Default::default(),
        }
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn install(
        custody: &std::sync::Arc<CarrierVmCustody>,
        resources: carrick_hal::fork_stock::NativeForkStockResources,
    ) -> Result<(), carrick_hal::TrapError> {
        use carrick_hal::TrapError;
        let fail = |message: &str| TrapError::Hypervisor(message.into());
        let pool = custody.root_slot_pool();
        let mut stock = custody.fork_stock.lock();
        if stock.backing.is_some() {
            return Err(fail("native fork stock already installed"));
        }
        let mut arenas = Vec::new();
        let mut tables = Vec::new();
        for root in resources.tables.arenas() {
            let epoch = crate::trap::next_structural_epoch()?;
            let base = root.address().raw();
            let len = crate::frame_pool::ROOT_SLOT_SIZE;
            let perms = u64::from(applevisor::memory::MemPerms::ReadWriteExec);
            let mut lease = crate::trap::GlobalFrameStage2Lease::fixed(base, len as u64);
            let owner =
                if let Some(arena) = pool.as_ref().and_then(|pool| pool.allocate_slot_at(base)) {
                    // The shared owner can populate every page, so pool recycling
                    // must clear the whole arena rather than a host-observed prefix.
                    arena.record_populated_prefix(len);
                    lease.mark_pre_mapped();
                    crate::trap::StructuralBackingOwner::new_pooled_root_in(
                        custody, arena, lease, perms, epoch, base, len,
                    )?
                } else {
                    // Same retained structural backing used by host roots outside
                    // the optional pre-map (including its existing =0 opt-out).
                    let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                        len,
                        crate::host_mapping::HostMappingKind::PerMmKernelState,
                    )
                    .map_err(|error| fail(&format!("native fork arena backing: {error}")))?;
                    // SAFETY: exclusively reserved physical slot and retained aligned mapping.
                    let result = unsafe {
                        crate::trap::inventory_hv_vm_map(mapping.as_ptr().cast(), base, len, perms)
                    };
                    if result != 0 {
                        return Err(fail(&format!("native fork arena map: {result:#x}")));
                    }
                    lease.mark_mapped();
                    crate::trap::StructuralBackingOwner::new_in(
                        custody, mapping, lease, perms, epoch, base, len,
                    )?
                };
            for offset in (0..len).step_by(4096) {
                tables.push(
                    RootGpa::page_aligned(FrameGpa::new(base + offset as u64))
                        .ok_or_else(|| fail("unaligned fork arena"))?,
                );
            }
            arenas.push(owner);
        }
        let generation = custody
            .live_generation()
            .ok_or_else(|| fail("native fork stock has no live carrier"))?;
        let reply = crate::metadata_grant::service_metadata_operation(
            custody,
            Some(generation),
            carrick_guest_arch::CpuId::new(0),
            None,
            carrick_el1_abi::METADATA_GRANT_OP_ALLOC,
            carrick_el1_abi::EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64,
            0,
            0,
        )?;
        if reply[0] != carrick_el1_abi::METADATA_GRANT_SUCCESS {
            return Err(fail("native fork lifecycle extent unavailable"));
        }
        let lifecycles = carrick_hal::fork_stock::lifecycle_slots(
            carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE,
            reply[1],
            reply[2] / carrick_hal::fork_stock::LIFECYCLE_SLOT_STRIDE,
        )
        .ok_or_else(|| fail("native fork lifecycle extent layout"))?;
        stock
            .owner
            .install(tables, lifecycles)
            .map_err(|error| fail(&format!("native fork stock install: {error:?}")))?;
        stock.backing = Some(NativeForkBacking {
            resources,
            _arenas: arenas,
        });
        Ok(())
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn inventory(
        &self,
    ) -> Option<std::sync::Arc<dyn carrick_hal::PhysicalFrameInventory>> {
        Some(std::sync::Arc::clone(
            &self.backing.as_ref()?.resources.inventory,
        ))
    }

    pub fn asids(&self) -> &AsidAllocator {
        self.owner.tags()
    }
    pub(crate) fn service_run_failure(
        &mut self,
        execution: GrantExecution,
        record: &carrick_core_abi::NativeRunFailure,
    ) -> Result<(carrick_core_abi::NativeRunFailureReason, u64), ForkStockServiceError> {
        self.run_failure
            .consume(record, execution.binding)
            .ok_or(ForkStockServiceError::StaleExecution)
    }
    pub(crate) fn service_root_exit(
        &mut self,
        execution: GrantExecution,
        record: &carrick_core_abi::NativeRootExit,
    ) -> Result<carrick_personality_linux::lifecycle::LinuxWaitStatus, ForkStockServiceError> {
        let status = record
            .status_for(execution.binding)
            .and_then(|s| {
                carrick_personality_linux::lifecycle::LinuxWaitStatus::from_termination_status(s)
                    .ok()
            })
            .ok_or(ForkStockServiceError::StaleExecution)?;
        let mm = carrick_el1_abi::ReservationMm::new(execution.binding.mm.raw())
            .ok_or(ForkStockServiceError::StaleExecution)?;
        self.owner.retire_exited_root(mm);
        Ok(status)
    }
    /// Resolve a complete physical object, never a kernel virtual wire record.
    pub(crate) fn physical_ptr<T>(
        custody: &CarrierVmCustody,
        frame: FrameGpa,
    ) -> Result<*mut T, ForkStockServiceError> {
        let address = frame.raw();
        let identity = custody
            .stage2_record_covering(address, core::mem::size_of::<T>())
            .ok_or(ForkStockServiceError::MemoryAccessFailed)?;
        let state = custody.state.lock();
        let record = state
            .stage2_records
            .get(&identity.record_id)
            .ok_or(ForkStockServiceError::MemoryAccessFailed)?;
        let offset = usize::try_from(
            address
                .checked_sub(record.snapshot.ipa)
                .ok_or(ForkStockServiceError::MemoryAccessFailed)?,
        )
        .map_err(|_| ForkStockServiceError::MemoryAccessFailed)?;
        let host = record
            .snapshot
            .host_addr
            .checked_add(offset)
            .filter(|host| *host != 0 && host.is_multiple_of(core::mem::align_of::<T>()))
            .ok_or(ForkStockServiceError::MemoryAccessFailed)?;
        Ok(host as *mut T)
    }
    pub(crate) fn clear_tables(custody: &CarrierVmCustody, pages: &[RootGpa]) -> bool {
        // Resolve every complete frame before clearing any of them.
        let Some(pointers) = pages
            .iter()
            .map(|page| Self::physical_ptr::<[u8; 4096]>(custody, page.address()).ok())
            .collect::<Option<Vec<_>>>()
        else {
            return false;
        };
        for pointer in pointers {
            // SAFETY: the HAL owner issued these quarantined frames only after
            // the neutral MM owner retired and every slot published absence.
            unsafe {
                pointer.write([0; 4096]);
            }
        }
        true
    }

    pub(crate) fn tables_clean(custody: &CarrierVmCustody, pages: &[RootGpa]) -> bool {
        pages.iter().all(|page| {
            Self::physical_ptr::<[u8; 4096]>(custody, page.address())
                .is_ok_and(|ptr| unsafe { &*ptr }.iter().all(|byte| *byte == 0))
        })
    }
}
impl ForkTableLedger for El1FrameGrantLedger {
    fn grant(&mut self, page: RootGpa, mm: carrick_el1_abi::ReservationMm) -> bool {
        El1FrameGrantMm::new(mm.raw())
            .is_some_and(|mm| self.mark_grant(page.address().raw(), 4096, mm).is_ok())
    }
    fn give_back(&mut self, page: RootGpa, mm: carrick_el1_abi::ReservationMm) {
        if let Some(mm) = El1FrameGrantMm::new(mm.raw()) {
            self.mark_return(page.address().raw(), 4096, mm, false);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use carrick_el1_abi::{
        EntryGeneration, EntryMmKey, EntryTaskKey, EntryThreadGeneration, ExecutionBinding,
        ForkLifecycleLoan, ForkStockExchange, PortalOperation, ReservationGeneration,
        ReservationMm,
    };
    use carrick_guest_arch::{AddressContext, ContextGeneration, CpuId, KernelVa, MmGeneration};
    fn page(addr: u64) -> RootGpa {
        RootGpa::page_aligned(FrameGpa::new(addr)).unwrap()
    }

    fn test_execution(task: u64, cpu: u32, mm: u64) -> GrantExecution {
        GrantExecution::new(
            CpuId::new(cpu),
            ExecutionBinding {
                task: EntryTaskKey::from_raw(task),
                generation: EntryGeneration::from_raw(11),
                mm: EntryMmKey::from_raw(mm),
                thread_generation: EntryThreadGeneration::from_raw(101),
            },
            AddressContext {
                mm: MmGeneration::new(NonZeroU64::new(mm).unwrap()),
                root: page(0x1000),
                generation: ContextGeneration::new(NonZeroU64::MIN),
            },
        )
    }

    fn test_request(
        exec: GrantExecution,
        child_mm: u64,
        child_pages: u64,
        parent_pages: u64,
    ) -> carrick_el1_abi::ForkStockRequest {
        carrick_el1_abi::ForkStockRequest {
            binding: exec.binding,
            context: exec.context,
            operation: PortalOperation {
                carrier: NonZeroU64::new(7).unwrap(),
                mm: ReservationMm::new(exec.context.mm.raw().get()).unwrap(),
                incarnation: NonZeroU64::MIN,
                sequence: NonZeroU64::new(2).unwrap(),
            },
            parent_generation: ReservationGeneration::INITIAL,
            child_mm: ReservationMm::new(child_mm).unwrap(),
            child_bytes: child_pages * 4096,
            parent_bytes: parent_pages * 4096,
        }
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn native_stock_crossing_reads_kernel_stack_and_current_execution() {
        let custody = CarrierVmCustody::new();
        let generation = custody.begin_create().unwrap();
        custody.commit_create(generation).unwrap();
        let region = carrick_test_support::TestEl1Region::zeroed();
        let physical = carrick_test_support::TestEl1Region::zeroed();
        let mut exec = test_execution(41, 0, 301);
        exec.context.root = page(carrick_el1_abi::AARCH64_STAGE1_TABLE_POOL_BASE);
        let ttbr0 = (1 << 48) | exec.context.root.address().raw();
        let slot = carrick_guest_arch::SlotId::new(0);
        // SAFETY: exclusively owned, aligned initialized ABI fixture storage.
        let zone = unsafe {
            &*region
                .as_ptr()
                .add(carrick_el1_abi::EL1_ZONE_OFFSET as usize)
                .cast::<carrick_el1_abi::ZoneTables>()
        };
        let space = zone.spaces.publish_closed(301, ttbr0, ttbr0).unwrap();
        zone.spaces.open(space);
        zone.drive(slot, 301);
        zone.publish_slot(slot, 301, Some(0), 1);
        zone.enter_guest(slot);
        zone.install_space(slot, 301).unwrap();
        // SAFETY: this stopped CPU's CurrentTask belongs to the fixture.
        let task = unsafe {
            &*region
                .as_ptr()
                .add(carrick_el1_abi::EL1_CURRENT_TASKS_OFFSET as usize)
                .cast::<carrick_el1_abi::CurrentTask>()
        };
        task.set(carrick_el1_abi::El1TaskId::from_linux_tid(41), 11, 1);
        task.mm
            .key
            .store(301, core::sync::atomic::Ordering::Release);
        task.mm
            .thread_generation
            .store(101, core::sync::atomic::Ordering::Release);
        task.publish_root_generation(exec.context.generation);
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
                        host_addr: unsafe { physical.as_ptr().add(offset) } as usize,
                        mapped: true,
                        backend_map_installed: true,
                        release_ipa: false,
                        perms: 3,
                        logical_owner: Some(crate::trap::CarrierLogicalOwner { id, generation: 1 }),
                    },
                    || 0,
                )
                .unwrap();
        }
        {
            let mut stock = custody.fork_stock.lock();
            stock.owner.set_carrier(NonZeroU64::new(7).unwrap());
            stock
                .owner
                .install(
                    (0..8)
                        .map(|index| page(stock_base + index * 4096))
                        .collect(),
                    vec![ForkLifecycleLoan::ARM_DEFAULT],
                )
                .unwrap();
        }
        let request = test_request(exec, 302, 4, 1);
        let address = KernelVa::new(carrick_el1_abi::EL1_STACKS_BASE);
        let offset = (address.raw() - carrick_el1_abi::EL1_REGION_BASE) as usize;
        // SAFETY: aligned complete loan record on this CPU's retained fixture stack.
        let record = unsafe {
            &mut *region
                .as_ptr()
                .add(offset)
                .cast_mut()
                .cast::<ForkStockExchange>()
        };
        *record = ForkStockExchange::new(request).unwrap();
        assert!(
            custody
                .stage2_record_covering(address.raw(), core::mem::size_of::<ForkStockExchange>())
                .is_none()
        );
        let bytes = unsafe {
            core::slice::from_raw_parts(region.as_ptr(), carrick_el1_abi::EL1_REGION_SIZE as usize)
        };
        // A caller cannot redirect the crossing to another CPU, root or VM.
        for (requested_cpu, root, live) in [
            (1, ttbr0, Some(generation)),
            (0, ttbr0 + 4096, Some(generation)),
            (0, ttbr0, None),
        ] {
            let reply = crate::metadata_grant::service_native_fork_stock(
                &custody,
                live,
                exec.cpu,
                address,
                requested_cpu,
                root,
                bytes,
            )
            .unwrap();
            assert_eq!(reply[0], carrick_el1_abi::METADATA_GRANT_ERR_DENIED);
            assert!(custody.fork_stock.lock().owner.pending(exec.cpu).is_none());
            *record = ForkStockExchange::new(request).unwrap();
        }
        for bad in [
            KernelVa::new(address.raw() + 1),
            KernelVa::new(address.raw() + carrick_el1_abi::EL1_STACK_SIZE - 64),
        ] {
            assert!(
                crate::metadata_grant::abi_stack_ptr::<ForkStockExchange>(bytes, exec.cpu, bad)
                    .is_none()
            );
        }
        let reply = crate::metadata_grant::service_native_fork_stock(
            &custody,
            Some(generation),
            exec.cpu,
            address,
            0,
            ttbr0,
            bytes,
        )
        .unwrap();
        assert_eq!(
            reply,
            [carrick_el1_abi::METADATA_GRANT_SUCCESS, 0, 0, 0],
            "native loan must use retained KernelVa and live lane identity"
        );
        let loan = record.take(request).unwrap().unwrap();
        assert_eq!(loan.request.child_tables.base, stock_base);
        assert_eq!(loan.request.child_tables.len, 4 * 4096);
        assert_ne!(loan.lifecycle.page, KernelVa::new(0));
        // A real typed abort restores the HAL owner's stock and physical ledger.
        let settlement =
            record as *mut ForkStockExchange as *mut carrick_el1_abi::ForkStockSettlement;
        unsafe {
            settlement.write(carrick_el1_abi::ForkStockSettlement::abort(loan));
        }
        let reply = crate::metadata_grant::service_native_fork_stock(
            &custody,
            Some(generation),
            exec.cpu,
            address,
            0,
            ttbr0,
            bytes,
        )
        .unwrap();
        assert_eq!(reply[0], carrick_el1_abi::METADATA_GRANT_SUCCESS);
        assert_eq!(unsafe { &mut *settlement }.take(loan), Some(Ok(())));
        let stock = custody.fork_stock.lock();
        assert_eq!(stock.owner.table_stock().len(), 8);
        assert!(stock.owner.lifecycle_available());
        assert!(stock.owner.pending(exec.cpu).is_none());
    }
}
