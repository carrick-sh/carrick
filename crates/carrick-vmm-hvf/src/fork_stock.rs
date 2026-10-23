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

#[derive(Default)]
pub(crate) struct NativeChildPhysical {
    pub inherited: Vec<crate::trap::ForkPhysicalRetention>,
    pub supplied: Option<
        carrick_hal::physical_grants::NativePhysicalGrants<std::sync::Arc<NativeFrameBacking>>,
    >,
    pub rollback: std::sync::Arc<carrick_hal::physical_grants::PhysicalGrantRollback>,
}
impl core::fmt::Debug for NativeChildPhysical {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativeChildPhysical")
            .field("inherited", &self.inherited)
            .field("supplied", &self.supplied)
            .finish_non_exhaustive()
    }
}
#[derive(Debug)]
pub(crate) struct NativeFrameBacking {
    pub carrier: std::sync::Weak<CarrierVmCustody>,
    pub ipa: u64,
    pub generation: u64,
}
impl Drop for NativeFrameBacking {
    fn drop(&mut self) {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        if let Some(carrier) = self.carrier.upgrade() {
            carrier
                .native_frame_backings
                .lock()
                .remove(&(self.ipa, self.generation));
            crate::trap::retire_global_frame_host_owner_if_generation_in(
                &carrier,
                self.ipa,
                carrick_el1_abi::COW_GRANT_SIZE,
                self.generation,
            );
        }
    }
}

#[derive(Debug)]
pub struct ForkStockHostCustody {
    pub(crate) owner: ForkStock<AsidAllocator, NativeChildPhysical>,
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
            owner: ForkStock::new(carrier, None, asids),
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
        if let Some(existing) = stock.backing.as_ref() {
            if existing.resources.matches(&resources) {
                return Ok(());
            }
            return Err(fail("native fork stock already installed"));
        }
        let mut arenas = Vec::new();
        let mut tables = Vec::new();
        let roots = resources.tables.arenas();
        for root in roots {
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
    pub(crate) fn ensure_control_capacity(
        &mut self,
        custody: &std::sync::Arc<CarrierVmCustody>,
    ) -> Result<(), carrick_hal::TrapError> {
        use carrick_hal::TrapError;
        if !self.owner.needs_control_capacity() {
            return Ok(());
        }
        if self.backing.is_none() {
            return Err(TrapError::Hypervisor("native fork backing absent".into()));
        }
        let len = usize::try_from(carrick_el1_abi::AARCH64_KERNEL_CONTROL_SIZE)
            .map_err(|_| TrapError::Hypervisor("native fork control size overflow".into()))?;
        let mut lease = crate::trap::GlobalFrameStage2Lease::reserve(len as u64, len as u64)?;
        let base = lease.base();
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            len,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .map_err(|error| TrapError::Hypervisor(format!("native fork control backing: {error}")))?;
        let perms = u64::from(applevisor::memory::MemPerms::ReadWriteExec);
        // SAFETY: the fresh IPA lease and mapping are retained by the owner.
        let result =
            unsafe { crate::trap::inventory_hv_vm_map(mapping.as_ptr().cast(), base, len, perms) };
        if result != 0 {
            return Err(TrapError::Hypervisor(format!(
                "native fork control map: {result:#x}"
            )));
        }
        lease.mark_mapped();
        let epoch = crate::trap::next_structural_epoch()?;
        let owner = crate::trap::StructuralBackingOwner::new_in(
            custody, mapping, lease, perms, epoch, base, len,
        )?;
        self.owner
            .provide_arm_control_capacity(base)
            .map_err(|error| {
                TrapError::Hypervisor(format!("native fork control install: {error:?}"))
            })?;
        if let Some(backing) = self.backing.as_mut() {
            backing._arenas.push(owner);
        }
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

    /// Qualify cold lifecycle storage without mutating it, then publish its
    /// exact control aliases only after the shared owner accepts the loan.
    /// The retained metadata window outlives this loan and its reclaim.
    pub(crate) fn loan(
        &mut self,
        ledger: &mut impl ForkTableLedger,
        execution: GrantExecution,
        exchange: &mut carrick_el1_abi::ForkStockExchange,
        resolve: impl FnOnce(
            carrick_el1_abi::ForkLifecycleLoan,
        ) -> Option<carrick_hal::fork_stock::LifecycleWindow>,
    ) -> Result<carrick_el1_abi::ForkStockLoan, carrick_el1_abi::ForkStockRefusal> {
        let mut prepared = None;
        let result = self.owner.loan(ledger, execution, exchange, |lifecycle| {
            prepared =
                resolve(lifecycle).and_then(|window| window.prepare_affinity_aliases(lifecycle));
            prepared.is_some()
        });
        if result.is_ok() {
            // An accepted loan necessarily consumed the successful cold
            // qualification above. Refused loans drop the unwritten token.
            // A lost qualification refuses exposure and leaves the pending
            // loan retained by the stock owner until carrier teardown.
            let Some(prepared) = prepared else {
                let refusal = carrick_el1_abi::ForkStockRefusal::Inventory;
                exchange.refuse(refusal);
                return Err(refusal);
            };
            prepared.publish();
        }
        result
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
        EntryMmKey, EntryTaskKey, EntryThreadGeneration, ExecutionBinding, ForkLifecycleLoan,
        ForkStockExchange, PortalOperation, ReservationGeneration, ReservationMm,
        SnapshotGeneration,
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
                generation: SnapshotGeneration::from_raw(11),
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
        let custody = std::sync::Arc::new(CarrierVmCustody::new());
        let generation = custody.begin_create().unwrap();
        custody.commit_create(generation).unwrap();
        let mut region = carrick_test_support::TestEl1Region::zeroed();
        let region_ptr = region.as_mut_ptr();
        let mut physical = carrick_test_support::TestEl1Region::zeroed();
        let physical_ptr = physical.as_mut_ptr();
        let mut exec = test_execution(41, 0, 301);
        exec.context.root = page(carrick_el1_abi::AARCH64_STAGE1_TABLE_POOL_BASE);
        let ttbr0 = (1 << 48) | exec.context.root.address().raw();
        let slot = carrick_guest_arch::SlotId::new(0);
        // SAFETY: exclusively owned, aligned initialized ABI fixture storage.
        let zone = unsafe {
            &*region_ptr
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
            &*region_ptr
                .add(carrick_el1_abi::EL1_CURRENT_TASKS_OFFSET as usize)
                .cast::<carrick_el1_abi::CurrentTask>()
        };
        task.set(
            carrick_el1_abi::El1TaskId::from_linux_tid(41),
            carrick_el1_abi::SnapshotGeneration::from_raw(11),
            1,
        );
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
                        host_addr: unsafe { physical_ptr.add(offset) } as usize,
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
            stock
                .owner
                .provide_arm_control_capacity(0x5000_0000)
                .unwrap();
        }
        let request = test_request(exec, 302, 4, 1);
        let address = KernelVa::new(carrick_el1_abi::EL1_STACKS_BASE);
        let offset = (address.raw() - carrick_el1_abi::EL1_REGION_BASE) as usize;
        // SAFETY: aligned complete loan record on this CPU's retained fixture stack.
        let record = unsafe { region_ptr.add(offset).cast::<ForkStockExchange>() };
        unsafe {
            record.write(ForkStockExchange::new(request).unwrap());
        }
        assert!(
            custody
                .stage2_record_covering(address.raw(), core::mem::size_of::<ForkStockExchange>())
                .is_none()
        );
        let bytes = unsafe {
            crate::metadata_grant::RetainedAbiRegion::new(
                region_ptr,
                carrick_el1_abi::EL1_REGION_SIZE as usize,
            )
            .unwrap()
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
            unsafe {
                record.write(ForkStockExchange::new(request).unwrap());
            }
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
        let loan = unsafe { &mut *record }.take(request).unwrap().unwrap();
        assert_eq!(loan.request.child_tables.base, stock_base);
        assert_eq!(loan.request.child_tables.len, 4 * 4096);
        assert_ne!(loan.lifecycle.page, KernelVa::new(0));
        // A real typed abort restores the HAL owner's stock and physical ledger.
        let settlement = record.cast::<carrick_el1_abi::ForkStockSettlement>();
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

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn native_stock_reserve_refuses_retiring_stage2_record_and_rolls_back_earlier_pin() {
        native_stock_retirement_race(false);
    }

    #[test]
    fn native_stock_reserve_accepts_custody_in_dynamic_metadata() {
        native_stock_retirement_race(true);
    }

    fn native_stock_retirement_race(dynamic_custody: bool) {
        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let custody = std::sync::Arc::new(CarrierVmCustody::new());
        let generation = custody.begin_create().unwrap();
        custody.commit_create(generation).unwrap();
        let mut region = carrick_test_support::TestEl1Region::zeroed();
        let region_ptr = region.as_mut_ptr();
        let mut physical = carrick_test_support::TestEl1Region::zeroed();
        let physical_ptr = physical.as_mut_ptr();
        let mut exec = test_execution(41, 0, 301);
        exec.context.root = page(carrick_el1_abi::AARCH64_STAGE1_TABLE_POOL_BASE);
        let ttbr0 = (1 << 48) | exec.context.root.address().raw();
        let slot = carrick_guest_arch::SlotId::new(0);
        // SAFETY: exclusively owned, aligned initialized ABI fixture storage.
        let zone = unsafe {
            &*region_ptr
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
            &*region_ptr
                .add(carrick_el1_abi::EL1_CURRENT_TASKS_OFFSET as usize)
                .cast::<carrick_el1_abi::CurrentTask>()
        };
        task.set(
            carrick_el1_abi::El1TaskId::from_linux_tid(41),
            carrick_el1_abi::SnapshotGeneration::from_raw(11),
            1,
        );
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
                        host_addr: unsafe { physical_ptr.add(offset) } as usize,
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
            stock.owner.set_carrier(custody.transfer_carrier);
            stock
                .owner
                .install(
                    (0..8)
                        .map(|index| page(stock_base + index * 4096))
                        .collect(),
                    vec![ForkLifecycleLoan::ARM_DEFAULT],
                )
                .unwrap();
            stock
                .owner
                .provide_arm_control_capacity(0x5000_0000)
                .unwrap();
        }
        let ipa_a = 0xa090_1000_0000;
        let ipa_b = ipa_a + 0x4000;
        let mut owners = Vec::new();
        for ipa in [ipa_a, ipa_b] {
            let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                0x4000,
                crate::host_mapping::HostMappingKind::PerMmKernelState,
            )
            .unwrap();
            let mut lease = crate::trap::GlobalFrameStage2Lease::fixed(ipa, 0x4000);
            lease.mark_test_mapped_without_backend();
            let owner = crate::trap::StructuralBackingOwner::new_in(
                &custody,
                mapping,
                lease,
                u64::from(applevisor::memory::MemPerms::ReadWrite),
                crate::trap::next_structural_epoch().unwrap(),
                ipa,
                0x4000,
            )
            .unwrap();
            owners.push(owner);
        }
        let owner_a = &owners[0];
        let owner_b = &owners[1];

        let mut request = test_request(exec, 302, 4, 1);
        request.operation.carrier = custody.transfer_carrier;
        let address = KernelVa::new(carrick_el1_abi::EL1_STACKS_BASE);
        let offset = (address.raw() - carrick_el1_abi::EL1_REGION_BASE) as usize;
        // SAFETY: aligned complete loan record on this CPU's retained fixture stack.
        let record = unsafe { region_ptr.add(offset).cast::<ForkStockExchange>() };
        unsafe {
            record.write(ForkStockExchange::new(request).unwrap());
        }
        let bytes = unsafe {
            crate::metadata_grant::RetainedAbiRegion::new(
                region_ptr,
                carrick_el1_abi::EL1_REGION_SIZE as usize,
            )
            .unwrap()
        };
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
        let loan = unsafe { &mut *record }.take(request).unwrap().unwrap();

        // The same retirement entry point used by munmap wins before Reserve.
        assert_eq!(
            custody.request_stage2_record_retirement(owner_b.record_identity()),
            crate::trap::CarrierStage2RetireOutcome::DeferredActivePins
        );

        let custody_offset = carrick_el1_abi::EL1_BOOTSTRAP_METADATA_OFFSET as usize;
        let (custody_va, custody_ptr) = if dynamic_custody {
            (
                KernelVa::new(carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE + 0x8000),
                unsafe { physical_ptr.add(0x18000) },
            )
        } else {
            (
                KernelVa::new(carrick_el1_abi::EL1_REGION_BASE + custody_offset as u64),
                unsafe { region_ptr.add(custody_offset) },
            )
        };
        let rows = [
            carrick_el1_abi::PortalForkCustody::Frame {
                va: 0x40_0000,
                ipa: ipa_a,
                len: 4096,
                shared: false,
            }
            .words(),
            carrick_el1_abi::PortalForkCustody::Frame {
                va: 0x40_1000,
                ipa: ipa_b,
                len: 4096,
                shared: false,
            }
            .words(),
        ];
        // SAFETY: aligned two-row array in the selected retained metadata grant.
        unsafe {
            custody_ptr.cast::<[[u64; 4]; 2]>().write(rows);
        }

        let completion_for =
            |loan: carrick_el1_abi::ForkStockLoan| carrick_el1_abi::PortalForkCompletion {
                request: loan.request,
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

        let settlement = record.cast::<carrick_el1_abi::ForkStockSettlement>();
        unsafe {
            settlement.write(
                carrick_el1_abi::ForkStockSettlement::reserve(
                    loan,
                    completion_for(loan),
                    custody_va,
                    2,
                )
                .unwrap(),
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
        assert_eq!(reply[0], carrick_el1_abi::METADATA_GRANT_ERR_DENIED);
        assert_eq!(
            unsafe { &mut *settlement }.take(loan),
            Some(Err(carrick_el1_abi::ForkStockRefusal::Inventory)),
            "Reserve must refuse when a selected stage-2 record is retiring"
        );
        assert_eq!(
            custody
                .stage2_record_snapshot(owner_a.record_identity().record_id)
                .unwrap()
                .pin_count,
            0,
            "earlier pinned frame must roll back when a later frame fails to pin"
        );
        assert_eq!(custody.fork_stock.lock().owner.live_children(), 0);

        // Abort the loan after the refused reservation and prove a subsequent
        // fork against the live frame succeeds end-to-end.
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

        let mut next_request = test_request(exec, 303, 4, 1);
        next_request.operation.carrier = custody.transfer_carrier;
        unsafe {
            record.write(ForkStockExchange::new(next_request).unwrap());
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
        let next_loan = unsafe { &mut *record }.take(next_request).unwrap().unwrap();
        unsafe {
            settlement.write(
                carrick_el1_abi::ForkStockSettlement::reserve(
                    next_loan,
                    completion_for(next_loan),
                    custody_va,
                    1,
                )
                .unwrap(),
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
        assert_eq!(reply[0], carrick_el1_abi::METADATA_GRANT_SUCCESS);
        assert_eq!(unsafe { &mut *settlement }.take(next_loan), Some(Ok(())));
        assert_eq!(
            custody
                .stage2_record_snapshot(owner_a.record_identity().record_id)
                .unwrap()
                .pin_count,
            1
        );
        assert_eq!(
            custody.request_stage2_record_retirement(owner_a.record_identity()),
            crate::trap::CarrierStage2RetireOutcome::DeferredActivePins,
            "retirement after Reserve cannot revoke the admitted child's backing"
        );

        unsafe {
            settlement.write(
                carrick_el1_abi::ForkStockSettlement::commit_reserved_with_child_identity(
                    next_loan,
                    completion_for(next_loan),
                    42,
                    102,
                )
                .unwrap(),
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
        assert_eq!(reply[0], carrick_el1_abi::METADATA_GRANT_SUCCESS);
        assert_eq!(unsafe { &mut *settlement }.take(next_loan), Some(Ok(())));
        assert_eq!(custody.fork_stock.lock().owner.live_children(), 1);
        assert_eq!(
            custody
                .stage2_record_snapshot(owner_a.record_identity().record_id)
                .unwrap()
                .pin_count,
            1,
            "committed child MM retains its stage-2 pin until MM retirement"
        );
    }
}
