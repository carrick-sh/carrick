//! HVF physical adapters for the shared HAL fork-stock owner.
//!
//! Wire records are kernel virtual addresses on the stopped CPU's retained
//! ABI stack. Only table frames are resolved through physical inventory.
use carrick_guest_arch::{FrameGpa, RootGpa};
use carrick_hal::asid::{AsidAllocator, AsidGeneration};
pub use carrick_hal::fork_stock::{ForkStockServiceError, GrantExecution, take_fork_table_stock};
use core::num::NonZeroU64;
pub type PendingForkLoan = carrick_hal::fork_stock::PendingForkLoan<AsidGeneration>;
use crate::trap::CarrierVmCustody;
use carrick_hal::fork_stock::{ForkStock, ForkTableLedger};

#[derive(Default)]
pub(crate) struct NativeChildPhysical {
    pub inherited: Vec<crate::trap::ForkPhysicalRetention>,
    pub sources: carrick_hal::fork_stock::ForkHostBackingCustody,
    pub supplied: Option<
        carrick_hal::physical_grants::NativePhysicalGrants<std::sync::Arc<NativeFrameBacking>>,
    >,
    pub rollback: std::sync::Arc<carrick_hal::physical_grants::PhysicalGrantRollback>,
}
impl carrick_hal::physical_grants::NativeSupplyCustody for NativeChildPhysical {
    type Backing = std::sync::Arc<NativeFrameBacking>;
    fn supplied(
        &mut self,
    ) -> Option<&mut carrick_hal::physical_grants::NativePhysicalGrants<Self::Backing>> {
        self.supplied.as_mut()
    }
}
impl carrick_hal::physical_grants::NativePreparedSupplyCustody for NativeChildPhysical {
    fn retained_prepared_frame(
        &self,
        address: carrick_guest_arch::UserVa,
    ) -> Option<carrick_el1_abi::PortalForkCustody> {
        self.inherited_frame(address)
    }
    fn prepared_supply(
        &mut self,
        owner: carrick_hal::GuestFrameOwner,
    ) -> (
        &mut carrick_hal::physical_grants::NativePhysicalGrants<Self::Backing>,
        std::sync::Arc<carrick_hal::physical_grants::PhysicalGrantRollback>,
    ) {
        let rollback = std::sync::Arc::clone(&self.rollback);
        let grants = self
            .supplied
            .get_or_insert_with(|| carrick_hal::physical_grants::NativePhysicalGrants::new(owner));
        (grants, rollback)
    }
}
impl NativeChildPhysical {
    pub fn new(mut inherited: Vec<crate::trap::ForkPhysicalRetention>) -> Self {
        // Keep the physical retentions themselves ordered, rather than a
        // second VA-to-output authority. First touch finds one covering frame
        // in logarithmic work even after a large fork.
        inherited.sort_by_key(|row| match row.selected() {
            carrick_el1_abi::PortalForkCustody::Frame { va, .. } => va,
            _ => u64::MAX,
        });
        let mut sources = carrick_hal::fork_stock::ForkHostBackingCustody::default();
        for row in &inherited {
            if let Some(source) = row.retained_host_backing() {
                sources.inherit(source);
            }
        }
        Self {
            inherited,
            sources,
            ..Default::default()
        }
    }

    /// Every byte source this MM's custody holds, as a fork from this MM
    /// must retain them. `sources` is that one set: `new` seeds it from the
    /// rows inherited at birth, and an exec image or a native private file
    /// mapping adds its source there after birth (and the ring's release
    /// list removes it). Reading only `inherited` refused every fork whose
    /// parent maps a source it acquired after birth (an exec successor's
    /// own image) as `Inventory`, which the guest saw as EAGAIN.
    pub fn fork_sources(&self) -> carrick_hal::fork_stock::ForkHostBackingCustody {
        self.sources.clone()
    }

    pub fn inherited_frame(
        &self,
        address: carrick_guest_arch::UserVa,
    ) -> Option<carrick_el1_abi::PortalForkCustody> {
        let index = self
            .inherited
            .partition_point(|row| match row.selected() {
                carrick_el1_abi::PortalForkCustody::Frame { va, .. } => va <= address.raw(),
                _ => false,
            })
            .checked_sub(1)?;
        let selected = self.inherited[index].selected();
        let carrick_el1_abi::PortalForkCustody::Frame {
            va,
            len,
            shared: false,
            ..
        } = selected
        else {
            return None;
        };
        address
            .raw()
            .checked_sub(va)?
            .checked_add(4096)
            .filter(|end| *end <= len)
            .map(|_| selected)
    }
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
    pub length: u64,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub retained_owner: std::sync::OnceLock<std::sync::Arc<crate::trap::GlobalFrameHostOwner>>,
}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl NativeFrameBacking {
    /// Pins retain unused bytes in their issuing MM, without claiming a
    /// physical-retirement receipt. Absence (carrier already torn down, or
    /// exact owner generation already retired by reconcile, drain, or an
    /// earlier release) is a completed release, not an invariant failure.
    pub(crate) fn release_unused(
        &self,
    ) -> Result<carrick_hal::physical_grants::PhysicalGrantRelease, carrick_hal::TrapError> {
        let Some(carrier) = self.carrier.upgrade() else {
            return Ok(carrick_hal::physical_grants::PhysicalGrantRelease::Released);
        };
        // Keep the exact immutable owner, not merely its weak carrier token.
        // The pin-drop idle turn may unmap stage-2 before MM retirement, but
        // retained custody still owns the host bytes and owner generation.
        let owner = carrier
            .global_frame_host_owners
            .lock()
            .get(&(self.ipa, self.length))
            .filter(|entry| entry.owner().generation() == self.generation)
            .map(|entry| std::sync::Arc::clone(entry.owner()));
        let Some(owner) = owner else {
            carrier
                .native_frame_backings
                .lock()
                .remove(&(self.ipa, self.generation));
            return Ok(carrick_hal::physical_grants::PhysicalGrantRelease::Released);
        };
        match crate::trap::retire_global_frame_host_owner_if_generation_in(
            &carrier,
            self.ipa,
            self.length,
            self.generation,
        ) {
            crate::trap::GlobalFrameRetirementOutcome::DeferredActivePins { .. }
            | crate::trap::GlobalFrameRetirementOutcome::RetryPending { .. } => {
                let _ = self.retained_owner.set(owner);
                Ok(carrick_hal::physical_grants::PhysicalGrantRelease::RetainUntilMmRetirement)
            }
            crate::trap::GlobalFrameRetirementOutcome::RetiredUnmapped { .. }
            | crate::trap::GlobalFrameRetirementOutcome::TerminalizedByVmDestroy { .. }
            | crate::trap::GlobalFrameRetirementOutcome::NotFound { .. }
            | crate::trap::GlobalFrameRetirementOutcome::MismatchedGeneration { .. }
            | crate::trap::GlobalFrameRetirementOutcome::MismatchedHost { .. } => {
                carrier
                    .native_frame_backings
                    .lock()
                    .remove(&(self.ipa, self.generation));
                Ok(carrick_hal::physical_grants::PhysicalGrantRelease::Released)
            }
        }
    }
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
                self.length,
                self.generation,
            );
        }
    }
}

#[derive(Debug)]
pub struct ForkStockHostCustody {
    /// RootOnly: the stopped root's live identity, consumed by its fork.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) root_executables: std::collections::BTreeMap<
        carrick_guest_arch::CpuId,
        (
            carrick_hal::fork_stock::GrantExecution,
            std::sync::Arc<dyn carrick_hal::fork_stock::ExecutableIdentity>,
        ),
    >,
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
            root_executables: Default::default(),
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
        let _install_guard = custody.fork_stock_install.lock();
        {
            let stock = custody.fork_stock.lock();
            if let Some(existing) = stock.backing.as_ref() {
                if existing.resources.matches(&resources) {
                    return Ok(());
                }
                return Err(fail("native fork stock already installed"));
            }
        }
        let generation = custody
            .live_generation()
            .ok_or_else(|| fail("native fork stock has no live carrier"))?;
        #[cfg(test)]
        custody
            .stage2
            .at_client_point(crate::trap::FORK_STOCK_INSTALL_BEFORE_ARENAS);
        let pool = custody
            .root_slot_pool()
            .filter(|pool| pool.vm_generation() == Some(generation));
        let mut arenas = Vec::new();
        let mut tables = Vec::new();
        let roots = resources.tables.arenas();
        for root in roots {
            let epoch = crate::trap::next_structural_epoch()?;
            let base = root.address().raw();
            let len = crate::frame_pool::ROOT_SLOT_SIZE;
            let perms =
                carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWriteExec);
            let mut lease = crate::trap::GlobalFrameStage2Lease::fixed(base, len as u64);
            let owner = if let Some(arena) =
                pool.as_ref().and_then(|pool| pool.allocate_slot_at(base))
            {
                // The shared owner can populate every page, so pool recycling
                // must clear the whole arena rather than a host-observed prefix.
                arena.record_populated_prefix(len);
                lease.mark_pre_mapped_in(arena.vm_generation());
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
                let mut stage2 = custody
                    .admitting_stage2_in(generation, "native fork arena map")
                    .map_err(|error| fail(&format!("native fork arena stage2: {error}")))?;
                // SAFETY: exclusively reserved physical slot and retained aligned mapping.
                let stage2_mapping = unsafe {
                    crate::trap::stage2_map(&mut stage2, mapping.as_ptr().cast(), base, len, perms)
                }
                .map_err(|result| fail(&format!("native fork arena map: {result:#x}")))?;
                drop(stage2);
                lease.mark_mapped(stage2_mapping);
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
        let extent = crate::metadata_grant::install_fork_lifecycle(custody, generation)
            .map_err(|error| fail(&format!("native fork lifecycle extent: {error:?}")))?;
        let lifecycles = carrick_hal::fork_stock::lifecycle_slots(
            carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE,
            extent.base(),
            extent.len() / carrick_hal::fork_stock::LIFECYCLE_SLOT_STRIDE,
        )
        .ok_or_else(|| fail("native fork lifecycle extent layout"))?;
        let mut unused_arenas = None;
        let outcome = {
            let Ok(_stage2) = custody.stage2.stage2_in(generation) else {
                drop(arenas);
                return Err(fail("native fork stock has no live carrier"));
            };
            let mut stock = custody.fork_stock.lock();
            if let Some(existing) = stock.backing.as_ref() {
                let matches = existing.resources.matches(&resources);
                unused_arenas = Some(arenas);
                if matches {
                    Ok(())
                } else {
                    Err(fail("native fork stock already installed"))
                }
            } else if let Err(error) = stock.owner.install(
                tables,
                carrick_hal::fork_stock::TableReserve::EMPTY,
                lifecycles,
            ) {
                unused_arenas = Some(arenas);
                Err(fail(&format!("native fork stock install: {error:?}")))
            } else {
                stock.backing = Some(NativeForkBacking {
                    resources,
                    _arenas: arenas,
                });
                Ok(())
            }
        };
        drop(unused_arenas);
        outcome
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn ensure_control_capacity(
        custody: &std::sync::Arc<CarrierVmCustody>,
    ) -> Result<(), carrick_hal::TrapError> {
        use carrick_hal::TrapError;
        {
            let stock = custody.fork_stock.lock();
            if !stock.owner.needs_control_capacity() {
                return Ok(());
            }
            if stock.backing.is_none() {
                return Err(TrapError::Hypervisor("native fork backing absent".into()));
            }
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
        let perms =
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWriteExec);
        let mut stage2 = custody.admitting_stage2("native fork control stage-2 map")?;
        let generation = stage2.generation();
        // SAFETY: the fresh IPA lease and mapping are retained by the owner.
        let stage2_mapping = unsafe {
            crate::trap::stage2_map(&mut stage2, mapping.as_ptr().cast(), base, len, perms)
        }
        .map_err(|result| TrapError::Hypervisor(format!("native fork control map: {result:#x}")))?;
        drop(stage2);
        lease.mark_mapped(stage2_mapping);
        let epoch = crate::trap::next_structural_epoch()?;
        let owner = crate::trap::StructuralBackingOwner::new_in(
            custody, mapping, lease, perms, epoch, base, len,
        )?;
        let mut unused_owner = Some(owner);
        #[cfg(test)]
        custody
            .stage2
            .at_client_point(crate::trap::FORK_CONTROL_CAPACITY_BEFORE_INSTALL);
        let result = {
            let _stage2 =
                custody.admitting_stage2_in(generation, "native fork control capacity install")?;
            let mut stock = custody.fork_stock.lock();
            if !stock.owner.needs_control_capacity() {
                Ok(())
            } else if stock.backing.is_none() {
                Err(TrapError::Hypervisor("native fork backing absent".into()))
            } else {
                stock
                    .owner
                    .provide_arm_control_capacity(base)
                    .map_err(|error| {
                        TrapError::Hypervisor(format!("native fork control install: {error:?}"))
                    })?;
                if let (Some(backing), Some(arena)) = (stock.backing.as_mut(), unused_owner.take())
                {
                    backing._arenas.push(arena);
                }
                Ok(())
            }
        };
        drop(unused_owner);
        result
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
    ) -> Result<(carrick_core_abi::NativeRunFailureReport, u64), ForkStockServiceError> {
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
        self.retire_root(mm);
        Ok(status)
    }

    /// Release the host-served root's seed on exit or image replacement.
    /// The neutral stock owner still decides which physical custody retires.
    pub(crate) fn retire_root(&mut self, mm: carrick_el1_abi::ReservationMm) {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        self.root_executables
            .retain(|_, (seed, _)| seed.binding.mm.raw() != mm.raw());
        self.owner.retire_exited_root(mm);
    }
    /// Resolve a complete physical object, never a kernel virtual wire record.
    pub(crate) fn physical_ptr<T>(
        custody: &CarrierVmCustody,
        frame: FrameGpa,
    ) -> Result<*mut T, ForkStockServiceError> {
        let state = custody.stage2.lock();
        Self::physical_ptr_in(&state, frame)
    }

    /// Resolve a complete physical object under a caller-held stage-2 guard.
    pub(crate) fn physical_ptr_in<T>(
        state: &carrick_aarch64::stage2::custody::Stage2CustodyState<
            crate::trap::CarrierStage2Records,
        >,
        frame: FrameGpa,
    ) -> Result<*mut T, ForkStockServiceError> {
        let address = frame.raw();
        let identity =
            CarrierVmCustody::stage2_record_covering_in(state, address, core::mem::size_of::<T>())
                .ok_or(ForkStockServiceError::MemoryAccessFailed)?;
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

    pub(crate) fn clear_tables_in(
        state: &carrick_aarch64::stage2::custody::Stage2CustodyState<
            crate::trap::CarrierStage2Records,
        >,
        pages: &[RootGpa],
    ) -> bool {
        // Resolve every complete frame before clearing any of them.
        let Some(pointers) = pages
            .iter()
            .map(|page| Self::physical_ptr_in::<[u8; 4096]>(state, page.address()).ok())
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

    pub(crate) fn tables_clean_in(
        state: &carrick_aarch64::stage2::custody::Stage2CustodyState<
            crate::trap::CarrierStage2Records,
        >,
        pages: &[RootGpa],
    ) -> bool {
        pages.iter().all(|page| {
            Self::physical_ptr_in::<[u8; 4096]>(state, page.address())
                .is_ok_and(|ptr| unsafe { &*ptr }.iter().all(|byte| *byte == 0))
        })
    }
}
/// Accounting venue used by every native fork-stock crossing. Its opaque
/// return type has no lock, Deref, or callback API: only leaf accounting.
pub(crate) fn fork_table_accounting(custody: &CarrierVmCustody) -> impl ForkTableLedger + '_ {
    &*custody.el1_frame_grants
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

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn root_seed_retirement_releases_only_matching_mm() {
        use std::sync::Arc;
        #[derive(Debug)]
        struct Executable;
        impl carrick_hal::fork_stock::ExecutableIdentity for Executable {
            fn display_path(&self) -> String {
                "/root-image".into()
            }
        }
        for through_exit in [false, true] {
            let mut stock = ForkStockHostCustody::new(NonZeroU64::MIN);
            let retired = test_execution(41, 0, 301);
            let other = test_execution(42, 1, 302);
            let seed: Arc<dyn carrick_hal::fork_stock::ExecutableIdentity> = Arc::new(Executable);
            let other_seed: Arc<dyn carrick_hal::fork_stock::ExecutableIdentity> =
                Arc::new(Executable);
            let retired_live = Arc::downgrade(&seed);
            let other_live = Arc::downgrade(&other_seed);
            stock.root_executables.insert(retired.cpu, (retired, seed));
            stock
                .root_executables
                .insert(other.cpu, (other, other_seed));
            if through_exit {
                let exit = carrick_core_abi::NativeRootExit::new(
                    retired.binding,
                    carrick_sched_core::process::TerminationStatus::exited(0),
                )
                .unwrap();
                stock.service_root_exit(retired, &exit).unwrap();
            } else {
                // Image replacement retires the predecessor MM without a
                // root-exit record through this same carrier entry point.
                stock.retire_root(ReservationMm::new(retired.binding.mm.raw()).unwrap());
            }
            assert_eq!(retired_live.strong_count(), 0);
            assert_eq!(other_live.strong_count(), 1);
            stock.retire_root(ReservationMm::new(other.binding.mm.raw()).unwrap());
            assert_eq!(other_live.strong_count(), 0);
            assert!(stock.root_executables.is_empty());
        }
    }

    #[test]
    fn child_reclaim_and_terminal_finalization_do_not_invert_accounting_lock() {
        use carrick_hal::fork_stock::{ForkControlCapacity, ForkStock, SlotAbsence, UntaggedRoots};
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        };
        use std::time::Duration;

        // A bounded directory acquisition detects the live #569 ABBA schedule
        // without leaving deadlocked test threads behind. The ledger adapter
        // and loan/reserve/commit/retire/reclaim transitions are production code.
        struct PhysicalPin {
            directory: Arc<parking_lot::Mutex<()>>,
            entered: mpsc::Sender<()>,
            finalized: Arc<AtomicBool>,
        }
        impl Drop for PhysicalPin {
            fn drop(&mut self) {
                self.entered.send(()).unwrap();
                let acquired = self.directory.try_lock_for(Duration::from_secs(2));
                self.finalized.store(acquired.is_some(), Ordering::SeqCst);
            }
        }

        let custody = Arc::new(CarrierVmCustody::new());
        let directory = Arc::new(parking_lot::Mutex::new(()));
        let finalized = Arc::new(AtomicBool::new(false));
        let (entered, dropping) = mpsc::channel();
        let mut stock = ForkStock::<UntaggedRoots, PhysicalPin>::new(
            NonZeroU64::new(7).unwrap(),
            ForkControlCapacity::unused(0x1_0000_0000),
            UntaggedRoots,
        );
        stock
            .install(
                (0..4).map(|n| page(0x20_0000 + n * 4096)).collect(),
                carrick_hal::fork_stock::TableReserve::EMPTY,
                vec![ForkLifecycleLoan::ARM_DEFAULT],
            )
            .unwrap();
        let parent = test_execution(41, 0, 301);
        let mut exchange = ForkStockExchange::new(test_request(parent, 302, 2, 1)).unwrap();
        let loan = stock
            .loan(
                &mut fork_table_accounting(&custody),
                parent,
                &mut exchange,
                |_| true,
            )
            .unwrap();
        let completion = carrick_el1_abi::PortalForkCompletion {
            request: loan.request,
            // SAFETY: the fixture uses the exact admitted child identity.
            child: unsafe {
                carrick_el1_abi::El1MmHandle::from_admitted_owner(
                    NonZeroU64::new(7).unwrap(),
                    loan.request.child_mm,
                    NonZeroU64::MIN,
                )
            },
            parent_generation: ReservationGeneration::INITIAL,
            child_tables_used: 4096,
            parent_tables_used: 0,
        };
        let mut reserve = carrick_el1_abi::ForkStockSettlement::reserve(
            loan,
            completion,
            KernelVa::new(0x1000),
            0,
        )
        .unwrap();
        stock
            .reserve_custody(
                parent,
                &mut reserve,
                |_| true,
                |_| true,
                |_, _, _| {
                    Ok(PhysicalPin {
                        directory: Arc::clone(&directory),
                        entered,
                        finalized: Arc::clone(&finalized),
                    })
                },
                |_| {},
            )
            .unwrap();
        let mut commit =
            carrick_el1_abi::ForkStockSettlement::commit_reserved(loan, completion).unwrap();
        stock
            .settle(
                &mut fork_table_accounting(&custody),
                parent,
                &mut commit,
                |_| true,
                |_| true,
                |_| true,
                &mut Vec::new(),
            )
            .unwrap();
        let mut child = test_execution(42, 1, 302);
        child.context.root = page(loan.request.child_tables.base);
        let mut retire =
            carrick_el1_abi::NativeChildRetire::new(child.binding, child.context).unwrap();
        stock.retire_child(child, &mut retire).unwrap();

        let (locked, ready) = mpsc::channel();
        let other_custody = Arc::clone(&custody);
        let other_directory = Arc::clone(&directory);
        let terminal = std::thread::spawn(move || {
            let _directory = other_directory.lock();
            locked.send(()).unwrap();
            dropping.recv_timeout(Duration::from_secs(5)).unwrap();
            // Terminal publication holds the directory while accounting for
            // its return, just as finalize_global_frame_owner_record does.
            crate::trap::El1FrameGrantObserver::new(&other_custody).snapshot()
        });
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        let reclaimed = stock
            .reclaim(
                &mut fork_table_accounting(&custody),
                ReservationMm::new(301).unwrap(),
                |mm| SlotAbsence::scan(mm, [0]),
                |_| true,
                |_| true,
                |_| true,
                &mut Vec::new(),
            )
            .unwrap();
        terminal.join().unwrap();
        assert_eq!(reclaimed, 1);
        assert!(
            finalized.load(Ordering::SeqCst),
            "child physical destruction held the grant ledger while terminal finalization held the directory (#569)"
        );
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
                .publish_test_stage2_record_using(
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
                    |_, _| carrick_aarch64::stage2::Stage2Status::SUCCESS,
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
                    carrick_hal::fork_stock::TableReserve::EMPTY,
                    vec![ForkLifecycleLoan::ARM_DEFAULT],
                )
                .unwrap();
            stock
                .owner
                .provide_arm_control_capacity(0x5000_0000)
                .unwrap();
        }
        let request = test_request(exec, 302, 4, 1);
        let address = KernelVa::new(carrick_el1_abi::stack_slot_usable_base(0));
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

    mod native_source;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    mod owed_returns;

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
                .publish_test_stage2_record_using(
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
                    |_, _| carrick_aarch64::stage2::Stage2Status::SUCCESS,
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
                    carrick_hal::fork_stock::TableReserve::EMPTY,
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
                carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
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
        let address = KernelVa::new(carrick_el1_abi::stack_slot_usable_base(0));
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

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn init_native_fork_crossing_fixture<'a>(
        custody: &std::sync::Arc<CarrierVmCustody>,
        generation: crate::trap::CarrierVmGeneration,
        region_ptr: *mut u8,
        physical_ptr: *mut u8,
    ) -> (
        carrick_hal::fork_stock::GrantExecution,
        u64,
        &'a carrick_el1_abi::ZoneTables,
        crate::metadata_grant::RetainedAbiRegion<'a>,
    ) {
        use carrick_hal::fork_stock::NativeForkTableReservation;
        use std::sync::Arc;

        #[derive(Debug)]
        struct TestTables(Vec<RootGpa>);
        impl NativeForkTableReservation for TestTables {
            fn arenas(&self) -> &[RootGpa] {
                &self.0
            }
        }
        struct TestInventory;
        impl carrick_hal::PhysicalFrameInventory for TestInventory {
            fn bind(
                &self,
                _: carrick_hal::GuestFrameOwner,
            ) -> Arc<dyn carrick_hal::FrameCowAuthority> {
                panic!("unused in reclaim witness")
            }
            fn allocate_backing_ids(
                &self,
            ) -> Result<
                (carrick_hal::FrameId, carrick_hal::MappingId),
                Box<dyn std::error::Error + Send + Sync>,
            > {
                Err("unused in reclaim witness".into())
            }
            fn retire_mm(
                &self,
                _: carrick_guest_arch::MmGeneration,
            ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
                Ok(0)
            }
        }

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
        let parent_space = zone.spaces.publish_closed(301, ttbr0, ttbr0).unwrap();
        zone.spaces.open(parent_space);
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
                .publish_test_stage2_record_using(
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
                    |_, _| carrick_aarch64::stage2::Stage2Status::SUCCESS,
                )
                .unwrap();
        }
        let table_pages: Vec<RootGpa> = (0..8)
            .map(|index| page(stock_base + index * 4096))
            .collect();
        {
            let mut stock = custody.fork_stock.lock();
            stock.owner.set_carrier(custody.transfer_carrier);
            stock
                .owner
                .install(
                    table_pages.clone(),
                    carrick_hal::fork_stock::TableReserve::EMPTY,
                    vec![ForkLifecycleLoan::ARM_DEFAULT],
                )
                .unwrap();
            stock
                .owner
                .provide_arm_control_capacity(0x5000_0000)
                .unwrap();
            stock.backing = Some(NativeForkBacking {
                resources: carrick_hal::fork_stock::NativeForkStockResources {
                    tables: Arc::new(TestTables(table_pages)),
                    inventory: Arc::new(TestInventory),
                },
                _arenas: Vec::new(),
            });
        }
        // SAFETY: `region_ptr` points to the exclusively owned `TestEl1Region`.
        let bytes = unsafe {
            crate::metadata_grant::RetainedAbiRegion::new(
                region_ptr,
                carrick_el1_abi::EL1_REGION_SIZE as usize,
            )
            .unwrap()
        };
        (exec, ttbr0, zone, bytes)
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn service_native_fork_stock_reclaims_quarantined_child_without_custody_lock_reentry() {
        use carrick_hal::fork_stock::ForkControlCapacity;
        use std::sync::Arc;

        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let custody = Arc::new(CarrierVmCustody::new());
        let generation = custody.begin_create().unwrap();
        custody.commit_create(generation).unwrap();
        let mut region = carrick_test_support::TestEl1Region::zeroed();
        let region_ptr = region.as_mut_ptr();
        let mut physical = carrick_test_support::TestEl1Region::zeroed();
        let (exec, ttbr0, zone, bytes) = init_native_fork_crossing_fixture(
            &custody,
            generation,
            region_ptr,
            physical.as_mut_ptr(),
        );

        // Loan, reserve, commit, then retire child 302 into quarantine.
        let mut req1 = test_request(exec, 302, 4, 1);
        req1.operation.carrier = custody.transfer_carrier;
        let address = KernelVa::new(carrick_el1_abi::stack_slot_usable_base(0));
        let offset = (address.raw() - carrick_el1_abi::EL1_REGION_BASE) as usize;
        // SAFETY: aligned complete record on this CPU's retained fixture stack.
        let record = unsafe { region_ptr.add(offset).cast::<ForkStockExchange>() };
        unsafe {
            record.write(ForkStockExchange::new(req1).unwrap());
        }
        assert_eq!(
            crate::metadata_grant::service_native_fork_stock(
                &custody,
                Some(generation),
                exec.cpu,
                address,
                0,
                ttbr0,
                bytes,
            )
            .unwrap(),
            [carrick_el1_abi::METADATA_GRANT_SUCCESS, 0, 0, 0]
        );
        let loan1 = unsafe { &mut *record }.take(req1).unwrap().unwrap();
        let completion1 = carrick_el1_abi::PortalForkCompletion {
            request: loan1.request,
            // SAFETY: fixture uses exact admitted child identity.
            child: unsafe {
                carrick_el1_abi::El1MmHandle::from_admitted_owner(
                    core::num::NonZeroU64::new(7).unwrap(),
                    loan1.request.child_mm,
                    core::num::NonZeroU64::MIN,
                )
            },
            parent_generation: ReservationGeneration::INITIAL,
            child_tables_used: 4096,
            parent_tables_used: 0,
        };
        let settlement = record.cast::<carrick_el1_abi::ForkStockSettlement>();
        unsafe {
            settlement.write(
                carrick_el1_abi::ForkStockSettlement::reserve(
                    loan1,
                    completion1,
                    KernelVa::new(carrick_el1_abi::EL1_BOOTSTRAP_METADATA_BASE),
                    0,
                )
                .unwrap(),
            );
        }
        assert_eq!(
            crate::metadata_grant::service_native_fork_stock(
                &custody,
                Some(generation),
                exec.cpu,
                address,
                0,
                ttbr0,
                bytes,
            )
            .unwrap()[0],
            carrick_el1_abi::METADATA_GRANT_SUCCESS
        );
        assert_eq!(unsafe { &mut *settlement }.take(loan1), Some(Ok(())));
        unsafe {
            settlement.write(
                carrick_el1_abi::ForkStockSettlement::commit_reserved_with_child_identity(
                    loan1,
                    completion1,
                    42,
                    102,
                )
                .unwrap(),
            );
        }
        assert_eq!(
            crate::metadata_grant::service_native_fork_stock(
                &custody,
                Some(generation),
                exec.cpu,
                address,
                0,
                ttbr0,
                bytes,
            )
            .unwrap()[0],
            carrick_el1_abi::METADATA_GRANT_SUCCESS
        );
        assert_eq!(unsafe { &mut *settlement }.take(loan1), Some(Ok(())));

        let mut child = test_execution(42, 1, 302);
        child.context.root = page(loan1.request.child_tables.base);
        let child_space = zone
            .spaces
            .publish_closed(302, child.context.root.address().raw(), ttbr0)
            .unwrap();
        let mut retire =
            carrick_el1_abi::NativeChildRetire::new(child.binding, child.context).unwrap();
        {
            let mut stock = custody.fork_stock.lock();
            stock.owner.retire_child(child, &mut retire).unwrap();
            assert!(stock.owner.has_quarantine());
            assert!(stock.owner.is_quarantined(loan1.request.child_mm));
        }
        zone.spaces.free(child_space);

        // Drive the real production crossing while quarantine is nonempty and inventory is available:
        // previously panicked re-entering `custody.stage2` inside `resolve_custody_residency`.
        let mut req2 = test_request(exec, 303, 4, 1);
        req2.operation.carrier = custody.transfer_carrier;
        unsafe {
            record.write(ForkStockExchange::new(req2).unwrap());
        }
        assert_eq!(
            crate::metadata_grant::service_native_fork_stock(
                &custody,
                Some(generation),
                exec.cpu,
                address,
                0,
                ttbr0,
                bytes,
            )
            .unwrap(),
            [carrick_el1_abi::METADATA_GRANT_SUCCESS, 0, 0, 0]
        );
        let loan2 = unsafe { &mut *record }.take(req2).unwrap().unwrap();
        {
            let stock = custody.fork_stock.lock();
            assert!(!stock.owner.has_quarantine());
            assert!(!stock.owner.is_quarantined(loan1.request.child_mm));
            assert_eq!(stock.owner.counters().returned_children, 1);
        }
        // Clean up second loan via Abort before dropping test VM.
        unsafe {
            settlement.write(carrick_el1_abi::ForkStockSettlement::abort(loan2));
        }
        assert_eq!(
            crate::metadata_grant::service_native_fork_stock(
                &custody,
                Some(generation),
                exec.cpu,
                address,
                0,
                ttbr0,
                bytes,
            )
            .unwrap()[0],
            carrick_el1_abi::METADATA_GRANT_SUCCESS
        );
        assert_eq!(
            custody
                .metadata_residency_resolutions
                .load(core::sync::atomic::Ordering::Relaxed),
            1,
            "quarantined Loan resolves residency once during pre-reclaim and skips pass-2 resolution"
        );
        let _ = ForkControlCapacity::unused;
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn empty_quarantine_fork_loan_skips_residency_resolution() {
        use std::sync::Arc;

        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let custody = Arc::new(CarrierVmCustody::new());
        let generation = custody.begin_create().unwrap();
        custody.commit_create(generation).unwrap();
        let mut region = carrick_test_support::TestEl1Region::zeroed();
        let region_ptr = region.as_mut_ptr();
        let mut physical = carrick_test_support::TestEl1Region::zeroed();
        let (exec, ttbr0, _zone, bytes) = init_native_fork_crossing_fixture(
            &custody,
            generation,
            region_ptr,
            physical.as_mut_ptr(),
        );
        custody
            .metadata_residency_resolutions
            .store(0, core::sync::atomic::Ordering::Relaxed);

        let mut req = test_request(exec, 304, 4, 1);
        req.operation.carrier = custody.transfer_carrier;
        let address = KernelVa::new(carrick_el1_abi::stack_slot_usable_base(0));
        let offset = (address.raw() - carrick_el1_abi::EL1_REGION_BASE) as usize;
        // SAFETY: aligned complete record on this CPU's retained fixture stack.
        let record = unsafe { region_ptr.add(offset).cast::<ForkStockExchange>() };
        unsafe {
            record.write(ForkStockExchange::new(req).unwrap());
        }
        assert_eq!(
            crate::metadata_grant::service_native_fork_stock(
                &custody,
                Some(generation),
                exec.cpu,
                address,
                0,
                ttbr0,
                bytes,
            )
            .unwrap(),
            [carrick_el1_abi::METADATA_GRANT_SUCCESS, 0, 0, 0]
        );
        assert_eq!(
            custody
                .metadata_residency_resolutions
                .load(core::sync::atomic::Ordering::Relaxed),
            0,
            "empty-quarantine ForkStockKind::Loan must not resolve residency"
        );
        let loan = unsafe { &mut *record }.take(req).unwrap().unwrap();
        let settlement = record.cast::<carrick_el1_abi::ForkStockSettlement>();
        unsafe {
            settlement.write(carrick_el1_abi::ForkStockSettlement::abort(loan));
        }
        assert_eq!(
            crate::metadata_grant::service_native_fork_stock(
                &custody,
                Some(generation),
                exec.cpu,
                address,
                0,
                ttbr0,
                bytes,
            )
            .unwrap()[0],
            carrick_el1_abi::METADATA_GRANT_SUCCESS
        );
        assert_eq!(
            custody
                .metadata_residency_resolutions
                .load(core::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn fork_stock_install_never_inverts_lock_order_with_commit_destroy() {
        use carrick_aarch64::stage2::custody::{Stage2HookPoint, Stage2Lifecycle};
        use std::sync::{Arc, Mutex, mpsc};
        use std::time::Duration;

        #[derive(Debug)]
        struct TestTables(Vec<RootGpa>);
        impl carrick_hal::fork_stock::NativeForkTableReservation for TestTables {
            fn arenas(&self) -> &[RootGpa] {
                &self.0
            }
        }
        struct TestInventory;
        impl carrick_hal::PhysicalFrameInventory for TestInventory {
            fn bind(
                &self,
                _: carrick_hal::GuestFrameOwner,
            ) -> Arc<dyn carrick_hal::FrameCowAuthority> {
                panic!("unused in lock-order witness")
            }
            fn allocate_backing_ids(
                &self,
            ) -> Result<
                (carrick_hal::FrameId, carrick_hal::MappingId),
                Box<dyn std::error::Error + Send + Sync>,
            > {
                Err("unused in lock-order witness".into())
            }
            fn retire_mm(
                &self,
                _: carrick_guest_arch::MmGeneration,
            ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
                Ok(0)
            }
        }

        let custody = Arc::new(CarrierVmCustody::new());
        let g1 = custody.begin_create().unwrap();
        custody.commit_create(g1).unwrap();
        // Skip allocating the 128 MiB root-slot pool in this isolated witness;
        // fallback arena creation exercises the production custody path.
        *custody.root_slot_pool.lock() = crate::trap::CarrierRootSlotPoolState::Failed;

        let (install_entered_tx, install_entered_rx) = mpsc::channel::<()>();
        let (install_go_tx, install_go_rx) = mpsc::channel::<()>();
        let install_go_rx = Mutex::new(install_go_rx);
        let install_go_tx = Mutex::new(Some(install_go_tx));
        custody
            .stage2
            .set_hook(Some(Arc::new(move |point| match point {
                Stage2HookPoint::Client(name)
                    if name == crate::trap::FORK_STOCK_INSTALL_BEFORE_ARENAS =>
                {
                    let _ = install_entered_tx.send(());
                    let _ = install_go_rx.lock().unwrap().recv();
                }
                Stage2HookPoint::Client(name)
                    if name == crate::trap::COMMIT_DESTROY_HOLDING_STAGE2 =>
                {
                    if let Some(tx) = install_go_tx.lock().unwrap().take() {
                        let _ = tx.send(());
                    }
                }
                _ => {}
            })));

        let (done_tx, done_rx) = mpsc::channel::<&'static str>();
        let resources = carrick_hal::fork_stock::NativeForkStockResources {
            tables: Arc::new(TestTables(vec![page(0x9a00_0000_0000)])),
            inventory: Arc::new(TestInventory),
        };
        let install_custody = Arc::clone(&custody);
        let install_done = done_tx.clone();
        let install_thread = std::thread::spawn(move || {
            let _stub = crate::trap::ScopedStage2MapTestStub::enable();
            let result = ForkStockHostCustody::install(&install_custody, resources);
            assert!(
                result.is_err(),
                "install into destroyed G1 must fail closed: {result:?}"
            );
            let _ = install_done.send("install");
        });

        install_entered_rx
            .recv()
            .expect("install thread reached FORK_STOCK_INSTALL_BEFORE_ARENAS");
        custody.begin_destroy(g1).expect("begin destroy G1");
        custody.destroy_stage2_for_test(g1);

        let destroy_custody = Arc::clone(&custody);
        let destroy_done = done_tx;
        let destroy_thread = std::thread::spawn(move || {
            let _ = destroy_custody.commit_destroy(g1);
            let _ = destroy_done.send("destroy");
        });

        let mut finished = Vec::new();
        for _ in 0..2 {
            let which = done_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap_or_else(|error| {
                    panic!(
                        "ForkStockHostCustody::install deadlocked with CarrierVmCustody::commit_destroy                          (finished={finished:?}): {error}"
                    )
                });
            finished.push(which);
        }
        install_thread.join().expect("install thread panicked");
        destroy_thread.join().expect("destroy thread panicked");
        custody.stage2.set_hook(None);
        assert_eq!(custody.stage2.lifecycle(), Stage2Lifecycle::Vacant);
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn ensure_control_capacity_refuses_stale_g1_arena_against_g2() {
        use carrick_aarch64::stage2::custody::Stage2HookPoint;
        use std::sync::{Arc, mpsc};

        #[derive(Debug)]
        struct TestTables(Vec<RootGpa>);
        impl carrick_hal::fork_stock::NativeForkTableReservation for TestTables {
            fn arenas(&self) -> &[RootGpa] {
                &self.0
            }
        }
        #[derive(Debug)]
        struct DummyInventory;
        impl carrick_hal::PhysicalFrameInventory for DummyInventory {
            fn bind(
                &self,
                _: carrick_hal::GuestFrameOwner,
            ) -> Arc<dyn carrick_hal::FrameCowAuthority> {
                panic!("unused in control capacity witness")
            }
            fn allocate_backing_ids(
                &self,
            ) -> Result<
                (carrick_hal::FrameId, carrick_hal::MappingId),
                Box<dyn std::error::Error + Send + Sync>,
            > {
                Err("unused in control capacity witness".into())
            }
            fn retire_mm(
                &self,
                _: carrick_guest_arch::MmGeneration,
            ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
                Ok(0)
            }
        }

        let _global_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = crate::trap::ScopedStage2MapTestStub::enable();
        let custody = Arc::new(CarrierVmCustody::new());
        let g1 = custody.begin_create().expect("begin G1");
        custody.commit_create(g1).expect("commit G1");
        *custody.root_slot_pool.lock() = crate::trap::CarrierRootSlotPoolState::Failed;

        let g1_resources = carrick_hal::fork_stock::NativeForkStockResources {
            tables: Arc::new(TestTables(vec![page(0xa081_f000_0000)])),
            inventory: Arc::new(DummyInventory),
        };
        ForkStockHostCustody::install(&custody, g1_resources).expect("install G1 fork stock");

        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let go_rx = std::sync::Mutex::new(go_rx);
        custody.stage2.set_hook(Some(Arc::new(move |point| {
            if matches!(
                point,
                Stage2HookPoint::Client(name) if name == crate::trap::FORK_CONTROL_CAPACITY_BEFORE_INSTALL
            ) {
                let _ = entered_tx.send(());
                let _ = go_rx.lock().unwrap().recv();
            }
        })));

        let cap_custody = Arc::clone(&custody);
        let worker = std::thread::spawn(move || {
            let _stub = crate::trap::ScopedStage2MapTestStub::enable();
            ForkStockHostCustody::ensure_control_capacity(&cap_custody)
        });

        entered_rx
            .recv()
            .expect("ensure_control_capacity paused before install");
        custody.begin_destroy(g1).expect("begin destroy G1");
        custody.destroy_stage2_for_test(g1);
        custody.commit_destroy(g1).expect("commit destroy G1");

        let g2 = custody.begin_create().expect("begin G2");
        custody.commit_create(g2).expect("commit G2");
        let g2_resources = carrick_hal::fork_stock::NativeForkStockResources {
            tables: Arc::new(TestTables(vec![page(0xa081_f200_0000)])),
            inventory: Arc::new(DummyInventory),
        };
        ForkStockHostCustody::install(&custody, g2_resources).expect("install G2 fork stock");
        assert!(custody.fork_stock.lock().owner.needs_control_capacity());
        go_tx.send(()).expect("resume G1 control capacity");

        let err = worker
            .join()
            .expect("worker join")
            .expect_err("stale G1 control arena must not install into G2");
        let _ = err;
        custody.stage2.set_hook(None);
        assert!(
            custody.fork_stock.lock().owner.needs_control_capacity(),
            "G1 arena must never publish into G2 fork stock"
        );
    }
}
