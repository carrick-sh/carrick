use super::*;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReclaimParkAuthority {
    Live,
    InitialRunnerParked,
    VcpuParked,
    VmParked,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ReclaimParkAuthority {
    pub(crate) fn mark_initial_runner_parked(&mut self) -> Result<(), TrapError> {
        if *self != Self::Live {
            return Err(TrapError::Hypervisor(
                "initial runner park attempted without live executor authority".to_owned(),
            ));
        }
        *self = Self::InitialRunnerParked;
        Ok(())
    }

    pub(crate) fn mark_vcpu_parked(&mut self) -> Result<(), TrapError> {
        if *self != Self::Live {
            return Err(TrapError::Hypervisor(
                "vCPU reclaim park attempted without live executor authority".to_owned(),
            ));
        }
        *self = Self::VcpuParked;
        Ok(())
    }

    pub(crate) fn mark_vm_parked(&mut self) -> Result<(), TrapError> {
        if *self != Self::VcpuParked {
            return Err(TrapError::Hypervisor(
                "VM reclaim park attempted without parked vCPU authority".to_owned(),
            ));
        }
        *self = Self::VmParked;
        Ok(())
    }

    pub(crate) fn destination_vcpu_is_live(self) -> Result<(), TrapError> {
        (self == Self::Live).then_some(()).ok_or_else(|| {
            TrapError::Hypervisor("destination executor vCPU is not live".to_owned())
        })
    }

    pub(crate) fn mark_live_after_recreate(&mut self) -> Result<(), TrapError> {
        if *self == Self::Live {
            return Err(TrapError::Hypervisor(
                "reclaim resume attempted to recreate a live destination vCPU".to_owned(),
            ));
        }
        *self = Self::Live;
        Ok(())
    }
}

/// lives in the same HVF VM as the parent, so the stage-2 entries are already
/// present; the descriptor only re-materialises local syscall-path metadata as
/// `HvfMappedRegion { memory: None }` (UNOWNED) so the sibling never
/// unmaps/frees buffers the main engine owns.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Clone)]
pub(crate) struct ThreadMappingDesc {
    pub(crate) start: u64,
    pub(crate) ipa: u64,
    pub(crate) end: u64,
    pub(crate) host_addr: *mut u8,
    pub(crate) size: usize,
    pub(crate) physical_ipa: u64,
    pub(crate) physical_host_addr: *mut u8,
    pub(crate) physical_size: usize,
    pub(crate) perms: applevisor::memory::MemPerms,
    pub(crate) is_dynamic_alias: bool,
    pub(crate) sharing: GuestMappingSharing,
    pub(crate) guest_writable: bool,
    pub(crate) shared_key_base: u64,
    pub(crate) shared_key_offset: u64,
    pub(crate) owner_generation: u64,
    pub(crate) structural_owner: Option<std::sync::Arc<StructuralBackingOwner>>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ThreadMappingDesc {
    /// Project a live region into a `Send`-safe descriptor for a `ThreadSpec` (the
    /// sibling thread mirrors it as an UNOWNED `HvfMappedRegion`). Called by
    /// `HvfVmState::build_thread_spec` (the per-VMM `build_sibling_builder`).
    pub(crate) fn from_region(region: &HvfMappedRegion) -> Self {
        let semantic_offset =
            usize::try_from(region.ipa.saturating_sub(region.physical_ipa)).unwrap_or(0);
        let physical_host_addr =
            (region.host_addr as usize).saturating_sub(semantic_offset) as *mut u8;
        Self {
            start: region.start,
            ipa: region.ipa,
            end: region.end,
            host_addr: region.host_addr,
            size: semantic_extent_size(region.start, region.end),
            physical_ipa: region.physical_ipa,
            physical_host_addr,
            physical_size: region.physical_size,
            perms: region.perms,
            is_dynamic_alias: region.is_dynamic_alias,
            sharing: region.sharing,
            guest_writable: region.guest_writable,
            shared_key_base: region.shared_key_base,
            shared_key_offset: region.shared_key_offset,
            owner_generation: region.owner_generation,
            structural_owner: region.structural_owner.clone(),
        }
    }

    pub(crate) fn from_alias(alias: AliasBacking) -> Option<Self> {
        let perms = match alias.perms {
            0 => applevisor::memory::MemPerms::None,
            1 => applevisor::memory::MemPerms::Read,
            2 => applevisor::memory::MemPerms::Write,
            3 => applevisor::memory::MemPerms::ReadWrite,
            4 => applevisor::memory::MemPerms::Exec,
            5 => applevisor::memory::MemPerms::ReadExec,
            6 => applevisor::memory::MemPerms::WriteExec,
            7 => applevisor::memory::MemPerms::ReadWriteExec,
            _ => return None,
        };
        Some(Self {
            start: alias.start,
            ipa: alias.ipa,
            end: alias.start.saturating_add(alias.size as u64),
            host_addr: alias.host_addr as *mut u8,
            size: alias.size,
            physical_ipa: alias.physical_ipa,
            physical_host_addr: alias.physical_host_addr as *mut u8,
            physical_size: alias.physical_size,
            perms,
            is_dynamic_alias: true,
            sharing: alias.sharing,
            guest_writable: alias.guest_writable,
            shared_key_base: alias.shared_key_base,
            shared_key_offset: alias.shared_key_offset,
            owner_generation: alias.owner_generation,
            structural_owner: None,
        })
    }

    pub(crate) fn from_alias_with_structural_owner(
        alias: AliasBacking,
        sources: &[Self],
    ) -> Option<Self> {
        let semantic_projection_is_exact = alias
            .ipa
            .checked_sub(alias.physical_ipa)
            .and_then(|offset| usize::try_from(offset).ok())
            .filter(|offset| {
                offset
                    .checked_add(alias.size)
                    .is_some_and(|end| end <= alias.physical_size)
                    && alias
                        .physical_host_addr
                        .checked_add(*offset)
                        .is_some_and(|host_addr| host_addr == alias.host_addr)
            })
            .is_some();
        let structural_owner = if semantic_projection_is_exact {
            sources
                .iter()
                .filter_map(|source| source.structural_owner.as_ref())
                .find(|owner| {
                    owner.ptr() as usize == alias.physical_host_addr
                        && owner.physical_ipa == alias.physical_ipa
                        && owner.physical_size == alias.physical_size
                        && owner.epoch().raw() == alias.owner_generation
                })
                .cloned()
        } else {
            None
        };
        let mut mapping = Self::from_alias(alias)?;
        mapping.structural_owner = structural_owner;
        Some(mapping)
    }

    pub(in crate::trap) fn into_shared_mm_task_mapping(self) -> HvpatchTaskMappingState {
        HvpatchTaskMappingState {
            start: self.start,
            ipa: self.ipa,
            physical_ipa: self.physical_ipa,
            end: self.end,
            host_addr: self.host_addr,
            physical_host_addr: self.physical_host_addr,
            size: self.size,
            physical_size: self.physical_size,
            perms: self.perms,
            guest_writable: self.guest_writable,
            host_mapping: None,
            structural_owner: self.structural_owner,
            is_dynamic_alias: self.is_dynamic_alias,
            sharing: self.sharing,
            shared_key_base: self.shared_key_base,
            shared_key_offset: self.shared_key_offset,
            owner_generation: self.owner_generation,
            // A CLONE_VM edge views rows its process already owns.
            global_frame_owner_role: GlobalFrameOwnerRole::Borrowed,
        }
    }

    pub(crate) fn into_unowned_region(self) -> HvfMappedRegion {
        HvfMappedRegion {
            start: self.start,
            ipa: self.ipa,
            physical_ipa: self.physical_ipa,
            end: self.end,
            host_addr: self.host_addr,
            size: self.physical_size,
            physical_size: self.physical_size,
            perms: self.perms,
            memory: None,
            host_mapping: None,
            structural_owner: self.structural_owner,
            stage2_lease: None,
            is_dynamic_alias: self.is_dynamic_alias,
            sharing: self.sharing,
            guest_writable: self.guest_writable,
            shared_key_base: self.shared_key_base,
            shared_key_offset: self.shared_key_offset,
            owner_generation: self.owner_generation,
        }
    }
}

/// A root booting inside a live carrier must carry the SAME control image the
/// carrier installed: identical geometry for all five fixed mappings, and
/// identical bytes for the three code pages (EL0 trampoline, EL1 vectors, EL1
/// maintenance). The mailbox arena and the carrier maintenance root are live
/// data, so only their geometry is compared. Divergence is a build/config
/// error, never something to paper over by remapping.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn audit_plan_against_installed_carrier(
    plan: &GuestMappingPlan,
    carrier: &PersistentCarrierMappings,
) -> Result<(), TrapError> {
    let code_pages = [
        carrick_mem::memory::LINUX_EL0_TRAMPOLINE_BASE,
        carrick_mem::memory::LINUX_EL1_VECTORS_BASE,
        carrick_mem::memory::LINUX_EL1_MAINT_BASE,
    ];
    let mut seen = 0_usize;
    for mapping in plan
        .mappings
        .iter()
        .filter(|mapping| is_persistent_executor_carrier_guest_mapping(mapping))
    {
        seen += 1;
        let installed = carrier
            .mappings
            .iter()
            .find(|installed| installed.start == mapping.guest_start)
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "carrier has no control mapping at 0x{:x}",
                    mapping.guest_start
                ))
            })?;
        if installed.end.saturating_sub(installed.start) != mapping.mapped_size {
            return Err(TrapError::Hypervisor(format!(
                "carrier control mapping 0x{:x} size {} differs from plan size {}",
                mapping.guest_start,
                installed.end.saturating_sub(installed.start),
                mapping.mapped_size
            )));
        }
        if code_pages.contains(&mapping.guest_start) {
            let payload = usize::try_from(mapping.payload_size)
                .map_err(|_| TrapError::MappingTooLarge(mapping.payload_size))?;
            let offset = usize::try_from(mapping.offset_in_mapping)
                .map_err(|_| TrapError::MappingTooLarge(mapping.offset_in_mapping))?;
            let planned = mapping.image.get(offset..offset + payload).ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "carrier control image at 0x{:x} is shorter than its payload",
                    mapping.guest_start
                ))
            })?;
            let live = carrier
                .host_pointer(mapping.guest_start + mapping.offset_in_mapping, payload)
                .ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "carrier control mapping 0x{:x} payload is not host-visible",
                        mapping.guest_start
                    ))
                })?;
            // SAFETY: `host_pointer` proved `[ptr, ptr+payload)` lies inside one
            // live carrier mapping; the code pages are immutable after install.
            let live = unsafe { std::slice::from_raw_parts(live.as_ptr(), payload) };
            if live != planned {
                return Err(TrapError::Hypervisor(format!(
                    "carrier control code at 0x{:x} differs from this image's bytes",
                    mapping.guest_start
                )));
            }
        }
    }
    if seen != 5 {
        return Err(TrapError::Hypervisor(format!(
            "root image carries {seen} carrier control mappings, expected 5"
        )));
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn is_persistent_executor_carrier_mapping(mapping: &HvfMappedRegion) -> bool {
    is_persistent_executor_carrier_address(mapping.start)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn is_persistent_executor_carrier_guest_mapping(mapping: &GuestMapping) -> bool {
    is_persistent_executor_carrier_address(mapping.guest_start)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn mapping_belongs_to_task_inventory(
    persistent_vm_lifecycle: bool,
    mapping: &HvfMappedRegion,
) -> bool {
    !persistent_vm_lifecycle || !is_persistent_executor_carrier_mapping(mapping)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn is_persistent_executor_carrier_address(address: u64) -> bool {
    matches!(
        address,
        carrick_mem::memory::LINUX_EL0_TRAMPOLINE_BASE
            | carrick_mem::memory::LINUX_EL1_VECTORS_BASE
            | carrick_mem::memory::LINUX_EL1_MAINT_BASE
            | carrick_mem::memory::LINUX_SYSCALL_MAILBOX_BASE
            | carrick_mem::memory::LINUX_CARRIER_MAINT_ROOT_BASE
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn persistent_executor_carrier_mappings<'a>(
    mappings: impl IntoIterator<Item = &'a HvfMappedRegion>,
) -> Vec<ThreadMappingDesc> {
    mappings
        .into_iter()
        .filter(|mapping| is_persistent_executor_carrier_mapping(mapping))
        .map(ThreadMappingDesc::from_region)
        .collect()
}

/// Owning carrier-wide lifetime for the five fixed HVPatch control mappings.
/// Logical MM/task cleanup never sees these rows. The last factory/worker Arc
/// drops only after every worker vCPU has been joined and destroyed.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct PersistentCarrierMappings {
    pub(crate) mappings: TaskMappingIndex,
    pub(crate) custody: std::sync::Arc<CarrierVmCustody>,
    pub(crate) vm_destroyed_after_custody_commit: std::sync::atomic::AtomicBool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PersistentCarrierMappings {
    pub(crate) fn extract(
        task_mappings: &mut TaskMappingIndex,
        custody: std::sync::Arc<CarrierVmCustody>,
    ) -> Result<Self, TrapError> {
        let mut carrier = TaskMappingIndex::new();
        let mut task = TaskMappingIndex::new();
        for mapping in std::mem::take(task_mappings).into_values() {
            if is_persistent_executor_carrier_mapping(&mapping) {
                carrier.insert(mapping);
            } else {
                task.insert(mapping);
            }
        }
        *task_mappings = task;
        let authority = Self {
            mappings: carrier,
            custody,
            vm_destroyed_after_custody_commit: std::sync::atomic::AtomicBool::new(false),
        };
        authority.audit()?;
        if authority.mappings.len() != 5 {
            return Err(TrapError::Hypervisor(format!(
                "persistent executor carrier owns {} mappings, expected 5",
                authority.mappings.len()
            )));
        }
        Ok(authority)
    }

    pub(crate) fn mark_vm_destroyed_after_custody_commit(&self) -> Result<(), TrapError> {
        let committed = matches!(
            self.custody.state.lock().lifecycle,
            CarrierVmLifecycle::Vacant
        );
        if !committed {
            return Err(TrapError::Hypervisor(
                "persistent carrier mappings cannot retire before exact VM custody destroy commits"
                    .to_owned(),
            ));
        }
        self.vm_destroyed_after_custody_commit
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    pub(crate) fn maintenance_root(&self) -> carrick_mem::memory::CarrierMaintenanceRoot {
        carrick_mem::memory::CarrierMaintenanceRoot(carrick_guest_mem::Gpa(
            carrick_mem::memory::LINUX_CARRIER_MAINT_ROOT_BASE,
        ))
    }

    pub(crate) fn host_pointer(
        &self,
        address: u64,
        length: usize,
    ) -> Option<std::ptr::NonNull<u8>> {
        let mapping = self.mappings.mapping_for_range(GuestVa(address), length)?;
        let offset = usize::try_from(address.checked_sub(mapping.start)?).ok()?;
        std::ptr::NonNull::new(unsafe { mapping.host_addr.add(offset) })
    }

    pub(crate) fn host_pointer_for_ipa(&self, ipa: u64, length: usize) -> Option<*mut u8> {
        let mapping = HvfVmState::mapping_for_ipa_range(&self.mappings, ipa, length.max(1))?;
        let offset = usize::try_from(ipa.checked_sub(mapping.ipa)?).ok()?;
        Some(unsafe { mapping.host_addr.add(offset) })
    }

    pub(crate) fn audit(&self) -> Result<(), TrapError> {
        let descriptors = persistent_executor_carrier_mappings(&self.mappings);
        audit_persistent_executor_carrier_mappings(&descriptors)
    }
}

// SAFETY: the owning mappings name VM-global MAP_SHARED host allocations. The
// carrier Arc is immutable after extraction; only its final Drop mutates the
// mapping owners, after all worker threads have joined.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Send for PersistentCarrierMappings {}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Sync for PersistentCarrierMappings {}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for PersistentCarrierMappings {
    fn drop(&mut self) {
        let vm_destroyed = self
            .vm_destroyed_after_custody_commit
            .load(std::sync::atomic::Ordering::Acquire);
        for mut mapping in std::mem::take(&mut self.mappings).into_values() {
            if let Some(mut lease) = mapping.stage2_lease.take() {
                // Retire EXPLICITLY. Dropping a lease does not unmap stage-2 --
                // it only releases the IPA reservation and (in a debug build)
                // asserts the lease was not mapped. This is the carrier
                // authority's own terminal point, which is why the lease-less
                // branch below issues the same `hv_vm_unmap`; leaving the
                // leased branch to `drop` alone unmapped nothing while the
                // `OwnedHostMapping` below still released the backing, so the
                // guest kept a stage-2 route to freed host memory.
                if vm_destroyed {
                    lease.forget_backend_mapping();
                    drop(lease);
                } else {
                    lease.try_retire().unwrap_or_else(|error| {
                        carrick_fatal!(
                            "hvpatch::host_alias",
                            "retire persistent carrier stage-2 lease failed at IPA 0x{:x} size {}: {error}",
                            mapping.physical_ipa, mapping.physical_size
                        );
                    });
                }
            } else if !vm_destroyed {
                let rc =
                    unsafe { inventory_hv_vm_unmap(mapping.physical_ipa, mapping.physical_size) };
                if rc != 0 {
                    carrick_fatal!(
                        "hvpatch::mm_authority",
                        "retire persistent carrier stage-2 IPA 0x{:x} size {} failed: 0x{rc:x}",
                        mapping.physical_ipa,
                        mapping.physical_size
                    );
                }
            }
            // Stage-2 is gone before OwnedHostMapping releases the backing.
            drop(mapping);
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn persistent_carrier_host_pointer(
    mappings: &[ThreadMappingDesc],
    address: u64,
    length: usize,
) -> Option<std::ptr::NonNull<u8>> {
    let end = address.checked_add(u64::try_from(length).ok()?)?;
    let mapping = mappings
        .iter()
        .find(|mapping| address >= mapping.start && end <= mapping.end)?;
    let offset = usize::try_from(address.checked_sub(mapping.start)?).ok()?;
    std::ptr::NonNull::new(unsafe { mapping.host_addr.add(offset) })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn audit_persistent_executor_carrier_mappings(
    mappings: &[ThreadMappingDesc],
) -> Result<(), TrapError> {
    for (name, start, size) in [
        (
            "EL0 trampoline",
            carrick_mem::memory::LINUX_EL0_TRAMPOLINE_BASE,
            carrick_mem::memory::LINUX_EL0_TRAMPOLINE_SIZE,
        ),
        (
            "EL1 vectors",
            carrick_mem::memory::LINUX_EL1_VECTORS_BASE,
            carrick_mem::memory::LINUX_EL1_VECTORS_SIZE,
        ),
        (
            "EL1 maintenance",
            carrick_mem::memory::LINUX_EL1_MAINT_BASE,
            carrick_mem::memory::LINUX_EL1_MAINT_SIZE,
        ),
        (
            "syscall mailbox",
            carrick_mem::memory::LINUX_SYSCALL_MAILBOX_BASE,
            carrick_mem::memory::LINUX_SYSCALL_MAILBOX_ARENA_SIZE,
        ),
        (
            "carrier maintenance root",
            carrick_mem::memory::LINUX_CARRIER_MAINT_ROOT_BASE,
            carrick_mem::memory::LINUX_CARRIER_MAINT_ROOT_SIZE,
        ),
    ] {
        let size = usize::try_from(size).map_err(|_| {
            TrapError::Hypervisor(format!("persistent executor {name} extent is too large"))
        })?;
        if persistent_carrier_host_pointer(mappings, start, size).is_none() {
            return Err(TrapError::Hypervisor(format!(
                "persistent executor carrier {name} mapping is absent"
            )));
        }
    }
    Ok(())
}

/// Everything a freshly-spawned host thread needs to stand up its own vCPU
/// in the SHARED process VM and resume the cloned guest thread.
///
/// `vm` is a `vm.clone()` handle: the applevisor VM is Arc-refcounted, so
/// holding a clone keeps the single process VM alive and lets the new thread
/// call `vcpu_create()` against it (HVF requires vCPU create on the owning
/// thread). `mappings` are raw descriptors of the SAME host buffers the main
/// engine mapped; they are local syscall-path metadata only, because the
/// stage-2 entries live on the shared HVF VM, not on each vCPU.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone)]
pub struct ThreadSpec {
    pub(crate) vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
    pub(crate) mappings: Vec<ThreadMappingDesc>,
    /// Sibling threads retain the exact MM authority; no per-MM field is
    /// copied independently into an executor specification.
    pub(crate) mm_access: std::sync::Arc<MmAccessState>,
    pub(crate) carrier_foreign_mm_transport: std::sync::Arc<CarrierForeignMmTransport>,
    pub(crate) mailbox_slots: std::sync::Arc<MailboxSlotAllocator>,
    pub(crate) syscall_transport: HvfSyscallTransport,
    pub(crate) persistent_vm_lifecycle: bool,
    pub(crate) mm_root_slot: Option<(u64, u64)>,
    pub(crate) container_root: ContainerRootToken,
    pub(crate) cow_authority: Option<std::sync::Arc<dyn carrick_hal::FrameCowAuthority>>,
    pub(crate) cow_identity: Option<carrick_hal::FrameCowIdentity>,
}

// SAFETY: `ThreadSpec` carries raw `*mut u8` host pointers (inside the
// mapping descriptors). Those pointers name buffers that are valid for the
// entire host process address space — they outlive every guest thread and
// are never reallocated for the life of the VM. The seeded register snapshot
// rides the engine's `Aarch64SiblingSpec`, NOT here (the engine restores it
// onto the sibling vCPU). The applevisor VM handle is itself `Send` (Arc-backed).
// Moving the spec to another thread to materialise a vCPU there is exactly
// the supported HVF pattern (create the vCPU on its owning thread), so the
// raw pointers crossing the thread boundary is sound.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Send for ThreadSpec {}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub struct ThreadSpec;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PersistentExecutorInvariantRegister {
    VbarEl1,
    SctlrEl1,
    MairEl1,
    CpacrEl1,
    CntkctlEl1,
    TpidrEl1,
    SpEl1,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) const PERSISTENT_EXECUTOR_CONFIGURED_REGISTERS: [PersistentExecutorInvariantRegister;
    6] = [
    PersistentExecutorInvariantRegister::VbarEl1,
    PersistentExecutorInvariantRegister::SctlrEl1,
    PersistentExecutorInvariantRegister::MairEl1,
    PersistentExecutorInvariantRegister::CpacrEl1,
    PersistentExecutorInvariantRegister::CntkctlEl1,
    PersistentExecutorInvariantRegister::TpidrEl1,
];

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) const PERSISTENT_EXECUTOR_INVARIANT_REGISTERS: [PersistentExecutorInvariantRegister; 7] = [
    PersistentExecutorInvariantRegister::VbarEl1,
    PersistentExecutorInvariantRegister::SctlrEl1,
    PersistentExecutorInvariantRegister::MairEl1,
    PersistentExecutorInvariantRegister::CpacrEl1,
    PersistentExecutorInvariantRegister::CntkctlEl1,
    PersistentExecutorInvariantRegister::TpidrEl1,
    PersistentExecutorInvariantRegister::SpEl1,
];

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn persistent_executor_invariant_value(
    register: PersistentExecutorInvariantRegister,
    mailbox_sp: u64,
) -> u64 {
    use carrick_hal::GuestArch as _;

    let boot = <HvfTrapEngine as carrick_hal::ThreadedEngine>::Arch::bootstrap_sysregs();
    match register {
        PersistentExecutorInvariantRegister::VbarEl1 => carrick_mem::memory::LINUX_EL1_VECTORS_BASE,
        PersistentExecutorInvariantRegister::SctlrEl1 => boot.sctlr_el1,
        PersistentExecutorInvariantRegister::MairEl1 => boot.mair_el1,
        PersistentExecutorInvariantRegister::CpacrEl1 => boot.cpacr_el1,
        PersistentExecutorInvariantRegister::CntkctlEl1 => (1 << 1) | (1 << 0),
        // The EL1 vector uses TPIDR_EL1 only as transient executor-local x16
        // scratch. A newly published worker must not inherit task residue.
        PersistentExecutorInvariantRegister::TpidrEl1 => 0,
        PersistentExecutorInvariantRegister::SpEl1 => mailbox_sp,
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn configure_persistent_executor_invariant_registers(
    mut write: impl FnMut(PersistentExecutorInvariantRegister, u64) -> Result<(), TrapError>,
) -> Result<(), TrapError> {
    for register in PERSISTENT_EXECUTOR_CONFIGURED_REGISTERS {
        write(register, persistent_executor_invariant_value(register, 0))?;
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn restore_persistent_executor_invariant_registers(
    mut write: impl FnMut(PersistentExecutorInvariantRegister, u64) -> Result<(), TrapError>,
    mailbox_sp: u64,
) -> Result<(), TrapError> {
    for register in PERSISTENT_EXECUTOR_INVARIANT_REGISTERS {
        write(
            register,
            persistent_executor_invariant_value(register, mailbox_sp),
        )?;
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn audit_persistent_executor_invariant_registers(
    mut read: impl FnMut(PersistentExecutorInvariantRegister) -> Result<u64, TrapError>,
    mailbox_sp: u64,
) -> Result<(), TrapError> {
    for register in PERSISTENT_EXECUTOR_INVARIANT_REGISTERS {
        let actual = read(register)?;
        let expected = persistent_executor_invariant_value(register, mailbox_sp);
        if actual != expected {
            return Err(TrapError::Hypervisor(format!(
                "persistent executor invariant {register:?} mismatch: {actual:#x}/{expected:#x}"
            )));
        }
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfVmState {
    pub(crate) fn configure_executor_invariants(
        vcpu: &applevisor::vcpu::Vcpu,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::SysReg;

        configure_persistent_executor_invariant_registers(|register, value| {
            let register = match register {
                PersistentExecutorInvariantRegister::VbarEl1 => SysReg::VBAR_EL1,
                PersistentExecutorInvariantRegister::SctlrEl1 => SysReg::SCTLR_EL1,
                PersistentExecutorInvariantRegister::MairEl1 => SysReg::MAIR_EL1,
                PersistentExecutorInvariantRegister::CpacrEl1 => SysReg::CPACR_EL1,
                PersistentExecutorInvariantRegister::CntkctlEl1 => SysReg::CNTKCTL_EL1,
                PersistentExecutorInvariantRegister::TpidrEl1 => SysReg::TPIDR_EL1,
                PersistentExecutorInvariantRegister::SpEl1 => {
                    unreachable!("SP_EL1 is mailbox-owned")
                }
            };
            vcpu.set_sys_reg(register, value).map_err(hvf_error)
        })
    }

    pub(crate) fn audit_executor_invariants(
        vcpu: &applevisor::vcpu::Vcpu,
        mailbox_sp: u64,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::SysReg;

        audit_persistent_executor_invariant_registers(
            |register| {
                let register = match register {
                    PersistentExecutorInvariantRegister::VbarEl1 => SysReg::VBAR_EL1,
                    PersistentExecutorInvariantRegister::SctlrEl1 => SysReg::SCTLR_EL1,
                    PersistentExecutorInvariantRegister::MairEl1 => SysReg::MAIR_EL1,
                    PersistentExecutorInvariantRegister::CpacrEl1 => SysReg::CPACR_EL1,
                    PersistentExecutorInvariantRegister::CntkctlEl1 => SysReg::CNTKCTL_EL1,
                    PersistentExecutorInvariantRegister::TpidrEl1 => SysReg::TPIDR_EL1,
                    PersistentExecutorInvariantRegister::SpEl1 => SysReg::SP_EL1,
                };
                vcpu.get_sys_reg(register).map_err(hvf_error)
            },
            mailbox_sp,
        )
    }

    /// M:N reclaim — BLOCK side. Snapshot this vCPU and DESTROY it (freeing one
    /// HVF concurrent-vCPU slot) so another guest thread can run while this one
    /// parks in the futex wait. The SAME thread recreates it via
    /// [`reclaim_resume`](Self::reclaim_resume) on wake. Unlike the fork
    /// path this does NOT publish mappings or rebuild the VM — the VM is unchanged;
    /// only the per-thread vCPU is recycled. Task state is returned through the
    /// typed engine boundary; this backend retains only executor lifecycle.
    ///
    /// WIRED via the HVF engine override `ThreadedEngine::save_guest_state`
    /// (`hvf_aarch64_engine.rs:536`), which passes the engine's separately-owned
    /// `&mut vcpu` through to this destroy-in-place reclaim; the wake side is
    /// `rebind_to_slot` (`hvf_aarch64_engine.rs:557`) → [`reclaim_resume`].
    /// This is the multi-threaded blocked-wait park (vCPU-only; the VM stays
    /// alive) that `park_vcpu_for_blocking_wait` routes to.
    pub(crate) fn reclaim_park(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
    ) -> Result<(), TrapError> {
        // Raw destroy — only the owning thread may, and applevisor's Drop would
        // panic on the post-destroy handle.
        let vcpu_id = vcpu.id();
        let rc = unsafe { applevisor_sys::hv_vcpu_destroy(vcpu_id) };
        if rc == 0 {
            self._vcpu_guard = None;
            vcpu_destroyed(vcpu_id);
        }
        if rc != 0 {
            return Err(TrapError::Hypervisor(format!(
                "reclaim_park: hv_vcpu_destroy rc={rc:#x}"
            )));
        }
        self.reclaim_authority.mark_vcpu_parked()?;
        self.release_mailbox_for_reclaim(mailbox)?;
        Ok(())
    }

    /// Owner-thread zero-instruction handoff. The initial mailbox must still be
    /// idle; validate before destroying the vCPU so an incompatible protocol
    /// state fails without partially relinquishing hardware authority.
    pub(crate) fn initial_runner_park(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
    ) -> Result<(), TrapError> {
        let diagnostics = mailbox.diagnostics();
        if diagnostics.state != carrick_aarch64::mailbox::MailboxState::Idle.raw() {
            return Err(TrapError::Hypervisor(format!(
                "initial runner mailbox is not idle: diagnostics={diagnostics:?}"
            )));
        }
        let vcpu_id = vcpu.id();
        let rc = unsafe { applevisor_sys::hv_vcpu_destroy(vcpu_id) };
        if rc == 0 {
            self._vcpu_guard = None;
            vcpu_destroyed(vcpu_id);
        }
        if rc != 0 {
            return Err(TrapError::Hypervisor(format!(
                "initial_runner_park: hv_vcpu_destroy rc={rc:#x}"
            )));
        }
        self.reclaim_authority.mark_initial_runner_parked()?;
        mailbox
            .release_idle_for_initial_handoff()
            .map_err(|error| TrapError::Hypervisor(format!("release initial mailbox: {error}")))
    }

    pub(crate) fn initial_runner_resume(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
    ) -> Result<(), TrapError> {
        if self.reclaim_authority != ReclaimParkAuthority::InitialRunnerParked {
            return Err(TrapError::Hypervisor(
                "initial_runner_resume: no idle initial-runner authority".to_owned(),
            ));
        }
        let new_vcpu = create_vcpu(&self._vm)?;
        enable_el0_counter_access(new_vcpu.id());
        Self::configure_executor_invariants(&new_vcpu)?;
        self.vcpu_id = new_vcpu.id();
        self.vcpu_handle = new_vcpu.get_handle();
        self._vcpu_guard = Some(vcpu_census().created());
        self.publish_live_vcpu();
        std::mem::forget(std::mem::replace(vcpu, new_vcpu));
        self.reacquire_mailbox_after_vcpu_create(vcpu, mailbox, None)?;
        self.reclaim_authority.mark_live_after_recreate()
    }

    /// M:N reclaim — WAKE side. Recreate this executor's vCPU in the EXISTING VM
    /// when it was locally parked. A live destination executor is retained as-is;
    /// the caller overlays only Kernel-owned typed task state. Writes the recreated
    /// vCPU back through `vcpu` via `std::mem::replace` + `forget` of the old
    /// (already-destroyed) handle (no applevisor Drop).
    ///
    /// WIRED — see [`reclaim_park`](Self::reclaim_park): reached via the HVF
    /// engine override `ThreadedEngine::rebind_to_slot`
    /// (`hvf_aarch64_engine.rs:557`), which passes the `&mut vcpu` this
    /// destroy/recreate-in-place reclaim needs.
    pub(crate) fn reclaim_resume(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
        continuation: Option<carrick_hal::threaded::Aarch64SyscallContinuationV1>,
    ) -> Result<(), TrapError> {
        if self.reclaim_authority.destination_vcpu_is_live().is_ok() {
            if let Some(continuation) = continuation {
                mailbox
                    .import_task_continuation(continuation)
                    .map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "restore task continuation into live destination mailbox: {error}"
                        ))
                    })?;
            }
            return Ok(());
        }
        if self.reclaim_authority != ReclaimParkAuthority::VcpuParked {
            return Err(TrapError::Hypervisor(
                "reclaim_resume: executor requires whole-VM recreation".to_owned(),
            ));
        }
        let continuation = continuation.ok_or_else(|| {
            TrapError::Hypervisor(
                "reclaim_resume: parked syscall has no typed continuation authority".to_owned(),
            )
        })?;
        let new_vcpu = create_vcpu(&self._vm)?;
        enable_el0_counter_access(new_vcpu.id());
        Self::configure_executor_invariants(&new_vcpu)?;
        self.vcpu_id = new_vcpu.id();
        self.vcpu_handle = new_vcpu.get_handle();
        self._vcpu_guard = Some(vcpu_census().created());
        self.publish_live_vcpu();
        // Replace the destroyed handle WITHOUT running applevisor's panicky Drop on
        // the (already hv_vcpu_destroy'd) old one — mirror the fork rebuild.
        std::mem::forget(std::mem::replace(vcpu, new_vcpu));
        self.reacquire_mailbox_after_vcpu_create(vcpu, mailbox, Some(continuation))?;
        self.reclaim_authority.mark_live_after_recreate()?;
        Ok(())
    }

    /// Single-threaded process shared-futex park. Unlike `reclaim_park`, this
    /// destroys the whole VM, not just the vCPU, so a large process-fork fanout
    /// parked in `FUTEX_WAIT` does not keep one HVF VM alive per waiter.
    pub(crate) fn shared_wait_park(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
    ) -> Result<(), TrapError> {
        let vcpu_id = vcpu.id();
        let vcpu_rc = unsafe { applevisor_sys::hv_vcpu_destroy(vcpu_id) };
        if vcpu_rc == 0 {
            self._vcpu_guard = None;
            vcpu_destroyed(vcpu_id);
        }
        if vcpu_rc != 0 {
            return Err(TrapError::Hypervisor(format!(
                "shared_wait_park: hv_vcpu_destroy rc={vcpu_rc:#x}"
            )));
        }
        self.reclaim_authority.mark_vcpu_parked()?;
        self.release_mailbox_for_reclaim(mailbox)?;
        destroy_vm_with_custody(
            &self.carrier_foreign_mm_transport.custody,
            "shared_wait_park",
        )?;
        self.reclaim_authority.mark_vm_parked()?;
        Ok(())
    }

    /// MT whole-VM lease — VM-only release by the LAST parker of a
    /// multi-threaded process. Its own vCPU was ALREADY destroyed by
    /// [`Self::reclaim_park`] (its executor lifecycle is recorded in
    /// `reclaim_authority`), and every
    /// sibling's registry "parked" mark is set only AFTER its own
    /// `reclaim_park` destroy — so when the runtime's re-check passes, zero
    /// vCPUs are live and the bare `hv_vm_destroy` succeeds. Any nonzero rc
    /// (e.g. HV_BUSY from a vCPU in a teardown window the registry no longer
    /// tracks, like a thread mid-exit) is a clean error: the VM was NOT
    /// destroyed, and the caller must NOT set the vm-released flag — the park
    /// stays vCPU-only and the wake side stays `reclaim_resume`.
    pub(crate) fn release_vm_after_reclaim_park(&mut self) -> Result<(), TrapError> {
        if self.reclaim_authority != ReclaimParkAuthority::VcpuParked {
            return Err(TrapError::Hypervisor(
                "release_vm_after_reclaim_park: no parked vCPU authority (reclaim_park did not run)"
                    .into(),
            ));
        }
        destroy_vm_with_custody(
            &self.carrier_foreign_mm_transport.custody,
            "release_vm_after_reclaim_park",
        )?;
        self.reclaim_authority.mark_vm_parked()?;
        Ok(())
    }

    /// Resume a process parked by [`Self::shared_wait_park`]: create a fresh VM
    /// and vCPU, re-map this process's existing host backings, then restore the
    /// saved guest registers.
    ///
    /// `replay_alias_union` (the MT whole-VM lease first-waker rebuild): also
    /// re-map every live process-global [`alias_registry`] entry this thread's
    /// per-thread `mappings` lacks. Threads share ONE VM but `mappings` is
    /// per-thread, so a high-VA alias a STILL-PARKED sibling mapped would
    /// otherwise be missing from the rebuilt stage-2 (the same shape the fork
    /// rebuild repairs with its quiesced-sibling union). Safe because every
    /// parked sibling holds its `OwnedHostMapping`s alive while parked, and no
    /// guest thread of this process runs during the rebuild (the caller holds
    /// the topology lock; claim-false wakers rebind behind it) — so no
    /// interleaving `munmap` can invalidate an entry mid-replay. Entries are
    /// NOT pushed into `self.mappings` (ownership stays with the mapping
    /// thread; a later rebuild re-reads the registry, which reflects any
    /// munmap since). Single-threaded resumes pass `false` — their own
    /// `mappings` list is complete by construction, and a forked child must
    /// NOT re-establish inherited parent/sibling aliases the fork rebuild
    /// deliberately dropped. The bounded lazy on-fault re-map in `run_to_exit`
    /// remains the backstop either way.
    pub(crate) fn shared_wait_resume(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
        replay_alias_union: bool,
        continuation: Option<carrick_hal::threaded::Aarch64SyscallContinuationV1>,
    ) -> Result<(), TrapError> {
        let mut pending_creation = None;
        let result = self.shared_wait_resume_inner(
            vcpu,
            mailbox,
            replay_alias_union,
            continuation,
            &mut pending_creation,
        );
        finish_pending_vm_creation(pending_creation, result)
    }

    pub(crate) fn shared_wait_resume_inner(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
        replay_alias_union: bool,
        continuation: Option<carrick_hal::threaded::Aarch64SyscallContinuationV1>,
        pending_creation: &mut Option<PendingCarrierVmCreation>,
    ) -> Result<(), TrapError> {
        if self.reclaim_authority != ReclaimParkAuthority::VmParked {
            return Err(TrapError::Hypervisor(
                "shared_wait_resume: no parked VM executor authority".to_owned(),
            ));
        }
        let continuation = continuation.ok_or_else(|| {
            TrapError::Hypervisor(
                "shared_wait_resume: parked syscall has no typed continuation authority".to_owned(),
            )
        })?;
        let (new_vm, permit, creation) = create_vm_with_admission(
            VmCreateAdmission::SharedWaitResume,
            &self.carrier_foreign_mm_transport.custody,
        )?;
        let new_vm = SetupVmGuard::new(new_vm, true);
        *pending_creation = Some(creation);
        let new_vcpu = SetupVcpuGuard::new(
            create_vcpu_with_permit(&new_vm, permit)?,
            SetupVcpuCleanup::PendingRaw,
        );
        let creation = pending_creation.as_mut().ok_or_else(|| {
            TrapError::Hypervisor("shared-wait creation transaction disappeared".to_owned())
        })?;
        creation.record_vcpu(new_vcpu.id());
        enable_el0_counter_access(new_vcpu.id());
        Self::configure_executor_invariants(&new_vcpu)?;
        // Snapshot the registry's CURRENT membership before the replay: an
        // alias another thread `munmap`'d while we were parked was removed
        // from the registry (`unregister_alias`) but may still sit in this
        // thread's per-thread `mappings` list — re-REGISTERING it below would
        // resurrect a dead index entry that a later syscall/fault could
        // resolve to a freed backing. Registration is creation-complete
        // (every `add_alias` registers; removal happens only on munmap /
        // execve-clear), so absence here means "gone on purpose".
        let registered_aliases = alias_registry()
            .lock()
            .process_visible_ordered(self.mm_root_slot, self.container_root);
        let mut mapped_extents = std::collections::HashSet::new();
        let mut replayed_global_owners = Vec::new();
        for mapping in &self.mappings {
            // Skip a sibling-munmap'd stale high-VA entry ENTIRELY (absence
            // from the registry = gone on purpose, mirroring the union loop
            // below): hv_vm_map'ing it would map a freed host VA
            // (ChildMapFailed → wake fatal) or squat a dead IPA a later mmap
            // collides with.
            let live_alias = mapping
                .is_dynamic_alias
                .then(|| {
                    registered_aliases.iter().find(|alias| {
                        alias_matches_process_scope(
                            alias.ownership_scope,
                            self.mm_root_slot,
                            self.container_root,
                        ) && alias.start == mapping.start
                            && alias.ipa == mapping.ipa
                            && alias.host_addr == mapping.host_addr as usize
                            && alias.size == semantic_extent_size(mapping.start, mapping.end)
                    })
                })
                .flatten();
            if mapping.is_dynamic_alias && live_alias.is_none() {
                continue;
            }
            let (host_addr, ipa, size, perms, owner_generation) = live_alias.map_or(
                (
                    mapping.host_addr,
                    mapping.ipa,
                    mapping.size,
                    u64::from(mapping.perms),
                    mapping.owner_generation,
                ),
                |alias| {
                    (
                        alias.physical_host_addr as *mut u8,
                        alias.physical_ipa,
                        alias.physical_size,
                        alias.perms,
                        alias.owner_generation,
                    )
                },
            );
            if is_reusable_global_frame_extent(ipa, size as u64)
                && !global_frame_owner_is_replayable_in(
                    &self.carrier_foreign_mm_transport.custody,
                    ipa,
                    size as u64,
                    host_addr as usize,
                    owner_generation,
                )
            {
                continue;
            }
            if !mapped_extents.insert((ipa, size)) {
                continue;
            }
            let r = unsafe { inventory_hv_vm_map(host_addr.cast(), ipa, size, perms) };
            if r != 0 {
                return Err(TrapError::ChildMapFailed {
                    host_addr: host_addr as u64,
                    guest_start: ipa,
                    size,
                    code: r as u32,
                });
            }
            replayed_global_owners.push(GlobalFrameReplayExtent {
                ipa,
                length: size as u64,
                host_addr: host_addr as usize,
                perms,
            });
        }

        if replay_alias_union || self.mappings.iter().any(|mapping| mapping.is_dynamic_alias) {
            // Copy the entries out so the registry mutex isn't held across the
            // hv_vm_map syscalls (`AliasBacking` is `Copy`).
            for b in registered_aliases {
                if !alias_matches_process_scope(
                    b.ownership_scope,
                    self.mm_root_slot,
                    self.container_root,
                ) || !mapped_extents.insert((b.physical_ipa, b.physical_size))
                    || !alias_backing_is_live(b.host_addr)
                {
                    continue;
                }
                if is_reusable_global_frame_extent(b.physical_ipa, b.physical_size as u64)
                    && !global_frame_owner_is_replayable_in(
                        &self.carrier_foreign_mm_transport.custody,
                        b.physical_ipa,
                        b.physical_size as u64,
                        b.physical_host_addr,
                        b.owner_generation,
                    )
                {
                    continue;
                }
                let r = unsafe {
                    inventory_hv_vm_map(
                        b.physical_host_addr as *mut std::ffi::c_void,
                        b.physical_ipa,
                        b.physical_size,
                        b.perms,
                    )
                };
                if r != 0 {
                    return Err(TrapError::ChildMapFailed {
                        host_addr: b.host_addr as u64,
                        guest_start: b.physical_ipa,
                        size: b.physical_size,
                        code: r as u32,
                    });
                }
                replayed_global_owners.push(GlobalFrameReplayExtent {
                    ipa: b.physical_ipa,
                    length: b.physical_size as u64,
                    host_addr: b.physical_host_addr,
                    perms: b.perms,
                });
            }
        }

        reconcile_global_frame_owners_after_replay_in(
            &self.carrier_foreign_mm_transport.custody,
            &replayed_global_owners,
            false,
        )?;

        self.reacquire_mailbox_after_vcpu_create(&new_vcpu, mailbox, Some(continuation))?;
        self.reclaim_authority.mark_live_after_recreate()?;
        commit_pending_creation_before_vcpu_handoff(pending_creation)?;
        self.vcpu_id = new_vcpu.id();
        self.vcpu_handle = new_vcpu.get_handle();
        self.publish_live_vcpu();
        std::mem::forget(std::mem::replace(vcpu, new_vcpu.into_inner()));
        replace_destroyed_vm(self, new_vm.into_inner());
        Ok(())
    }

    /// A guest thread is exiting: destroy ITS OWN vCPU (only the owning thread
    /// may) so the slot is freed in the process-global VM. Without this, the
    /// no-op `Drop` leaks the vCPU live forever, and a later fork's
    /// `hv_vm_destroy` trips over the accumulated dead-thread vCPUs (HV_BUSY).
    /// Raw `hv_vcpu_destroy`, not applevisor's panicky wrapper.
    pub(crate) fn destroy_vcpu_on_thread_exit(&mut self, vcpu: &mut applevisor::vcpu::Vcpu) {
        let vcpu_id = vcpu.id();
        let rc = unsafe { applevisor_sys::hv_vcpu_destroy(vcpu_id) };
        if rc == 0 {
            self._vcpu_guard = None;
            vcpu_destroyed(vcpu_id);
        }
    }

    pub(crate) fn take_persistent_executor_spec(
        &mut self,
    ) -> Result<PersistentExecutorSpec, TrapError> {
        if let Some(carrier_mappings) = self.carrier_mappings.as_ref() {
            // A later container's root was built INSIDE the carrier VM
            // (`new_with_plan` reuse lane) and already shares the carrier's
            // control-mapping authority: hand back the carrier's own bundle.
            // Any other holder (a worker) is still refused as before.
            let cell = persistent_carrier_cell().lock();
            return match cell.as_ref() {
                Some(PersistentCarrierCellEntry::Published(spec))
                    if std::sync::Arc::ptr_eq(&spec.carrier_mappings, carrier_mappings) =>
                {
                    Ok(spec.clone())
                }
                _ => Err(TrapError::Hypervisor(
                    "persistent executor carrier authority was already extracted".to_owned(),
                )),
            };
        }
        let custody = std::sync::Arc::clone(&self.carrier_foreign_mm_transport.custody);
        let carrier_mappings = std::sync::Arc::new(PersistentCarrierMappings::extract(
            &mut self.mappings,
            custody,
        )?);
        let spec = PersistentExecutorSpec {
            vm: (*self._vm).clone(),
            carrier_mappings,
            mailbox_slots: std::sync::Arc::clone(&self.mailbox_slots),
            syscall_transport: self.syscall_transport,
            carrier_foreign_mm_transport: std::sync::Arc::clone(&self.carrier_foreign_mm_transport),
        };
        // First root of this carrier: publish the VM-global bundle for every
        // later container's root bring-up and wake any root parked on it. The
        // boot gate in `new_with_plan` guarantees only ONE first root exists,
        // so the cell is empty here; the guard is defensive.
        {
            let mut cell = persistent_carrier_cell().lock();
            if cell.is_none() {
                *cell = Some(PersistentCarrierCellEntry::Published(spec.clone()));
            }
        }
        carrier_published().notify_all();
        Ok(spec)
    }

    pub(crate) fn allocate_persistent_mailbox_for_vcpu(
        spec: &PersistentExecutorSpec,
        vcpu: &applevisor::vcpu::Vcpu,
    ) -> Result<MailboxBinding, TrapError> {
        use applevisor::prelude::SysReg;

        let lease = spec
            .mailbox_slots
            .allocate()
            .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
        let address = lease.id().guest_address();
        let pointer = spec
            .carrier_mappings
            .host_pointer(
                address,
                carrick_aarch64::mailbox::AARCH64_SYSCALL_MAILBOX_SIZE as usize,
            )
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "persistent executor syscall mailbox slot {} at {address:#x} is not mapped",
                    lease.id().raw()
                ))
            })?
            .cast::<carrick_aarch64::mailbox::Aarch64SyscallMailbox>();
        // SAFETY: the carrier projection was validated to contain the complete
        // fixed mailbox arena, and the lease uniquely owns this slot.
        let binding = unsafe { MailboxBinding::new(lease, pointer, spec.syscall_transport) };
        vcpu.set_sys_reg(SysReg::SP_EL1, address)
            .map_err(hvf_error)?;
        Ok(binding)
    }

    pub(crate) fn from_persistent_executor_spec(
        spec: &PersistentExecutorSpec,
    ) -> Result<(HvfVmState, applevisor::vcpu::Vcpu, MailboxBinding), TrapError> {
        spec.carrier_mappings.audit()?;
        let vm = spec.vm.clone();
        let vcpu = create_vcpu(&vm)?;
        enable_el0_counter_access(vcpu.id());
        let state = HvfVmState {
            _vm: std::mem::ManuallyDrop::new(vm),
            carrier_foreign_mm_transport: std::sync::Arc::clone(&spec.carrier_foreign_mm_transport),
            task: HvfTaskState::neutral(),
            carrier_mappings: Some(std::sync::Arc::clone(&spec.carrier_mappings)),
            reclaim_authority: ReclaimParkAuthority::Live,
            mailbox_slots: std::sync::Arc::clone(&spec.mailbox_slots),
            syscall_transport: spec.syscall_transport,
            vcpu_id: vcpu.id(),
            vcpu_handle: vcpu.get_handle(),
            _vcpu_guard: Some(vcpu_census().created()),
        };
        state.publish_live_vcpu();
        Self::configure_executor_invariants(&vcpu)?;
        let mailbox = Self::allocate_persistent_mailbox_for_vcpu(spec, &vcpu)?;
        Self::audit_executor_invariants(&vcpu, mailbox.slot().guest_address())?;
        state.task.audit_neutral()?;
        Ok((state, vcpu, mailbox))
    }

    pub(crate) fn audit_persistent_executor_idle(&self) -> Result<(), TrapError> {
        self.task.audit_neutral()?;
        self.carrier_mappings
            .as_ref()
            .ok_or_else(|| {
                TrapError::Hypervisor(
                    "persistent executor lost carrier mapping authority".to_owned(),
                )
            })?
            .audit()?;
        // Maintenance failures remain recorded on the exact Pending owner and
        // re-arm the custody-local request bit. They must not kill an otherwise
        // clean persistent worker; the next executor-idle boundary retries.
        let _remaining = retry_pending_global_frame_retirements_at_idle_in_using(
            &self.carrier_foreign_mm_transport.custody,
            &mut unmap_global_frame_stage2_record,
        );
        Ok(())
    }

    pub(crate) fn carrier_maintenance_root(
        &self,
    ) -> Result<carrick_mem::memory::CarrierMaintenanceRoot, TrapError> {
        let carrier = self.carrier_mappings.as_ref().ok_or_else(|| {
            TrapError::Hypervisor("persistent executor lost carrier mapping authority".to_owned())
        })?;
        Ok(carrier.maintenance_root())
    }

    pub(crate) fn audit_persistent_worker_vcpu_boundary(
        &self,
        vcpu: &applevisor::vcpu::Vcpu,
        mailbox: &MailboxBinding,
    ) -> Result<(), TrapError> {
        self.audit_persistent_executor_idle()?;
        if self.reclaim_authority != ReclaimParkAuthority::Live {
            return Err(TrapError::Hypervisor(
                "persistent worker lost its live owner-thread vCPU authority".to_owned(),
            ));
        }
        if mailbox.is_released_for_executor_boundary() {
            return Err(TrapError::Hypervisor(
                "persistent worker released its executor-local mailbox".to_owned(),
            ));
        }
        if mailbox
            .export_task_continuation()
            .map_err(|error| {
                TrapError::Hypervisor(format!("audit persistent worker mailbox boundary: {error}"))
            })?
            .is_some()
        {
            return Err(TrapError::Hypervisor(
                "persistent worker retained a task syscall continuation".to_owned(),
            ));
        }
        use applevisor::prelude::SysReg;
        let sp_el1 = vcpu.get_sys_reg(SysReg::SP_EL1).map_err(hvf_error)?;
        if sp_el1 != mailbox.slot().guest_address() {
            return Err(TrapError::Hypervisor(format!(
                "persistent worker mailbox SP_EL1 drifted: {sp_el1:#x}/{:#x}",
                mailbox.slot().guest_address()
            )));
        }
        Ok(())
    }

    pub(crate) fn restore_persistent_worker_vcpu_boundary(
        &self,
        vcpu: &applevisor::vcpu::Vcpu,
        mailbox: &MailboxBinding,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::SysReg;

        restore_persistent_executor_invariant_registers(
            |register, value| {
                let register = match register {
                    PersistentExecutorInvariantRegister::VbarEl1 => SysReg::VBAR_EL1,
                    PersistentExecutorInvariantRegister::SctlrEl1 => SysReg::SCTLR_EL1,
                    PersistentExecutorInvariantRegister::MairEl1 => SysReg::MAIR_EL1,
                    PersistentExecutorInvariantRegister::CpacrEl1 => SysReg::CPACR_EL1,
                    PersistentExecutorInvariantRegister::CntkctlEl1 => SysReg::CNTKCTL_EL1,
                    PersistentExecutorInvariantRegister::TpidrEl1 => SysReg::TPIDR_EL1,
                    PersistentExecutorInvariantRegister::SpEl1 => SysReg::SP_EL1,
                };
                vcpu.set_sys_reg(register, value).map_err(hvf_error)
            },
            mailbox.slot().guest_address(),
        )?;
        Self::audit_executor_invariants(vcpu, mailbox.slot().guest_address())
    }

    /// Build a [`ThreadSpec`] for a thread-creating `clone(CLONE_THREAD)`: clone the
    /// SHARED VM handle (Arc-refcounted, so the new thread can `vcpu_create` against
    /// it) + the SHARED protections/page-table Arcs + a COPY of the mapping
    /// descriptors (the new thread's vCPU sees the same guest memory; the stage-2
    /// entries are VM-global). Does NOT snapshot the vCPU — the engine carries the
    /// seeded register snapshot in its own `Aarch64SiblingSpec` and restores it onto
    /// the sibling vCPU via `restore_thread_start` after `from_thread_spec`.
    pub(crate) fn build_thread_spec(&self) -> Result<ThreadSpec, TrapError> {
        let mappings: Vec<ThreadMappingDesc> = self
            .mappings
            .iter()
            .map(ThreadMappingDesc::from_region)
            .collect();
        Ok(ThreadSpec {
            vm: (*self._vm).clone(),
            mappings,
            mm_access: std::sync::Arc::clone(&self.mm_access),
            carrier_foreign_mm_transport: std::sync::Arc::clone(&self.carrier_foreign_mm_transport),
            mailbox_slots: std::sync::Arc::clone(&self.mailbox_slots),
            syscall_transport: self.syscall_transport,
            persistent_vm_lifecycle: self.persistent_vm_lifecycle,
            mm_root_slot: self.mm_root_slot,
            container_root: self.container_root,
            cow_authority: self.cow_authority.clone(),
            cow_identity: self.cow_identity,
        })
    }

    /// Stand up a thread sibling on the current host thread from a [`ThreadSpec`]:
    /// create a new vCPU in the shared VM and mirror the inherited (UNOWNED)
    /// mapping metadata. Returns the `(state, vcpu)` pair; the engine restores the
    /// seeded register snapshot. MUST be called on the host thread that will own
    /// the vCPU (HVF requires vCPU create+run+destroy on one thread).
    pub(crate) fn from_thread_spec(
        spec: ThreadSpec,
    ) -> Result<(HvfVmState, applevisor::vcpu::Vcpu, MailboxBinding), TrapError> {
        let ThreadSpec {
            vm,
            mappings,
            mm_access,
            carrier_foreign_mm_transport,
            mailbox_slots,
            syscall_transport,
            persistent_vm_lifecycle,
            mm_root_slot,
            container_root,
            cow_authority,
            cow_identity,
        } = spec;

        let vcpu = create_vcpu(&vm)?;
        enable_el0_counter_access(vcpu.id());

        #[cfg(not(test))]
        let custody = std::sync::Arc::clone(&carrier_foreign_mm_transport.custody);
        let mut state = HvfVmState {
            _vm: std::mem::ManuallyDrop::new(vm),
            carrier_foreign_mm_transport,
            task: HvfTaskState {
                #[cfg(not(test))]
                custody,
                mappings: TaskMappingIndex::new(),
                mm_root_slot,
                container_root,
                pending_exec_mm_root_slot: None,
                pending_exec_asid: None,
                pending_exec_predecessor_identity: None,
                pending_exec_stage2_cleanup: None,
                shared_process_mm: false,
                mm_access,
                last_exit_class: 0,
                last_fault_esr: 0,
                is_forked_child: false,
                forked_no_exec: false,
                last_syscall_nr: None,
                last_syscall_orig_x0: 0,
                live_vcpu: crate::vcpu_kick::LiveVcpuSlot::new(),
                persistent_vm_lifecycle,
                cow_authority,
                cow_identity,
                pending_fork_frame_receipts: Vec::new(),
                pending_process_aliases: Vec::new(),
                fail_next_begin_exec_inventory: false,
                cow_rollback_scratch: None,
                registration: None,
            },
            carrier_mappings: None,
            reclaim_authority: ReclaimParkAuthority::Live,
            mailbox_slots,
            syscall_transport,
            vcpu_id: vcpu.id(),
            vcpu_handle: vcpu.get_handle(),
            _vcpu_guard: Some(vcpu_census().created()),
        };
        state.publish_live_vcpu();

        for mapping in mappings {
            // `hv_vm_map` is VM-global on Hypervisor.framework. The new vCPU is
            // created in the parent's VM clone, so the parent mappings are
            // already visible here; reissuing them for every sibling is at best
            // an already-mapped no-op and at worst map-table churn while other
            // vCPUs are running. Keep only local metadata used by syscall-path
            // guest-memory accessors.
            state.mappings.insert(mapping.into_unowned_region());
        }

        let mailbox = state.allocate_mailbox_for_vcpu(&vcpu)?;
        Ok((state, vcpu, mailbox))
    }

    pub(crate) fn build_process_spec(
        &self,
        request: carrick_hal::ProcessForkRequest,
        page_tables: &mut crate::page_table::PageTableManager,
        cow_ranges: &[carrick_aarch64::vmm::ForkCowRange],
    ) -> Result<ProcessSpec, TrapError> {
        let plan = self.task.build_process_plan(
            request,
            page_tables,
            cow_ranges,
            std::sync::Arc::clone(&self.mailbox_slots),
            self.syscall_transport,
            std::sync::Arc::clone(&self.carrier_foreign_mm_transport),
        )?;
        Ok(ProcessSpec::new((*self._vm).clone(), plan))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_no_non_test_hv_vm_destroy_call_and_no_rebuilt_vm_cell_in_persistent_executor() {
        let executor_source = include_str!("persistent_executor.rs")
            .split("mod tests {")
            .next()
            .expect("persistent_executor source before tests");
        assert!(
            !executor_source.contains(concat!("rebuilt_", "vm_cell")),
            "persistent_executor.rs must not read or reference rebuilt_vm_cell"
        );

        let crate_sources = concat!(
            include_str!("persistent_executor.rs"),
            include_str!("../trap.rs"),
            include_str!("carrier_custody.rs"),
            include_str!("execve_rebuild.rs"),
            include_str!("mapping_plan.rs"),
            include_str!("cow_engine.rs"),
            include_str!("../hvf_aarch64_engine.rs"),
            include_str!("../fork_coord.rs"),
            include_str!("../fork_quiesce.rs"),
        );
        assert_eq!(
            crate_sources
                .matches(concat!("applevisor_sys::hv_vm_", "destroy()"))
                .count(),
            0,
            "no non-test raw hv_vm_destroy call may exist in these modules"
        );
        assert_eq!(
            crate_sources
                .matches(concat!("inventory_hv_vm_", "destroy()"))
                .count(),
            1,
            "inventory_hv_vm_destroy appears only in the custody wrapper"
        );
    }
}
