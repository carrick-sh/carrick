//! Stage-2 Raw Mapping Backend, Audit, and HAL Register Access.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use super::*;
use carrick_fatal::carrick_fatal;

impl HvfMappedRegion {
    /// Whether `[address, address+length)` lies wholly within this region's
    /// VA span `[start, end)`. Delegates the whole-range containment+bounds math
    /// to the neutral [`carrick_guest_mem::region::GuestMemoryRegion::contains_range`]
    /// so the bounds test can't drift across backends. HVF keeps its RICHER
    /// region SELECTION (newest-first + stage-1-IPA preference, chunked per page,
    /// `translate_va` for high-VA aliases — see `mapping_index_for_range`) as its
    /// own glue; only this per-region bounds primitive is shared. The projected
    /// region keys on `start`/`end` (NOT `size`: a 16 KiB host-rounded `end` can
    /// over-claim, and the copy loops compute `host_addr + (addr - start)`).
    pub(crate) fn contains_range(&self, address: u64, length: usize) -> bool {
        carrick_guest_mem::region::GuestMemoryRegion {
            base: self.start,
            len: (self.end - self.start) as usize,
            host_addr: self.host_addr,
        }
        .contains_range(address, length)
    }

    pub(crate) fn view(&self) -> MappingView {
        MappingView {
            start: self.start,
            end: self.end,
            ipa: self.ipa,
            host_addr: self.host_addr,
            guest_writable: self.guest_writable,
            sharing: self.sharing,
            shared_key_base: self.shared_key_base,
            shared_key_offset: self.shared_key_offset,
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl MappingView {
    pub(crate) fn is_shared_aperture_identity(&self) -> bool {
        self.ipa == self.start
            && self.sharing == GuestMappingSharing::GlobalShared
            && self.end > self.start
            && crate::memory::va_in_shared_aperture(self.start, self.end - self.start)
    }

    /// Synthesize a view from a process-shared `alias_registry` entry (the
    /// cross-thread fallback). The alias is a contiguous VA→IPA→host window, so
    /// the VA base + backing base reproduce the same `host_addr + (addr - start)`
    /// offset math a real region uses.
    pub(crate) fn from_alias(b: &AliasBacking) -> Self {
        MappingView {
            start: b.start,
            end: b.start.saturating_add(b.size as u64),
            ipa: b.ipa,
            host_addr: b.host_addr as *mut u8,
            guest_writable: b.guest_writable,
            sharing: b.sharing,
            shared_key_base: b.shared_key_base,
            shared_key_offset: b.shared_key_offset,
        }
    }

    pub(crate) fn shared_futex_location_for_ipa(
        &self,
        backing_gpa: u64,
    ) -> Option<carrick_guest_mem::SharedFutexLocation> {
        if !self.sharing.has_shared_futex_identity() {
            return None;
        }
        let offset = usize::try_from(backing_gpa.checked_sub(self.ipa)?).ok()?;
        if offset.checked_add(std::mem::size_of::<u32>())?
            > self.end.checked_sub(self.start)? as usize
        {
            return None;
        }
        let word = carrick_guest_mem::HostVa(unsafe { self.host_addr.add(offset) } as usize);
        let waiter_key = if self.shared_key_base == 0 {
            word.raw()
        } else {
            let file_offset = self.shared_key_offset.saturating_add(offset as u64);
            shared_futex_waiter_key(self.shared_key_base, file_offset)
        };
        Some(carrick_guest_mem::SharedFutexLocation::Direct { word, waiter_key })
    }
}

/// True for a memory abort taken from a LOWER exception level (EL0 guest code):
/// instruction abort (`EC = 0x20`) or data abort (`EC = 0x24`). HVF normally
/// funnels guest EL0 faults through our EL1 vector trampoline (an HVC), but a
/// fault HVF itself can't satisfy (e.g. a stack overflow whose SP ran off the
/// mapped guest stack) surfaces DIRECTLY as an EXCEPTION exit with this EC. It
/// must be delivered to the guest as SIGSEGV (faulthandler._stack_overflow,
/// Go's sigpanic), not treated as a fatal "unexpected exception".
pub fn is_aarch64_el0_abort_exception(syndrome: u64) -> bool {
    matches!(aarch64_exception_class(syndrome), 0x20 | 0x24)
}

pub(crate) fn align_down(value: u64, alignment: u64) -> u64 {
    value / alignment * alignment
}

pub(crate) fn align_up(value: u64, alignment: u64) -> Result<u64, TrapError> {
    if alignment == 0 {
        return Err(TrapError::Hypervisor(
            "cannot align a guest mapping to zero bytes".to_owned(),
        ));
    }
    let remainder = value % alignment;
    if remainder == 0 {
        Ok(value)
    } else {
        value
            .checked_add(alignment - remainder)
            .ok_or(TrapError::MappingOverflow {
                guest_start: value,
                mapped_size: alignment,
            })
    }
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Stage2BackendEvent {
    Map {
        ipa: u64,
        size: usize,
        host: usize,
        perms: u64,
    },
    Unmap {
        ipa: u64,
        size: usize,
    },
    UnmapAttemptFailed {
        ipa: u64,
        size: usize,
    },
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct Stage2TestAuditState {
    pub(crate) enabled: bool,
    pub(crate) fail_sparse_publication_after_sync: bool,
    pub(crate) fail_next_map: bool,
    pub(crate) fail_map_on_call: Option<usize>,
    pub(crate) map_call_count: usize,
    pub(crate) fail_next_unmap: bool,
    pub(crate) fail_stage_mapping: bool,
    pub(crate) fail_stage_mapping_on_row: Option<usize>,
    pub(crate) stage_mapping_count: usize,
    pub(crate) mapped_extents: std::collections::BTreeSet<(u64, usize)>,
    pub(crate) events: Vec<Stage2BackendEvent>,
}

#[cfg(test)]
thread_local! {
    pub(crate) static STAGE2_AUDIT_STATE: std::cell::RefCell<Stage2TestAuditState> =
        std::cell::RefCell::new(Stage2TestAuditState::default());
}

#[cfg(test)]
pub(crate) struct ScopedStage2MapTestStub;

#[cfg(test)]
impl ScopedStage2MapTestStub {
    pub(crate) fn enable() -> Self {
        STAGE2_AUDIT_STATE.with(|s| {
            let mut state = s.borrow_mut();
            state.enabled = true;
            state.fail_sparse_publication_after_sync = false;
            state.fail_next_map = false;
            state.fail_map_on_call = None;
            state.map_call_count = 0;
            state.fail_next_unmap = false;
            state.fail_stage_mapping = false;
            state.fail_stage_mapping_on_row = None;
            state.stage_mapping_count = 0;
            state.mapped_extents.clear();
            state.events.clear();
        });
        Self
    }

    pub(crate) fn set_fail_next_map(&self, fail: bool) {
        STAGE2_AUDIT_STATE.with(|s| s.borrow_mut().fail_next_map = fail);
    }

    pub(crate) fn set_fail_map_on_call(&self, call: Option<usize>) {
        STAGE2_AUDIT_STATE.with(|s| {
            let mut state = s.borrow_mut();
            state.fail_map_on_call = call;
            state.map_call_count = 0;
        });
    }

    pub(crate) fn set_fail_next_unmap(&self, fail: bool) {
        STAGE2_AUDIT_STATE.with(|s| s.borrow_mut().fail_next_unmap = fail);
    }

    #[allow(dead_code)]
    pub(crate) fn set_fail_stage_mapping(&self, fail: bool) {
        STAGE2_AUDIT_STATE.with(|s| s.borrow_mut().fail_stage_mapping = fail);
    }

    pub(crate) fn set_fail_stage_mapping_on_row(&self, row: Option<usize>) {
        STAGE2_AUDIT_STATE.with(|s| {
            let mut state = s.borrow_mut();
            state.fail_stage_mapping_on_row = row;
            state.stage_mapping_count = 0;
        });
    }

    pub(crate) fn is_mapped(ipa: u64, size: usize) -> bool {
        STAGE2_AUDIT_STATE.with(|s| s.borrow().mapped_extents.contains(&(ipa, size)))
    }

    pub(crate) fn events() -> Vec<Stage2BackendEvent> {
        STAGE2_AUDIT_STATE.with(|s| s.borrow().events.clone())
    }

    pub(crate) fn mapped_count() -> usize {
        STAGE2_AUDIT_STATE.with(|s| s.borrow().mapped_extents.len())
    }

    #[allow(dead_code)]
    pub(crate) fn clear_events() {
        STAGE2_AUDIT_STATE.with(|s| s.borrow_mut().events.clear());
    }
}

#[cfg(test)]
impl Drop for ScopedStage2MapTestStub {
    fn drop(&mut self) {
        STAGE2_AUDIT_STATE.with(|s| {
            let mut state = s.borrow_mut();
            state.enabled = false;
            state.fail_next_map = false;
            state.fail_map_on_call = None;
            state.map_call_count = 0;
            state.fail_next_unmap = false;
            state.fail_stage_mapping = false;
            state.fail_stage_mapping_on_row = None;
            state.stage_mapping_count = 0;
            state.mapped_extents.clear();
            state.events.clear();
        });
    }
}

#[cfg(test)]
#[test]
#[ignore = "negative control: scripts/test-signed.sh runs it on an UNENTITLED copy of this executable"]
fn unsigned_executable_maps_hv_denied_to_entitlement() {
    let outcome = applevisor::vm::VirtualMachine::with_config(
        applevisor::vm::VirtualMachineConfig::default(),
    );
    match outcome {
        Err(err)
            if err.to_string().contains("0xfae94007") || err.to_string().contains("HV_DENIED") => {}
        Err(other) => {
            panic!("expected HV_DENIED from an unentitled executable, got: {other:?}")
        }
        Ok(_) => panic!(
            "an unentitled executable created a VM: this process IS entitled, \
             so the negative control proves nothing"
        ),
    }
}

/// Sole raw Hypervisor.framework stage-2 map boundary. Inventory-aware callers
/// own logical publication; VM/vCPU replay calls this only to reinstall the
/// same physical extent and must still treat every nonzero result as failure.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) unsafe fn inventory_hv_vm_map(
    host: *mut std::ffi::c_void,
    ipa: u64,
    size: usize,
    permissions: u64,
) -> applevisor_sys::hv_return_t {
    #[cfg(test)]
    if STAGE2_AUDIT_STATE.with(|s| s.borrow().enabled) {
        let should_fail = STAGE2_AUDIT_STATE.with(|s| {
            let mut state = s.borrow_mut();
            state.map_call_count = state.map_call_count.saturating_add(1);
            if state.fail_next_map {
                state.fail_next_map = false;
                true
            } else if state.fail_map_on_call == Some(state.map_call_count) {
                state.fail_map_on_call = None;
                true
            } else if !state.mapped_extents.insert((ipa, size)) {
                true
            } else {
                state.events.push(Stage2BackendEvent::Map {
                    ipa,
                    size,
                    host: host as usize,
                    perms: permissions,
                });
                false
            }
        });
        if should_fail {
            return 0xfae9_4005u32 as applevisor_sys::hv_return_t;
        }
        return 0;
    }
    let result = unsafe { applevisor_sys::hv_vm_map(host, ipa, size, permissions) };
    if result == 0 {
        emit_global_frame_stage2(
            carrick_observability::probes::HvpatchGlobalFrameStage2Phase::Mapped,
            ipa,
            size,
            host as u64,
            permissions,
        );
    }
    result
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn emit_global_frame_stage2(
    phase: carrick_observability::probes::HvpatchGlobalFrameStage2Phase,
    ipa: u64,
    size: usize,
    host_addr: u64,
    permissions: u64,
) {
    let event = carrick_observability::probes::HvpatchGlobalFrameStage2::new(
        phase,
        ipa,
        size as u64,
        host_addr,
        permissions,
    )
    .unwrap_or_else(|error| {
        carrick_fatal!(
            "hvpatch::frame_inventory",
            "construct global-frame stage-2 receipt: {error}"
        );
    });
    crate::probes::hvpatch_global_frame_stage2(event);
}

/// Serialize lazy replay and make a sibling that lost the race observe the
/// exact already-installed extent as success without accepting arbitrary HVF
/// errors. The marker is cleared on unmap and every VM destruction.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) unsafe fn inventory_hv_vm_map_replay(
    backing: AliasBacking,
) -> applevisor_sys::hv_return_t {
    let key = replay_mapping_key(backing);
    mutate_external_alias_state(|registry| {
        if registry.contains_replay(&key) {
            return 0;
        }
        let result = unsafe {
            inventory_hv_vm_map(
                backing.physical_host_addr as *mut std::ffi::c_void,
                backing.physical_ipa,
                backing.physical_size,
                backing.perms,
            )
        };
        if result == 0 {
            let bucket = registry
                .by_scope
                .entry(backing.ownership_scope)
                .or_default();
            bucket.replay.insert(key);
        }
        result
    })
}

/// Sole raw Hypervisor.framework stage-2 unmap boundary.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) unsafe fn inventory_hv_vm_unmap(ipa: u64, size: usize) -> applevisor_sys::hv_return_t {
    #[cfg(test)]
    if STAGE2_AUDIT_STATE.with(|s| s.borrow().enabled) {
        let should_fail = STAGE2_AUDIT_STATE.with(|s| {
            let mut state = s.borrow_mut();
            if state.fail_next_unmap {
                state.fail_next_unmap = false;
                state
                    .events
                    .push(Stage2BackendEvent::UnmapAttemptFailed { ipa, size });
                true
            } else {
                false
            }
        });
        if should_fail {
            return 0xfae9_4001u32 as applevisor_sys::hv_return_t;
        }
        forget_replay_extent(ipa, size);
        STAGE2_AUDIT_STATE.with(|s| {
            let mut state = s.borrow_mut();
            state.mapped_extents.remove(&(ipa, size));
            state.events.push(Stage2BackendEvent::Unmap { ipa, size });
        });
        return 0;
    }
    let result = unsafe { applevisor_sys::hv_vm_unmap(ipa, size) };
    if result == 0 {
        forget_replay_extent(ipa, size);
        emit_global_frame_stage2(
            carrick_observability::probes::HvpatchGlobalFrameStage2Phase::Unmapped,
            ipa,
            size,
            0,
            0,
        );
    }
    result
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) unsafe fn inventory_hv_vm_destroy() -> applevisor_sys::hv_return_t {
    let result = unsafe { applevisor_sys::hv_vm_destroy() };
    if result == 0 {
        clear_replay_mappings();
    }
    result
}

#[cfg(test)]
#[test]
fn raw_hvf_stage2_calls_are_inventory_gated() {
    let source = concat!(
        include_str!("../trap.rs"),
        include_str!("stage2_backend.rs"),
        include_str!("cow_engine.rs")
    );
    assert_eq!(
        source
            .matches(concat!("applevisor_sys::hv_vm_", "map("))
            .count(),
        1,
        "raw hv_vm_map must appear only in inventory_hv_vm_map"
    );
    assert_eq!(
        source
            .matches(concat!("applevisor_sys::hv_vm_", "unmap("))
            .count(),
        1,
        "raw hv_vm_unmap must appear only in inventory_hv_vm_unmap"
    );
    assert_eq!(
        source
            .matches(concat!("inventory_hv_vm_map_replay", "(b)"))
            .count(),
        2,
        "both lazy replay paths must use exact serialized replay"
    );
}

#[cfg(test)]
#[test]
fn raw_vm_destroy_is_custody_transaction_gated() {
    let source = concat!(
        include_str!("../trap.rs"),
        include_str!("stage2_backend.rs"),
        include_str!("carrier_custody.rs")
    );
    assert_eq!(
        source
            .matches(concat!("applevisor_sys::hv_vm_", "destroy()"))
            .count(),
        1,
        "the inventory boundary must remain the sole raw hv_vm_destroy caller"
    );
    assert_eq!(
        source
            .matches(concat!("inventory_hv_vm_", "destroy()"))
            .count(),
        2,
        "inventory_hv_vm_destroy must appear only in its definition and the custody wrapper"
    );
}

#[cfg(test)]
#[test]
fn reclaim_park_authority_contains_no_task_snapshot() {
    let mut authority = ReclaimParkAuthority::Live;
    authority.mark_vcpu_parked().unwrap();
    assert_eq!(authority, ReclaimParkAuthority::VcpuParked);
    assert!(authority.destination_vcpu_is_live().is_err());
    authority.mark_live_after_recreate().unwrap();
    assert_eq!(authority, ReclaimParkAuthority::Live);
    assert!(authority.destination_vcpu_is_live().is_ok());
}

#[cfg(test)]
#[test]
fn carrier_exit_without_a_vm_is_a_recorded_no_op() {
    use carrick_observability::vm_lifecycle::{VmLifecycleOperation, process_snapshot};
    fn destroy_events() -> usize {
        process_snapshot()
            .events
            .iter()
            .filter(|event| {
                matches!(
                    event.operation,
                    VmLifecycleOperation::DestroyAttempt | VmLifecycleOperation::DestroySuccess
                )
            })
            .count()
    }
    // An unsigned test executable can never create a VM (HV_DENIED), so this
    // process has no live carrier VM: carrier exit must destroy nothing and
    // must NOT append DestroyAttempt/DestroySuccess to the lifecycle ledger.
    // Only destroy-class events are counted: a sibling test in this binary may
    // record a failed LogicalCreateAttempt concurrently.
    let before = destroy_events();
    assert!(!carrier_vm_live());
    destroy_persistent_vm_at_carrier_exit().expect("no VM: nothing to destroy");
    assert_eq!(
        destroy_events(),
        before,
        "carrier exit without a VM must not record destroy events"
    );
}

pub(crate) fn prepare_exec_region_raw_in(
    custody: &CarrierVmCustody,
    mapping: &GuestMapping,
) -> Result<HvfMappedRegion, TrapError> {
    let requested_size = usize::try_from(mapping.mapped_size)
        .map_err(|_| TrapError::MappingTooLarge(mapping.mapped_size))?;
    let backing_started = std::time::Instant::now();
    let (host, size, host_mapping) = map_exclusive_region(mapping, requested_size)?;
    let elapsed_ns = backing_started
        .elapsed()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64;
    crate::probes::hvpatch_exec_backing(carrick_observability::probes::HvpatchExecBacking::new(
        if mapping.private_file_backing.is_some() {
            carrick_observability::probes::HvpatchExecBackingPhase::PrivateFileMapped
        } else {
            carrick_observability::probes::HvpatchExecBackingPhase::Materialized
        },
        mapping.guest_start,
        mapping.ipa_start,
        mapping.mapped_size,
        elapsed_ns,
    ));
    let end =
        mapping
            .guest_start
            .checked_add(mapping.mapped_size)
            .ok_or(TrapError::MappingOverflow {
                guest_start: mapping.guest_start,
                mapped_size: mapping.mapped_size,
            })?;
    Ok(HvfMappedRegion {
        start: mapping.guest_start,
        ipa: mapping.ipa_start,
        physical_ipa: mapping.ipa_start,
        end,
        host_addr: host,
        size,
        physical_size: size,
        perms: hvf_perms(mapping.perms),
        memory: None,
        host_mapping: Some(host_mapping),
        structural_owner: None,
        stage2_lease: None,
        is_dynamic_alias: false,
        sharing: if mapping.shared {
            GuestMappingSharing::GlobalShared
        } else {
            GuestMappingSharing::Private
        },
        guest_writable: mapping.perms.write,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: global_frame_host_owner_generation_in(
            custody,
            mapping.ipa_start,
            size as u64,
        ),
    })
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn prepare_exec_region_raw(
    mapping: &GuestMapping,
) -> Result<HvfMappedRegion, TrapError> {
    prepare_exec_region_raw_in(legacy_test_carrier_vm_custody(), mapping)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn exec_stage2_install(
    mapping: &GuestMapping,
    region: &HvfMappedRegion,
) -> ExecStage2Install {
    ExecStage2Install {
        ipa: mapping.ipa_start,
        size: region.physical_size,
        host: region.host_addr,
        perms: u64::from(region.perms),
        replay_registered: false,
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn map_region_raw_in(
    custody: &std::sync::Arc<CarrierVmCustody>,
    mapping: &GuestMapping,
    emit_exec_backing_census: bool,
    retain_structural_owner: bool,
) -> Result<HvfMappedRegion, TrapError> {
    map_region_raw_in_using_epoch_allocator(
        custody,
        mapping,
        emit_exec_backing_census,
        retain_structural_owner,
        next_structural_epoch,
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn map_region_raw_in_using_epoch_allocator(
    custody: &std::sync::Arc<CarrierVmCustody>,
    mapping: &GuestMapping,
    emit_exec_backing_census: bool,
    retain_structural_owner: bool,
    allocate_epoch: impl FnOnce() -> Result<StructuralEpoch, TrapError>,
) -> Result<HvfMappedRegion, TrapError> {
    let size = usize::try_from(mapping.mapped_size)
        .map_err(|_| TrapError::MappingTooLarge(mapping.mapped_size))?;
    let end =
        mapping
            .guest_start
            .checked_add(mapping.mapped_size)
            .ok_or(TrapError::MappingOverflow {
                guest_start: mapping.guest_start,
                mapped_size: mapping.mapped_size,
            })?;
    let retain_structural_owner =
        retain_structural_owner && !is_persistent_executor_carrier_guest_mapping(mapping);
    // Mint every fallible structural identity before stage-2 publication. If
    // this fails, dropping the not-yet-mapped host backing is sufficient
    // rollback; no HVF mapping or custody record exists yet.
    let structural_epoch = retain_structural_owner.then(allocate_epoch).transpose()?;
    // MAP_SHARED, not MAP_PRIVATE: a MAP_PRIVATE anon page mapped into the
    // guest via hv_vm_map desyncs from the host buffer — the guest's own store
    // and a later guest load observe different memory (the "PROT_REA" wild-PC
    // crash: a dynamic binary's GOT slot that ld.so resolved reads back stale).
    // MAP_SHARED anon is HVF-coherent (same as `map_shared_file`). The cost:
    // fork(2) no longer COW-isolates these pages. HVPatch isolates them with
    // per-mm stage-1 COW; the legacy VMM fork path separately clones only its
    // page-table/control backing.
    // The aperture region is host-MAP_SHARED so it stays shared across fork(2)
    // (never snapshotted); all other regions are private guest RAM.
    let backing_started = std::time::Instant::now();
    let (host, size, host_mapping) = map_exclusive_region(mapping, size)?;
    if emit_exec_backing_census {
        let elapsed_ns = backing_started
            .elapsed()
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        crate::probes::hvpatch_exec_backing(
            carrick_observability::probes::HvpatchExecBacking::new(
                if mapping.private_file_backing.is_some() {
                    carrick_observability::probes::HvpatchExecBackingPhase::PrivateFileMapped
                } else {
                    carrick_observability::probes::HvpatchExecBackingPhase::Materialized
                },
                mapping.guest_start,
                mapping.ipa_start,
                mapping.mapped_size,
                elapsed_ns,
            ),
        );
    }
    let perms = hvf_perms(mapping.perms);
    let perms_raw: u64 = u64::from(perms);
    // Map at the IPA (identity for all but the Rosetta alias); the guest's
    // stage-1 page tables translate the VIRTUAL `guest_start` to this IPA.
    if emit_exec_backing_census {
        crate::probes::hvpatch_exec_stage2(carrick_observability::probes::HvpatchExecStage2::new(
            carrick_observability::probes::HvpatchExecStage2Phase::MapBegin,
            mapping.ipa_start,
            size as u64,
            mapping.guest_start,
            0,
        ));
    }
    let r = unsafe {
        inventory_hv_vm_map(
            host.cast::<std::ffi::c_void>(),
            mapping.ipa_start,
            size,
            perms_raw,
        )
    };
    if emit_exec_backing_census {
        crate::probes::hvpatch_exec_stage2(carrick_observability::probes::HvpatchExecStage2::new(
            carrick_observability::probes::HvpatchExecStage2Phase::MapEnd,
            mapping.ipa_start,
            size as u64,
            mapping.guest_start,
            r as i32,
        ));
    }
    if r != 0 {
        return Err(TrapError::Hypervisor(format!(
            "hv_vm_map(ipa=0x{:x}, va=0x{:x}, size={size}) failed: 0x{r:x}",
            mapping.ipa_start, mapping.guest_start
        )));
    }
    let sharing = if mapping.shared {
        GuestMappingSharing::GlobalShared
    } else {
        GuestMappingSharing::Private
    };
    let mut region = HvfMappedRegion {
        start: mapping.guest_start,
        ipa: mapping.ipa_start,
        physical_ipa: mapping.ipa_start,
        end,
        host_addr: host,
        size,
        physical_size: size,
        perms,
        memory: None,
        host_mapping: Some(host_mapping),
        structural_owner: None,
        stage2_lease: None,
        is_dynamic_alias: false,
        // Private guest RAM (data/bss/heap/stack/MAP_PRIVATE): HVPatch fork
        // shares the global frame read-only until the writer COWs it.
        sharing,
        // Boot regions carry their true guest write-intent (image=RX, page
        // tables=RO -> not writable; heap/stack/data=RW -> writable).
        guest_writable: mapping.perms.write,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: global_frame_host_owner_generation_in(
            custody,
            mapping.ipa_start,
            size as u64,
        ),
    };
    if retain_structural_owner {
        let host_mapping = region.host_mapping.take().ok_or_else(|| {
            TrapError::Hypervisor(format!(
                "initial fixed mapping at IPA 0x{:x} has no host owner",
                region.physical_ipa
            ))
        })?;
        let epoch = structural_epoch.ok_or_else(|| {
            TrapError::Hypervisor(format!(
                "initial fixed mapping at IPA 0x{:x} has no structural epoch",
                region.physical_ipa
            ))
        })?;
        let mut lease =
            GlobalFrameStage2Lease::fixed(region.physical_ipa, region.physical_size as u64);
        lease.mark_mapped();
        let owner = StructuralBackingOwner::new_in(
            custody,
            host_mapping,
            lease,
            u64::from(region.perms),
            epoch,
            region.physical_ipa,
            region.physical_size,
        )?;
        region.owner_generation = epoch.raw();
        region.structural_owner = Some(owner);
    }
    Ok(region)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn map_exclusive_region(
    mapping: &GuestMapping,
    size: usize,
) -> Result<(*mut u8, usize, crate::host_mapping::OwnedHostMapping), TrapError> {
    if let Some(backing) = &mapping.private_file_backing {
        let host_mapping = crate::host_mapping::OwnedHostMapping::map_private_file(
            backing.file.as_raw_fd(),
            0,
            size,
        )
        .map_err(|error| {
            TrapError::Hypervisor(format!(
                "mmap private executable artifact (size={size}) failed: {error}"
            ))
        })?;
        return Ok((host_mapping.as_ptr(), host_mapping.len(), host_mapping));
    }
    let kind = if mapping.shared {
        crate::host_mapping::HostMappingKind::SharedAnon
    } else {
        crate::host_mapping::HostMappingKind::PrivateAnon
    };
    let host_mapping =
        crate::host_mapping::OwnedHostMapping::map_shared_anon(size, kind).map_err(|error| {
            TrapError::Hypervisor(format!("mmap guest region (size={size}) failed: {error}"))
        })?;
    let host = host_mapping.as_ptr();
    let size = host_mapping.len();
    // Copy the payload prefix into the freshly-zeroed region; the rest stays
    // zero (lazy). offset_in_mapping + image.len() <= mapped_size is guaranteed
    // by GuestMappingPlan::from_address_space.
    if !mapping.image.is_empty() {
        let off = usize::try_from(mapping.offset_in_mapping)
            .map_err(|_| TrapError::MappingTooLarge(mapping.offset_in_mapping))?;
        unsafe {
            std::ptr::copy_nonoverlapping(
                mapping.image.as_ptr(),
                host.add(off),
                mapping.image.len(),
            );
        }
    }
    Ok((host, size, host_mapping))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvf_perms(perms: SegmentPerms) -> applevisor::memory::MemPerms {
    use applevisor::memory::MemPerms;

    // HVF stage-2 quirk on macOS 26 (Tahoe) / Apple Silicon: a stage-2
    // mapping created with `HV_MEMORY_READ | HV_MEMORY_WRITE` (no
    // `HV_MEMORY_EXEC`) fails to translate EL0 data accesses — the guest
    // takes a stage-2 translation fault (DFSC=0x05, "translation fault
    // level 1") even though the IPA falls inside the mapping and the
    // host-side `Memory::read`/`Memory::write` accessors succeed. The
    // ARM stage-2 attribute model has no per-EL data-access bit, so the
    // fault is HVF-specific behaviour rather than ARMv8 architectural.
    //
    // Empirically, escalating the stage-2 permission to
    // `ReadWriteExec` makes the fault go away. The guest still uses
    // stage-1 (`SCTLR_EL1.M=0` in the bootstrap), so the stage-2 X bit
    // is the only thing that controls instruction fetch from the
    // region; the guest is already executing without stage-1 enforcement
    // and the host process is single-tenant, so granting stage-2 X on
    // data/stack regions does not add a meaningful new attack surface.
    //
    // The escalation is gated on the original perms still being some
    // form of `Write` so we don't accidentally upgrade a `Read`-only or
    // `Exec`-only mapping: those translate fine as-is. This keeps the
    // workaround narrow.
    let escalated_perms = SegmentPerms {
        read: perms.read,
        write: perms.write,
        execute: perms.execute || perms.write,
    };

    match (
        escalated_perms.read,
        escalated_perms.write,
        escalated_perms.execute,
    ) {
        (false, false, false) => MemPerms::None,
        (true, false, false) => MemPerms::Read,
        (false, true, false) => MemPerms::Write,
        (false, false, true) => MemPerms::Exec,
        (true, true, false) => MemPerms::ReadWrite,
        (true, false, true) => MemPerms::ReadExec,
        (false, true, true) => MemPerms::WriteExec,
        (true, true, true) => MemPerms::ReadWriteExec,
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvf_error(error: applevisor::error::HypervisorError) -> TrapError {
    TrapError::Hypervisor(error.to_string())
}

/// Convert a neutral [`carrick_hal::MemPerms`] to the applevisor stage-2
/// `MemPerms` for [`HvfVmState::map_stage2`]. A DIRECT mapping (no RWX
/// escalation): that escalation is the `hvf_perms(SegmentPerms)` boot/alias path;
/// the engine's `map_stage2` callers pass the perms they want verbatim.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvf_mem_perms(perms: carrick_hal::MemPerms) -> applevisor::memory::MemPerms {
    use applevisor::memory::MemPerms;
    match (perms.read, perms.write, perms.exec) {
        (false, false, false) => MemPerms::None,
        (true, false, false) => MemPerms::Read,
        (false, true, false) => MemPerms::Write,
        (false, false, true) => MemPerms::Exec,
        (true, true, false) => MemPerms::ReadWrite,
        (true, false, true) => MemPerms::ReadExec,
        (false, true, true) => MemPerms::WriteExec,
        (true, true, true) => MemPerms::ReadWriteExec,
    }
}

/// The HVF concurrent-vCPU budget for the bounded M:N scheduler the engine
/// installs via `GuestVmBackend::vcpu_budget`: physical host cores, capped by
/// HVF's usable per-VM vCPU ceiling. Reclaim recycles vCPUs so >budget guest
/// threads run instead of hanging. macOS/HVF-only: `vcpu_gate` (and the whole HVF
/// backend) is cfg'd out off the HVF lane, and the only caller (the new module's
/// `GuestVmBackend::vcpu_budget`) is macOS-only too.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvf_vcpu_budget() -> usize {
    vcpu_gate::budget().max(1)
}

// NOTE: the thread-sibling register seeding (`seed_child_snapshot`) now lives
// ONCE in the shared engine (`carrick_aarch64::seed_sibling_snapshot`), which the
// engine's `build_sibling_spec` applies before `materialize_sibling`. HVF's
// `from_thread_spec` only stands up the vCPU + mirrors the mapping metadata; the
// engine restores the seeded snapshot onto it.

// ---------------------------------------------------------------------------
// carrick-hal trait impls: RegAccess + ThreadedEngine
//
// These are forwarding impls only.  Every method delegates to an existing
// HvfTrapEngine / HvfInner method verbatim.  No behaviour is changed.
//
// The HAL Reg/SysReg enums were designed for KVM's register naming; we map
// each variant to the equivalent applevisor register below.
//
// HypervisorError does not carry a POSIX errno.  We map any HVF error to
// EIO (5) — a generic I/O error the caller can distinguish from EINVAL/ENOSYS.
// ---------------------------------------------------------------------------

/// Convert an applevisor error to a HAL OsError, using EIO as the errno.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[inline]
pub(crate) fn hvf_os_error(_e: applevisor::error::HypervisorError) -> carrick_hal::OsError {
    carrick_hal::OsError::from_raw(libc::EIO)
}

/// Map a HAL [`carrick_hal::Reg`] to the corresponding applevisor value and
/// read it from `vcpu`.  On non-HVF targets returns ENOSYS (never called).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvf_get_reg(
    vcpu: &applevisor::vcpu::Vcpu,
    r: carrick_hal::Reg,
) -> Result<u64, carrick_hal::OsError> {
    // `applevisor::prelude::*` brings `Reg`/`SysReg`; we locally shadow the
    // HAL types only inside the `match r` arm patterns.
    use applevisor::prelude::*;
    let hal_r = r;
    match hal_r {
        carrick_hal::Reg::X(n) => match GPR_TABLE.get(n as usize) {
            Some(&reg) => vcpu.get_reg(reg).map_err(hvf_os_error),
            None => Err(carrick_hal::OsError::from_raw(libc::EINVAL)),
        },
        carrick_hal::Reg::Sp => vcpu.get_sys_reg(SysReg::SP_EL0).map_err(hvf_os_error),
        carrick_hal::Reg::Pc => vcpu.get_reg(Reg::PC).map_err(hvf_os_error),
        carrick_hal::Reg::Pstate => vcpu.get_reg(Reg::CPSR).map_err(hvf_os_error),
        carrick_hal::Reg::SpEl1 => vcpu.get_sys_reg(SysReg::SP_EL1).map_err(hvf_os_error),
        carrick_hal::Reg::ElrEl1 => vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_os_error),
        carrick_hal::Reg::SpsrEl1 => vcpu.get_sys_reg(SysReg::SPSR_EL1).map_err(hvf_os_error),
        _ => Err(carrick_hal::OsError::from_raw(libc::EINVAL)),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvf_set_reg(
    vcpu: &applevisor::vcpu::Vcpu,
    r: carrick_hal::Reg,
    v: u64,
) -> Result<(), carrick_hal::OsError> {
    use applevisor::prelude::*;
    let hal_r = r;
    match hal_r {
        carrick_hal::Reg::X(n) => match GPR_TABLE.get(n as usize) {
            Some(&reg) => vcpu.set_reg(reg, v).map_err(hvf_os_error),
            None => Err(carrick_hal::OsError::from_raw(libc::EINVAL)),
        },
        carrick_hal::Reg::Sp => vcpu.set_sys_reg(SysReg::SP_EL0, v).map_err(hvf_os_error),
        carrick_hal::Reg::Pc => vcpu.set_reg(Reg::PC, v).map_err(hvf_os_error),
        carrick_hal::Reg::Pstate => vcpu.set_reg(Reg::CPSR, v).map_err(hvf_os_error),
        carrick_hal::Reg::SpEl1 => vcpu.set_sys_reg(SysReg::SP_EL1, v).map_err(hvf_os_error),
        carrick_hal::Reg::ElrEl1 => vcpu.set_sys_reg(SysReg::ELR_EL1, v).map_err(hvf_os_error),
        carrick_hal::Reg::SpsrEl1 => vcpu.set_sys_reg(SysReg::SPSR_EL1, v).map_err(hvf_os_error),
        _ => Err(carrick_hal::OsError::from_raw(libc::EINVAL)),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvf_get_sys_reg(
    vcpu: &applevisor::vcpu::Vcpu,
    r: carrick_hal::SysReg,
) -> Result<u64, carrick_hal::OsError> {
    use applevisor::prelude::*;
    let hvf_reg = match r {
        carrick_hal::SysReg::Sctlr => SysReg::SCTLR_EL1,
        carrick_hal::SysReg::Ttbr0 => SysReg::TTBR0_EL1,
        carrick_hal::SysReg::Ttbr1 => SysReg::TTBR1_EL1,
        carrick_hal::SysReg::Tcr => SysReg::TCR_EL1,
        carrick_hal::SysReg::Mair => SysReg::MAIR_EL1,
        carrick_hal::SysReg::Vbar => SysReg::VBAR_EL1,
        carrick_hal::SysReg::Cpacr => SysReg::CPACR_EL1,
        carrick_hal::SysReg::TpidrEl0 => SysReg::TPIDR_EL0,
        // x86_64 FsBase/GsBase are a disjoint ISA view; never on the macOS/HVF lane.
        _ => return Err(carrick_hal::OsError::from_raw(libc::EINVAL)),
    };
    vcpu.get_sys_reg(hvf_reg).map_err(hvf_os_error)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvf_set_sys_reg(
    vcpu: &applevisor::vcpu::Vcpu,
    r: carrick_hal::SysReg,
    v: u64,
) -> Result<(), carrick_hal::OsError> {
    use applevisor::prelude::*;
    let hvf_reg = match r {
        carrick_hal::SysReg::Sctlr => SysReg::SCTLR_EL1,
        carrick_hal::SysReg::Ttbr0 => SysReg::TTBR0_EL1,
        carrick_hal::SysReg::Ttbr1 => SysReg::TTBR1_EL1,
        carrick_hal::SysReg::Tcr => SysReg::TCR_EL1,
        carrick_hal::SysReg::Mair => SysReg::MAIR_EL1,
        carrick_hal::SysReg::Vbar => SysReg::VBAR_EL1,
        carrick_hal::SysReg::Cpacr => SysReg::CPACR_EL1,
        carrick_hal::SysReg::TpidrEl0 => SysReg::TPIDR_EL0,
        // x86_64 FsBase/GsBase are a disjoint ISA view; never on the macOS/HVF lane.
        _ => return Err(carrick_hal::OsError::from_raw(libc::EINVAL)),
    };
    vcpu.set_sys_reg(hvf_reg, v).map_err(hvf_os_error)
}
