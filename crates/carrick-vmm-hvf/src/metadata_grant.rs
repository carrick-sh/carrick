//! Host engine for servicing in-guest EL1 metadata extent grant (`HVC #6`) requests.

use crate::host_mapping::{HostMappingKind, OwnedHostMapping};
use carrick_core_abi::NativeRootExit;
use carrick_el1_abi::{
    EL1_DYNAMIC_METADATA_BASE, EL1_DYNAMIC_METADATA_EXTENT_SIZE, EL1_DYNAMIC_METADATA_SIZE,
    ForkStockExchange, ForkStockKind, ForkStockRefusal, ForkStockSettlement, GRANT_OP_FORK_STOCK,
    GRANT_OP_ROOT_EXIT, METADATA_GRANT_ERR_ALIGNMENT, METADATA_GRANT_ERR_DENIED,
    METADATA_GRANT_ERR_INVALID, METADATA_GRANT_ERR_NOT_FOUND, METADATA_GRANT_OP_ALLOC,
    METADATA_GRANT_OP_FREE, METADATA_GRANT_SUCCESS,
};
use carrick_el1_abi::{
    MetadataExtent, MetadataExtentResolver, MetadataResolutionError, PinnedMetadataExtent,
};
use carrick_hal::TrapError;
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Raw view of the retained kernel ABI mapping. It carries no shared byte
/// slice: a wire reply mutates its stopped CPU's stack while other CPUs may
/// use disjoint atomic ABI records in the same mapping.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug)]
pub(crate) struct RetainedAbiRegion<'a> {
    base: core::ptr::NonNull<u8>,
    _retained: core::marker::PhantomData<&'a core::cell::UnsafeCell<u8>>,
}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl<'a> RetainedAbiRegion<'a> {
    /// # Safety
    /// The caller retains an initialized EL1 mapping of `len` bytes through
    /// `'a`. Only the synchronously stopped CPU may access its wire stack;
    /// shared fixed records use their ABI atomics and ownership protocol.
    pub(crate) unsafe fn new(base: *mut u8, len: usize) -> Option<Self> {
        let base = core::ptr::NonNull::new(base)?;
        if len != carrick_el1_abi::EL1_REGION_SIZE as usize {
            return None;
        }
        Some(Self {
            base,
            _retained: core::marker::PhantomData,
        })
    }
    fn record_ptr<T>(self, offset: usize) -> Option<*mut T> {
        if offset.checked_add(core::mem::size_of::<T>())?
            > carrick_el1_abi::EL1_REGION_SIZE as usize
        {
            return None;
        }
        // SAFETY: checked offset remains inside the retained mapping.
        let pointer = unsafe { self.base.as_ptr().add(offset) };
        pointer
            .addr()
            .is_multiple_of(core::mem::align_of::<T>())
            .then_some(pointer.cast())
    }
}

/// Runtime-owned handback venue for an already enrolled parent wait.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub trait NativeWaitChannelWake: std::fmt::Debug + Send + Sync {
    fn wake(&self, mm: carrick_el1_abi::EntryMmKey, address: core::num::NonZeroU64) -> Option<u32>;
}

/// Authenticate the exact released task, independently of its former record.
/// The CPU is synchronously stopped; a new slot entry invalidates this custody.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn terminal_child_execution(
    custody: &crate::trap::CarrierVmCustody,
    cpu: carrick_guest_arch::CpuId,
    phase: carrick_sched_core::TerminalPhase,
) -> Option<crate::fork_stock::GrantExecution> {
    let slot = carrick_guest_arch::SlotId::from_index(cpu.raw() as usize)?;
    let region = retained_abi_region(custody)?;
    let (task, zone) = stopped_records(region, cpu)?;
    let binding = carrick_core::entry::binding(&task.execution, &task.mm);
    let source = carrick_el1_abi::BornInZoneSource { zone, slot };
    if !carrick_core::entry::terminal_matches(binding, source, phase) {
        return None;
    }
    let stock = custody.fork_stock.lock();
    let mm = carrick_el1_abi::ReservationMm::new(binding.mm.raw())?;
    if stock.owner.is_quarantined(mm) != (phase == carrick_sched_core::TerminalPhase::Retired) {
        return None;
    }
    let context = carrick_guest_arch::AddressContext {
        root: stock.owner.child_root(mm)?,
        mm: carrick_guest_arch::MmGeneration::new(core::num::NonZeroU64::new(mm.raw())?),
        generation: task.root_generation()?,
    };
    Some(crate::fork_stock::GrantExecution::new(
        cpu, binding, context,
    ))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn service_terminal_operation(
    custody: &crate::trap::CarrierVmCustody,
    generation: Option<crate::trap::CarrierVmGeneration>,
    cpu: carrick_guest_arch::CpuId,
    op: u64,
    args: [u64; 3],
    ttbr0: u64,
) -> [u64; 4] {
    use carrick_el1_abi::{GRANT_OP_CHILD_RETIRE, METADATA_GRANT_ERR_DENIED, NativeChildRetire};
    let retired = op != GRANT_OP_CHILD_RETIRE;
    let expected_cpu = if retired { args[2] } else { args[1] };
    if !request_has_live_vm(custody, generation) || expected_cpu != u64::from(cpu.raw()) {
        return [METADATA_GRANT_ERR_DENIED, 0, 0, 0];
    }
    let Some(execution) = terminal_child_execution(
        custody,
        cpu,
        if retired {
            carrick_sched_core::TerminalPhase::Retired
        } else {
            carrick_sched_core::TerminalPhase::PendingRetirement
        },
    ) else {
        return [METADATA_GRANT_ERR_DENIED, 0, 0, 0];
    };
    if retired {
        let Some(zone) = carrick_el1_abi::zone_tables() else {
            return [METADATA_GRANT_ERR_DENIED, 0, 0, 0];
        };
        let idle = zone.spaces.idle_ttbr();
        if idle == 0
            || (ttbr0 & carrick_sched_core::AARCH64_ROOT_ADDRESS_MASK)
                != (idle & carrick_sched_core::AARCH64_ROOT_ADDRESS_MASK)
        {
            return [METADATA_GRANT_ERR_DENIED, 0, 0, 0];
        }
        let Some(address) = core::num::NonZeroU64::new(args[1]) else {
            return [METADATA_GRANT_ERR_DENIED, 0, 0, 0];
        };
        let wake = custody.native_wait_channel_wake.lock().clone();
        return match wake
            .and_then(|wake| wake.wake(carrick_el1_abi::EntryMmKey::from_raw(args[0]), address))
        {
            Some(count) => [METADATA_GRANT_SUCCESS, u64::from(count), 0, 0],
            None => [METADATA_GRANT_ERR_DENIED, 0, 0, 0],
        };
    }
    if execution.context.root.address().raw()
        != ttbr0 & carrick_sched_core::AARCH64_ROOT_ADDRESS_MASK
    {
        return [METADATA_GRANT_ERR_DENIED, 0, 0, 0];
    }
    let Some(pointer) = retained_abi_region(custody).and_then(|region| {
        abi_stack_ptr::<NativeChildRetire>(region, cpu, carrick_guest_arch::KernelVa::new(args[0]))
    }) else {
        return [METADATA_GRANT_ERR_INVALID, 0, 0, 0];
    };
    // SAFETY: the synchronous crossing retains the caller's aligned wire record.
    let retire = unsafe { &mut *pointer };
    if custody
        .fork_stock
        .lock()
        .owner
        .retire_child(execution, retire)
        .is_err()
    {
        return [METADATA_GRANT_ERR_DENIED, 0, 0, 0];
    }
    let Some(zone) = carrick_el1_abi::zone_tables() else {
        return [METADATA_GRANT_ERR_DENIED, 0, 0, 0];
    };
    let Some(slot) = carrick_guest_arch::SlotId::from_index(cpu.raw() as usize) else {
        return [METADATA_GRANT_ERR_DENIED, 0, 0, 0];
    };
    let identity = carrick_sched_core::ThreadIdentity {
        tid: execution.binding.task.raw(),
        generation: execution.binding.generation.raw(),
        mm: execution.binding.mm.raw(),
        serial: execution.binding.thread_generation.raw(),
        ..Default::default()
    };
    if !zone.accept_terminal(slot, identity) {
        return [METADATA_GRANT_ERR_DENIED, 0, 0, 0];
    }
    [METADATA_GRANT_SUCCESS, 0, 0, 0]
}

pub const MAX_DYNAMIC_EXTENT_SLOTS: usize = 128;

#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::default::Default,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub struct MetadataGrantStats {
    pub grants_requested: u64,
    pub grants_succeeded: u64,
    pub grants_denied: u64,
    pub returns_completed: u64,
    pub bytes_granted: u64,
    pub bytes_returned: u64,
    pub inline_hvc_traps: u64,
}

/// Storage published read/write to EL1 without copying it.
///
/// # Safety
/// The range must remain allocated and at a stable address until this owner
/// drops. It must contain only shared ABI data, permit concurrent atomic
/// access, and be aligned and sized to the host's 16 KiB mapping granule.
/// The host VM object must also remain stable while published (for example,
/// MAP_SHARED backing); host COW must not replace the object mapped by HVF.
pub unsafe trait RetainedMetadataBacking: std::fmt::Debug + Send + Sync {
    fn host_base(&self) -> carrick_guest_mem::HostVa;
    fn mapped_len(&self) -> usize;
}

#[derive(::core::fmt::Debug)]
enum MetadataBacking {
    Allocated(OwnedHostMapping),
    Retained(Arc<dyn RetainedMetadataBacking>),
}
// SAFETY: this wrapper shares only ownership and raw addresses, never Rust
// references to the bytes. All access requires the metadata consumer's locks;
// the final Arc drops the mapping after every pin has released ownership.
unsafe impl Send for MetadataBacking {}
unsafe impl Sync for MetadataBacking {}
impl MetadataBacking {
    fn as_ptr(&self) -> *mut u8 {
        match self {
            Self::Allocated(mapping) => mapping.as_ptr(),
            Self::Retained(owner) => owner.host_base().0 as *mut u8,
        }
    }
    fn len(&self) -> usize {
        match self {
            Self::Allocated(mapping) => mapping.len(),
            Self::Retained(owner) => owner.mapped_len(),
        }
    }
}

#[derive(::core::fmt::Debug)]
struct GrantedSlotRecord {
    backing: Arc<MetadataBacking>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    identity: crate::trap::CarrierStage2RecordIdentity,
    num_slots: usize,
    token: u64,
    generation: u64,
}

// SAFETY: each variant owns stable, synchronized storage for its entire lifetime.
unsafe impl RetainedMetadataBacking for MetadataBacking {
    fn host_base(&self) -> carrick_guest_mem::HostVa {
        carrick_guest_mem::HostVa(self.as_ptr() as usize)
    }
    fn mapped_len(&self) -> usize {
        self.len()
    }
}

/// A pin retains the exact mapping even after VM teardown removes its grant
/// record. Ordinary grant return is refused before stage-2 unmap while pinned.
pub struct HostMetadataExtentPin {
    extent: MetadataExtent,
    base: core::ptr::NonNull<u8>,
    _backing: Arc<MetadataBacking>,
}

// SAFETY: the Arc owns the mapped bytes. Normal return checks outstanding pins;
// VM destruction can remove stage-2 mappings but cannot destroy this host owner.
unsafe impl PinnedMetadataExtent for HostMetadataExtentPin {
    fn extent(&self) -> MetadataExtent {
        self.extent
    }
    fn host_base(&self) -> core::ptr::NonNull<u8> {
        self.base
    }
}

/// Bound to the custody object and exact live generation that issued grants.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub struct HostMetadataExtentResolver<'a> {
    pub(crate) custody: &'a crate::trap::CarrierVmCustody,
    pub(crate) generation: crate::trap::CarrierVmGeneration,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl MetadataExtentResolver for HostMetadataExtentResolver<'_> {
    type Pin = HostMetadataExtentPin;
    fn pin(&self, extent: MetadataExtent) -> Result<Self::Pin, MetadataResolutionError> {
        if !request_has_live_vm(self.custody, Some(self.generation)) {
            return Err(MetadataResolutionError::StaleOwner);
        }
        metadata_aperture(self.custody)
            .lock()
            .pin_extent(extent, self.generation.0)
    }
}

/// Exact carrier control mapping and dynamic-extent resolver lifetime.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(::core::clone::Clone)]
pub struct CarrierMetadataAccess {
    carrier: Arc<crate::trap::PersistentCarrierMappings>,
    generation: crate::trap::CarrierVmGeneration,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl CarrierMetadataAccess {
    pub(crate) fn new(carrier: Arc<crate::trap::PersistentCarrierMappings>) -> Option<Self> {
        let generation = carrier.custody.live_generation()?;
        let access = Self {
            carrier,
            generation,
        };
        access.region().ok()?;
        Some(access)
    }

    /// Map the existing ABI storage into the carrier's EL1-only metadata
    /// aperture. Stage-1 already covers this aperture; stage-2 publication and
    /// its inventory entry commit together before the extent is returned.
    pub fn map_retained(
        &self,
        backing: Arc<dyn RetainedMetadataBacking>,
    ) -> Result<RetainedMetadataMapping, MetadataResolutionError> {
        let extent = metadata_aperture(&self.carrier.custody)
            .lock()
            .install_retained_using(
                &self.carrier.custody,
                self.generation,
                backing,
                |spec| unsafe {
                    crate::trap::inventory_hv_vm_map(
                        spec.host_addr as *mut std::ffi::c_void,
                        spec.ipa,
                        spec.len,
                        spec.perms,
                    )
                },
            )?;
        Ok(RetainedMetadataMapping {
            access: self.clone(),
            extent,
        })
    }

    pub fn install_completion_wake(
        &self,
        wake: Arc<dyn carrick_el1_abi::MetadataCompletionWake>,
    ) -> Result<(), MetadataResolutionError> {
        self.region()?;
        *self.carrier.custody.metadata_completion.lock() = Some(wake);
        Ok(())
    }

    pub fn install_native_wait_channel_wake(
        &self,
        wake: Arc<dyn NativeWaitChannelWake>,
    ) -> Result<(), MetadataResolutionError> {
        self.region()?;
        *self.carrier.custody.native_wait_channel_wake.lock() = Some(wake);
        Ok(())
    }

    /// The returned address is borrowed from this retained carrier mapping.
    pub fn region(&self) -> Result<core::ptr::NonNull<u8>, MetadataResolutionError> {
        if self.carrier.custody.live_generation() != Some(self.generation) {
            return Err(MetadataResolutionError::StaleOwner);
        }
        self.carrier
            .host_pointer(
                carrick_el1_abi::EL1_REGION_BASE,
                carrick_el1_abi::EL1_REGION_SIZE as usize,
            )
            .ok_or(MetadataResolutionError::StaleOwner)
    }
}

/// Authority to retire one retained mapping in its exact carrier. Dropping
/// this handle cannot release live backing: custody keeps it through VM
/// destruction. Consumers pin the extent while any EL1 reference can reach it.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub struct RetainedMetadataMapping {
    access: CarrierMetadataAccess,
    extent: MetadataExtent,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl RetainedMetadataMapping {
    pub fn pin(&self) -> Result<HostMetadataExtentPin, MetadataResolutionError> {
        self.access.pin(self.extent)
    }

    /// Pins exclude retirement; failed unmaps keep the mapping and its backing
    /// available for another retirement attempt.
    pub fn try_retire(self) -> Result<(), Self> {
        let status =
            if request_has_live_vm(&self.access.carrier.custody, Some(self.access.generation)) {
                metadata_aperture(&self.access.carrier.custody)
                    .lock()
                    .retire_retained_using(self.extent, self.access.generation.0, |record| {
                        retire_metadata_record_using(
                            &self.access.carrier.custody,
                            record.identity,
                            |ipa, len| {
                                let rc = unsafe { crate::trap::inventory_hv_vm_unmap(ipa, len) };
                                if rc == 0 {
                                    Ok(())
                                } else {
                                    Err(crate::trap::CarrierStage2BackendError::HvReturn(rc as u32))
                                }
                            },
                        )
                    })
            } else {
                METADATA_GRANT_ERR_DENIED
            };
        if status == METADATA_GRANT_SUCCESS {
            Ok(())
        } else {
            Err(self)
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl MetadataExtentResolver for CarrierMetadataAccess {
    type Pin = HostMetadataExtentPin;
    fn pin(&self, extent: MetadataExtent) -> Result<Self::Pin, MetadataResolutionError> {
        HostMetadataExtentResolver {
            custody: &self.carrier.custody,
            generation: self.generation,
        }
        .pin(extent)
    }
}

// Backing ownership moves only under its carrier aperture lock; access is synchronized by
// the guest allocator and the record is retained until stage-2 unmap succeeds.
unsafe impl Send for GrantedSlotRecord {}

#[derive(::core::fmt::Debug)]
pub(crate) struct HostApertureState {
    occupied_bitmap: [u64; 2],
    slots: [Option<GrantedSlotRecord>; MAX_DYNAMIC_EXTENT_SLOTS],
}

impl HostApertureState {
    pub(crate) const fn new() -> Self {
        Self {
            occupied_bitmap: [0; 2],
            slots: [const { None }; MAX_DYNAMIC_EXTENT_SLOTS],
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn install_retained_using(
        &mut self,
        custody: &crate::trap::CarrierVmCustody,
        generation: crate::trap::CarrierVmGeneration,
        backing: Arc<dyn RetainedMetadataBacking>,
        map: impl FnOnce(crate::trap::CarrierStage2RecordSpec) -> i32,
    ) -> Result<MetadataExtent, MetadataResolutionError> {
        let len = backing.mapped_len();
        let host = backing.host_base().0;
        if len == 0
            || len > EL1_DYNAMIC_METADATA_SIZE as usize
            || !len.is_multiple_of(16384)
            || host == 0
            || !host.is_multiple_of(16384)
            || host.checked_add(len).is_none()
        {
            return Err(MetadataResolutionError::InvalidExtent);
        }
        if !request_has_live_vm(custody, Some(generation)) {
            return Err(MetadataResolutionError::StaleOwner);
        }
        let token = reserve_metadata_token(&NEXT_TOKEN).ok_or(MetadataResolutionError::Busy)?;
        let count = len.div_ceil(EL1_DYNAMIC_METADATA_EXTENT_SIZE);
        let slot = self
            .find_and_reserve_slots(count)
            .ok_or(MetadataResolutionError::Busy)?;
        let ipa = EL1_DYNAMIC_METADATA_BASE + (slot * EL1_DYNAMIC_METADATA_EXTENT_SIZE) as u64;
        let spec = crate::trap::CarrierStage2RecordSpec {
            vm_generation: generation,
            ipa,
            len,
            host_addr: host,
            mapped: true,
            backend_map_installed: true,
            release_ipa: false,
            perms: 3,
            logical_owner: Some(crate::trap::CarrierLogicalOwner {
                id: token,
                generation: token,
            }),
        };
        let identity = match publish_metadata_mapping_using(custody, spec, || map(spec)) {
            Ok(identity) => identity,
            Err(_) => {
                self.unreserve_slots(slot, count);
                return Err(MetadataResolutionError::Busy);
            }
        };
        self.slots[slot] = Some(GrantedSlotRecord {
            backing: Arc::new(MetadataBacking::Retained(backing)),
            identity,
            num_slots: count,
            token,
            generation: generation.0,
        });
        MetadataExtent::new(ipa, len as u64, token).ok_or(MetadataResolutionError::InvalidExtent)
    }

    fn pin_extent(
        &self,
        extent: MetadataExtent,
        generation: u64,
    ) -> Result<HostMetadataExtentPin, MetadataResolutionError> {
        let offset = extent
            .base()
            .checked_sub(EL1_DYNAMIC_METADATA_BASE)
            .filter(|offset| offset.is_multiple_of(EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64))
            .ok_or(MetadataResolutionError::InvalidExtent)?;
        let slot = usize::try_from(offset / EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64)
            .map_err(|_| MetadataResolutionError::InvalidExtent)?;
        let record = self
            .slots
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(MetadataResolutionError::StaleOwner)?;
        if record.generation != generation || record.token != extent.token() {
            return Err(MetadataResolutionError::StaleOwner);
        }
        if record.backing.len() as u64 != extent.len() {
            return Err(MetadataResolutionError::InvalidExtent);
        }
        Ok(HostMetadataExtentPin {
            extent,
            base: core::ptr::NonNull::new(record.backing.as_ptr())
                .ok_or(MetadataResolutionError::InvalidExtent)?,
            _backing: Arc::clone(&record.backing),
        })
    }

    fn return_extent_using(
        &mut self,
        slot: usize,
        size: usize,
        token: u64,
        generation: u64,
        unmap: impl FnOnce(&GrantedSlotRecord) -> bool,
    ) -> u64 {
        if self
            .slots
            .get(slot)
            .and_then(Option::as_ref)
            .is_some_and(|record| matches!(record.backing.as_ref(), MetadataBacking::Retained(_)))
        {
            return METADATA_GRANT_ERR_DENIED;
        }
        self.retire_extent_using(slot, size, token, generation, unmap)
    }

    fn retire_retained_using(
        &mut self,
        extent: MetadataExtent,
        generation: u64,
        unmap: impl FnOnce(&GrantedSlotRecord) -> bool,
    ) -> u64 {
        let Some(offset) = extent.base().checked_sub(EL1_DYNAMIC_METADATA_BASE) else {
            return METADATA_GRANT_ERR_INVALID;
        };
        if !offset.is_multiple_of(EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64) {
            return METADATA_GRANT_ERR_INVALID;
        }
        let Ok(slot) = usize::try_from(offset / EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64) else {
            return METADATA_GRANT_ERR_INVALID;
        };
        if !self
            .slots
            .get(slot)
            .and_then(Option::as_ref)
            .is_some_and(|record| matches!(record.backing.as_ref(), MetadataBacking::Retained(_)))
        {
            return METADATA_GRANT_ERR_NOT_FOUND;
        }
        let Ok(size) = usize::try_from(extent.len()) else {
            return METADATA_GRANT_ERR_INVALID;
        };
        self.retire_extent_using(slot, size, extent.token(), generation, unmap)
    }

    fn retire_extent_using(
        &mut self,
        slot: usize,
        size: usize,
        token: u64,
        generation: u64,
        unmap: impl FnOnce(&GrantedSlotRecord) -> bool,
    ) -> u64 {
        let Some(record) = self.slots.get(slot).and_then(Option::as_ref) else {
            return METADATA_GRANT_ERR_NOT_FOUND;
        };
        if record.backing.len() != size || record.token != token || record.generation != generation
        {
            return METADATA_GRANT_ERR_INVALID;
        }
        if Arc::strong_count(&record.backing) != 1 {
            return METADATA_GRANT_ERR_DENIED;
        }
        if !unmap(record) {
            return METADATA_GRANT_ERR_DENIED;
        }
        let count = record.num_slots;
        self.slots[slot] = None;
        self.unreserve_slots(slot, count);
        METADATA_GRANT_SUCCESS
    }

    /// Called only after the exact VM generation has been destroyed by HVF.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn release_destroyed_vm(
        &mut self,
        generation: u64,
        mut retire: impl FnMut(crate::trap::CarrierStage2RecordIdentity),
    ) {
        for i in 0..self.slots.len() {
            if let Some(record) = &self.slots[i]
                && record.generation == generation
            {
                let count = record.num_slots;
                retire(record.identity);
                self.slots[i] = None;
                self.unreserve_slots(i, count);
            }
        }
    }

    fn is_slot_occupied(&self, slot: usize) -> bool {
        if slot < 64 {
            (self.occupied_bitmap[0] & (1u64 << slot)) != 0
        } else if slot < 128 {
            (self.occupied_bitmap[1] & (1u64 << (slot - 64))) != 0
        } else {
            true
        }
    }

    /// Atomically find and reserve `num_slots` contiguous unoccupied slots.
    fn find_and_reserve_slots(&mut self, num_slots: usize) -> Option<usize> {
        if num_slots == 0 || num_slots > MAX_DYNAMIC_EXTENT_SLOTS {
            return None;
        }
        let max_start = MAX_DYNAMIC_EXTENT_SLOTS - num_slots;
        for start in 0..=max_start {
            let mut all_free = true;
            for s in start..start + num_slots {
                if self.is_slot_occupied(s) {
                    all_free = false;
                    break;
                }
            }
            if all_free {
                self.reserve_slots(start, num_slots);
                return Some(start);
            }
        }
        None
    }

    fn reserve_slots(&mut self, start: usize, num_slots: usize) {
        for s in start..start + num_slots {
            if s < 64 {
                self.occupied_bitmap[0] |= 1u64 << s;
            } else if s < 128 {
                self.occupied_bitmap[1] |= 1u64 << (s - 64);
            }
        }
    }

    fn unreserve_slots(&mut self, start: usize, num_slots: usize) {
        for s in start..start + num_slots {
            if s < 64 {
                self.occupied_bitmap[0] &= !(1u64 << s);
            } else if s < 128 {
                self.occupied_bitmap[1] &= !(1u64 << (s - 64));
            }
        }
    }
}

static GRANTS_REQUESTED: AtomicU64 = AtomicU64::new(0);
static GRANTS_SUCCEEDED: AtomicU64 = AtomicU64::new(0);
static GRANTS_DENIED: AtomicU64 = AtomicU64::new(0);
static RETURNS_COMPLETED: AtomicU64 = AtomicU64::new(0);
static BYTES_GRANTED: AtomicU64 = AtomicU64::new(0);
static BYTES_RETURNED: AtomicU64 = AtomicU64::new(0);
static INLINE_HVC_TRAPS: AtomicU64 = AtomicU64::new(0);

static FAILPOINT_DENY_NEXT: AtomicBool = AtomicBool::new(false);
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

fn reserve_metadata_token(counter: &AtomicU64) -> Option<u64> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |token| {
            if token == 0 || token == u64::MAX {
                None
            } else {
                Some(token + 1)
            }
        })
        .ok()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn metadata_aperture(custody: &crate::trap::CarrierVmCustody) -> &Mutex<HostApertureState> {
    &custody.metadata_aperture
}

fn allocate_metadata_backing(size: usize) -> Result<OwnedHostMapping, std::io::Error> {
    OwnedHostMapping::map_shared_anon(size, HostMappingKind::SharedAnon)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn publish_metadata_mapping_using(
    custody: &crate::trap::CarrierVmCustody,
    spec: crate::trap::CarrierStage2RecordSpec,
    map: impl FnOnce() -> i32,
) -> Result<crate::trap::CarrierStage2RecordIdentity, TrapError> {
    custody.publish_stage2_record_using(spec, map)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn retire_metadata_record_using(
    custody: &crate::trap::CarrierVmCustody,
    identity: crate::trap::CarrierStage2RecordIdentity,
    unmap: impl FnOnce(u64, usize) -> Result<(), crate::trap::CarrierStage2BackendError>,
) -> bool {
    use crate::trap::CarrierStage2RetireOutcome;
    match custody.retire_stage2_record_using(identity, unmap) {
        CarrierStage2RetireOutcome::RetiredUnmapped
        | CarrierStage2RetireOutcome::TerminalizedByVmDestroy => {
            custody.remove_terminal_stage2_record(identity).is_some()
        }
        _ => false,
    }
}

/// Return a snapshot of metadata grant counters.
pub fn metadata_grant_stats() -> MetadataGrantStats {
    MetadataGrantStats {
        grants_requested: GRANTS_REQUESTED.load(Ordering::Relaxed),
        grants_succeeded: GRANTS_SUCCEEDED.load(Ordering::Relaxed),
        grants_denied: GRANTS_DENIED.load(Ordering::Relaxed),
        returns_completed: RETURNS_COMPLETED.load(Ordering::Relaxed),
        bytes_granted: BYTES_GRANTED.load(Ordering::Relaxed),
        bytes_returned: BYTES_RETURNED.load(Ordering::Relaxed),
        inline_hvc_traps: INLINE_HVC_TRAPS.load(Ordering::Relaxed),
    }
}

/// Arm failpoint to deny the next metadata extent allocation request.
pub fn arm_deny_next_metadata_grant() {
    FAILPOINT_DENY_NEXT.store(true, Ordering::SeqCst);
}

/// Reset diagnostic counters and failpoints. Live backing belongs to its carrier
/// and is never unmapped by a process-wide diagnostic reset.
pub fn reset_metadata_grant_state() {
    GRANTS_REQUESTED.store(0, Ordering::Relaxed);
    GRANTS_SUCCEEDED.store(0, Ordering::Relaxed);
    GRANTS_DENIED.store(0, Ordering::Relaxed);
    RETURNS_COMPLETED.store(0, Ordering::Relaxed);
    BYTES_GRANTED.store(0, Ordering::Relaxed);
    BYTES_RETURNED.store(0, Ordering::Relaxed);
    INLINE_HVC_TRAPS.store(0, Ordering::Relaxed);
    FAILPOINT_DENY_NEXT.store(false, Ordering::SeqCst);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn request_has_live_vm(
    custody: &crate::trap::CarrierVmCustody,
    generation: Option<crate::trap::CarrierVmGeneration>,
) -> bool {
    generation.is_some() && custody.live_generation() == generation
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn service_metadata_operation(
    custody: &crate::trap::CarrierVmCustody,
    generation: Option<crate::trap::CarrierVmGeneration>,
    cpu: carrick_guest_arch::CpuId,
    active_execution: Option<(crate::fork_stock::GrantExecution, &NativeRootExit)>,
    op: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> Result<[u64; 4], TrapError> {
    let generation = generation
        .filter(|_| request_has_live_vm(custody, generation))
        .ok_or_else(|| TrapError::Hypervisor("metadata request from a stale VM generation".into()))?
        .0;
    let aperture = metadata_aperture(custody);

    if op == METADATA_GRANT_OP_ALLOC {
        GRANTS_REQUESTED.fetch_add(1, Ordering::Relaxed);

        // 1. Check test failpoint denial
        if FAILPOINT_DENY_NEXT.swap(false, Ordering::SeqCst) {
            GRANTS_DENIED.fetch_add(1, Ordering::Relaxed);
            return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
        }

        let Ok(requested_size) = usize::try_from(arg1) else {
            return Ok([METADATA_GRANT_ERR_INVALID, 0, 0, 0]);
        };
        if requested_size == 0 || requested_size > EL1_DYNAMIC_METADATA_SIZE as usize {
            return Ok([METADATA_GRANT_ERR_INVALID, 0, 0, 0]);
        }
        let extent_quantum = EL1_DYNAMIC_METADATA_EXTENT_SIZE;
        let num_slots = requested_size.div_ceil(extent_quantum);
        let Some(extent_size) = num_slots.checked_mul(extent_quantum) else {
            return Ok([METADATA_GRANT_ERR_INVALID, 0, 0, 0]);
        };

        // 2. Find and atomically reserve contiguous aperture slots
        let slot_idx = {
            let mut state = aperture.lock();
            state.find_and_reserve_slots(num_slots)
        };

        let Some(slot_idx) = slot_idx else {
            GRANTS_DENIED.fetch_add(1, Ordering::Relaxed);
            return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
        };

        let Some(ipa) = (slot_idx as u64)
            .checked_mul(EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64)
            .and_then(|offset| EL1_DYNAMIC_METADATA_BASE.checked_add(offset))
        else {
            {
                let mut state = aperture.lock();
                state.unreserve_slots(slot_idx, num_slots);
            }
            GRANTS_DENIED.fetch_add(1, Ordering::Relaxed);
            return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
        };
        let Some(extent_end) = ipa.checked_add(extent_size as u64) else {
            aperture.lock().unreserve_slots(slot_idx, num_slots);
            return Ok([METADATA_GRANT_ERR_INVALID, 0, 0, 0]);
        };
        if extent_end > EL1_DYNAMIC_METADATA_BASE + EL1_DYNAMIC_METADATA_SIZE {
            aperture.lock().unreserve_slots(slot_idx, num_slots);
            GRANTS_DENIED.fetch_add(1, Ordering::Relaxed);
            return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
        }

        // 3. Use host-page-aligned MAP_SHARED backing so HVF and the host
        // always observe the same VM object; guest privacy is stage-1 owned.
        let backing = match allocate_metadata_backing(extent_size) {
            Ok(backing) => backing,
            Err(_) => {
                aperture.lock().unreserve_slots(slot_idx, num_slots);
                GRANTS_DENIED.fetch_add(1, Ordering::Relaxed);
                return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
            }
        };

        // 4. Map into stage-2 with Read/Write permissions (strictly non-executable)
        let permissions = 0b011; // HV_MEMORY_READ | HV_MEMORY_WRITE
        let Some(token) = reserve_metadata_token(&NEXT_TOKEN) else {
            aperture.lock().unreserve_slots(slot_idx, num_slots);
            GRANTS_DENIED.fetch_add(1, Ordering::Relaxed);
            return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
        };
        let spec = crate::trap::CarrierStage2RecordSpec {
            vm_generation: crate::trap::CarrierVmGeneration(generation),
            ipa,
            len: extent_size,
            host_addr: backing.as_ptr() as usize,
            mapped: true,
            backend_map_installed: true,
            release_ipa: false,
            perms: permissions,
            logical_owner: Some(crate::trap::CarrierLogicalOwner {
                id: token,
                generation: token,
            }),
        };
        let mut state = aperture.lock();
        let publication = publish_metadata_mapping_using(custody, spec, || unsafe {
            crate::trap::inventory_hv_vm_map(backing.as_ptr().cast(), ipa, extent_size, permissions)
        });
        let identity = match publication {
            Ok(identity) => identity,
            Err(_) => {
                state.unreserve_slots(slot_idx, num_slots);
                GRANTS_DENIED.fetch_add(1, Ordering::Relaxed);
                return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
            }
        };
        state.slots[slot_idx] = Some(GrantedSlotRecord {
            backing: Arc::new(MetadataBacking::Allocated(backing)),
            identity,
            num_slots,
            token,
            generation,
        });
        drop(state);

        GRANTS_SUCCEEDED.fetch_add(1, Ordering::Relaxed);
        BYTES_GRANTED.fetch_add(extent_size as u64, Ordering::Relaxed);
        Ok([METADATA_GRANT_SUCCESS, ipa, extent_size as u64, token])
    } else if op == METADATA_GRANT_OP_FREE {
        let ipa = arg1;
        let Ok(size) = usize::try_from(arg2) else {
            return Ok([METADATA_GRANT_ERR_INVALID, 0, 0, 0]);
        };
        let token = arg3;

        // Validate IPA bounds, alignment, and non-zero token
        if !(EL1_DYNAMIC_METADATA_BASE..EL1_DYNAMIC_METADATA_BASE + EL1_DYNAMIC_METADATA_SIZE)
            .contains(&ipa)
            || !ipa.is_multiple_of(EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64)
            || token == 0
        {
            return Ok([METADATA_GRANT_ERR_ALIGNMENT, 0, 0, 0]);
        }

        let slot_idx = ((ipa - EL1_DYNAMIC_METADATA_BASE)
            / (EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64)) as usize;
        if slot_idx >= MAX_DYNAMIC_EXTENT_SLOTS {
            return Ok([METADATA_GRANT_ERR_INVALID, 0, 0, 0]);
        }

        let status =
            aperture
                .lock()
                .return_extent_using(slot_idx, size, token, generation, |record| {
                    retire_metadata_record_using(custody, record.identity, |ipa, size| {
                        let rc = unsafe { crate::trap::inventory_hv_vm_unmap(ipa, size) };
                        if rc == 0 {
                            Ok(())
                        } else {
                            Err(crate::trap::CarrierStage2BackendError::HvReturn(rc as u32))
                        }
                    })
                });
        if status == METADATA_GRANT_SUCCESS {
            RETURNS_COMPLETED.fetch_add(1, Ordering::Relaxed);
            BYTES_RETURNED.fetch_add(size as u64, Ordering::Relaxed);
        }
        Ok([status, 0, 0, 0])
    } else if op == GRANT_OP_ROOT_EXIT {
        let record_va = carrick_guest_arch::KernelVa::new(arg1);
        if !record_va.raw().is_multiple_of(64) {
            return Ok([METADATA_GRANT_ERR_ALIGNMENT, 0, 0, 0]);
        }
        // Foreign or out-of-range guest-supplied CPU index is refused immediately.
        if arg2 != 0 && arg2 != cpu.raw() as u64 {
            return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
        }
        let Some((execution, root_exit)) =
            active_execution.filter(|(execution, _)| execution.cpu == cpu)
        else {
            return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
        };
        let mut fork_stock = custody.fork_stock.lock();
        match fork_stock.service_root_exit(execution, root_exit) {
            Ok(status) => Ok([METADATA_GRANT_SUCCESS, status.raw() as u64, 0, 0]),
            Err(_) => Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]),
        }
    } else {
        Ok([METADATA_GRANT_ERR_INVALID, 0, 0, 0])
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn report_stock_refusal(
    exchange: &ForkStockExchange,
    execution: Option<crate::fork_stock::GrantExecution>,
    reason: &str,
) {
    let request = exchange.request();
    carrick_observability::probes::el1_native_fork_stock_refusal(
        reason,
        &format!("{:?}", request.map(|r| r.binding)),
        &format!("{:?}", execution.map(|e| e.binding)),
        &format!("{:?}", request.map(|r| r.context)),
        &format!("{:?}", execution.map(|e| e.context)),
    );
}

#[cfg(all(
    feature = "metadata-grant-test-support",
    target_os = "macos",
    target_arch = "aarch64"
))]
mod delayed_owner {
    use super::*;
    use std::sync::{atomic::AtomicBool, mpsc};

    #[derive(::core::fmt::Debug)]
    pub enum Observation {
        OwnerClaimed,
        Contended { parked: u32 },
    }
    struct Gate {
        minimum_bytes: u64,
        active: AtomicBool,
        events: mpsc::Sender<Observation>,
        release: Mutex<mpsc::Receiver<()>>,
        owner: Mutex<Option<std::thread::JoinHandle<()>>>,
    }
    static GATE: Mutex<Option<Arc<Gate>>> = Mutex::new(None);

    pub struct Probe {
        pub events: mpsc::Receiver<Observation>,
        release: mpsc::Sender<()>,
    }
    impl Drop for Probe {
        fn drop(&mut self) {
            let _ = self.release.send(());
            let gate = GATE.lock().take();
            if let Some(gate) = gate
                && let Some(owner) = gate.owner.lock().take()
            {
                let _ = owner.join();
            }
        }
    }
    pub fn arm(minimum_bytes: u64) -> Probe {
        let (events, receiver) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let gate = Arc::new(Gate {
            minimum_bytes,
            active: AtomicBool::new(false),
            events,
            release: Mutex::new(released),
            owner: Mutex::new(None),
        });
        *GATE.lock() = Some(gate);
        Probe {
            events: receiver,
            release,
        }
    }
    pub(super) fn defer(
        request: carrick_el1_abi::MetadataGrantRequest,
        mailbox: &carrick_el1_abi::MetadataGrantMailbox,
        custody: &crate::trap::CarrierVmCustody,
        generation: Option<crate::trap::CarrierVmGeneration>,
    ) -> bool {
        let gate = GATE.lock().clone();
        let Some(gate) = gate.filter(|gate| {
            request.op == METADATA_GRANT_OP_ALLOC
                && request.arg1 >= gate.minimum_bytes
                && !gate.active.swap(true, Ordering::AcqRel)
        }) else {
            return false;
        };
        let access = match crate::trap::persistent_carrier_cell().lock().as_ref() {
            Some(crate::trap::PersistentCarrierCellEntry::Published(spec)) => {
                spec.reservation_metadata_access()
            }
            _ => None,
        };
        let Some(access) = access.filter(|access| {
            core::ptr::eq(access.carrier.custody.as_ref(), custody)
                && Some(access.generation) == generation
        }) else {
            gate.active.store(false, Ordering::Release);
            return false;
        };
        let request_generation = mailbox.request_generation();
        let _ = gate.events.send(Observation::OwnerClaimed);
        loser(mailbox);
        // Test-only custody: defer completion without holding an executor or
        // trap/engine ownership while the remaining records enroll.
        let owner_gate = Arc::clone(&gate);
        let owner = std::thread::spawn(move || {
            let _ = owner_gate
                .release
                .lock()
                .recv_timeout(std::time::Duration::from_secs(20));
            if let Ok(region) = access.region() {
                // SAFETY: exact live-generation access retains the whole ABI
                // mapping until completion; the mailbox contains only atomics.
                let mailbox = unsafe {
                    &*region
                        .as_ptr()
                        .add(carrick_el1_abi::EL1_METADATA_MAILBOX_OFFSET as usize)
                        .cast::<carrick_el1_abi::MetadataGrantMailbox>()
                };
                let _ = complete_metadata_request(
                    &access.carrier.custody,
                    Some(access.generation),
                    mailbox,
                    request_generation,
                    request,
                );
            }
        });
        *gate.owner.lock() = Some(owner);
        true
    }
    pub(super) fn loser(mailbox: &carrick_el1_abi::MetadataGrantMailbox) {
        let gate = GATE.lock().clone();
        if let Some(gate) = gate
            && gate.active.load(Ordering::Acquire)
            && mailbox.state.load(Ordering::Acquire)
                == carrick_el1_abi::METADATA_MAILBOX_HOST_WORKING
        {
            let parked = carrick_el1_abi::zone_tables()
                .and_then(|zone| {
                    zone.object_queue_census(carrick_el1_abi::METADATA_WAIT_QUEUE_INDEX)
                })
                .map_or(0, |census| census.waiters);
            let _ = gate.events.send(Observation::Contended { parked });
        }
    }
}
#[cfg(all(
    feature = "metadata-grant-test-support",
    target_os = "macos",
    target_arch = "aarch64"
))]
pub use delayed_owner::{
    Observation as MetadataDelayObservation, Probe as MetadataDelayProbe,
    arm as arm_delayed_metadata_request,
};

/// Service one shared request after EL1 has unwound to its ordinary
/// pending-host-work boundary. Returns whether this boundary claimed work.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn service_pending_metadata_request(
    custody: &crate::trap::CarrierVmCustody,
    generation: Option<crate::trap::CarrierVmGeneration>,
) -> Result<bool, TrapError> {
    let Some(mailbox) = carrick_el1_abi::metadata_mailbox_host() else {
        return Ok(false);
    };
    let Some(request) = mailbox.claim_request() else {
        #[cfg(feature = "metadata-grant-test-support")]
        delayed_owner::loser(mailbox);
        return Ok(false);
    };
    #[cfg(feature = "metadata-grant-test-support")]
    if delayed_owner::defer(request, mailbox, custody, generation) {
        return Ok(false);
    }
    complete_metadata_request(
        custody,
        generation,
        mailbox,
        mailbox.request_generation(),
        request,
    )?;
    Ok(true)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn complete_metadata_request(
    custody: &crate::trap::CarrierVmCustody,
    generation: Option<crate::trap::CarrierVmGeneration>,
    mailbox: &carrick_el1_abi::MetadataGrantMailbox,
    request_generation: u64,
    request: carrick_el1_abi::MetadataGrantRequest,
) -> Result<(), TrapError> {
    let result = service_metadata_operation(
        custody,
        generation,
        carrick_guest_arch::CpuId::new(0),
        None,
        request.op,
        request.arg1,
        request.arg2,
        request.arg3,
    );
    // Failure still completes the incarnation and releases every enrolled record.
    let response = result
        .as_ref()
        .copied()
        .unwrap_or([METADATA_GRANT_ERR_INVALID, 0, 0, 0]);
    let wake = custody.metadata_completion.lock().clone();
    if let Some(wake) = wake {
        wake.publish_and_wake(mailbox, request_generation, response);
    } else {
        mailbox.publish_response(response[0], response[1], response[2], response[3]);
    }
    result?;
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn fork_custody_in_retained_region(offset: usize, bytes: usize) -> bool {
    // The EL1 allocator starts in retained bootstrap metadata, then uses the
    // adjacent heap. A fork before heap expansion may select either range.
    offset >= carrick_el1_abi::EL1_BOOTSTRAP_METADATA_OFFSET as usize
        && offset
            .checked_add(bytes)
            .is_some_and(|end| end <= carrick_el1_abi::EL1_REGION_SIZE as usize)
}

/// Native stock crossings retain an ABI stack, not a physical inventory row.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn service_native_fork_stock(
    custody: &Arc<crate::trap::CarrierVmCustody>,
    generation: Option<crate::trap::CarrierVmGeneration>,
    cpu: carrick_guest_arch::CpuId,
    address: carrick_guest_arch::KernelVa,
    requested_cpu: u64,
    ttbr0: u64,
    region: RetainedAbiRegion<'_>,
) -> Result<[u64; 4], TrapError> {
    use crate::fork_stock::ForkStockHostCustody;
    if !request_has_live_vm(custody, generation) {
        return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
    }
    let Some(tag) = abi_stack_ptr::<u64>(region, cpu, address) else {
        return Ok([METADATA_GRANT_ERR_INVALID, 0, 0, 0]);
    };
    // SAFETY: complete aligned tag on this stopped CPU's retained stack.
    let kind = ForkStockKind::decode(unsafe { *tag });
    let execution = (requested_cpu == u64::from(cpu.raw()))
        .then(|| stopped_execution(region, cpu, ttbr0))
        .flatten();
    let reply = match kind {
        Some(ForkStockKind::Loan) => {
            let Some(pointer) = abi_stack_ptr::<ForkStockExchange>(region, cpu, address) else {
                return Ok([METADATA_GRANT_ERR_INVALID, 0, 0, 0]);
            };
            // SAFETY: the synchronous crossing exclusively retains this complete wire record.
            let exchange = unsafe { &mut *pointer };
            let Some(execution) = execution else {
                report_stock_refusal(exchange, None, "NoLiveExecution");
                exchange.refuse(ForkStockRefusal::Stale);
                return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
            };
            let mut stock = custody.fork_stock.lock();
            let mut ledger = custody.el1_frame_grants.lock();
            if stock.owner.has_quarantine() {
                let Some(inventory) = stock.inventory() else {
                    exchange.refuse(ForkStockRefusal::Inventory);
                    return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
                };
                let Some((_, zone)) = stopped_records(region, cpu) else {
                    exchange.refuse(ForkStockRefusal::Stale);
                    return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
                };
                let Some(pointer) = region.record_ptr::<carrick_el1_abi::FrameGrantResidencyTable>(
                    carrick_el1_abi::EL1_FRAME_GRANT_RESIDENCY_OFFSET as usize,
                ) else {
                    return Ok([METADATA_GRANT_ERR_INVALID, 0, 0, 0]);
                };
                // SAFETY: initialized fixed atomic ABI record in the retained region.
                let residency = unsafe { &*pointer };
                let Some(active) = carrick_el1_abi::ReservationMm::new(execution.binding.mm.raw())
                else {
                    return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
                };
                let reclaimed = stock.owner.reclaim(
                    &mut *ledger,
                    active,
                    |mm| {
                        // The neutral guest MM owner retires the reservation root
                        // before freeing its space entry. An absent slot alone is
                        // insufficient to reuse still-published table storage.
                        if zone.spaces.find(mm.raw()).is_some() {
                            return None;
                        }
                        carrick_hal::fork_stock::SlotAbsence::scan(
                            mm,
                            (0..carrick_sched_core::ZONE_SLOTS)
                                .filter_map(carrick_guest_arch::SlotId::from_index)
                                .map(|slot| zone.installed_space(slot)),
                        )
                    },
                    |pages| ForkStockHostCustody::clear_tables(custody, pages),
                    |life| lifecycle_window(custody, life).is_some_and(|window| window.clear(life)),
                    |absence| {
                        carrick_hal::fork_stock::release_child_mm(
                            &*inventory,
                            residency,
                            absence.mm(),
                        )
                    },
                );
                if reclaimed.is_err() {
                    exchange.refuse(ForkStockRefusal::Inventory);
                    return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
                }
            }
            if stock.ensure_control_capacity(custody).is_err() {
                exchange.refuse(ForkStockRefusal::Capacity);
                return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
            }
            let result = stock.owner.loan(&mut *ledger, execution, exchange, |life| {
                lifecycle_window(custody, life).is_some_and(|window| window.is_zero(life))
            });
            if let Err(refusal) = result {
                report_stock_refusal(exchange, Some(execution), &format!("{refusal:?}"));
            }
            result.is_ok()
        }
        Some(ForkStockKind::Commit | ForkStockKind::Abort) => {
            let Some(pointer) = abi_stack_ptr::<ForkStockSettlement>(region, cpu, address) else {
                return Ok([METADATA_GRANT_ERR_INVALID, 0, 0, 0]);
            };
            // SAFETY: the same full stack-record custody as the loan.
            let settlement = unsafe { &mut *pointer };
            let Some(execution) = execution else {
                settlement.refuse(ForkStockRefusal::Stale);
                return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
            };
            let mut stock = custody.fork_stock.lock();
            let mut ledger = custody.el1_frame_grants.lock();
            let physical = if kind == Some(ForkStockKind::Commit) {
                use carrick_aarch64::fork::ForkCustody;
                let loan = stock.owner.settlement_loan(execution);
                let Some((request, address, count)) = loan.ok().and_then(|loan| {
                    settlement
                        .request(loan)
                        .map(|(_, address, count)| (loan.request, address, count))
                }) else {
                    settlement.refuse(ForkStockRefusal::Invalid);
                    return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
                };
                let Some(count) = usize::try_from(count).ok() else {
                    settlement.refuse(ForkStockRefusal::Inventory);
                    return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
                };
                let Some(bytes) = count.checked_mul(32) else {
                    settlement.refuse(ForkStockRefusal::Inventory);
                    return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
                };
                let Some(offset) = address
                    .raw()
                    .checked_sub(carrick_el1_abi::EL1_REGION_BASE)
                    .and_then(|offset| usize::try_from(offset).ok())
                else {
                    settlement.refuse(ForkStockRefusal::Inventory);
                    return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
                };
                if !fork_custody_in_retained_region(offset, bytes) {
                    settlement.refuse(ForkStockRefusal::Inventory);
                    return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
                }
                let authority = custody
                    .guest_cow_state(execution.binding.mm.raw())
                    .ok()
                    .flatten()
                    .and_then(|state| state.cow_runtime.read().clone())
                    .map(|runtime| runtime.authority);
                let source = Arc::new(move |handle, generation| {
                    authority
                        .as_ref()
                        .is_some_and(|authority| authority.retains_host_backing(handle, generation))
                });
                let owner = crate::trap::ForkPhysicalCustody::new(Arc::clone(custody), source);
                let mut retained = Vec::new();
                if retained.try_reserve_exact(count).is_err() {
                    settlement.refuse(ForkStockRefusal::Capacity);
                    return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
                }
                for index in 0..count {
                    let Some(row_offset) = index
                        .checked_mul(32)
                        .and_then(|index| offset.checked_add(index))
                    else {
                        settlement.refuse(ForkStockRefusal::Inventory);
                        return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
                    };
                    let Some(pointer) = region.record_ptr::<[u64; 4]>(row_offset) else {
                        settlement.refuse(ForkStockRefusal::Inventory);
                        return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
                    };
                    // SAFETY: this complete row lies in the stopped CPU's retained
                    // EL1 allocation, checked above against the region bounds.
                    let words = unsafe { *pointer };
                    let Some(selected) = carrick_el1_abi::PortalForkCustody::decode(words) else {
                        settlement.refuse(ForkStockRefusal::Inventory);
                        return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
                    };
                    match owner.retain(request, selected) {
                        Ok(Some(pin)) => retained.push(pin),
                        _ => {
                            settlement.refuse(ForkStockRefusal::Inventory);
                            return Ok([METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
                        }
                    }
                }
                retained
            } else {
                Vec::new()
            };
            match stock.owner.settle(
                &mut *ledger,
                execution,
                carrick_hal::fork_stock::ForkStockSettlementReceipt {
                    record: settlement,
                    physical,
                },
                |pages| {
                    pages.iter().all(|page| {
                        ForkStockHostCustody::physical_ptr::<[u8; 4096]>(custody, page.address())
                            .is_ok()
                    })
                },
                |pages| ForkStockHostCustody::tables_clean(custody, pages),
                |life| lifecycle_window(custody, life).is_some_and(|window| window.clear(life)),
            ) {
                Ok(()) => true,
                Err(error) => {
                    settlement.refuse(
                        if error == carrick_hal::fork_stock::ForkStockServiceError::StaleExecution {
                            ForkStockRefusal::Stale
                        } else {
                            ForkStockRefusal::Invalid
                        },
                    );
                    false
                }
            }
        }
        None => return Ok([METADATA_GRANT_ERR_INVALID, 0, 0, 0]),
    };
    Ok([
        if reply {
            METADATA_GRANT_SUCCESS
        } else {
            METADATA_GRANT_ERR_DENIED
        },
        0,
        0,
        0,
    ])
}

/// Dynamic metadata is explicitly identity-mapped by this module's extent
/// owner. Validate that venue before projecting its KernelVa into that mapping.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn lifecycle_window(
    custody: &crate::trap::CarrierVmCustody,
    life: carrick_el1_abi::ForkLifecycleLoan,
) -> Option<carrick_hal::fork_stock::LifecycleWindow> {
    if carrick_el1_abi::ForkLifecycleLoan::new(life.page, life.controls)? != life {
        return None;
    }
    let identity = custody.stage2_record_covering(
        life.page.raw(),
        core::mem::size_of::<carrick_el1_abi::ThreadLifecyclePage>(),
    )?;
    let state = custody.state.lock();
    let record = state.stage2_records.get(&identity.record_id)?;
    if record.snapshot.ipa < EL1_DYNAMIC_METADATA_BASE
        || record
            .snapshot
            .ipa
            .checked_add(record.snapshot.len as u64)?
            > EL1_DYNAMIC_METADATA_BASE + EL1_DYNAMIC_METADATA_SIZE
    {
        return None;
    }
    let host = core::ptr::NonNull::new(record.snapshot.host_addr as *mut u8)?;
    // SAFETY: retained metadata aperture backing owns the identity-mapped range.
    Some(unsafe {
        carrick_hal::fork_stock::LifecycleWindow::new(
            host,
            record.snapshot.ipa,
            record.snapshot.len as u64,
        )
    })
}

/// Physical process crossings use HVC #6. Metadata allocation uses its mailbox.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn service_native_cow_supply(
    custody: &Arc<crate::trap::CarrierVmCustody>,
    region: Option<RetainedAbiRegion<'_>>,
    cpu: carrick_guest_arch::CpuId,
    ttbr0: u64,
    address: u64,
    claimed_cpu: u64,
) -> Result<[u64; 4], TrapError> {
    let denied = [METADATA_GRANT_ERR_DENIED, 0, 0, 0];
    let Some(region) = region else {
        return Ok(denied);
    };
    if claimed_cpu != u64::from(cpu.raw()) {
        return Ok(denied);
    }
    let Some(execution) = stopped_execution(region, cpu, ttbr0) else {
        return Ok(denied);
    };
    let Some(pointer) = region.record_ptr::<carrick_el1_abi::MmPortalSlots>(
        carrick_el1_abi::EL1_MM_PORTAL_OFFSET as usize,
    ) else {
        return Ok(denied);
    };
    // SAFETY: the retained ABI mapping owns this atomic portal record while
    // the stopped CPU owns its slot's selection.
    let slots = unsafe { &*pointer };
    let Some(slot) = slots.grant(cpu.raw() as usize) else {
        return Ok(denied);
    };
    let mm = execution.binding.mm.raw();
    let Some((_, window)) = slot.pending_cow_fault_selection(mm, address) else {
        return Ok(denied);
    };
    if slots.carrier() != Some(window.operation.carrier)
        || window.operation.carrier != custody.transfer_carrier
        || window.fault_page != address & !4095
    {
        return Ok(denied);
    }
    let Some(pool) = carrick_el1_abi::cow_grant_pool_host() else {
        return Ok(denied);
    };
    let Ok(Some(state)) = custody.guest_cow_state(mm) else {
        return Ok(denied);
    };
    let supplied = pool.ready(mm).next().is_some()
        || crate::trap::refill_guest_cow_pool(&state, custody, pool, address, |candidate| {
            candidate == mm && slots.carrier() == Some(window.operation.carrier)
        })?
        || pool.ready(mm).next().is_some();
    if !supplied || !slot.take_cow_fault_selection(window) {
        return Ok(denied);
    }
    Ok([METADATA_GRANT_SUCCESS, 0, 0, 0])
}

/// Physical process crossings use HVC #6. Metadata allocation uses its mailbox.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn handle_metadata_grant_trap(
    vcpu: &mut applevisor::vcpu::Vcpu,
    cpu: carrick_guest_arch::CpuId,
    custody: &Arc<crate::trap::CarrierVmCustody>,
    generation: Option<crate::trap::CarrierVmGeneration>,
) -> Result<MetadataTrapOutcome, TrapError> {
    use applevisor::vcpu::Reg;
    INLINE_HVC_TRAPS.fetch_add(1, Ordering::Relaxed);
    let op = vcpu
        .get_reg(Reg::X0)
        .map_err(|e| TrapError::Hypervisor(format!("failed to read X0 for metadata grant: {e}")))?;
    let arg1 = vcpu
        .get_reg(Reg::X1)
        .map_err(|e| TrapError::Hypervisor(format!("failed to read X1 for metadata grant: {e}")))?;
    let arg2 = vcpu
        .get_reg(Reg::X2)
        .map_err(|e| TrapError::Hypervisor(format!("failed to read X2 for metadata grant: {e}")))?;
    let arg3 = vcpu
        .get_reg(Reg::X3)
        .map_err(|e| TrapError::Hypervisor(format!("failed to read X3 for metadata grant: {e}")))?;
    let region = retained_abi_region(custody);
    let execution = if op == GRANT_OP_ROOT_EXIT {
        let ttbr0 = vcpu
            .get_sys_reg(applevisor::vcpu::SysReg::TTBR0_EL1)
            .map_err(|error| TrapError::Hypervisor(format!("read terminal root: {error}")))?;
        region.and_then(|region| {
            stopped_execution(region, cpu, ttbr0).zip(root_stack_record(
                region,
                cpu,
                carrick_guest_arch::KernelVa::new(arg1),
            ))
        })
    } else {
        None
    };
    let result = if op == GRANT_OP_FORK_STOCK {
        if let Some(region) = region {
            let ttbr0 = vcpu
                .get_sys_reg(applevisor::vcpu::SysReg::TTBR0_EL1)
                .map_err(|error| TrapError::Hypervisor(format!("read fork root: {error}")))?;
            service_native_fork_stock(
                custody,
                generation,
                cpu,
                carrick_guest_arch::KernelVa::new(arg1),
                arg2,
                ttbr0,
                region,
            )?
        } else {
            [METADATA_GRANT_ERR_INVALID, 0, 0, 0]
        }
    } else if op == carrick_el1_abi::GRANT_OP_COW_SUPPLY {
        let ttbr0 = vcpu
            .get_sys_reg(applevisor::vcpu::SysReg::TTBR0_EL1)
            .map_err(|e| TrapError::Hypervisor(format!("read COW supply root: {e}")))?;
        service_native_cow_supply(custody, region, cpu, ttbr0, arg1, arg2)?
    } else if op == carrick_el1_abi::GRANT_OP_FORK_REFUSAL {
        service_fork_refusal(
            custody,
            generation,
            cpu,
            carrick_guest_arch::KernelVa::new(arg1),
            vcpu.get_sys_reg(applevisor::vcpu::SysReg::TTBR0_EL1)
                .map_err(|e| TrapError::Hypervisor(format!("read diagnostic root: {e}")))?,
        )
    } else if matches!(
        op,
        carrick_el1_abi::GRANT_OP_CHILD_RETIRE | carrick_el1_abi::GRANT_OP_WAIT_CHANNEL_WAKE
    ) {
        let ttbr0 = vcpu
            .get_sys_reg(applevisor::vcpu::SysReg::TTBR0_EL1)
            .map_err(|e| TrapError::Hypervisor(format!("read terminal child root: {e}")))?;
        service_terminal_operation(custody, generation, cpu, op, [arg1, arg2, arg3], ttbr0)
    } else {
        service_metadata_operation(custody, generation, cpu, execution, op, arg1, arg2, arg3)?
    };
    vcpu.set_reg(Reg::X0, result[0])
        .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
    vcpu.set_reg(Reg::X1, result[1])
        .map_err(|e| TrapError::Hypervisor(format!("set X1: {e}")))?;
    vcpu.set_reg(Reg::X2, result[2])
        .map_err(|e| TrapError::Hypervisor(format!("set X2: {e}")))?;
    vcpu.set_reg(Reg::X3, result[3])
        .map_err(|e| TrapError::Hypervisor(format!("set X3: {e}")))?;
    classify_metadata_trap(op, result)
}

/// Observe an authenticated stopped execution without granting or editing it.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn service_fork_refusal(
    custody: &crate::trap::CarrierVmCustody,
    generation: Option<crate::trap::CarrierVmGeneration>,
    cpu: carrick_guest_arch::CpuId,
    address: carrick_guest_arch::KernelVa,
    ttbr0: u64,
) -> [u64; 4] {
    let Some(region) = retained_abi_region(custody) else {
        return [METADATA_GRANT_ERR_DENIED, 0, 0, 0];
    };
    service_fork_refusal_using_region(custody, generation, cpu, address, ttbr0, region)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn service_fork_refusal_using_region(
    custody: &crate::trap::CarrierVmCustody,
    generation: Option<crate::trap::CarrierVmGeneration>,
    cpu: carrick_guest_arch::CpuId,
    address: carrick_guest_arch::KernelVa,
    ttbr0: u64,
    region: RetainedAbiRegion<'_>,
) -> [u64; 4] {
    let refused = [METADATA_GRANT_ERR_DENIED, 0, 0, 0];
    if !request_has_live_vm(custody, generation) {
        return refused;
    }
    let Some((task, zone)) = stopped_records(region, cpu) else {
        return refused;
    };
    let Some((binding, root)) = diagnostic_identity(cpu, task, zone, ttbr0) else {
        return refused;
    };
    let Some(record) =
        abi_stack_record::<carrick_el1_abi::NativeForkDiagnostic>(region, cpu, address)
    else {
        return refused;
    };
    let Some(message) = record.message() else {
        return refused;
    };
    carrick_observability::probes::el1_native_fork_refusal(
        cpu.raw(),
        binding.mm.raw(),
        root.address().raw(),
        message,
    );
    [METADATA_GRANT_SUCCESS, 0, 0, 0]
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(::core::fmt::Debug, ::core::cmp::PartialEq, ::core::cmp::Eq)]
pub(crate) enum MetadataTrapOutcome {
    Resume,
    RootExit(carrick_sched_core::process::TerminationStatus),
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn classify_metadata_trap(op: u64, reply: [u64; 4]) -> Result<MetadataTrapOutcome, TrapError> {
    if op != GRANT_OP_ROOT_EXIT {
        return Ok(MetadataTrapOutcome::Resume);
    }
    if reply[0] != METADATA_GRANT_SUCCESS {
        return Err(TrapError::Hypervisor(format!(
            "native root-exit crossing refused: {}",
            reply[0]
        )));
    }
    let status = i32::try_from(reply[1])
        .map_err(|_| TrapError::Hypervisor("invalid root-exit status".into()))?;
    Ok(MetadataTrapOutcome::RootExit(
        carrick_personality_linux::lifecycle::LinuxWaitStatus::from_wait_encoding(status)
            .to_termination_status(),
    ))
}

/// Read only a complete aligned terminal record on the stopped CPU's ABI stack.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn root_stack_record<'a>(
    region: RetainedAbiRegion<'a>,
    cpu: carrick_guest_arch::CpuId,
    address: carrick_guest_arch::KernelVa,
) -> Option<&'a NativeRootExit> {
    let pointer = abi_stack_ptr::<NativeRootExit>(region, cpu, address)?;
    // SAFETY: complete aligned immutable record on a retained stopped stack.
    Some(unsafe { &*pointer })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn abi_stack_record<'a, T>(
    region: RetainedAbiRegion<'a>,
    cpu: carrick_guest_arch::CpuId,
    address: carrick_guest_arch::KernelVa,
) -> Option<&'a T> {
    let pointer = abi_stack_ptr::<T>(region, cpu, address)?;
    // SAFETY: complete aligned immutable record retained on the stopped CPU stack.
    Some(unsafe { &*pointer })
}

/// Resolve only this CPU's complete aligned kernel-stack record. The address
/// type cannot be passed to the physical table-frame resolver.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn abi_stack_ptr<T>(
    region: RetainedAbiRegion<'_>,
    cpu: carrick_guest_arch::CpuId,
    address: carrick_guest_arch::KernelVa,
) -> Option<*mut T> {
    if cpu.raw() >= carrick_el1_abi::EL1_STACK_SLOTS as u32 {
        return None;
    }
    let slot = carrick_guest_arch::SlotId::from_index(cpu.raw() as usize)?;
    let start =
        carrick_el1_abi::EL1_STACKS_BASE + u64::from(slot.raw()) * carrick_el1_abi::EL1_STACK_SIZE;
    let end = address
        .raw()
        .checked_add(core::mem::size_of::<T>() as u64)?;
    if address.raw() < start
        || end > start + carrick_el1_abi::EL1_STACK_SIZE
        || !address
            .raw()
            .is_multiple_of(core::mem::align_of::<T>() as u64)
    {
        return None;
    }
    region.record_ptr::<T>(
        usize::try_from(
            address
                .raw()
                .checked_sub(carrick_el1_abi::EL1_REGION_BASE)?,
        )
        .ok()?,
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn retained_abi_region(
    _custody: &crate::trap::CarrierVmCustody,
) -> Option<RetainedAbiRegion<'_>> {
    // SAFETY: the synchronous stopped lane retains this carrier's ABI mapping.
    unsafe {
        RetainedAbiRegion::new(
            carrick_el1_abi::get_el1_region_host_ptr() as *mut u8,
            carrick_el1_abi::EL1_REGION_SIZE as usize,
        )
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn stopped_execution(
    region: RetainedAbiRegion<'_>,
    cpu: carrick_guest_arch::CpuId,
    ttbr0: u64,
) -> Option<crate::fork_stock::GrantExecution> {
    let (task, zone) = stopped_records(region, cpu)?;
    root_execution(cpu, task, zone, ttbr0)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn stopped_records<'a>(
    region: RetainedAbiRegion<'a>,
    cpu: carrick_guest_arch::CpuId,
) -> Option<(
    &'a carrick_el1_abi::CurrentTask,
    &'a carrick_el1_abi::ZoneTables,
)> {
    let slot = carrick_guest_arch::SlotId::from_index(cpu.raw() as usize)?;
    let task_offset = carrick_el1_abi::EL1_CURRENT_TASKS_OFFSET as usize
        + usize::from(slot.raw()) * core::mem::size_of::<carrick_el1_abi::CurrentTask>();
    let task = region.record_ptr::<carrick_el1_abi::CurrentTask>(task_offset)?;
    let zone = region
        .record_ptr::<carrick_el1_abi::ZoneTables>(carrick_el1_abi::EL1_ZONE_OFFSET as usize)?;
    // SAFETY: initialized disjoint fixed ABI records; mutation uses their atomics.
    Some(unsafe { (&*task, &*zone) })
}

/// Observation-only identity of a stopped lane. Unlike terminal custody,
/// diagnostics need not have a published root incarnation.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn diagnostic_identity(
    cpu: carrick_guest_arch::CpuId,
    task: &carrick_el1_abi::CurrentTask,
    zone: &carrick_el1_abi::ZoneTables,
    ttbr0: u64,
) -> Option<(
    carrick_el1_abi::ExecutionBinding,
    carrick_guest_arch::RootGpa,
)> {
    let slot = carrick_guest_arch::SlotId::from_index(cpu.raw() as usize)?;
    let binding = carrick_core::entry::binding(&task.execution, &task.mm);
    let index = zone.spaces.find(binding.mm.raw())?;
    let grant = zone.spaces.grant(index, binding.mm.raw())?;
    let root = ttbr0 & carrick_sched_core::AARCH64_ROOT_ADDRESS_MASK;
    if !binding.issued()
        || zone.slot(slot).mm() != binding.mm.raw()
        || zone.installed_space(slot) != binding.mm.raw()
        || root != grant.ttbr0 & carrick_sched_core::AARCH64_ROOT_ADDRESS_MASK
    {
        return None;
    }
    Some((
        binding,
        carrick_guest_arch::RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(root))?,
    ))
}

/// Root retirement has released its record. Authenticate the stopped lane
/// against its retained host execution, installed MM grant and hardware root.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn root_execution(
    cpu: carrick_guest_arch::CpuId,
    task: &carrick_el1_abi::CurrentTask,
    zone: &carrick_el1_abi::ZoneTables,
    ttbr0: u64,
) -> Option<crate::fork_stock::GrantExecution> {
    let (binding, root) = diagnostic_identity(cpu, task, zone, ttbr0)?;
    Some(crate::fork_stock::GrantExecution::new(
        cpu,
        binding,
        carrick_guest_arch::AddressContext {
            root,
            mm: carrick_guest_arch::MmGeneration::new(core::num::NonZeroU64::new(
                binding.mm.raw(),
            )?),
            generation: task.root_generation()?,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn fork_custody_accepts_retained_bootstrap_metadata_and_rejects_abi_stacks() {
        let bootstrap = carrick_el1_abi::EL1_BOOTSTRAP_METADATA_OFFSET as usize;
        let heap = carrick_el1_abi::EL1_HEAP_OFFSET as usize;
        let limit = carrick_el1_abi::EL1_REGION_SIZE as usize;
        assert!(fork_custody_in_retained_region(bootstrap, 32));
        assert!(fork_custody_in_retained_region(heap - 32, 32));
        assert!(fork_custody_in_retained_region(heap, 32));
        assert!(!fork_custody_in_retained_region(bootstrap - 32, 32));
        assert!(!fork_custody_in_retained_region(limit - 16, 32));
        assert!(!fork_custody_in_retained_region(usize::MAX, 32));
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn refusal_observation_reads_retained_abi_stack_without_physical_stock() {
        use core::fmt::Write;
        let mut region = carrick_test_support::TestEl1Region::zeroed();
        let ptr = region.as_mut_ptr();
        // SAFETY: exclusive aligned, zero-valid fixture ABI storage.
        let zone = unsafe {
            &*ptr
                .add(carrick_el1_abi::EL1_ZONE_OFFSET as usize)
                .cast::<carrick_el1_abi::ZoneTables>()
        };
        let cpu = carrick_guest_arch::CpuId::new(3);
        let slot = carrick_guest_arch::SlotId::new(3);
        let ttbr = (4 << 48) | 0x90000;
        let space = zone.spaces.publish_closed(5, ttbr, ttbr).unwrap();
        zone.spaces.open(space);
        zone.drive(slot, 5);
        zone.publish_slot(slot, 5, Some(3), 1);
        zone.enter_guest(slot);
        zone.install_space(slot, 5).unwrap();
        // SAFETY: this CPU's fixed initialized CurrentTask record belongs to the fixture.
        let task = unsafe {
            &*ptr
                .add(
                    carrick_el1_abi::EL1_CURRENT_TASKS_OFFSET as usize
                        + 3 * core::mem::size_of::<carrick_el1_abi::CurrentTask>(),
                )
                .cast::<carrick_el1_abi::CurrentTask>()
        };
        task.set(carrick_el1_abi::El1TaskId::from_linux_tid(41), 11, 1);
        task.mm.key.store(5, Ordering::Release);
        task.mm.thread_generation.store(101, Ordering::Release);
        assert!(task.root_generation().is_none());
        let address = carrick_el1_abi::EL1_STACKS_BASE + 3 * carrick_el1_abi::EL1_STACK_SIZE;
        let mut diagnostic = carrick_el1_abi::NativeForkDiagnostic::new();
        write!(&mut diagnostic, "Census: Core").unwrap();
        // SAFETY: aligned complete stack record in this exclusively owned ABI region.
        unsafe {
            ptr.add((address - carrick_el1_abi::EL1_REGION_BASE) as usize)
                .cast::<carrick_el1_abi::NativeForkDiagnostic>()
                .write(diagnostic);
        }
        let bytes = unsafe {
            RetainedAbiRegion::new(ptr, carrick_el1_abi::EL1_REGION_SIZE as usize).unwrap()
        };
        let custody = crate::trap::CarrierVmCustody::new();
        let generation = custody.begin_create().unwrap();
        custody.commit_create(generation).unwrap();
        assert!(
            crate::fork_stock::ForkStockHostCustody::resolve_record_ptr::<
                carrick_el1_abi::NativeForkDiagnostic,
            >(&custody, address)
            .is_err(),
            "ABI stacks are not physical fork-stock rows"
        );
        assert_eq!(
            service_fork_refusal_using_region(
                &custody,
                Some(generation),
                cpu,
                carrick_guest_arch::KernelVa::new(address),
                ttbr,
                bytes
            ),
            [METADATA_GRANT_SUCCESS, 0, 0, 0]
        );
        for (wrong_cpu, wrong_address, wrong_ttbr) in [
            (carrick_guest_arch::CpuId::new(2), address, ttbr),
            (cpu, address + 1, ttbr),
            (cpu, address, ttbr + 4096),
        ] {
            assert_eq!(
                service_fork_refusal_using_region(
                    &custody,
                    Some(generation),
                    wrong_cpu,
                    carrick_guest_arch::KernelVa::new(wrong_address),
                    wrong_ttbr,
                    bytes
                ),
                [METADATA_GRANT_ERR_DENIED, 0, 0, 0]
            );
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn root_terminal_authentication_needs_no_parked_record_or_stock_row() {
        let mut region = carrick_test_support::TestEl1Region::zeroed();
        let ptr = region.as_mut_ptr();
        // SAFETY: aligned retained zeroed ABI storage; all zone fields accept zero.
        let zone = unsafe {
            &*ptr
                .add(carrick_el1_abi::EL1_ZONE_OFFSET as usize)
                .cast::<carrick_el1_abi::ZoneTables>()
        };
        let cpu = carrick_guest_arch::CpuId::new(3);
        let slot = carrick_guest_arch::SlotId::new(3);
        let ttbr = (4 << 48) | 0x90000;
        let space = zone.spaces.publish_closed(5, ttbr, ttbr).unwrap();
        zone.spaces.open(space);
        zone.drive(slot, 5);
        zone.publish_slot(slot, 5, Some(3), 1);
        zone.enter_guest(slot);
        zone.install_space(slot, 5).unwrap();
        let task = carrick_el1_abi::CurrentTask::new();
        task.set(carrick_el1_abi::El1TaskId::from_linux_tid(41), 11, 1);
        task.mm.key.store(5, Ordering::Release);
        task.mm.thread_generation.store(101, Ordering::Release);
        assert!(root_execution(cpu, &task, zone, ttbr).is_none());
        assert!(
            diagnostic_identity(cpu, &task, zone, ttbr).is_some(),
            "refusal diagnostic must observe an initial root without granting custody"
        );
        task.publish_root_generation(carrick_guest_arch::ContextGeneration::new(
            core::num::NonZeroU64::new(77).unwrap(),
        ));
        let execution = root_execution(cpu, &task, zone, ttbr).unwrap();
        assert_eq!(execution.binding.generation.raw(), 11);
        assert_eq!(execution.context.generation.raw().get(), 77);
        assert_eq!(execution.context.root.address().raw(), 0x90000);
        assert!(zone.slot(slot).host_record().is_none());
        let custody = crate::trap::CarrierVmCustody::new();
        let generation = custody.begin_create().unwrap();
        custody.commit_create(generation).unwrap();
        let address = carrick_guest_arch::KernelVa::new(
            carrick_el1_abi::EL1_STACKS_BASE + 3 * carrick_el1_abi::EL1_STACK_SIZE,
        );
        let offset = (address.raw() - carrick_el1_abi::EL1_REGION_BASE) as usize;
        // SAFETY: retained ABI storage is aligned; this fixture exclusively owns this stack.
        unsafe {
            ptr.add(offset).cast::<NativeRootExit>().write(
                NativeRootExit::new(
                    execution.binding,
                    carrick_sched_core::process::TerminationStatus::exited(7),
                )
                .unwrap(),
            );
        }
        let bytes = unsafe {
            RetainedAbiRegion::new(ptr, carrick_el1_abi::EL1_REGION_SIZE as usize).unwrap()
        };
        let record = root_stack_record(bytes, cpu, address).unwrap();
        assert!(root_stack_record(bytes, carrick_guest_arch::CpuId::new(2), address).is_none());
        assert_eq!(
            service_metadata_operation(
                &custody,
                Some(generation),
                cpu,
                Some((execution, record)),
                GRANT_OP_ROOT_EXIT,
                address.raw(),
                cpu.raw() as u64,
                0
            )
            .unwrap(),
            [0, 7 << 8, 0, 0]
        );

        assert!(root_execution(cpu, &task, zone, ttbr + 4096).is_none());
        assert!(root_execution(carrick_guest_arch::CpuId::new(2), &task, zone, ttbr).is_none());
        assert!(diagnostic_identity(cpu, &task, zone, ttbr + 4096).is_none());
        assert!(
            diagnostic_identity(carrick_guest_arch::CpuId::new(2), &task, zone, ttbr).is_none()
        );
        task.execution.generation.store(0, Ordering::Release);
        assert!(root_execution(cpu, &task, zone, ttbr).is_none());
        assert!(diagnostic_identity(cpu, &task, zone, ttbr).is_none());
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn authenticated_root_exit_is_terminal() {
        for (wire, status) in [
            (
                7 << 8,
                carrick_sched_core::process::TerminationStatus::exited(7),
            ),
            (
                9,
                carrick_sched_core::process::TerminationStatus::signaled(9, false),
            ),
        ] {
            assert_eq!(
                classify_metadata_trap(GRANT_OP_ROOT_EXIT, [0, wire, 0, 0]).unwrap(),
                MetadataTrapOutcome::RootExit(status)
            );
        }
        assert!(classify_metadata_trap(GRANT_OP_ROOT_EXIT, [1, 0, 0, 0]).is_err());
        assert_eq!(
            classify_metadata_trap(METADATA_GRANT_OP_ALLOC, [0; 4]).unwrap(),
            MetadataTrapOutcome::Resume
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn test_record(
        custody: &crate::trap::CarrierVmCustody,
        generation: crate::trap::CarrierVmGeneration,
        backing: &OwnedHostMapping,
        token: u64,
    ) -> crate::trap::CarrierStage2RecordIdentity {
        publish_metadata_mapping_using(
            custody,
            crate::trap::CarrierStage2RecordSpec {
                vm_generation: generation,
                ipa: EL1_DYNAMIC_METADATA_BASE,
                len: backing.len(),
                host_addr: backing.as_ptr() as usize,
                mapped: true,
                backend_map_installed: true,
                release_ipa: false,
                perms: 3,
                logical_owner: Some(crate::trap::CarrierLogicalOwner {
                    id: token,
                    generation: token,
                }),
            },
            || 0,
        )
        .expect("publish fake backend record")
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn metadata_extent_pin_authenticates_owner_and_blocks_return() {
        let custody = crate::trap::CarrierVmCustody::new();
        let generation = custody.begin_create().unwrap();
        custody.commit_create(generation).unwrap();
        let size = EL1_DYNAMIC_METADATA_EXTENT_SIZE;
        let backing = allocate_metadata_backing(size).unwrap();
        let mut state = HostApertureState::new();
        state.reserve_slots(0, 1);
        state.slots[0] = Some(GrantedSlotRecord {
            identity: test_record(&custody, generation, &backing, 19),
            backing: Arc::new(MetadataBacking::Allocated(backing)),
            num_slots: 1,
            token: 19,
            generation: generation.0,
        });
        let extent = MetadataExtent::new(EL1_DYNAMIC_METADATA_BASE, size as u64, 19).unwrap();
        for wrong in [
            MetadataExtent::new(extent.base(), extent.len(), 20).unwrap(),
            MetadataExtent::new(extent.base(), extent.len() / 2, 19).unwrap(),
            MetadataExtent::new(extent.base() + 4096, extent.len(), 19).unwrap(),
        ] {
            assert!(state.pin_extent(wrong, generation.0).is_err());
        }
        assert!(state.pin_extent(extent, generation.0 + 1).is_err());
        let pin = state.pin_extent(extent, generation.0).unwrap();
        unsafe { pin.host_base().as_ptr().write(0x5a) };
        let mut unmapped = false;
        assert_eq!(
            state.return_extent_using(0, size, 19, generation.0, |_| {
                unmapped = true;
                true
            }),
            METADATA_GRANT_ERR_DENIED,
            "live metadata pin must exclude return"
        );
        assert!(!unmapped);
        assert_eq!(unsafe { pin.host_base().as_ptr().read() }, 0x5a);
        drop(pin);
        assert_eq!(
            state.return_extent_using(0, size, 19, generation.0, |_| true),
            METADATA_GRANT_SUCCESS
        );
        assert!(state.pin_extent(extent, generation.0).is_err());
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn metadata_publication_has_an_exact_stage2_record() {
        let custody = crate::trap::CarrierVmCustody::new();
        let generation = custody.begin_create().expect("create");
        custody.commit_create(generation).expect("live");
        let spec = crate::trap::CarrierStage2RecordSpec {
            vm_generation: generation,
            ipa: EL1_DYNAMIC_METADATA_BASE,
            len: EL1_DYNAMIC_METADATA_EXTENT_SIZE,
            host_addr: 0x10000,
            mapped: true,
            backend_map_installed: true,
            release_ipa: false,
            perms: 3,
            logical_owner: Some(crate::trap::CarrierLogicalOwner {
                id: 19,
                generation: 19,
            }),
        };
        let mut calls = 0;
        assert!(
            publish_metadata_mapping_using(&custody, spec, || {
                calls += 1;
                -1
            })
            .is_err()
        );
        assert_eq!(calls, 1);
        assert!(
            custody.stage2_record_identities().is_empty(),
            "failed map published a record"
        );
        let mut stale = spec;
        stale.vm_generation = crate::trap::CarrierVmGeneration(generation.0 + 1);
        assert!(
            publish_metadata_mapping_using(&custody, stale, || panic!("stale VM must not map"))
                .is_err()
        );
        assert!(custody.stage2_record_identities().is_empty());
        let identity = publish_metadata_mapping_using(&custody, spec, || 0).expect("map");
        let record = custody
            .stage2_record_snapshot(identity.record_id)
            .expect("record");
        assert_eq!(record.vm_generation, generation);
        assert_eq!(record.logical_owner, spec.logical_owner);
        assert!(record.mapped && record.backend_map_installed);
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn metadata_backing_follows_exact_vm_terminal_transition() {
        let custody = crate::trap::CarrierVmCustody::new();
        let first = custody.begin_create().expect("create first");
        custody.commit_create(first).expect("publish first");
        assert!(request_has_live_vm(&custody, Some(first)));
        assert!(!request_has_live_vm(&custody, None));
        let backing = allocate_metadata_backing(EL1_DYNAMIC_METADATA_EXTENT_SIZE).expect("backing");
        let ptr = backing.as_ptr();
        unsafe { ptr.write(0x5a) };
        {
            let mut aperture = metadata_aperture(&custody).lock();
            assert_eq!(aperture.find_and_reserve_slots(1), Some(0));
            aperture.slots[0] = Some(GrantedSlotRecord {
                identity: test_record(&custody, first, &backing, 91),
                backing: Arc::new(MetadataBacking::Allocated(backing)),
                num_slots: 1,
                token: 91,
                generation: first.0,
            });
        }
        reset_metadata_grant_state();
        assert!(metadata_aperture(&custody).lock().slots[0].is_some());
        custody.begin_destroy(first).expect("begin destroy");
        assert!(!request_has_live_vm(&custody, Some(first)));
        custody
            .abort_destroy(first)
            .expect("failed destroy retains VM");
        assert!(request_has_live_vm(&custody, Some(first)));
        assert_eq!(unsafe { ptr.read() }, 0x5a);
        assert!(metadata_aperture(&custody).lock().is_slot_occupied(0));
        custody.begin_destroy(first).expect("retry destroy");
        custody
            .commit_destroy(first)
            .expect("successful raw VM destroy");
        assert!(metadata_aperture(&custody).lock().slots[0].is_none());
        assert!(
            custody.stage2_record_identities().is_empty(),
            "destroy left stale metadata records"
        );
        assert!(!metadata_aperture(&custody).lock().is_slot_occupied(0));
        let second = custody.begin_create().expect("create successor");
        custody.commit_create(second).expect("publish successor");
        assert_ne!(first, second);
        assert!(!request_has_live_vm(&custody, Some(first)));
        assert!(request_has_live_vm(&custody, Some(second)));
        assert!(custody.commit_destroy(first).is_err());
        assert!(request_has_live_vm(&custody, Some(second)));
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn metadata_apertures_are_owned_by_their_carrier() {
        let a = crate::trap::CarrierVmCustody::new();
        let b = crate::trap::CarrierVmCustody::new();
        metadata_aperture(&a).lock().reserve_slots(0, 1);
        let b_occupied = metadata_aperture(&b).lock().is_slot_occupied(0);
        metadata_aperture(&a).lock().unreserve_slots(0, 1);
        assert!(
            !b_occupied,
            "one carrier's reservation leaked into another carrier"
        );
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn failed_return_keeps_backing_and_aperture_reserved() {
        let custody = crate::trap::CarrierVmCustody::new();
        let generation = custody.begin_create().expect("create");
        custody.commit_create(generation).expect("live");
        let mut state = HostApertureState::new();
        let slot = state.find_and_reserve_slots(2).expect("reserve");
        let size = 2 * EL1_DYNAMIC_METADATA_EXTENT_SIZE;
        let backing = allocate_metadata_backing(size).expect("backing");
        assert!(backing.shares_across_host_fork());
        let ptr = backing.as_ptr();
        unsafe { ptr.write(0xa5) };
        state.slots[slot] = Some(GrantedSlotRecord {
            identity: test_record(&custody, generation, &backing, 7),
            backing: Arc::new(MetadataBacking::Allocated(backing)),
            num_slots: 2,
            token: 7,
            generation: 1,
        });
        for (token, generation) in [(0, 1), (8, 1), (7, 2)] {
            assert_eq!(
                state.return_extent_using(slot, size, token, generation, |_| panic!(
                    "mismatched identity must not unmap"
                )),
                METADATA_GRANT_ERR_INVALID
            );
        }
        assert_eq!(
            state.return_extent_using(slot, size, 7, 1, |record| retire_metadata_record_using(
                &custody,
                record.identity,
                |_, _| Err(crate::trap::CarrierStage2BackendError::HvReturn(1))
            )),
            METADATA_GRANT_ERR_DENIED
        );
        let retained = state.slots[slot]
            .as_ref()
            .expect("failed unmap lost backing");
        let snapshot = custody
            .stage2_record_snapshot(retained.identity.record_id)
            .expect("retained record");
        assert!(snapshot.mapped && snapshot.retry_pending.is_some());
        assert_eq!(retained.backing.as_ptr(), ptr);
        assert_eq!(unsafe { ptr.read() }, 0xa5);
        assert!(state.is_slot_occupied(slot) && state.is_slot_occupied(slot + 1));
        assert_eq!(state.find_and_reserve_slots(1), Some(2));
        assert_eq!(
            state.return_extent_using(slot, size, 7, 1, |record| {
                retire_metadata_record_using(&custody, record.identity, |ipa, bytes| {
                    assert_eq!(ipa, EL1_DYNAMIC_METADATA_BASE);
                    assert_eq!(bytes, size);
                    Ok(())
                })
            }),
            METADATA_GRANT_SUCCESS
        );
        assert!(state.slots[slot].is_none());
        assert!(
            custody.stage2_record_identities().is_empty(),
            "return left stale record"
        );
        assert_eq!(state.find_and_reserve_slots(2), Some(0));
        assert!(
            state.is_slot_occupied(2),
            "unpublished reservation must remain occupied"
        );
        assert_eq!(
            state.return_extent_using(slot, size, 7, 1, |_| panic!(
                "already returned backing must not unmap twice"
            )),
            METADATA_GRANT_ERR_NOT_FOUND
        );
    }

    #[test]
    fn test_host_aperture_multi_slot_reservation_and_overlap_rejection() {
        let mut state = HostApertureState::new();

        // 1. Request 3 slots (1,114,112 bytes rounded to 3x 512 KiB = 1.5 MiB)
        let s0 = state.find_and_reserve_slots(3).expect("reserve 3 slots");
        assert_eq!(s0, 0);
        assert!(state.is_slot_occupied(0));
        assert!(state.is_slot_occupied(1));
        assert!(state.is_slot_occupied(2));
        assert!(!state.is_slot_occupied(3));

        // 2. Next request for 1 slot must return slot 3 (no overlap with slots 0..2)
        let s1 = state.find_and_reserve_slots(1).expect("reserve 1 slot");
        assert_eq!(s1, 3);
        assert!(state.is_slot_occupied(3));

        // 3. Unreserve slot 0..2 (freeing 3 slots)
        state.unreserve_slots(0, 3);
        assert!(!state.is_slot_occupied(0));
        assert!(!state.is_slot_occupied(1));
        assert!(!state.is_slot_occupied(2));
        assert!(state.is_slot_occupied(3)); // slot 3 remains occupied

        // 4. Allocate 2 slots: reuses freed slots 0..1
        let s2 = state.find_and_reserve_slots(2).expect("reuse 2 slots");
        assert_eq!(s2, 0);
        assert!(state.is_slot_occupied(0));
        assert!(state.is_slot_occupied(1));
        assert!(!state.is_slot_occupied(2));
        assert!(state.is_slot_occupied(3));
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn oversized_metadata_request_is_invalid_without_reserving_aperture() {
        let custody = crate::trap::CarrierVmCustody::new();
        let generation = custody.begin_create().expect("create");
        custody.commit_create(generation).expect("live");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            service_metadata_operation(
                &custody,
                Some(generation),
                carrick_guest_arch::CpuId::new(0),
                None,
                METADATA_GRANT_OP_ALLOC,
                u64::MAX,
                0,
                0,
            )
        }));
        assert!(result.is_ok(), "oversized grant arithmetic panicked");
        assert_eq!(
            result
                .expect("checked grant result")
                .expect("typed outcome"),
            [METADATA_GRANT_ERR_INVALID, 0, 0, 0]
        );
        let aperture = metadata_aperture(&custody).lock();
        assert!(aperture.slots.iter().all(Option::is_none));
        assert!(aperture.occupied_bitmap.iter().all(|word| *word == 0));
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn retained_slab_exhaustion_refuses_without_backend_work() {
        let custody = crate::trap::CarrierVmCustody::new();
        let generation = custody.begin_create().unwrap();
        custody.commit_create(generation).unwrap();
        let mut aperture = metadata_aperture(&custody).lock();
        for _ in 0..MAX_DYNAMIC_EXTENT_SLOTS {
            let backing = Arc::new(MetadataBacking::Allocated(
                allocate_metadata_backing(EL1_DYNAMIC_METADATA_EXTENT_SIZE).unwrap(),
            ));
            aperture
                .install_retained_using(&custody, generation, backing, |_| 0)
                .unwrap();
        }
        let before = custody.stage2_record_identities();
        let occupied = aperture.occupied_bitmap;
        let backing = Arc::new(MetadataBacking::Allocated(
            allocate_metadata_backing(EL1_DYNAMIC_METADATA_EXTENT_SIZE).unwrap(),
        ));
        assert_eq!(
            aperture.install_retained_using(&custody, generation, backing, |_| {
                panic!("exhaustion must decline before backend publication")
            }),
            Err(MetadataResolutionError::Busy)
        );
        assert_eq!(custody.stage2_record_identities(), before);
        assert_eq!(aperture.occupied_bitmap, occupied);
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn retained_lifecycle_mapping_keeps_one_backing_and_exact_carrier() {
        let first = crate::trap::CarrierVmCustody::new();
        let second = crate::trap::CarrierVmCustody::new();
        let a = first.begin_create().unwrap();
        first.commit_create(a).unwrap();
        let b = second.begin_create().unwrap();
        second.commit_create(b).unwrap();
        let backing = Arc::new(MetadataBacking::Allocated(
            allocate_metadata_backing(16384).unwrap(),
        ));
        let weak = Arc::downgrade(&backing);
        let host = backing.as_ptr();
        let mut state = metadata_aperture(&first).lock();
        assert!(
            state
                .install_retained_using(&first, a, backing.clone(), |_| -1)
                .is_err()
        );
        assert!(first.stage2_record_identities().is_empty());
        assert!(state.occupied_bitmap.iter().all(|bits| *bits == 0));
        let extent = state
            .install_retained_using(&first, a, backing.clone(), |spec| {
                assert_eq!(spec.host_addr, host as usize);
                assert_eq!(spec.len, 16384);
                0
            })
            .unwrap();
        drop(backing);
        let pin = state.pin_extent(extent, a.0).unwrap();
        assert_eq!(pin.host_base().as_ptr(), host);
        let other = Arc::new(MetadataBacking::Allocated(
            allocate_metadata_backing(16384).unwrap(),
        ));
        let other_weak = Arc::downgrade(&other);
        let other_extent = metadata_aperture(&second)
            .lock()
            .install_retained_using(&second, b, other, |_| 0)
            .unwrap();
        assert_eq!(extent.base(), other_extent.base());
        assert_ne!(extent.token(), other_extent.token());
        assert!(
            metadata_aperture(&second)
                .lock()
                .pin_extent(extent, b.0)
                .is_err()
        );
        assert_eq!(
            state.return_extent_using(0, 16384, extent.token(), a.0, |_| panic!(
                "guest cannot release lifecycle backing"
            )),
            METADATA_GRANT_ERR_DENIED
        );
        assert_eq!(
            state.retire_retained_using(extent, a.0, |_| panic!("pin excludes retirement")),
            METADATA_GRANT_ERR_DENIED
        );
        drop(pin);
        assert_eq!(
            state.retire_retained_using(extent, a.0, |_| false),
            METADATA_GRANT_ERR_DENIED
        );
        assert!(
            weak.upgrade().is_some(),
            "failed unmap released live backing"
        );
        assert_eq!(
            state.retire_retained_using(extent, a.0, |record| retire_metadata_record_using(
                &first,
                record.identity,
                |_, _| Ok(())
            )),
            METADATA_GRANT_SUCCESS
        );
        assert!(weak.upgrade().is_none());
        assert!(first.stage2_record_identities().is_empty());
        assert!(other_weak.upgrade().is_some());
        let surviving_pin = metadata_aperture(&second)
            .lock()
            .pin_extent(other_extent, b.0)
            .unwrap();
        second.begin_destroy(b).unwrap();
        second.commit_destroy(b).unwrap();
        assert!(other_weak.upgrade().is_some());
        drop(surviving_pin);
        assert!(other_weak.upgrade().is_none());
    }

    /// The delay injector and ordinary boundary call this identical completion
    /// function. Retirement between claim and service cannot publish backing.
    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn deferred_metadata_service_reauthenticates_retired_generation() {
        let custody = crate::trap::CarrierVmCustody::new();
        let generation = custody.begin_create().unwrap();
        custody.commit_create(generation).unwrap();
        let mailbox = carrick_el1_abi::MetadataGrantMailbox::new();
        let request = carrick_el1_abi::MetadataGrantRequest {
            op: METADATA_GRANT_OP_ALLOC,
            arg1: EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64,
            arg2: 0,
            arg3: 0,
            cookie: 0,
        };
        assert!(mailbox.try_publish_request(request));
        let claimed = mailbox.claim_request().unwrap();
        let incarnation = mailbox.request_generation();
        custody.begin_destroy(generation).unwrap();
        custody.commit_destroy(generation).unwrap();
        assert!(
            complete_metadata_request(&custody, Some(generation), &mailbox, incarnation, claimed,)
                .is_err()
        );
        assert_eq!(
            mailbox.claim_response().unwrap().status,
            METADATA_GRANT_ERR_INVALID
        );
        assert!(custody.stage2_record_identities().is_empty());
        assert!(
            metadata_aperture(&custody)
                .lock()
                .slots
                .iter()
                .all(Option::is_none)
        );
    }

    #[test]
    fn metadata_tokens_never_wrap_or_issue_zero() {
        let counter = AtomicU64::new(u64::MAX - 1);
        assert_eq!(reserve_metadata_token(&counter), Some(u64::MAX - 1));
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
        assert_eq!(reserve_metadata_token(&counter), None);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);

        let invalid = AtomicU64::new(0);
        assert_eq!(reserve_metadata_token(&invalid), None);
        assert_eq!(invalid.load(Ordering::Relaxed), 0);
    }
}
