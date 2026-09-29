//! Host engine for servicing in-guest EL1 metadata extent grant (`HVC #6`) requests.

use crate::host_mapping::{HostMappingKind, OwnedHostMapping};
use carrick_el1_abi::{
    EL1_DYNAMIC_METADATA_BASE, EL1_DYNAMIC_METADATA_EXTENT_SIZE, EL1_DYNAMIC_METADATA_SIZE,
    METADATA_GRANT_ERR_ALIGNMENT, METADATA_GRANT_ERR_DENIED, METADATA_GRANT_ERR_INVALID,
    METADATA_GRANT_ERR_NOT_FOUND, METADATA_GRANT_OP_ALLOC, METADATA_GRANT_OP_FREE,
    METADATA_GRANT_SUCCESS,
};
use carrick_el1_abi::{
    MetadataExtent, MetadataExtentResolver, MetadataResolutionError, PinnedMetadataExtent,
};
use carrick_hal::TrapError;
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub const MAX_DYNAMIC_EXTENT_SLOTS: usize = 128;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetadataGrantStats {
    pub grants_requested: u64,
    pub grants_succeeded: u64,
    pub grants_denied: u64,
    pub returns_completed: u64,
    pub bytes_granted: u64,
    pub bytes_returned: u64,
    pub inline_hvc_traps: u64,
}

#[derive(Debug)]
struct GrantedSlotRecord {
    backing: Arc<OwnedHostMapping>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    identity: crate::trap::CarrierStage2RecordIdentity,
    num_slots: usize,
    token: u64,
    generation: u64,
}

/// A pin retains the exact mapping even after VM teardown removes its grant
/// record. Ordinary grant return is refused before stage-2 unmap while pinned.
pub struct HostMetadataExtentPin {
    extent: MetadataExtent,
    backing: Arc<OwnedHostMapping>,
}

// SAFETY: the Arc owns the mapped bytes. Normal return checks outstanding pins;
// VM destruction can remove stage-2 mappings but cannot destroy this host owner.
unsafe impl PinnedMetadataExtent for HostMetadataExtentPin {
    fn extent(&self) -> MetadataExtent {
        self.extent
    }
    fn host_base(&self) -> core::ptr::NonNull<u8> {
        core::ptr::NonNull::new(self.backing.as_ptr()).expect("owned mapping")
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

// Backing ownership moves only under its carrier aperture lock; access is synchronized by
// the guest allocator and the record is retained until stage-2 unmap succeeds.
unsafe impl Send for GrantedSlotRecord {}

#[derive(Debug)]
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
            backing: Arc::clone(&record.backing),
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
fn service_metadata_operation(
    custody: &crate::trap::CarrierVmCustody,
    generation: Option<crate::trap::CarrierVmGeneration>,
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
            backing: Arc::new(backing),
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
    } else {
        Ok([METADATA_GRANT_ERR_INVALID, 0, 0, 0])
    }
}

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
        return Ok(false);
    };
    let result = service_metadata_operation(
        custody,
        generation,
        request.op,
        request.arg1,
        request.arg2,
        request.arg3,
    )?;
    mailbox.publish_response(result[0], result[1], result[2], result[3]);
    Ok(true)
}

/// Legacy synchronous transport retained only as a fail-closed compatibility
/// decoder while the exact signed red/green evidence is promoted. Production
/// guest allocation publishes the shared mailbox and never executes HVC #6.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn handle_metadata_grant_trap(
    vcpu: &mut applevisor::vcpu::Vcpu,
    custody: &crate::trap::CarrierVmCustody,
    generation: Option<crate::trap::CarrierVmGeneration>,
) -> Result<(), TrapError> {
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
    let result = service_metadata_operation(custody, generation, op, arg1, arg2, arg3)?;
    vcpu.set_reg(Reg::X0, result[0])
        .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
    vcpu.set_reg(Reg::X1, result[1])
        .map_err(|e| TrapError::Hypervisor(format!("set X1: {e}")))?;
    vcpu.set_reg(Reg::X2, result[2])
        .map_err(|e| TrapError::Hypervisor(format!("set X2: {e}")))?;
    vcpu.set_reg(Reg::X3, result[3])
        .map_err(|e| TrapError::Hypervisor(format!("set X3: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            backing: Arc::new(backing),
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
                backing: Arc::new(backing),
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
            backing: Arc::new(backing),
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
