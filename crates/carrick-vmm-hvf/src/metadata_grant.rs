//! Host engine for servicing in-guest EL1 metadata extent grant (`HVC #6`) requests.

use crate::host_mapping::{HostMappingKind, OwnedHostMapping};
use carrick_el1_abi::{
    EL1_DYNAMIC_METADATA_BASE, EL1_DYNAMIC_METADATA_EXTENT_SIZE, EL1_DYNAMIC_METADATA_SIZE,
    METADATA_GRANT_ERR_ALIGNMENT, METADATA_GRANT_ERR_DENIED, METADATA_GRANT_ERR_INVALID,
    METADATA_GRANT_ERR_NOT_FOUND, METADATA_GRANT_OP_ALLOC, METADATA_GRANT_OP_FREE,
    METADATA_GRANT_SUCCESS,
};
use carrick_hal::TrapError;
use parking_lot::Mutex;
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
}

#[derive(Debug)]
struct GrantedSlotRecord {
    backing: OwnedHostMapping,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    identity: crate::trap::CarrierStage2RecordIdentity,
    num_slots: usize,
    token: u64,
    generation: u64,
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

static FAILPOINT_DENY_NEXT: AtomicBool = AtomicBool::new(false);
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

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
    FAILPOINT_DENY_NEXT.store(false, Ordering::SeqCst);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn request_has_live_vm(
    custody: &crate::trap::CarrierVmCustody,
    generation: Option<crate::trap::CarrierVmGeneration>,
) -> bool {
    generation.is_some() && custody.live_generation() == generation
}

/// Handle a trapped metadata grant hypercall (`HVC #6`) from EL1.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn handle_metadata_grant_trap(
    vcpu: &mut applevisor::vcpu::Vcpu,
    custody: &crate::trap::CarrierVmCustody,
    generation: Option<crate::trap::CarrierVmGeneration>,
) -> Result<(), TrapError> {
    use applevisor::vcpu::Reg;

    let generation = generation
        .filter(|_| request_has_live_vm(custody, generation))
        .ok_or_else(|| TrapError::Hypervisor("metadata request from a stale VM generation".into()))?
        .0;
    let aperture = metadata_aperture(custody);

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
    // HVF reports PC after the trapping HVC instruction. Preserve it: advancing
    // again skips the first guest instruction consuming the completion registers.

    if op == METADATA_GRANT_OP_ALLOC {
        GRANTS_REQUESTED.fetch_add(1, Ordering::Relaxed);

        // 1. Check test failpoint denial
        if FAILPOINT_DENY_NEXT.swap(false, Ordering::SeqCst) {
            GRANTS_DENIED.fetch_add(1, Ordering::Relaxed);
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_DENIED)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            return Ok(());
        }

        let requested_size = arg1 as usize;
        let extent_quantum = EL1_DYNAMIC_METADATA_EXTENT_SIZE;
        let num_slots = requested_size.max(1).div_ceil(extent_quantum);
        let extent_size = num_slots * extent_quantum;

        // 2. Find and atomically reserve contiguous aperture slots
        let slot_idx = {
            let mut state = aperture.lock();
            state.find_and_reserve_slots(num_slots)
        };

        let Some(slot_idx) = slot_idx else {
            GRANTS_DENIED.fetch_add(1, Ordering::Relaxed);
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_DENIED)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            return Ok(());
        };

        let ipa = EL1_DYNAMIC_METADATA_BASE
            + (slot_idx as u64) * (EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64);
        if ipa.saturating_add(extent_size as u64)
            > EL1_DYNAMIC_METADATA_BASE + EL1_DYNAMIC_METADATA_SIZE
        {
            {
                let mut state = aperture.lock();
                state.unreserve_slots(slot_idx, num_slots);
            }
            GRANTS_DENIED.fetch_add(1, Ordering::Relaxed);
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_DENIED)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            return Ok(());
        }

        // 3. Use host-page-aligned MAP_SHARED backing so HVF and the host
        // always observe the same VM object; guest privacy is stage-1 owned.
        let backing = match allocate_metadata_backing(extent_size) {
            Ok(backing) => backing,
            Err(_) => {
                aperture.lock().unreserve_slots(slot_idx, num_slots);
                GRANTS_DENIED.fetch_add(1, Ordering::Relaxed);
                vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_DENIED)
                    .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
                return Ok(());
            }
        };

        // 4. Map into stage-2 with Read/Write permissions (strictly non-executable)
        let permissions = 0b011; // HV_MEMORY_READ | HV_MEMORY_WRITE
        let token = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
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
                vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_DENIED)
                    .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
                return Ok(());
            }
        };
        state.slots[slot_idx] = Some(GrantedSlotRecord {
            backing,
            identity,
            num_slots,
            token,
            generation,
        });
        drop(state);

        GRANTS_SUCCEEDED.fetch_add(1, Ordering::Relaxed);
        BYTES_GRANTED.fetch_add(extent_size as u64, Ordering::Relaxed);

        vcpu.set_reg(Reg::X0, METADATA_GRANT_SUCCESS)
            .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
        vcpu.set_reg(Reg::X1, ipa)
            .map_err(|e| TrapError::Hypervisor(format!("set X1: {e}")))?;
        vcpu.set_reg(Reg::X2, extent_size as u64)
            .map_err(|e| TrapError::Hypervisor(format!("set X2: {e}")))?;
        vcpu.set_reg(Reg::X3, token)
            .map_err(|e| TrapError::Hypervisor(format!("set X3: {e}")))?;
        Ok(())
    } else if op == METADATA_GRANT_OP_FREE {
        let ipa = arg1;
        let size = arg2 as usize;
        let token = arg3;

        // Validate IPA bounds, alignment, and non-zero token
        if !(EL1_DYNAMIC_METADATA_BASE..EL1_DYNAMIC_METADATA_BASE + EL1_DYNAMIC_METADATA_SIZE)
            .contains(&ipa)
            || !ipa.is_multiple_of(EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64)
            || token == 0
        {
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_ALIGNMENT)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            return Ok(());
        }

        let slot_idx = ((ipa - EL1_DYNAMIC_METADATA_BASE)
            / (EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64)) as usize;
        if slot_idx >= MAX_DYNAMIC_EXTENT_SLOTS {
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_INVALID)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            return Ok(());
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
        vcpu.set_reg(Reg::X0, status)
            .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
        Ok(())
    } else {
        vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_INVALID)
            .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
        Ok(())
    }
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
                backing,
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
            backing,
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
}
