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

struct GrantedSlotRecord {
    backing: OwnedHostMapping,
    size: usize,
    num_slots: usize,
    token: u64,
    #[allow(dead_code)]
    generation: u64,
}

// Backing ownership moves only under HOST_APERTURE; access is synchronized by
// the guest allocator and the record is retained until stage-2 unmap succeeds.
unsafe impl Send for GrantedSlotRecord {}

struct HostApertureState {
    occupied_bitmap: [u64; 2],
    slots: [Option<GrantedSlotRecord>; MAX_DYNAMIC_EXTENT_SLOTS],
}

impl HostApertureState {
    const fn new() -> Self {
        Self {
            occupied_bitmap: [0; 2],
            slots: [const { None }; MAX_DYNAMIC_EXTENT_SLOTS],
        }
    }

    fn reset_using(&mut self, mut unmap: impl FnMut(u64, &GrantedSlotRecord) -> bool) {
        for i in 0..self.slots.len() {
            let Some(record) = self.slots[i].as_ref() else {
                continue;
            };
            let ipa =
                EL1_DYNAMIC_METADATA_BASE + (i as u64) * EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64;
            if unmap(ipa, record) {
                let num_slots = record.num_slots;
                // Drop host backing only after the stage-2 mapping is gone.
                self.slots[i] = None;
                self.unreserve_slots(i, num_slots);
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
static GLOBAL_GENERATION: AtomicU64 = AtomicU64::new(1);

static HOST_APERTURE: Mutex<HostApertureState> = Mutex::new(HostApertureState::new());

fn allocate_metadata_backing(size: usize) -> Result<OwnedHostMapping, std::io::Error> {
    OwnedHostMapping::map_shared_anon(size, HostMappingKind::SharedAnon)
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

/// Reset statistics/failpoints and release active grants whose unmap succeeds.
/// Failed unmaps retain their exact backing and aperture reservation for retry.
pub fn reset_metadata_grant_state() {
    GRANTS_REQUESTED.store(0, Ordering::Relaxed);
    GRANTS_SUCCEEDED.store(0, Ordering::Relaxed);
    GRANTS_DENIED.store(0, Ordering::Relaxed);
    RETURNS_COMPLETED.store(0, Ordering::Relaxed);
    BYTES_GRANTED.store(0, Ordering::Relaxed);
    BYTES_RETURNED.store(0, Ordering::Relaxed);
    FAILPOINT_DENY_NEXT.store(false, Ordering::SeqCst);

    HOST_APERTURE.lock().reset_using(|ipa, record| {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            unsafe { crate::trap::inventory_hv_vm_unmap(ipa, record.size) == 0 }
        }
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        {
            let _ = (ipa, record);
            true
        }
    });
}

/// Handle a trapped metadata grant hypercall (`HVC #6`) from EL1.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn handle_metadata_grant_trap(vcpu: &mut applevisor::vcpu::Vcpu) -> Result<(), TrapError> {
    use applevisor::vcpu::Reg;

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
            let mut state = HOST_APERTURE.lock();
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
                let mut state = HOST_APERTURE.lock();
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
                HOST_APERTURE.lock().unreserve_slots(slot_idx, num_slots);
                GRANTS_DENIED.fetch_add(1, Ordering::Relaxed);
                vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_DENIED)
                    .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
                return Ok(());
            }
        };

        // 4. Map into stage-2 with Read/Write permissions (strictly non-executable)
        let permissions = 0b011; // HV_MEMORY_READ | HV_MEMORY_WRITE
        let rc = unsafe {
            crate::trap::inventory_hv_vm_map(backing.as_ptr().cast(), ipa, extent_size, permissions)
        };
        if rc != 0 {
            {
                let mut state = HOST_APERTURE.lock();
                state.unreserve_slots(slot_idx, num_slots);
            }
            GRANTS_DENIED.fetch_add(1, Ordering::Relaxed);
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_DENIED)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            return Ok(());
        }

        // 5. Register in slot table
        let token = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
        let generation = GLOBAL_GENERATION.fetch_add(1, Ordering::Relaxed);
        {
            let mut state = HOST_APERTURE.lock();
            state.slots[slot_idx] = Some(GrantedSlotRecord {
                backing,
                size: extent_size,
                num_slots,
                token,
                generation,
            });
        }

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

        let record_opt = {
            let mut state = HOST_APERTURE.lock();
            if state.is_slot_occupied(slot_idx) {
                state.slots[slot_idx].take()
            } else {
                None
            }
        };

        let Some(record) = record_opt else {
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_NOT_FOUND)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            return Ok(());
        };

        if record.size != size || record.token != token {
            // Restore slot record on parameter/token mismatch
            let mut state = HOST_APERTURE.lock();
            state.slots[slot_idx] = Some(record);
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_INVALID)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            return Ok(());
        }

        // Unmap from stage-2
        let rc = unsafe { crate::trap::inventory_hv_vm_unmap(ipa, record.size) };
        if rc != 0 {
            // Failed unmap: do NOT deallocate host memory to avoid UAF, restore record
            let mut state = HOST_APERTURE.lock();
            state.slots[slot_idx] = Some(record);
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_DENIED)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            return Ok(());
        }

        // Deallocate host memory and clear bitmap reservation across all covered slots
        drop(record.backing);
        {
            let mut state = HOST_APERTURE.lock();
            state.unreserve_slots(slot_idx, record.num_slots);
        }

        RETURNS_COMPLETED.fetch_add(1, Ordering::Relaxed);
        BYTES_RETURNED.fetch_add(record.size as u64, Ordering::Relaxed);

        vcpu.set_reg(Reg::X0, METADATA_GRANT_SUCCESS)
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

    #[test]
    fn failed_reset_keeps_backing_and_aperture_reserved() {
        let mut state = HostApertureState::new();
        let slot = state.find_and_reserve_slots(2).expect("reserve");
        let backing =
            allocate_metadata_backing(2 * EL1_DYNAMIC_METADATA_EXTENT_SIZE).expect("backing");
        assert!(backing.shares_across_host_fork());
        let host_ptr = backing.as_ptr();
        unsafe { host_ptr.write(0xa5) };
        state.slots[slot] = Some(GrantedSlotRecord {
            size: backing.len(),
            backing,
            num_slots: 2,
            token: 7,
            generation: 1,
        });
        state.reset_using(|_, _| false);
        let retained = state.slots[slot]
            .as_ref()
            .expect("failed unmap lost backing");
        assert_eq!(retained.backing.as_ptr(), host_ptr);
        assert_eq!(unsafe { host_ptr.read() }, 0xa5);
        assert!(state.is_slot_occupied(slot) && state.is_slot_occupied(slot + 1));
        assert_eq!(state.find_and_reserve_slots(1), Some(2));
        let mut attempts = 0;
        state.reset_using(|ipa, record| {
            assert_eq!(ipa, EL1_DYNAMIC_METADATA_BASE);
            assert_eq!(record.token, 7);
            attempts += 1;
            true
        });
        assert_eq!(attempts, 1);
        assert!(state.slots[slot].is_none());
        assert_eq!(state.find_and_reserve_slots(2), Some(0));
        assert!(
            state.is_slot_occupied(2),
            "unpublished reservation must survive reset"
        );
        state.reset_using(|_, _| panic!("already returned backing must not unmap twice"));
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
