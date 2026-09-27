//! Host engine for servicing in-guest EL1 metadata extent grant (`HVC #6`) requests.

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

#[derive(Copy, Clone)]
struct GrantedSlotRecord {
    host_ptr: *mut u8,
    layout: std::alloc::Layout,
    size: usize,
    token: u64,
    #[allow(dead_code)]
    generation: u64,
}

unsafe impl Send for GrantedSlotRecord {}
unsafe impl Sync for GrantedSlotRecord {}

struct HostApertureState {
    occupied_bitmap: [u64; 2],
    slots: [Option<GrantedSlotRecord>; MAX_DYNAMIC_EXTENT_SLOTS],
}

impl HostApertureState {
    const fn new() -> Self {
        Self {
            occupied_bitmap: [0; 2],
            slots: [None; MAX_DYNAMIC_EXTENT_SLOTS],
        }
    }

    fn find_free_slot(&self) -> Option<usize> {
        if self.occupied_bitmap[0] != u64::MAX {
            let bit = self.occupied_bitmap[0].trailing_ones() as usize;
            if bit < 64 {
                return Some(bit);
            }
        }
        if self.occupied_bitmap[1] != u64::MAX {
            let bit = self.occupied_bitmap[1].trailing_ones() as usize;
            if bit < 64 {
                return Some(64 + bit);
            }
        }
        None
    }

    fn set_slot_occupied(&mut self, slot: usize) {
        if slot < 64 {
            self.occupied_bitmap[0] |= 1u64 << slot;
        } else if slot < 128 {
            self.occupied_bitmap[1] |= 1u64 << (slot - 64);
        }
    }

    fn clear_slot_occupied(&mut self, slot: usize) {
        if slot < 64 {
            self.occupied_bitmap[0] &= !(1u64 << slot);
        } else if slot < 128 {
            self.occupied_bitmap[1] &= !(1u64 << (slot - 64));
        }
    }

    fn is_slot_occupied(&self, slot: usize) -> bool {
        if slot < 64 {
            (self.occupied_bitmap[0] & (1u64 << slot)) != 0
        } else if slot < 128 {
            (self.occupied_bitmap[1] & (1u64 << (slot - 64))) != 0
        } else {
            false
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

/// Reset all metadata grant statistics, failpoints, and active grant records.
pub fn reset_metadata_grant_state() {
    GRANTS_REQUESTED.store(0, Ordering::Relaxed);
    GRANTS_SUCCEEDED.store(0, Ordering::Relaxed);
    GRANTS_DENIED.store(0, Ordering::Relaxed);
    RETURNS_COMPLETED.store(0, Ordering::Relaxed);
    BYTES_GRANTED.store(0, Ordering::Relaxed);
    BYTES_RETURNED.store(0, Ordering::Relaxed);
    FAILPOINT_DENY_NEXT.store(false, Ordering::SeqCst);
    NEXT_TOKEN.store(1, Ordering::Relaxed);
    GLOBAL_GENERATION.store(1, Ordering::Relaxed);

    let mut state = HOST_APERTURE.lock();
    for (i, slot_opt) in state.slots.iter_mut().enumerate() {
        if let Some(record) = slot_opt.take() {
            let ipa =
                EL1_DYNAMIC_METADATA_BASE + (i as u64) * (EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64);
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            unsafe {
                let _ = crate::trap::inventory_hv_vm_unmap(ipa, record.size);
                std::alloc::dealloc(record.host_ptr, record.layout);
            }
            #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
            {
                let _ = (ipa, record);
            }
        }
    }
    state.occupied_bitmap = [0; 2];
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
    let pc = vcpu
        .get_reg(Reg::PC)
        .map_err(|e| TrapError::Hypervisor(format!("failed to read PC for metadata grant: {e}")))?;

    if op == METADATA_GRANT_OP_ALLOC {
        GRANTS_REQUESTED.fetch_add(1, Ordering::Relaxed);

        // 1. Check test failpoint denial
        if FAILPOINT_DENY_NEXT.swap(false, Ordering::SeqCst) {
            GRANTS_DENIED.fetch_add(1, Ordering::Relaxed);
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_DENIED)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            vcpu.set_reg(Reg::PC, pc + 4)
                .map_err(|e| TrapError::Hypervisor(format!("set PC: {e}")))?;
            return Ok(());
        }

        let requested_size = arg1 as usize;
        let extent_size = (requested_size.max(EL1_DYNAMIC_METADATA_EXTENT_SIZE) + 0xFFFF) & !0xFFFF;

        // 2. Find a free aperture slot
        let slot_idx = {
            let state = HOST_APERTURE.lock();
            state.find_free_slot()
        };

        let Some(slot_idx) = slot_idx else {
            GRANTS_DENIED.fetch_add(1, Ordering::Relaxed);
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_DENIED)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            vcpu.set_reg(Reg::PC, pc + 4)
                .map_err(|e| TrapError::Hypervisor(format!("set PC: {e}")))?;
            return Ok(());
        };

        let ipa = EL1_DYNAMIC_METADATA_BASE
            + (slot_idx as u64) * (EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64);
        if ipa.saturating_add(extent_size as u64)
            > EL1_DYNAMIC_METADATA_BASE + EL1_DYNAMIC_METADATA_SIZE
        {
            GRANTS_DENIED.fetch_add(1, Ordering::Relaxed);
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_DENIED)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            vcpu.set_reg(Reg::PC, pc + 4)
                .map_err(|e| TrapError::Hypervisor(format!("set PC: {e}")))?;
            return Ok(());
        }

        // 3. Allocate anonymous host backing (4 KiB aligned)
        let layout = match std::alloc::Layout::from_size_align(extent_size, 4096) {
            Ok(l) => l,
            Err(_) => {
                GRANTS_DENIED.fetch_add(1, Ordering::Relaxed);
                vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_DENIED)
                    .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
                vcpu.set_reg(Reg::PC, pc + 4)
                    .map_err(|e| TrapError::Hypervisor(format!("set PC: {e}")))?;
                return Ok(());
            }
        };

        let host_ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        if host_ptr.is_null() {
            GRANTS_DENIED.fetch_add(1, Ordering::Relaxed);
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_DENIED)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            vcpu.set_reg(Reg::PC, pc + 4)
                .map_err(|e| TrapError::Hypervisor(format!("set PC: {e}")))?;
            return Ok(());
        }

        // 4. Map into stage-2 with Read/Write permissions (strictly non-executable)
        let permissions = 0b011; // HV_MEMORY_READ | HV_MEMORY_WRITE
        let rc = unsafe {
            crate::trap::inventory_hv_vm_map(host_ptr.cast(), ipa, extent_size, permissions)
        };
        if rc != 0 {
            unsafe {
                std::alloc::dealloc(host_ptr, layout);
            }
            GRANTS_DENIED.fetch_add(1, Ordering::Relaxed);
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_DENIED)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            vcpu.set_reg(Reg::PC, pc + 4)
                .map_err(|e| TrapError::Hypervisor(format!("set PC: {e}")))?;
            return Ok(());
        }

        // 5. Register in slot table
        let token = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
        let generation = GLOBAL_GENERATION.fetch_add(1, Ordering::Relaxed);
        {
            let mut state = HOST_APERTURE.lock();
            state.set_slot_occupied(slot_idx);
            state.slots[slot_idx] = Some(GrantedSlotRecord {
                host_ptr,
                layout,
                size: extent_size,
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
        vcpu.set_reg(Reg::PC, pc + 4)
            .map_err(|e| TrapError::Hypervisor(format!("set PC: {e}")))?;
        Ok(())
    } else if op == METADATA_GRANT_OP_FREE {
        let ipa = arg1;
        let size = arg2 as usize;
        let token = arg3;

        // Validate IPA bounds and alignment
        if !(EL1_DYNAMIC_METADATA_BASE..EL1_DYNAMIC_METADATA_BASE + EL1_DYNAMIC_METADATA_SIZE)
            .contains(&ipa)
            || !ipa.is_multiple_of(EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64)
        {
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_ALIGNMENT)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            vcpu.set_reg(Reg::PC, pc + 4)
                .map_err(|e| TrapError::Hypervisor(format!("set PC: {e}")))?;
            return Ok(());
        }

        let slot_idx = ((ipa - EL1_DYNAMIC_METADATA_BASE)
            / (EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64)) as usize;
        if slot_idx >= MAX_DYNAMIC_EXTENT_SLOTS {
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_INVALID)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            vcpu.set_reg(Reg::PC, pc + 4)
                .map_err(|e| TrapError::Hypervisor(format!("set PC: {e}")))?;
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
            vcpu.set_reg(Reg::PC, pc + 4)
                .map_err(|e| TrapError::Hypervisor(format!("set PC: {e}")))?;
            return Ok(());
        };

        if record.size != size || (token != 0 && record.token != token) {
            // Restore slot record on parameter mismatch
            let mut state = HOST_APERTURE.lock();
            state.slots[slot_idx] = Some(record);
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_INVALID)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            vcpu.set_reg(Reg::PC, pc + 4)
                .map_err(|e| TrapError::Hypervisor(format!("set PC: {e}")))?;
            return Ok(());
        }

        // Unmap from stage-2
        let rc = unsafe { crate::trap::inventory_hv_vm_unmap(ipa, record.size) };
        if rc != 0 {
            // Failed unmap: do NOT deallocate host memory to avoid UAF
            let mut state = HOST_APERTURE.lock();
            state.slots[slot_idx] = Some(record);
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_DENIED)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            vcpu.set_reg(Reg::PC, pc + 4)
                .map_err(|e| TrapError::Hypervisor(format!("set PC: {e}")))?;
            return Ok(());
        }

        // Deallocate host memory and clear bitmap slot
        unsafe {
            std::alloc::dealloc(record.host_ptr, record.layout);
        }
        {
            let mut state = HOST_APERTURE.lock();
            state.clear_slot_occupied(slot_idx);
        }

        RETURNS_COMPLETED.fetch_add(1, Ordering::Relaxed);
        BYTES_RETURNED.fetch_add(record.size as u64, Ordering::Relaxed);

        vcpu.set_reg(Reg::X0, METADATA_GRANT_SUCCESS)
            .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
        vcpu.set_reg(Reg::PC, pc + 4)
            .map_err(|e| TrapError::Hypervisor(format!("set PC: {e}")))?;
        Ok(())
    } else {
        vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_INVALID)
            .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
        vcpu.set_reg(Reg::PC, pc + 4)
            .map_err(|e| TrapError::Hypervisor(format!("set PC: {e}")))?;
        Ok(())
    }
}
