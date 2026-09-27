//! Host engine for servicing in-guest EL1 metadata extent grant (`HVC #6`) requests.

use carrick_el1_abi::{
    EL1_DYNAMIC_METADATA_BASE, EL1_DYNAMIC_METADATA_SIZE, METADATA_GRANT_ERR_DENIED,
    METADATA_GRANT_ERR_INVALID, METADATA_GRANT_ERR_NOT_FOUND, METADATA_GRANT_OP_ALLOC,
    METADATA_GRANT_OP_FREE, METADATA_GRANT_SUCCESS,
};
use carrick_hal::TrapError;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataGrantStats {
    pub extents_granted: u64,
    pub extents_returned: u64,
    pub grant_failures: u64,
}

struct GrantedExtentRecord {
    host_ptr: *mut u8,
    layout: std::alloc::Layout,
    size: usize,
    token: u64,
}

unsafe impl Send for GrantedExtentRecord {}
unsafe impl Sync for GrantedExtentRecord {}

static EXTENTS_GRANTED: AtomicU64 = AtomicU64::new(0);
static EXTENTS_RETURNED: AtomicU64 = AtomicU64::new(0);
static GRANT_FAILURES: AtomicU64 = AtomicU64::new(0);
static FAILPOINT_DENY_NEXT: AtomicBool = AtomicBool::new(false);
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
static NEXT_DYNAMIC_IPA: AtomicU64 = AtomicU64::new(EL1_DYNAMIC_METADATA_BASE);

static GRANTED_EXTENTS: Mutex<Option<HashMap<u64, GrantedExtentRecord>>> = Mutex::new(None);

/// Return a snapshot of metadata grant counters.
pub fn metadata_grant_stats() -> MetadataGrantStats {
    MetadataGrantStats {
        extents_granted: EXTENTS_GRANTED.load(Ordering::Relaxed),
        extents_returned: EXTENTS_RETURNED.load(Ordering::Relaxed),
        grant_failures: GRANT_FAILURES.load(Ordering::Relaxed),
    }
}

/// Arm failpoint to deny the next metadata extent allocation request.
pub fn arm_deny_next_metadata_grant() {
    FAILPOINT_DENY_NEXT.store(true, Ordering::SeqCst);
}

/// Reset all metadata grant statistics, failpoints, and active grant records.
pub fn reset_metadata_grant_state() {
    EXTENTS_GRANTED.store(0, Ordering::Relaxed);
    EXTENTS_RETURNED.store(0, Ordering::Relaxed);
    GRANT_FAILURES.store(0, Ordering::Relaxed);
    FAILPOINT_DENY_NEXT.store(false, Ordering::SeqCst);
    NEXT_TOKEN.store(1, Ordering::Relaxed);
    NEXT_DYNAMIC_IPA.store(EL1_DYNAMIC_METADATA_BASE, Ordering::Relaxed);

    let mut lock = GRANTED_EXTENTS.lock();
    if let Some(mut map) = lock.take() {
        for (ipa, record) in map.drain() {
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
        // Failpoint denial check
        if FAILPOINT_DENY_NEXT.swap(false, Ordering::SeqCst) {
            GRANT_FAILURES.fetch_add(1, Ordering::Relaxed);
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_DENIED)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            vcpu.set_reg(Reg::PC, pc + 4)
                .map_err(|e| TrapError::Hypervisor(format!("set PC: {e}")))?;
            return Ok(());
        }

        let requested_size = arg1 as usize;
        let size = (requested_size.max(64 * 1024) + 0xFFFF) & !0xFFFF;

        let ipa = NEXT_DYNAMIC_IPA.fetch_add(size as u64, Ordering::SeqCst);
        if ipa.saturating_add(size as u64) > EL1_DYNAMIC_METADATA_BASE + EL1_DYNAMIC_METADATA_SIZE {
            GRANT_FAILURES.fetch_add(1, Ordering::Relaxed);
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_DENIED)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            vcpu.set_reg(Reg::PC, pc + 4)
                .map_err(|e| TrapError::Hypervisor(format!("set PC: {e}")))?;
            return Ok(());
        }

        let layout = std::alloc::Layout::from_size_align(size, 4096)
            .map_err(|e| TrapError::Hypervisor(format!("bad layout for grant size {size}: {e}")))?;
        let host_ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        if host_ptr.is_null() {
            GRANT_FAILURES.fetch_add(1, Ordering::Relaxed);
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_DENIED)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            vcpu.set_reg(Reg::PC, pc + 4)
                .map_err(|e| TrapError::Hypervisor(format!("set PC: {e}")))?;
            return Ok(());
        }

        let permissions = 0b111; // HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC
        let rc =
            unsafe { crate::trap::inventory_hv_vm_map(host_ptr.cast(), ipa, size, permissions) };
        if rc != 0 {
            unsafe {
                std::alloc::dealloc(host_ptr, layout);
            }
            GRANT_FAILURES.fetch_add(1, Ordering::Relaxed);
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_DENIED)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            vcpu.set_reg(Reg::PC, pc + 4)
                .map_err(|e| TrapError::Hypervisor(format!("set PC: {e}")))?;
            return Ok(());
        }

        let token = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
        {
            let mut lock = GRANTED_EXTENTS.lock();
            let map = lock.get_or_insert_with(HashMap::new);
            map.insert(
                ipa,
                GrantedExtentRecord {
                    host_ptr,
                    layout,
                    size,
                    token,
                },
            );
        }

        EXTENTS_GRANTED.fetch_add(1, Ordering::Relaxed);

        vcpu.set_reg(Reg::X0, METADATA_GRANT_SUCCESS)
            .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
        vcpu.set_reg(Reg::X1, ipa)
            .map_err(|e| TrapError::Hypervisor(format!("set X1: {e}")))?;
        vcpu.set_reg(Reg::X2, size as u64)
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

        let record_opt = {
            let mut lock = GRANTED_EXTENTS.lock();
            lock.as_mut().and_then(|map| map.remove(&ipa))
        };

        let Some(record) = record_opt else {
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_NOT_FOUND)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            vcpu.set_reg(Reg::PC, pc + 4)
                .map_err(|e| TrapError::Hypervisor(format!("set PC: {e}")))?;
            return Ok(());
        };

        if record.size != size || record.token != token {
            // Put it back if token/size mismatched
            let mut lock = GRANTED_EXTENTS.lock();
            if let Some(map) = lock.as_mut() {
                map.insert(ipa, record);
            }
            vcpu.set_reg(Reg::X0, METADATA_GRANT_ERR_INVALID)
                .map_err(|e| TrapError::Hypervisor(format!("set X0: {e}")))?;
            vcpu.set_reg(Reg::PC, pc + 4)
                .map_err(|e| TrapError::Hypervisor(format!("set PC: {e}")))?;
            return Ok(());
        }

        unsafe {
            let _ = crate::trap::inventory_hv_vm_unmap(ipa, record.size);
            std::alloc::dealloc(record.host_ptr, record.layout);
        }

        EXTENTS_RETURNED.fetch_add(1, Ordering::Relaxed);

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
