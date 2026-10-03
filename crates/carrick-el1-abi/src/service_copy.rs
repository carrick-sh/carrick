//! Slot-owned temporary aliases used only on the carrier maintenance root.
use core::sync::atomic::{AtomicU64, Ordering};

pub const EL1_SERVICE_COPY_TABLE_OFFSET: u64 = 0x1B_0000;
pub const EL1_SERVICE_COPY_TABLE_BASE: u64 = crate::EL1_REGION_BASE + EL1_SERVICE_COPY_TABLE_OFFSET;
pub const EL1_SERVICE_COPY_BASE: u64 = 0x2D_3FE0_0000;
pub const EL1_SERVICE_COPY_SIZE: u64 = crate::EL1_STACK_SLOTS * 2 * 4096;
pub const EL1_CARRIER_MAINT_ROOT_BASE: u64 = 0x2D_001F_8000;
pub const EL1_CARRIER_MAINT_ROOT_SIZE: u64 = 0x4000;

/// Authenticate a host service's claimed slot against the executing EL1
/// stack. A request cannot borrow another executor's alias or wire slots.
pub fn service_slot_from_stack(sp: u64, claimed: u64) -> Option<crate::SlotId> {
    let offset = sp.checked_sub(crate::EL1_STACKS_BASE)?;
    if offset >= crate::EL1_STACK_SLOTS * crate::EL1_STACK_SIZE {
        return None;
    }
    let index = offset / crate::EL1_STACK_SIZE;
    if index != claimed {
        return None;
    }
    crate::SlotId::from_index(index as usize)
}

/// Translation geometry only; callers must separately own the exact target
/// MM generation and editor. A carrier root never uses the current-MM alias.
pub fn service_target_table_window(
    live_ttbr: u64,
    target_ttbr: u64,
) -> Option<carrick_mmu_core::aarch64::descriptor_txn::TableWindow> {
    let root = target_ttbr & 0x0000_FFFF_FFFF_F000;
    let bytes = crate::AARCH64_STAGE1_TABLES_PRIMARY_SIZE;
    let in_pool = root >= crate::AARCH64_STAGE1_TABLE_POOL_BASE
        && root.checked_add(bytes)?
            <= crate::AARCH64_STAGE1_TABLE_POOL_BASE + crate::AARCH64_STAGE1_TABLE_POOL_SIZE;
    let words = if live_ttbr == EL1_CARRIER_MAINT_ROOT_BASE {
        if !in_pool {
            return None;
        }
        root
    } else if live_ttbr == target_ttbr {
        if in_pool {
            root
        } else {
            crate::AARCH64_STAGE1_TABLES_ALIAS_BASE
        }
    } else {
        return None;
    };
    Some(carrick_mmu_core::aarch64::descriptor_txn::TableWindow {
        words: words as *mut AtomicU64,
        physical_base: root,
        byte_len: bytes as usize,
    })
}

/// The first page is an L3 table, followed by exclusive slot claims. Zero
/// initialization is valid. Carrier physical custody retains this region for
/// every executor; counters and per-MM alias cleanup never own these bytes.
#[repr(C, align(4096))]
pub struct ServiceCopyTable {
    leaves: [AtomicU64; 512],
    claims: [AtomicU64; crate::EL1_STACK_SLOTS as usize],
}

impl ServiceCopyTable {
    pub const fn new() -> Self {
        Self {
            leaves: [const { AtomicU64::new(0) }; 512],
            claims: [const { AtomicU64::new(0) }; crate::EL1_STACK_SLOTS as usize],
        }
    }

    /// Refuses reentry instead of waiting for another executor. The caller
    /// supplies its scheduler-owned slot, never a user-selected number.
    pub fn try_claim(&self, slot: crate::SlotId) -> Option<ServiceCopyLease<'_>> {
        let index = usize::from(slot.raw());
        let claim = &self.claims[index];
        claim
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        let base = EL1_SERVICE_COPY_BASE + index as u64 * 8192;
        for page in 0..2 {
            let idle = base + page as u64 * 4096;
            let word = &self.leaves[index * 2 + page];
            // Only the successful slot claimant may initialize these leaves.
            let value = word.load(Ordering::Acquire);
            if value == 0 {
                word.store(idle, Ordering::Release);
            } else {
                // Do not release a slot whose mappings still name live bytes.
                assert_eq!(value, idle, "maintenance copy slot retained a live alias");
            }
        }
        Some(ServiceCopyLease {
            table: self,
            slot,
            base,
            executor: core::marker::PhantomData,
        })
    }
}

impl Default for ServiceCopyTable {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ServiceCopyLease<'a> {
    table: &'a ServiceCopyTable,
    slot: crate::SlotId,
    base: u64,
    // ASID-0 invalidation is local: custody cannot move to another CPU.
    executor: core::marker::PhantomData<*mut ()>,
}

impl ServiceCopyLease<'_> {
    pub fn base(&self) -> u64 {
        self.base
    }
}

impl Drop for ServiceCopyLease<'_> {
    fn drop(&mut self) {
        let index = usize::from(self.slot.raw());
        for page in 0..2 {
            assert_eq!(
                self.table.leaves[index * 2 + page].load(Ordering::Acquire),
                self.base + page as u64 * 4096,
                "cannot recycle a maintenance copy slot before alias restoration"
            );
        }
        self.table.claims[index].store(0, Ordering::Release);
    }
}

const _: () = assert!(EL1_SERVICE_COPY_SIZE == 2 * 1024 * 1024);
const _: () = assert!(crate::EL1_IPC_BASE + crate::EL1_IPC_SIZE <= EL1_SERVICE_COPY_BASE);
const _: () = assert!(EL1_SERVICE_COPY_BASE + EL1_SERVICE_COPY_SIZE == 0x2D_4000_0000);
const _: () =
    assert!(crate::EL1_COW_COPY_OFFSET + crate::EL1_COW_COPY_SIZE <= EL1_SERVICE_COPY_TABLE_OFFSET);
const _: () = assert!(
    EL1_SERVICE_COPY_TABLE_OFFSET + core::mem::size_of::<ServiceCopyTable>() as u64
        <= crate::EL1_MM_PORTAL_OFFSET
);
const _: () = assert!(core::mem::offset_of!(ServiceCopyTable, claims) == 4096);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;
    #[test]
    fn service_copy_slots_are_disjoint_and_refuse_live_reentry() {
        let table = ServiceCopyTable::new();
        let mut leases = Vec::new();
        for raw in 0..=u8::MAX {
            let slot = crate::SlotId::new(raw);
            let lease = table.try_claim(slot).unwrap();
            assert_eq!(lease.base(), EL1_SERVICE_COPY_BASE + u64::from(raw) * 8192);
            assert!(table.try_claim(slot).is_none());
            leases.push(lease);
        }
        drop(leases);
        for raw in 0..=u8::MAX {
            drop(table.try_claim(crate::SlotId::new(raw)).unwrap());
        }
    }

    #[test]
    fn maintenance_service_authenticates_target_pool_not_current_alias() {
        let root = crate::AARCH64_STAGE1_TABLE_POOL_BASE + 0x20_0000;
        let target = root | (23 << 48);
        let window = service_target_table_window(EL1_CARRIER_MAINT_ROOT_BASE, target).unwrap();
        assert_eq!(window.physical_base, root);
        assert_eq!(window.words as u64, root);
        assert!(service_target_table_window(target + 4096, target).is_none());
        assert!(service_target_table_window(EL1_CARRIER_MAINT_ROOT_BASE, 0x8000).is_none());
        assert!(
            service_target_table_window(EL1_CARRIER_MAINT_ROOT_BASE | (1 << 48), target).is_none()
        );
        assert!(
            service_target_table_window(
                EL1_CARRIER_MAINT_ROOT_BASE,
                crate::AARCH64_STAGE1_TABLE_POOL_BASE + crate::AARCH64_STAGE1_TABLE_POOL_SIZE
                    - 4096
            )
            .is_none()
        );
    }

    #[test]
    fn service_slot_requires_the_executing_stack() {
        for index in 0..crate::EL1_STACK_SLOTS {
            let sp = crate::EL1_STACKS_BASE + index * crate::EL1_STACK_SIZE + 128;
            assert_eq!(
                service_slot_from_stack(sp, index).unwrap().raw() as u64,
                index
            );
            assert!(service_slot_from_stack(sp, (index + 1) % crate::EL1_STACK_SLOTS).is_none());
        }
        assert!(service_slot_from_stack(crate::EL1_STACKS_BASE - 1, 0).is_none());
        assert!(
            service_slot_from_stack(
                crate::EL1_STACKS_BASE + crate::EL1_STACK_SLOTS * crate::EL1_STACK_SIZE,
                0
            )
            .is_none()
        );
    }
}
