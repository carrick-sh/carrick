//! Native EL1 placement and mapped views of the one neutral COW grant pool.

use carrick_core_abi::COW_GRANT_SIZE;
pub use carrick_core_abi::{
    COW_DECLINE_REASONS, COW_GRANT_POOL_SLOTS, COW_GRANT_PROBES, COW_GRANT_PROTOCOL_VERSION,
    CowDecline, CowGrantPool, CowGrantRecord, CowGrantSettlement,
};

/// Offset of [`CowGrantPool`] in the EL1 region: the unused heap window
/// between the inotify name cache and the zone tables.
pub const EL1_COW_GRANT_POOL_OFFSET: u64 =
    crate::EL1_NAME_CACHE_OFFSET + crate::EL1_NAME_CACHE_SIZE;
pub const EL1_COW_GRANT_POOL_BASE: u64 = crate::EL1_REGION_BASE + EL1_COW_GRANT_POOL_OFFSET;

const _: () =
    assert!(EL1_COW_GRANT_POOL_OFFSET.is_multiple_of(core::mem::align_of::<CowGrantPool>() as u64));
const _: () = assert!(
    EL1_COW_GRANT_POOL_OFFSET + core::mem::size_of::<CowGrantPool>() as u64
        <= crate::EL1_ZONE_OFFSET
);
const _: () = assert!(COW_GRANT_POOL_SLOTS.is_power_of_two());
const _: () = assert!(COW_GRANT_PROBES <= COW_GRANT_POOL_SLOTS);

/// Layout facts folded into [`crate::EL1_ABI_LAYOUT_HASH`].
pub const COW_GRANT_LAYOUT_FACTS: [u64; 8] = [
    EL1_COW_GRANT_POOL_OFFSET,
    COW_GRANT_PROTOCOL_VERSION,
    COW_GRANT_POOL_SLOTS as u64,
    COW_GRANT_PROBES as u64,
    COW_GRANT_SIZE,
    core::mem::size_of::<CowGrantRecord>() as u64,
    core::mem::size_of::<CowGrantPool>() as u64,
    carrick_core_abi::COW_GRANT_RECORDS_OFFSET,
];

/// Host view of the pool, if an EL1 region is installed.
pub fn cow_grant_pool_host() -> Option<&'static CowGrantPool> {
    let ptr = crate::get_el1_region_host_ptr();
    if ptr == 0 {
        return None;
    }
    // SAFETY: the EL1 region owner keeps this mapping alive until it first
    // clears the region pointer; the pool holds only atomics, all-zero is an
    // empty pool, and the offset preserves its alignment.
    Some(unsafe { &*((ptr + EL1_COW_GRANT_POOL_OFFSET as usize) as *const CowGrantPool) })
}

/// Guest view of the pool. Call only while executing in the installed
/// Carrick EL1 image.
#[cfg(target_os = "none")]
pub fn cow_grant_pool_guest() -> &'static CowGrantPool {
    // SAFETY: EL1_COW_GRANT_POOL_BASE is inside the mapped kernel-only EL1
    // region and the layout is included in EL1_ABI_LAYOUT_HASH.
    unsafe { &*(EL1_COW_GRANT_POOL_BASE as *const CowGrantPool) }
}
