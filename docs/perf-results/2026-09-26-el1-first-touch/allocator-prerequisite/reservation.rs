use carrick_el1::alloc::BumpAllocator;
use carrick_el1_abi::{EL1_OBJECT_TABLE_BASE, EL1_OBJECT_TABLE_SIZE};
#[test]
fn dynamic_metadata_must_not_overlap_live_object_table() {
    let allocator = BumpAllocator::new();
    let address = allocator.allocate(64, 8).expect("first allocation") as u64;
    let object_end = EL1_OBJECT_TABLE_BASE + EL1_OBJECT_TABLE_SIZE;
    assert!(address + 64 <= EL1_OBJECT_TABLE_BASE || address >= object_end,
        "metadata allocation {address:#x} overlaps the assigned EL1 object table");
}
