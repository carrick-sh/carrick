//! Leaf selection must retain a native physical extent exactly once per MM.
#![allow(clippy::unwrap_used)]
use carrick_core::mm::frames::{ForkFrameExtent, ForkFrameInventory, FrameReferences};
use carrick_guest_arch::{FrameGpa, GuestLen};

fn extent(start: u64, len: u64) -> ForkFrameExtent {
    ForkFrameExtent::new(FrameGpa::new(start), GuestLen::new(len)).unwrap()
}

#[test]
fn fork_leaf_inventory_keeps_native_compound_and_one_reference() {
    for base in [0x2e00000000, 0x9b00000000] {
        for population in [1, 4, 1024] {
            for imported in [false, true] {
                let physical = extent(base, 0x4000);
                let mut inventory = ForkFrameInventory::default();
                let mut references = FrameReferences::default();
                references.retain().unwrap(); // live parent
                let mut publications = 0;
                for ordinal in 0..population {
                    let selected = extent(base + (ordinal % 4) * 0x1000, 0x1000);
                    if let Some(inherited) = inventory
                        .select(selected, physical, imported.then_some(physical))
                        .unwrap()
                    {
                        assert_eq!(
                            inherited, physical,
                            "a selected 4 KiB leaf must retain its 16 KiB COW source"
                        );
                        references.retain().unwrap();
                        publications += 1;
                    }
                }
                assert_eq!(
                    publications, 1,
                    "aliases cannot manufacture frame references"
                );
                assert_eq!(references.count(), 2);
                assert!(!references.unmap().unwrap());
                assert_eq!(
                    references.count(),
                    1,
                    "child retirement must preserve parent"
                );
            }
        }
    }
}

#[test]
fn fork_inventory_retains_logical_fragment_inside_larger_stage2_lease() {
    let mut inventory = ForkFrameInventory::default();
    let physical = extent(0x9b00000000, 0x100000);
    let source = extent(0x9b00004000, 0x8000);
    let selected = extent(0x9b00005000, 0x1000);
    assert_eq!(
        inventory.select(selected, physical, Some(source)).unwrap(),
        Some(source)
    );
}
