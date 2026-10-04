#![allow(clippy::unwrap_used)]
use super::*;
use carrick_guest_arch::{ContextGeneration, MmGeneration};
fn nz(n: u64) -> NonZeroU64 {
    NonZeroU64::new(n).unwrap()
}
fn root(pa: u64) -> RootGpa {
    RootGpa::page_aligned(FrameGpa::new(pa)).unwrap()
}
fn backing(pa: u64, len: usize, tag: u64) -> PreparedBacking {
    PreparedBacking {
        extent: Arc::new(BackingExtent::private(FrameGpa::new(pa), len).unwrap()),
        identity: BackingIdentity {
            frame_id: nz(tag),
            mapping_id: nz(tag),
            owner_generation: nz(tag),
            inventory_revision: nz(tag),
        },
    }
}
#[test]
fn failed_second_memslot_install_restores_custody_and_reuses_slot_zero() {
    let mut memory = CarrierMemory::create().unwrap();
    memory.fail_install = Some(1);
    let a = backing(0x1000, PAGE as usize, 1);
    let b = backing(0x2000, PAGE as usize, 2);
    assert!(memory.install(&[a.clone(), b]).is_err());
    assert_eq!(
        memory.slot_count(),
        0,
        "all earlier physical publications must roll back"
    );
    assert_eq!(memory.retained_bytes(), 0);
    memory.fail_install = None;
    assert_eq!(
        memory.install(&[a]).unwrap()[0].slot_index(),
        0,
        "failed installs do not burn IDs"
    );
}
struct Inventory {
    live: bool,
    fail_publish: bool,
    fail_commit: bool,
    fail_rollback: bool,
}
impl InventoryTransaction for Inventory {
    fn publish(&mut self) -> Result<(), MemoryError> {
        self.live = true;
        if self.fail_publish {
            Err(error("injected inventory publish failure"))
        } else {
            Ok(())
        }
    }
    fn commit(&mut self, _: &DescriptorReceipt) -> Result<(), MemoryError> {
        if self.fail_commit {
            Err(error("injected inventory commit failure"))
        } else {
            Ok(())
        }
    }
    fn rollback(&mut self) -> Result<(), MemoryError> {
        if self.fail_rollback {
            Err(error("injected rollback failure"))
        } else {
            self.live = false;
            Ok(())
        }
    }
}
#[test]
fn inventory_failure_restores_descriptors_slots_and_inventory_as_one_unit() {
    for fail_commit in [false, true] {
        let mut memory = CarrierMemory::create().unwrap();
        memory.install(&[backing(0x1000, 0x4000, 1)]).unwrap();
        let context = AddressContext {
            root: root(0x1000),
            mm: MmGeneration::new(nz(1)),
            generation: ContextGeneration::new(nz(1)),
        };
        memory.install_root(nz(1), context).unwrap();
        let data = backing(0x800000, 4096, 2);
        let tables = [root(0x2000), root(0x3000), root(0x4000)];
        let txn = DescriptorTxn {
            id: DescriptorTxnId {
                mm_key: nz(1),
                generation: nz(1),
            },
            root: context.root,
            tables: &tables,
            op: DescriptorOp::Map {
                span: PageSpan::new(0x4000, PAGE),
                output: FrameGpa::new(0x800000),
                permissions: Permissions {
                    writable: true,
                    executable: false,
                    user: true,
                },
                size: LeafSize::Page,
                resident: true,
                backing: data.identity,
            },
        };
        let before = memory.read(FrameGpa::new(0x1000), 0x4000).unwrap();
        let mut inventory = Inventory {
            live: false,
            fail_publish: !fail_commit,
            fail_commit,
            fail_rollback: false,
        };
        assert!(memory.publish(&txn, &[data], &mut inventory).is_err());
        assert!(!inventory.live);
        assert_eq!(memory.slot_count(), 1);
        assert_eq!(memory.read(FrameGpa::new(0x1000), 0x4000).unwrap(), before);
        assert!(memory.read(FrameGpa::new(0x800000), 1).is_err());
    }
}
#[test]
fn inventory_rollback_failure_quarantines_and_retains_registered_bytes() {
    let mut memory = CarrierMemory::create().unwrap();
    memory.install(&[backing(0x1000, 0x4000, 1)]).unwrap();
    let context = AddressContext {
        root: root(0x1000),
        mm: MmGeneration::new(nz(1)),
        generation: ContextGeneration::new(nz(1)),
    };
    memory.install_root(nz(1), context).unwrap();
    let data = backing(0x800000, 4096, 2);
    let tables = [root(0x2000), root(0x3000), root(0x4000)];
    let txn = DescriptorTxn {
        id: DescriptorTxnId {
            mm_key: nz(1),
            generation: nz(1),
        },
        root: context.root,
        tables: &tables,
        op: DescriptorOp::Map {
            span: PageSpan::new(0x4000, PAGE),
            output: FrameGpa::new(0x800000),
            permissions: Permissions {
                writable: true,
                executable: false,
                user: true,
            },
            size: LeafSize::Page,
            resident: true,
            backing: data.identity,
        },
    };
    let mut inventory = Inventory {
        live: false,
        fail_publish: true,
        fail_commit: false,
        fail_rollback: true,
    };
    assert!(memory.publish(&txn, &[data], &mut inventory).is_err());
    assert!(memory.is_quarantined());
    assert_eq!(memory.slot_count(), 2);
    assert!(memory.install(&[backing(0x900000, 4096, 3)]).is_err());
    assert!(memory.read(FrameGpa::new(0x1000), 8).is_err());
}
#[test]
fn extent_custody_scales_in_bytes_not_page_slots() {
    for pages in [16, 64, 256] {
        let mut memory = CarrierMemory::create().unwrap();
        memory
            .install(&[backing(0x100000, pages * 4096, 1)])
            .unwrap();
        assert_eq!(memory.slot_count(), 1);
        assert_eq!(memory.retained_bytes(), pages * 4096);
    }
}
#[test]
fn physical_alias_unlink_visits_only_touched_edges_at_three_populations() {
    for population in [16, 128, 512] {
        let mut memory = CarrierMemory::create().unwrap();
        let handle = memory.install(&[backing(0x100000, 4096, 1)]).unwrap()[0];
        let context = AddressContext {
            root: root(0x100000),
            mm: MmGeneration::new(nz(1)),
            generation: ContextGeneration::new(nz(1)),
        };
        let aliases = memory.aliases.entry(nz(1)).or_default();
        for index in 0..population {
            let span = PageSpan::new(0x10000 + index * 3 * PAGE, 2 * PAGE);
            aliases.insert(
                span.va,
                Alias {
                    slot: handle.slot,
                    span,
                },
            );
        }
        memory.slots.get_mut(&handle.slot).unwrap().alias_count = population as usize;
        memory.remove_aliases(nz(1), PageSpan::new(0x10000 + PAGE, PAGE), context);
        assert_eq!(
            memory.alias_visits, 1,
            "512 unrelated edges cannot amplify unlink"
        );
        assert_eq!(memory.aliases[&nz(1)][&0x10000].span.len, PAGE);
        assert_eq!(memory.slots[&handle.slot].alias_count, population as usize);
    }
}
struct TestDrain {
    calls: usize,
    fail: bool,
}
// SAFETY: these unit cases register no CPUs; the test contexts have no live
// translation users. Failure injection tests the receipt ordering only.
unsafe impl TranslationDrain for TestDrain {
    fn drain(&mut self, _: ShootdownPlan) -> Result<(), MemoryError> {
        self.calls += 1;
        if self.fail {
            Err(error("injected drain failure"))
        } else {
            Ok(())
        }
    }
}
struct Retirement {
    failed: bool,
    live: bool,
}
impl InventoryRetirement for Retirement {
    fn retire(&mut self, _: BackingIdentity) -> Result<(), MemoryError> {
        self.live = false;
        if self.failed {
            Err(error("injected retirement failure"))
        } else {
            Ok(())
        }
    }
    fn rollback(&mut self) -> Result<(), MemoryError> {
        self.live = true;
        Ok(())
    }
}
#[test]
fn drain_failure_retains_slot_and_retirement_failure_reinstalls_same_generation() {
    let mut memory = CarrierMemory::create().unwrap();
    let handle = memory.install(&[backing(0x100000, 4096, 1)]).unwrap()[0];
    let context = AddressContext {
        root: root(0x100000),
        mm: MmGeneration::new(nz(1)),
        generation: ContextGeneration::new(nz(1)),
    };
    memory
        .slots
        .get_mut(&handle.slot)
        .unwrap()
        .drains
        .push(context);
    let mut drain = TestDrain {
        calls: 0,
        fail: true,
    };
    let mut retirement = Retirement {
        failed: true,
        live: true,
    };
    assert!(memory.revoke(handle, &mut drain, &mut retirement).is_err());
    assert_eq!(memory.slot_count(), 1);
    assert!(retirement.live);
    drain.fail = false;
    assert!(memory.revoke(handle, &mut drain, &mut retirement).is_err());
    assert_eq!(memory.record(handle).unwrap().handle, handle);
    assert!(retirement.live);
    assert!(!memory.is_quarantined());
    retirement.failed = false;
    memory.revoke(handle, &mut drain, &mut retirement).unwrap();
    assert_eq!(memory.slot_count(), 0);
    assert!(!retirement.live);
    let replacement = memory.install(&[backing(0x100000, 4096, 2)]).unwrap()[0];
    assert_eq!(replacement.slot, handle.slot);
    assert_ne!(replacement.generation, handle.generation);
}
