#![allow(clippy::unwrap_used)]
use super::*;
use carrick_guest_arch::{ContextGeneration, MmGeneration};
use carrick_hal::{HvVcpu, VcpuExit};
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
fn one_memslot_authenticates_each_inventoried_frame_independently() {
    let mut memory = CarrierMemory::create().unwrap();
    let handle = memory
        .install(&[backing(0x800000, 3 * PAGE as usize, 9)])
        .unwrap()[0];
    let first = backing(0x900000, PAGE as usize, 11).identity;
    let second = backing(0xa00000, PAGE as usize, 12).identity;
    memory
        .bind_frame_identities(
            handle,
            &[
                (FrameGpa::new(0x800000), first),
                (FrameGpa::new(0x801000), second),
            ],
        )
        .unwrap();
    let map = |gpa, identity| DescriptorOp::Map {
        span: PageSpan::new(0x4000, PAGE),
        output: FrameGpa::new(gpa),
        permissions: Permissions {
            writable: true,
            executable: false,
            user: true,
        },
        size: LeafSize::Page,
        resident: true,
        backing: identity,
    };
    assert!(memory.authenticate(nz(1), map(0x800000, first)).is_ok());
    assert!(memory.authenticate(nz(1), map(0x801000, second)).is_ok());
    assert!(memory.authenticate(nz(1), map(0x800000, second)).is_err());
    assert!(memory.authenticate(nz(1), map(0x801000, first)).is_err());
    assert!(memory.authenticate(nz(1), map(0x802000, first)).is_err());
}

#[test]
fn three_vcpus_observe_one_carrier_backing_in_order() {
    let mut machine = CarrierMachine::create_stopped(3).unwrap();
    let mut extent = BackingExtent::private(FrameGpa::new(0), PAGE as usize).unwrap();
    // Real-mode MOV AL, [0x100]; OUT 0xe9, AL; HLT. Each KVM_RUN must
    // observe the same retained host page through its own vCPU in this VM.
    extent
        .initialize(0, &[0xa0, 0x00, 0x01, 0xe6, 0xe9, 0xf4])
        .unwrap();
    extent.initialize(0x100, b"A").unwrap();
    let backing = PreparedBacking {
        extent: Arc::new(extent),
        identity: BackingIdentity {
            frame_id: nz(1),
            mapping_id: nz(1),
            owner_generation: nz(1),
            inventory_revision: nz(1),
        },
    };
    machine.memory_mut().install(&[backing]).unwrap();
    assert_eq!(machine.memory_mut().slot_count(), 1);
    for index in 0..machine.vcpu_count() {
        let cpu = machine.cpu_mut(index).unwrap();
        let mut sregs = cpu.fd().get_sregs().unwrap();
        sregs.cs.base = 0;
        sregs.cs.selector = 0;
        sregs.ds.base = 0;
        sregs.ds.selector = 0;
        cpu.fd().set_sregs(&sregs).unwrap();
        let mut regs = cpu.fd().get_regs().unwrap();
        regs.rip = 0;
        regs.rflags = 2;
        cpu.fd().set_regs(&regs).unwrap();
        let exit = HvVcpu::run(cpu).unwrap();
        assert!(
            matches!(&exit, VcpuExit::IoOut { port: 0xe9, data } if data == &[b'A' + index as u8]),
            "vCPU {index} did not read the current shared GPA byte"
        );
        machine
            .memory_mut()
            .write(FrameGpa::new(0x100), &[b'B' + index as u8])
            .unwrap();
    }
    assert_eq!(machine.memory_mut().retained_bytes(), PAGE as usize);
}

#[test]
fn carrier_publication_requires_an_already_applied_guest_edit() {
    let mut memory = CarrierMemory::create().unwrap();
    memory.install(&[backing(0x1000, 0x4000, 1)]).unwrap();
    let context = AddressContext {
        root: root(0x1000),
        mm: MmGeneration::new(nz(1)),
        generation: ContextGeneration::new(nz(1)),
    };
    memory.install_root(nz(1), context).unwrap();
    let data = backing(0x800000, 4096, 2);
    let txn = DescriptorTxn {
        id: DescriptorTxnId {
            mm_key: nz(1),
            generation: nz(1),
        },
        root: context.root,
        tables: &[root(0x2000), root(0x3000), root(0x4000)],
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
        fail_publish: false,
        fail_commit: false,
        fail_rollback: false,
    };
    memory.prepare(&[data], &mut inventory).unwrap();
    let forged = GuestMmuPublication {
        revision: GuestMmuPublication::REVISION,
        outcome: GuestMmuPublication::APPLIED,
        mm_key: 1,
        root_gpa: 0x1000,
        generation: 1,
        edit_identity: txn.edit_identity(),
        span_va: 0x4000,
        span_len: PAGE,
        live_stores: 4,
        tables_linked: 3,
    };
    assert!(memory.publish(&txn, forged, &mut inventory).is_err());
    assert!(memory.is_quarantined());
    assert_eq!(memory.words().load(0x1000).unwrap(), 0);
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
    fn commit(&mut self, _: &GuestMmuPublication) -> Result<(), MemoryError> {
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
fn inventory_failure_before_guest_edit_rolls_back_and_after_edit_quarantines() {
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
        if !fail_commit {
            assert!(memory.prepare(&[data], &mut inventory).is_err());
            assert!(!inventory.live);
            assert_eq!(memory.slot_count(), 1);
            assert_eq!(memory.read(FrameGpa::new(0x1000), 0x4000).unwrap(), before);
            assert!(memory.read(FrameGpa::new(0x800000), 1).is_err());
        } else {
            memory.prepare(&[data], &mut inventory).unwrap();
            // Fixture-only guest executor: CarrierMemory::publish must consume
            // the result without authoring or undoing a descriptor.
            let receipt = execute_descriptor_txn(
                &memory.words(),
                &txn,
                context.root,
                &mut InlineJournal::new(),
            );
            let publication = GuestMmuPublication::from_x86_receipt(&txn, &receipt).unwrap();
            assert!(memory.publish(&txn, publication, &mut inventory).is_err());
            assert!(memory.is_quarantined());
            assert!(inventory.live);
            assert_eq!(memory.slot_count(), 2);
            assert_ne!(memory.words().load(0x1000).unwrap(), 0);
        }
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
    let mut inventory = Inventory {
        live: false,
        fail_publish: true,
        fail_commit: false,
        fail_rollback: true,
    };
    assert!(memory.prepare(&[data], &mut inventory).is_err());
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
                    inherited: None,
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

#[test]
fn two_live_vms_reject_each_others_local_mm_backing_capabilities() {
    let mut first = CarrierMemory::create().unwrap();
    let mut second = CarrierMemory::create().unwrap();
    let first_handle = first.install(&[backing(0x1000, PAGE as usize, 1)]).unwrap()[0];
    let second_handle = second
        .install(&[backing(0x1000, PAGE as usize, 1)])
        .unwrap()[0];
    assert_eq!(first_handle.slot_index(), second_handle.slot_index());
    assert_eq!(first_handle.generation(), second_handle.generation());
    let context = AddressContext {
        root: root(0x1000),
        mm: MmGeneration::new(nz(1)),
        generation: ContextGeneration::new(nz(1)),
    };
    first.install_root(nz(1), context).unwrap();
    second.install_root(nz(1), context).unwrap();
    assert_eq!(first.root(nz(1)), second.root(nz(1)));
    assert!(
        first.record(second_handle).is_err(),
        "foreign VM handle authenticated as local backing"
    );
    assert!(second.record(first_handle).is_err());
    let edge = first.share(first_handle).unwrap();
    assert!(second.attach_shared(nz(1), &edge).is_err());
    assert!(
        second
            .bind_frame_identities(
                first_handle,
                &[(
                    FrameGpa::new(0x1000),
                    backing(0x2000, PAGE as usize, 2).identity
                )]
            )
            .is_err()
    );
    first.write(FrameGpa::new(0x1000), b"A").unwrap();
    second.write(FrameGpa::new(0x1000), b"B").unwrap();
    assert_eq!(first.read(FrameGpa::new(0x1000), 1).unwrap(), b"A");
    assert_eq!(second.read(FrameGpa::new(0x1000), 1).unwrap(), b"B");
}

#[test]
fn inherited_inventory_edges_authorize_only_selected_child_pages() {
    use carrick_hal::{
        FrameEventCapacity, FrameId, FrameInventoryEvent, FrameLength, MappingGeneration, MemPerms,
    };
    use carrick_kernel::kernel::frame_inventory::FrameInventoryAuthority;
    use carrick_kernel::kernel::{MmId, ObjectIdRegistry};
    let authority = Arc::new(FrameInventoryAuthority::new());
    let ids = Arc::new(ObjectIdRegistry::new());
    let parent_mm = ids.mm_id().unwrap();
    let child_mm = ids.mm_id().unwrap();
    let inventory_row = |mm: MmId, inherited: Option<FrameId>, gpa: u64| {
        let mut reservation = authority
            .reserve(
                &ids,
                usize::from(inherited.is_none()),
                1,
                FrameEventCapacity::for_event_count(2).unwrap(),
            )
            .unwrap();
        let transaction = reservation.transaction();
        let frame = inherited.unwrap_or_else(|| reservation.claim_frame().unwrap());
        let mapping = reservation.claim_mapping().unwrap();
        let generation = MappingGeneration::from_backend_counter(nz(1));
        reservation
            .push(FrameInventoryEvent::PrepareMapping {
                transaction,
                frame,
                mapping,
                generation,
                gpa: carrick_guest_mem::Gpa(gpa),
                length: FrameLength::from_mapping_extent(nz(PAGE)),
                permissions: MemPerms {
                    read: true,
                    write: true,
                    exec: false,
                },
            })
            .unwrap();
        reservation
            .push(FrameInventoryEvent::PublishMapping {
                transaction,
                mapping,
                generation,
            })
            .unwrap();
        let (_, receipt) = authority
            .apply_with_receipt(mm, reservation.commit(()))
            .unwrap();
        (
            BackingIdentity {
                frame_id: nz(frame.raw()),
                mapping_id: nz(mapping.raw()),
                owner_generation: nz(1),
                inventory_revision: nz(receipt.revision()),
            },
            receipt,
        )
    };
    let (first, _) = inventory_row(parent_mm, None, 0x800000);
    let (adjacent, _) = inventory_row(parent_mm, None, 0x801000);
    let (child_identity, child_receipt) = inventory_row(
        child_mm,
        Some(FrameId::from_kernel_allocation(first.frame_id)),
        0x800000,
    );
    let (child_adjacent, _) = inventory_row(
        child_mm,
        Some(FrameId::from_kernel_allocation(adjacent.frame_id)),
        0x801000,
    );
    let mut memory = CarrierMemory::create().unwrap();
    memory.install(&[backing(0x1000, 0x8000, 90)]).unwrap();
    let data = memory.install(&[backing(0x800000, 0x2000, 91)]).unwrap()[0];
    memory
        .bind_frame_identities(
            data,
            &[
                (FrameGpa::new(0x800000), first),
                (FrameGpa::new(0x801000), adjacent),
            ],
        )
        .unwrap();
    let contexts = [parent_mm, child_mm].map(|mm| AddressContext {
        root: root(if mm == parent_mm { 0x1000 } else { 0x5000 }),
        mm: MmGeneration::new(nz(mm.raw())),
        generation: ContextGeneration::new(nz(1)),
    });
    for context in contexts {
        memory.install_root(context.mm.raw(), context).unwrap();
    }
    let map = |context: AddressContext<RootGpa>, va, gpa, identity| DescriptorTxn {
        id: DescriptorTxnId {
            mm_key: context.mm.raw(),
            generation: nz(1),
        },
        root: context.root,
        tables: &[],
        op: DescriptorOp::Map {
            span: PageSpan::new(va, PAGE),
            output: FrameGpa::new(gpa),
            permissions: Permissions {
                writable: true,
                executable: false,
                user: true,
            },
            size: LeafSize::Page,
            resident: true,
            backing: identity,
        },
    };
    let mut inventory = Inventory {
        live: true,
        fail_publish: false,
        fail_commit: false,
        fail_rollback: false,
    };
    for (index, context) in contexts.into_iter().enumerate() {
        let tables = if index == 0 {
            [root(0x2000), root(0x3000), root(0x4000)]
        } else {
            [root(0x6000), root(0x7000), root(0x8000)]
        };
        let mut txn = map(context, 0x4000, 0x800000, first);
        txn.op = DescriptorOp::Prepare {
            span: PageSpan::new(0x4000, PAGE),
            output: FrameGpa::new(0x800000),
            permissions: Permissions {
                writable: true,
                executable: false,
                user: true,
            },
            resident: PageSpan::new(0x4000, PAGE),
            backing: first,
        };
        txn.tables = &tables;
        let receipt = execute_descriptor_txn(
            &memory.words(),
            &txn,
            context.root,
            &mut InlineJournal::new(),
        );
        let publication = GuestMmuPublication::from_x86_receipt(&txn, &receipt).unwrap();
        if index == 0 {
            memory.publish(&txn, publication, &mut inventory).unwrap();
        }
    }
    let selection = carrick_el1_abi::PortalForkCustody::Frame {
        va: 0x4000,
        ipa: 0x800000,
        len: PAGE,
        shared: false,
    };
    let edge = memory
        .select_inherited_frames(
            contexts[0],
            selection,
            &*authority.physical_projection(Arc::clone(&ids)),
        )
        .unwrap()
        .remove(0);
    assert!(
        memory
            .authenticate(
                contexts[1].mm.raw(),
                map(contexts[1], 0x4000, 0x800000, child_identity).op
            )
            .is_err()
    );
    assert!(
        memory
            .attach_inherited_frame(
                contexts[1],
                &edge,
                first,
                &child_receipt,
                &*authority.physical_projection(Arc::clone(&ids))
            )
            .is_err()
    );
    let changed_parent = AddressContext {
        generation: ContextGeneration::new(nz(2)),
        ..contexts[0]
    };
    memory.roots.insert(contexts[0].mm.raw(), changed_parent);
    assert!(
        memory
            .attach_inherited_frame(
                contexts[1],
                &edge,
                child_identity,
                &child_receipt,
                &*authority.physical_projection(Arc::clone(&ids))
            )
            .is_err()
    );
    memory.roots.insert(contexts[0].mm.raw(), contexts[0]);
    assert!(
        memory
            .attach_inherited_frame(
                contexts[1],
                &edge,
                child_identity,
                &child_receipt,
                &*authority.physical_projection(Arc::clone(&ids))
            )
            .is_err(),
        "private inheritance must reject writable parent and child aliases"
    );
    assert_eq!(memory.slots[&data.slot].alias_count, 1);
    let shared = memory
        .select_inherited_frames(
            contexts[0],
            carrick_el1_abi::PortalForkCustody::Frame {
                va: 0x4000,
                ipa: 0x800000,
                len: PAGE,
                shared: true,
            },
            &*authority.physical_projection(Arc::clone(&ids)),
        )
        .unwrap()
        .remove(0);
    memory
        .attach_inherited_frame(
            contexts[1],
            &shared,
            child_identity,
            &child_receipt,
            &*authority.physical_projection(Arc::clone(&ids)),
        )
        .unwrap();
    memory.remove_aliases(
        contexts[1].mm.raw(),
        PageSpan::new(0x4000, PAGE),
        contexts[1],
    );
    for context in contexts {
        // The stopped fixture executes the guest's permission publication.
        // Physical attachment must observe it, never author these stores.
        let txn = DescriptorTxn {
            op: DescriptorOp::ArmCow(PageSpan::new(0x4000, PAGE)),
            ..map(context, 0x4000, 0x800000, first)
        };
        let receipt = execute_descriptor_txn(
            &memory.words(),
            &txn,
            context.root,
            &mut InlineJournal::new(),
        );
        assert!(GuestMmuPublication::from_x86_receipt(&txn, &receipt).is_some());
        if context == contexts[0] {
            assert!(
                memory
                    .attach_inherited_frame(
                        contexts[1],
                        &edge,
                        child_identity,
                        &child_receipt,
                        &*authority.physical_projection(Arc::clone(&ids))
                    )
                    .is_err(),
                "one read-only leaf cannot license the other writable alias"
            );
        }
    }
    memory
        .attach_inherited_frame(
            contexts[1],
            &edge,
            child_identity,
            &child_receipt,
            &*authority.physical_projection(Arc::clone(&ids)),
        )
        .unwrap();
    assert!(
        memory
            .authenticate(
                contexts[1].mm.raw(),
                map(contexts[1], 0x4000, 0x800000, child_identity).op
            )
            .is_ok()
    );
    assert!(
        memory
            .authenticate(
                contexts[1].mm.raw(),
                map(contexts[1], 0x5000, 0x801000, adjacent).op
            )
            .is_err()
    );
    let prepare = |va, gpa, identity| DescriptorTxn {
        op: DescriptorOp::Prepare {
            span: PageSpan::new(va, PAGE),
            output: FrameGpa::new(gpa),
            permissions: Permissions {
                writable: true,
                executable: false,
                user: true,
            },
            resident: PageSpan::new(va, PAGE),
            backing: identity,
        },
        ..map(contexts[1], va, gpa, identity)
    };
    assert!(
        memory
            .admit_guest_edit(&prepare(0x4000, 0x800000, child_identity))
            .is_ok()
    );
    assert!(
        memory
            .admit_guest_edit(&prepare(0x4000, 0x800000, first))
            .is_err()
    );
    assert!(
        memory
            .admit_guest_edit(&prepare(0x5000, 0x801000, child_adjacent))
            .is_err(),
        "a valid child inventory row cannot authorize an unselected adjacent page"
    );
    assert_eq!(
        memory.slot_count(),
        2,
        "inheritance must not allocate a memslot"
    );
    assert_eq!(memory.slots[&data.slot].alias_count, 2);
    assert!(
        memory
            .attach_inherited_frame(
                contexts[1],
                &edge,
                child_identity,
                &child_receipt,
                &*authority.physical_projection(Arc::clone(&ids))
            )
            .is_err()
    );
    let stale = AddressContext {
        generation: ContextGeneration::new(nz(2)),
        ..contexts[1]
    };
    assert!(
        memory
            .attach_inherited_frame(
                stale,
                &edge,
                child_identity,
                &child_receipt,
                &*authority.physical_projection(Arc::clone(&ids))
            )
            .is_err()
    );
    let mut transition = authority
        .reserve(&ids, 0, 0, FrameEventCapacity::for_event_count(1).unwrap())
        .unwrap();
    transition
        .push(FrameInventoryEvent::ProtectMapping {
            transaction: transition.transaction(),
            mapping: carrick_hal::MappingId::from_kernel_allocation(first.mapping_id),
            generation: MappingGeneration::from_backend_counter(nz(2)),
            permissions: MemPerms {
                read: true,
                write: false,
                exec: false,
            },
        })
        .unwrap();
    authority.apply(parent_mm, transition.commit(())).unwrap();
    assert!(
        memory
            .select_inherited_frames(
                contexts[0],
                selection,
                &*authority.physical_projection(Arc::clone(&ids))
            )
            .is_err(),
        "unchanged frame, mapping and GPA cannot authenticate an old owner generation"
    );
    memory.remove_aliases(
        contexts[0].mm.raw(),
        PageSpan::new(0x4000, PAGE),
        contexts[0],
    );
    assert_eq!(
        memory.slots[&data.slot].alias_count, 1,
        "child retains physical custody after parent unlink"
    );
    let mut drain = TestDrain {
        calls: 0,
        fail: false,
    };
    let mut retirement = Retirement {
        failed: false,
        live: true,
    };
    assert!(memory.revoke(data, &mut drain, &mut retirement).is_err());
    assert!(
        retirement.live,
        "child alias must prevent physical inventory retirement"
    );
    assert_eq!(drain.calls, 0);
    memory.remove_aliases(
        contexts[1].mm.raw(),
        PageSpan::new(0x4000, PAGE),
        contexts[1],
    );
    assert!(
        memory
            .authenticate(
                contexts[1].mm.raw(),
                map(contexts[1], 0x4000, 0x800000, child_identity).op
            )
            .is_err()
    );
    memory.revoke(data, &mut drain, &mut retirement).unwrap();
    assert!(!retirement.live);
    assert_eq!(drain.calls, 2);
}

#[test]
fn inherited_prepared_leaf_retains_exact_storage_without_committing_it() {
    let gpa = FrameGpa::new(0x800000);
    let prepared = gpa.raw() | USER | PREPARED | PRIVATE | COW | MAY_WRITE;
    assert!(inherited_leaf_names(prepared, PAGE, gpa));
    assert!(!inherited_leaf_names(prepared | RETIRED, PAGE, gpa));
    assert!(!inherited_leaf_names(prepared | PRESENT, PAGE, gpa));
    assert!(!inherited_leaf_names(
        prepared,
        PAGE,
        FrameGpa::new(0x801000)
    ));
    assert!(!inherited_leaf_names(prepared & !USER, PAGE, gpa));
    assert!(!inherited_leaf_names(prepared, 0x200000, gpa));
    assert!(inherited_leaf_names(
        (prepared & !PREPARED) | PRESENT,
        PAGE,
        gpa
    ));
}

#[test]
fn inherited_compound_inventory_authenticates_only_exact_live_owner_pages() {
    use carrick_hal::{
        FrameEventCapacity, FrameInventoryEvent, FrameLength, MappingGeneration, MemPerms,
    };
    use carrick_kernel::kernel::{FrameInventoryAuthority, ObjectIdRegistry};
    let authority = Arc::new(FrameInventoryAuthority::new());
    let ids = Arc::new(ObjectIdRegistry::new());
    let mm = ids.mm_id().unwrap();
    let other_mm = ids.mm_id().unwrap();
    let mut reservation = authority
        .reserve(&ids, 1, 1, FrameEventCapacity::for_event_count(2).unwrap())
        .unwrap();
    let transaction = reservation.transaction();
    let frame = reservation.claim_frame().unwrap();
    let mapping = reservation.claim_mapping().unwrap();
    let generation = MappingGeneration::from_backend_counter(nz(1));
    reservation
        .push(FrameInventoryEvent::PrepareMapping {
            transaction,
            frame,
            mapping,
            generation,
            gpa: carrick_guest_mem::Gpa(0x800000),
            length: FrameLength::from_mapping_extent(nz(0x4000)),
            permissions: MemPerms {
                read: true,
                write: true,
                exec: false,
            },
        })
        .unwrap();
    reservation
        .push(FrameInventoryEvent::PublishMapping {
            transaction,
            mapping,
            generation,
        })
        .unwrap();
    let (_, receipt) = authority
        .apply_with_receipt(mm, reservation.commit(()))
        .unwrap();
    let identity = BackingIdentity {
        frame_id: nz(frame.raw()),
        mapping_id: nz(mapping.raw()),
        owner_generation: nz(1),
        inventory_revision: nz(receipt.revision()),
    };
    assert!(inventory_page_live(
        &*authority.physical_projection(Arc::clone(&ids)),
        nz(mm.raw()),
        identity,
        FrameGpa::new(0x801000)
    ));
    assert!(!inventory_page_live(
        &*authority.physical_projection(Arc::clone(&ids)),
        nz(other_mm.raw()),
        identity,
        FrameGpa::new(0x801000)
    ));
    assert!(!inventory_page_live(
        &*authority.physical_projection(Arc::clone(&ids)),
        nz(mm.raw()),
        BackingIdentity {
            owner_generation: nz(2),
            ..identity
        },
        FrameGpa::new(0x801000)
    ));
    assert!(!inventory_page_live(
        &*authority.physical_projection(Arc::clone(&ids)),
        nz(mm.raw()),
        identity,
        FrameGpa::new(0x804000)
    ));
    assert!(!inventory_page_live(
        &*authority.physical_projection(Arc::clone(&ids)),
        nz(mm.raw()),
        identity,
        FrameGpa::new(0x801001)
    ));
}

/// Retire-child fixture: one root arena slot with a CR3 root per MM, and
/// the real frame inventory projection.
struct RetireFixture {
    memory: CarrierMemory,
    /// Carrier MM keys are kernel MM ids; `mms[n - 1]` is fixture MM `n`.
    mms: Vec<carrick_kernel::kernel::MmId>,
    authority: Arc<carrick_kernel::kernel::frame_inventory::FrameInventoryAuthority>,
    ids: Arc<carrick_kernel::kernel::ObjectIdRegistry>,
}

impl RetireFixture {
    /// MMs 1..=`mms`, MM `n` rooted at `n * PAGE` in one arena slot.
    fn new(count: u64) -> Self {
        let ids = Arc::new(carrick_kernel::kernel::ObjectIdRegistry::new());
        let mut fixture = Self {
            memory: CarrierMemory::create().unwrap(),
            mms: (0..count).map(|_| ids.mm_id().unwrap()).collect(),
            authority: Arc::new(
                carrick_kernel::kernel::frame_inventory::FrameInventoryAuthority::new(),
            ),
            ids,
        };
        fixture
            .memory
            .install(&[backing(PAGE, (count * PAGE) as usize, 900)])
            .unwrap();
        for mm in 1..=count {
            let context = fixture.context(mm);
            fixture
                .memory
                .install_root(fixture.key(mm), context)
                .unwrap();
        }
        fixture
    }

    fn key(&self, mm: u64) -> NonZeroU64 {
        nz(self.mms[(mm - 1) as usize].raw())
    }

    fn context(&self, mm: u64) -> AddressContext<RootGpa> {
        AddressContext {
            root: root(mm * PAGE),
            mm: MmGeneration::new(self.key(mm)),
            generation: ContextGeneration::new(nz(1)),
        }
    }

    fn inventory(&self) -> Arc<dyn carrick_hal::PhysicalFrameInventory> {
        self.authority.physical_projection(Arc::clone(&self.ids))
    }

    /// A data slot admitted to each of `mms`.
    fn slot(&mut self, pa: u64, tag: u64, mms: &[u64]) -> BackingHandle {
        self.slot_with(backing(pa, PAGE as usize, tag), mms)
    }

    fn slot_with(&mut self, prepared: PreparedBacking, mms: &[u64]) -> BackingHandle {
        let handle = self.memory.install(&[prepared]).unwrap()[0];
        let edge = self.memory.share(handle).unwrap();
        for mm in mms {
            self.memory.attach_shared(self.key(*mm), &edge).unwrap();
        }
        handle
    }

    /// A descriptor alias of `mm` naming `handle` (as `publish` records one).
    fn alias(&mut self, mm: u64, handle: BackingHandle, va: u64, inherited: Option<u64>) {
        let key = self.key(mm);
        let slot = self.memory.slots.get_mut(&handle.slot).unwrap();
        slot.alias_count += 1;
        if let Some(gpa) = inherited {
            slot.inherited_identities
                .insert((key, gpa), slot.backing.identity);
        }
        self.memory.aliases.entry(key).or_default().insert(
            va,
            Alias {
                slot: handle.slot,
                span: PageSpan::new(va, PAGE),
                inherited: inherited.map(FrameGpa::new),
            },
        );
    }

    /// A drain owed to `mm`'s context on `handle` (as `remove_aliases`
    /// records one).
    fn owe_drain(&mut self, mm: u64, handle: BackingHandle) {
        let context = self.context(mm);
        self.memory
            .slots
            .get_mut(&handle.slot)
            .unwrap()
            .drains
            .push(context);
        self.memory
            .drained_by
            .entry(self.key(mm))
            .or_default()
            .insert(handle.slot);
    }

    fn retire(&mut self, mm: u64) -> Result<RetiredChild, MemoryError> {
        let absence = carrick_hal::fork_stock::SlotAbsence::scan(
            carrick_el1_abi::ReservationMm::new(self.key(mm).get()).unwrap(),
            [0],
        )
        .unwrap();
        let inventory = self.inventory();
        self.memory.retire_child(&absence, &*inventory)
    }

    fn allowed(&self, handle: BackingHandle) -> Vec<NonZeroU64> {
        self.memory.record(handle).unwrap().allowed.clone()
    }

    /// `admitted` equals the slots whose `allowed` names each MM.
    fn assert_admitted_exact(&self) {
        let mut derived: BTreeMap<NonZeroU64, BTreeSet<u32>> = BTreeMap::new();
        for (index, slot) in &self.memory.slots {
            for mm in &slot.allowed {
                derived.entry(*mm).or_default().insert(*index);
            }
        }
        let indexed: BTreeMap<_, _> = self
            .memory
            .admitted
            .iter()
            .filter(|(_, slots)| !slots.is_empty())
            .map(|(mm, slots)| (*mm, slots.clone()))
            .collect();
        assert_eq!(indexed, derived);
    }
}

#[test]
fn retire_child_revokes_private_slots_and_keeps_slots_a_live_parent_shares() {
    let mut fixture = RetireFixture::new(2);
    let private = fixture.slot(0x800000, 91, &[2]);
    let shared = fixture.slot(0x900000, 92, &[1, 2]);
    fixture.alias(2, shared, 0x4000, Some(0x900000));
    fixture.owe_drain(1, shared);
    fixture.owe_drain(2, shared);
    fixture.owe_drain(2, private);
    let slots = fixture.memory.slot_count();
    fixture.assert_admitted_exact();

    let retired = fixture.retire(2).unwrap();

    assert_eq!(
        retired,
        RetiredChild {
            aliases: 1,
            revoked_slots: 1
        }
    );
    assert!(
        fixture.memory.record(private).is_err(),
        "private slot revoked"
    );
    assert_eq!(fixture.memory.slot_count(), slots - 1);
    let kept = fixture.memory.record(shared).unwrap();
    assert_eq!(
        kept.allowed,
        vec![fixture.key(1)],
        "child left the shared slot"
    );
    assert_eq!(kept.alias_count, 0);
    assert!(kept.inherited_identities.is_empty());
    // Drains of the retired context are gone through `drained_by`; the
    // live parent's drain debt is untouched.
    assert_eq!(kept.drains, vec![fixture.context(1)]);
    assert!(!fixture.memory.drained_by.contains_key(&fixture.key(2)));
    assert_eq!(
        fixture.memory.drained_by.get(&fixture.key(1)),
        Some(&BTreeSet::from([shared.slot]))
    );
    assert!(fixture.memory.root(fixture.key(2)).is_none());
    assert!(fixture.memory.root(fixture.key(1)).is_some());
    assert!(!fixture.memory.aliases.contains_key(&fixture.key(2)));
    assert!(!fixture.memory.admitted.contains_key(&fixture.key(2)));
    fixture.assert_admitted_exact();
    assert!(!fixture.memory.is_quarantined());
}

#[test]
fn grandchild_inherits_a_slot_after_its_parent_retired() {
    let mut fixture = RetireFixture::new(3);
    // MM 2 forked MM 3; both map the same inherited slot.
    let inherited = fixture.slot(0x800000, 91, &[2, 3]);
    fixture.alias(2, inherited, 0x4000, Some(0x800000));
    fixture.alias(3, inherited, 0x4000, Some(0x800000));

    let first = fixture.retire(2).unwrap();
    assert_eq!(
        first,
        RetiredChild {
            aliases: 1,
            revoked_slots: 0
        }
    );
    let kept = fixture.memory.record(inherited).unwrap();
    assert_eq!(kept.allowed, vec![fixture.key(3)]);
    assert_eq!(kept.alias_count, 1);
    assert_eq!(
        kept.inherited_identities
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        vec![(fixture.key(3), 0x800000)]
    );
    fixture.assert_admitted_exact();

    // The grandchild now owns the slot alone; its retirement revokes it.
    let second = fixture.retire(3).unwrap();
    assert_eq!(
        second,
        RetiredChild {
            aliases: 1,
            revoked_slots: 1
        }
    );
    assert!(fixture.memory.record(inherited).is_err());
    fixture.assert_admitted_exact();
    assert!(fixture.memory.admitted.is_empty());
}

#[test]
fn refused_retire_child_mutates_nothing_and_its_retry_completes() {
    use carrick_hal::{FrameEventCapacity, FrameInventoryEvent, FrameLength, MappingGeneration};
    let mut fixture = RetireFixture::new(2);
    // The child's private frame is still mapped in the inventory: the
    // carrier must refuse before touching any of its own state.
    let child = fixture.mms[1];
    let mut reservation = fixture
        .authority
        .reserve(
            &fixture.ids,
            1,
            1,
            FrameEventCapacity::for_event_count(2).unwrap(),
        )
        .unwrap();
    let transaction = reservation.transaction();
    let frame = reservation.claim_frame().unwrap();
    let mapping = reservation.claim_mapping().unwrap();
    let generation = MappingGeneration::from_backend_counter(nz(1));
    reservation
        .push(FrameInventoryEvent::PrepareMapping {
            transaction,
            frame,
            mapping,
            generation,
            gpa: carrick_guest_mem::Gpa(0x800000),
            length: FrameLength::from_mapping_extent(nz(PAGE)),
            permissions: carrick_hal::MemPerms {
                read: true,
                write: true,
                exec: false,
            },
        })
        .unwrap();
    reservation
        .push(FrameInventoryEvent::PublishMapping {
            transaction,
            mapping,
            generation,
        })
        .unwrap();
    fixture
        .authority
        .apply(child, reservation.commit(()))
        .unwrap();
    let mut prepared = backing(0x800000, PAGE as usize, 91);
    prepared.identity.frame_id = nz(frame.raw());
    prepared.identity.mapping_id = nz(mapping.raw());
    let private = fixture.slot_with(prepared, &[2]);
    let shared = fixture.slot(0x900000, 92, &[1, 2]);
    fixture.alias(2, shared, 0x4000, Some(0x900000));
    fixture.owe_drain(2, shared);

    assert!(fixture.retire(2).is_err());
    // Nothing moved: root, aliases, drains and admissions all intact.
    assert!(fixture.memory.root(fixture.key(2)).is_some());
    assert_eq!(fixture.allowed(private), vec![fixture.key(2)]);
    assert_eq!(
        fixture.allowed(shared),
        vec![fixture.key(1), fixture.key(2)]
    );
    assert_eq!(fixture.memory.record(shared).unwrap().alias_count, 1);
    assert_eq!(
        fixture.memory.record(shared).unwrap().drains,
        vec![fixture.context(2)]
    );
    assert!(fixture.memory.drained_by.contains_key(&fixture.key(2)));
    assert_eq!(
        fixture.memory.admitted.get(&fixture.key(2)),
        Some(&BTreeSet::from([private.slot, shared.slot]))
    );
    assert!(!fixture.memory.is_quarantined());

    // Once the inventory side releases the MM, the same call completes.
    fixture
        .inventory()
        .retire_mm(MmGeneration::new(fixture.key(2)))
        .unwrap();
    let retired = fixture.retire(2).unwrap();
    assert_eq!(
        retired,
        RetiredChild {
            aliases: 1,
            revoked_slots: 1
        }
    );
    assert!(fixture.memory.record(private).is_err());
    assert_eq!(fixture.allowed(shared), vec![fixture.key(1)]);
    fixture.assert_admitted_exact();
}
