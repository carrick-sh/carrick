//! KVM bindings: stage1-publication, address-space-occupancy and exact context
//! drain. Intel SDM page-fault P/W/U/I bits plus Linux mmap/mprotect/fork
//! semantics. These are hardware fixtures, not N1 or OCI acceptance.
//! No Docker, absent-KVM skips, retries, or timing claims.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used, clippy::panic)]
use carrick_mmu_core::x86::descriptor_txn::{DescriptorOp, PAGE, PageSpan, Permissions};
use carrick_vmm_kvm::carrier_memory::fixture::{DATA_VA, MemoryWitness, Observation};
fn code(ops: &[(u64, Option<u8>)]) -> Vec<u8> {
    let mut code = Vec::new();
    for &(va, write) in ops {
        code.extend_from_slice(&[0x48, 0xbb]);
        code.extend_from_slice(&va.to_le_bytes());
        if let Some(value) = write {
            code.extend_from_slice(&[0xc6, 0x03, value]);
        }
        code.extend_from_slice(&[0x0f, 0xb6, 0x03, 0x0f, 0x05]); // movzx eax,[rbx]; syscall observation
    }
    code.extend_from_slice(&[0x0f, 0x0b]);
    code
}
fn byte(w: &mut MemoryWitness, mm: usize, value: u8) {
    assert!(matches!(w.observe(mm).unwrap(),Observation::Byte(actual) if actual==value));
}
fn fault(w: &mut MemoryWitness, mm: usize, error: u64) {
    match w.observe(mm).unwrap() {
        Observation::Fault(record) => {
            assert_eq!(record.vector, 14);
            assert_eq!(record.error_code, error);
            assert_eq!(record.cr2, DATA_VA);
            assert_eq!(record.cs & 3, 3);
        }
        other => panic!("expected page fault, got {other:?}"),
    }
}
#[test]
fn two_live_mms_map_identical_vas_to_private_bytes_and_share_only_explicit_edges() {
    let shared_va = DATA_VA + PAGE;
    let a = code(&[(DATA_VA, None), (shared_va, Some(0x77)), (shared_va, None)]);
    let b = code(&[(DATA_VA, None), (shared_va, None), (DATA_VA, None)]);
    let mut w = MemoryWitness::boot([&a, &b]).unwrap();
    let private_a = w.private_extent(0x41).unwrap();
    let private_b = w.private_extent(0x42).unwrap();
    let shared = w.private_extent(0x66).unwrap();
    w.map(0, DATA_VA, private_a, true).unwrap();
    w.map(1, DATA_VA, private_b, true).unwrap();
    w.map(0, shared_va, shared, true).unwrap();
    assert!(
        w.map(1, shared_va, shared, true).is_err(),
        "sharing requires the issued frame edge"
    );
    w.share_with(1, shared).unwrap();
    w.map(1, shared_va, shared, true).unwrap();
    byte(&mut w, 0, 0x41);
    byte(&mut w, 1, 0x42);
    byte(&mut w, 0, 0x77);
    byte(&mut w, 1, 0x77);
    byte(&mut w, 0, 0x77);
    byte(&mut w, 1, 0x42);
    assert_eq!(w.backing_byte(private_a).unwrap(), 0x41);
    assert_eq!(w.backing_byte(private_b).unwrap(), 0x42);
    assert_eq!(w.backing_byte(shared).unwrap(), 0x77);
    assert_eq!(
        w.slot_count(),
        4,
        "one system plus three extents, independent of MM aliases"
    );
}
#[test]
fn first_touch_faults_then_retries_on_private_backing() {
    let program = code(&[(DATA_VA, None)]);
    let mut w = MemoryWitness::boot([&program, &program]).unwrap();
    let a = w.private_extent(0).unwrap();
    let b = w.private_extent(0x42).unwrap();
    w.map(0, DATA_VA, a, false).unwrap();
    w.map(1, DATA_VA, b, false).unwrap();
    fault(&mut w, 0, 4);
    fault(&mut w, 1, 4);
    w.first_touch(0, a).unwrap();
    w.first_touch(1, b).unwrap();
    byte(&mut w, 0, 0);
    byte(&mut w, 1, 0x42);
}
#[test]
fn cow_write_fault_breaks_to_private_bytes_without_changing_the_sibling() {
    let writer = code(&[(DATA_VA, Some(0x99))]);
    let reader = code(&[(DATA_VA, None)]);
    let mut w = MemoryWitness::boot([&writer, &reader]).unwrap();
    let shared = w.private_extent(0x41).unwrap();
    let private = w.private_extent(0).unwrap();
    w.map(0, DATA_VA, shared, true).unwrap();
    w.share_with(1, shared).unwrap();
    w.map(1, DATA_VA, shared, true).unwrap();
    for mm in 0..2 {
        w.edit(mm, DescriptorOp::ArmCow(PageSpan::new(DATA_VA, PAGE)))
            .unwrap();
    }
    fault(&mut w, 0, 7);
    w.cow_break(0, shared, private).unwrap();
    byte(&mut w, 0, 0x99);
    byte(&mut w, 1, 0x41);
    assert_eq!(w.backing_byte(private).unwrap(), 0x99);
    assert_eq!(w.backing_byte(shared).unwrap(), 0x41);
}
#[test]
fn nx_and_readonly_violations_report_user_instruction_and_write_faults() {
    let mut jump = vec![0x48, 0xbb];
    jump.extend_from_slice(&DATA_VA.to_le_bytes());
    jump.extend_from_slice(&[0xff, 0xe3]);
    let writer = code(&[(DATA_VA, Some(0x99))]);
    let mut w = MemoryWitness::boot([&jump, &writer]).unwrap();
    let a = w.private_extent(0x41).unwrap();
    let b = w.private_extent(0x42).unwrap();
    w.map(0, DATA_VA, a, true).unwrap();
    w.map(1, DATA_VA, b, true).unwrap();
    w.edit(
        1,
        DescriptorOp::Protect {
            span: PageSpan::new(DATA_VA, PAGE),
            permissions: Permissions {
                writable: false,
                executable: false,
                user: true,
            },
        },
    )
    .unwrap();
    fault(&mut w, 0, 21);
    fault(&mut w, 1, 7);
    assert_eq!(w.backing_byte(b).unwrap(), 0x42);
}
#[test]
fn revoke_drains_loaded_translation_and_rejects_recycled_slot_edges() {
    let program = code(&[(DATA_VA, None), (DATA_VA, None)]);
    let mut w = MemoryWitness::boot([&program, &program]).unwrap();
    let a = w.private_extent(0x41).unwrap();
    let b = w.private_extent(0x42).unwrap();
    w.map(0, DATA_VA, a, true).unwrap();
    w.map(1, DATA_VA, b, true).unwrap();
    byte(&mut w, 0, 0x41);
    byte(&mut w, 1, 0x42);
    assert!(
        w.revoke(a).is_err(),
        "a live stage-1 alias prevents physical revoke"
    );
    w.edit(0, DescriptorOp::Unmap(PageSpan::new(DATA_VA, PAGE)))
        .unwrap();
    let drains = w.drain_count;
    w.revoke(a).unwrap();
    assert_eq!(w.drain_count, drains + 1);
    fault(&mut w, 0, 4);
    byte(&mut w, 1, 0x42);
    let replacement = w.private_extent(0x99).unwrap();
    assert_eq!(replacement.slot_index(), a.slot_index());
    assert_ne!(replacement.generation(), a.generation());
    assert!(w.share_with(1, a).is_err());
    w.map(0, DATA_VA, replacement, true).unwrap();
    byte(&mut w, 0, 0x99);
}
#[test]
fn shared_revoke_requires_both_alias_unlinks_and_both_exact_context_drains() {
    let program = code(&[(DATA_VA, None), (DATA_VA, None)]);
    let mut w = MemoryWitness::boot([&program, &program]).unwrap();
    let shared = w.private_extent(0x55).unwrap();
    w.map(0, DATA_VA, shared, true).unwrap();
    w.share_with(1, shared).unwrap();
    w.map(1, DATA_VA, shared, true).unwrap();
    byte(&mut w, 0, 0x55);
    byte(&mut w, 1, 0x55);
    w.edit(0, DescriptorOp::Unmap(PageSpan::new(DATA_VA, PAGE)))
        .unwrap();
    assert!(w.revoke(shared).is_err());
    byte(&mut w, 1, 0x55);
    w.edit(1, DescriptorOp::Unmap(PageSpan::new(DATA_VA, PAGE)))
        .unwrap();
    let drains = w.drain_count;
    w.revoke(shared).unwrap();
    assert_eq!(w.drain_count, drains + 2);
    fault(&mut w, 0, 4);
}
