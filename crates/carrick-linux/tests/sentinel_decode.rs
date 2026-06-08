//! Pure-logic tests for carrick-linux guest_setup (no KVM needed).
#![cfg(target_os = "linux")]
use carrick_linux::guest_setup::{SENTINEL_GPA, el1_vectors_sentinel_bytes};

fn op_at(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

#[test]
fn sentinel_slot_materialises_sentinel_gpa_and_stores() {
    let v = el1_vectors_sentinel_bytes();
    assert_eq!(v.len(), 0x4000, "vector page is one 16 KiB page");
    let s = 0x400; // lower-EL sync slot
    // The slot opens with `msr tpidr_el1, x9` (saves the guest's live x9, dst x9)
    // at s+0, then the ESR.EC discriminator (mrs/ubfx/cmp/b.ne); on the SVC path it
    // re-materialises SENTINEL_GPA into x9 (s+20..s+32) and stores at s+36. (See
    // `lower_el_sync_slot_discriminates_svc_vs_fault` in guest_setup for the full
    // byte-level assertion.)
    assert_eq!(
        op_at(&v, s) & 0x1F,
        9,
        "first instr (msr tpidr_el1, x9) targets x9"
    );
    // str x8, [x9] at slot+36 (save + 4-instr discriminator + 4-instr re-materialize)
    assert_eq!(op_at(&v, s + 36), 0xf900_0128, "str x8,[x9] (SVC path)");
    // eret closes the SVC path at slot+40
    assert_eq!(
        op_at(&v, s + 40),
        0xd69f_03e0,
        "eret after the sentinel store"
    );
    // a non-sync slot (slot 0) is a bare eret
    assert_eq!(op_at(&v, 0), 0xd69f_03e0, "slot 0 is eret");
    // sanity: SENTINEL_GPA is the stage-1-mapped hole we chose (320 GiB),
    // in the gap between the heap (256 GiB) and the mmap arena (384 GiB).
    assert_eq!(SENTINEL_GPA, 0x50_0000_0000);
}

use carrick_mem::memory::stage1_identity_page_tables;

#[test]
fn reused_page_tables_have_valid_l0_root() {
    let pt = stage1_identity_page_tables();
    assert!(!pt.is_empty());
    let l0e0 = u64::from_le_bytes(pt[0..8].try_into().unwrap());
    // L0[0] is a table descriptor: bits[1:0] == 0b11 (valid table).
    assert_eq!(l0e0 & 0b11, 0b11, "L0[0] is a valid table descriptor");
}
