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
    // movz x9, #(SENTINEL_GPA & 0xFFFF)
    assert_eq!(op_at(&v, s) & 0x1F, 9, "dst is x9");
    // str x8, [x9] at slot+16
    assert_eq!(op_at(&v, s + 16), 0xf900_0128, "str x8,[x9]");
    // eret closes the slot at slot+20
    assert_eq!(
        op_at(&v, s + 20),
        0xd69f_03e0,
        "eret after the sentinel store"
    );
    // a non-sync slot (slot 0) is a bare eret
    assert_eq!(op_at(&v, 0), 0xd69f_03e0, "slot 0 is eret");
    // sanity: SENTINEL_GPA is the 4-MiB-aligned high address we chose
    assert_eq!(SENTINEL_GPA, 0x40_0000_0000);
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
