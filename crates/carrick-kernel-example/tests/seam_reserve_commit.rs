//! Contract test for address-space reservation and range commit/decommit seam (issue #198).
//!
//! Verifies:
//! 1. Reserving 64 MiB uses zero physical backing frames.
//! 2. Committing a 4 KiB sub-range enables read/write access.
//! 3. Decommitting revokes access (faults on access) while retaining the reservation.
//! 4. Decommitted pages release physical frame custody and return frames to the pool.
//! 5. Atomic rollback: failure during commit rolls back all stage-1 and frame allocations.

use carrick_guest_arch::{FrameGpa, GuestLen, UserVa};
use carrick_kernel_example::ExamplePersonality;
use carrick_mem::memory::{
    LINUX_GIC_WINDOW_BASE, LINUX_GIC_WINDOW_SIZE, LINUX_MMAP_BASE, LINUX_NULL_GUARD_END,
    LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE, stage1_identity_page_tables,
};
use carrick_mmu_core::aarch64::{PageTableLayoutConfig, PageTableManager, UserLeafAccess};

fn test_page_table_manager() -> PageTableManager {
    let mut bytes = stage1_identity_page_tables();
    bytes.resize(0x80000, 0);
    let layout = PageTableLayoutConfig {
        user_leaf_check_va: LINUX_NULL_GUARD_END,
        extension_arena_capacity: LINUX_PAGE_TABLES_SIZE as usize,
        excluded_ipa_start: LINUX_GIC_WINDOW_BASE,
        excluded_ipa_len: LINUX_GIC_WINDOW_SIZE,
    };
    PageTableManager::new(bytes, LINUX_PAGE_TABLES_BASE, layout)
}

#[test]
fn address_space_reserve_commit_decommit_witness_contract() {
    let personality = ExamplePersonality::new();
    let pt_manager = test_page_table_manager();

    let frame_pool_base = FrameGpa::new(0x8000_0000);
    let total_pool_frames = 1024;
    let mut authority =
        personality.create_mm_authority(pt_manager, frame_pool_base, total_pool_frames);

    assert_eq!(authority.total_frames(), total_pool_frames);
    assert_eq!(authority.free_frames(), total_pool_frames);
    assert_eq!(authority.allocated_frames(), 0);

    // 1. Reserving 64 MiB uses 0 physical frames.
    let reserve_va = UserVa::new(LINUX_MMAP_BASE);
    let reserve_len = GuestLen::new(64 * 1024 * 1024); // 64 MiB
    authority
        .reserve_range(reserve_va, reserve_len)
        .expect("reserve 64 MiB must succeed");

    assert!(authority.is_reserved(reserve_va, reserve_len));
    assert_eq!(authority.allocated_frames(), 0);
    assert_eq!(authority.free_frames(), total_pool_frames);

    // Initial access to the reserved (but uncommitted) range must fault.
    assert!(!authority.can_read(reserve_va));
    assert!(!authority.can_write(reserve_va));
    let mut read_buf = [0u8; 16];
    assert!(authority.read(reserve_va, &mut read_buf).is_err());
    assert!(authority.write(reserve_va, b"uncommitted").is_err());

    // 2. Committing a 4 KiB sub-range enables read/write access.
    let commit_va = reserve_va;
    let commit_len = GuestLen::new(4096);
    authority
        .commit_range(commit_va, commit_len, UserLeafAccess::READ_WRITE)
        .expect("commit 4 KiB must succeed");

    assert_eq!(authority.allocated_frames(), 1);
    assert_eq!(authority.free_frames(), total_pool_frames - 1);
    assert!(authority.is_committed(commit_va, commit_len));

    // Access to the committed sub-range succeeds for read and write.
    assert!(authority.can_read(commit_va));
    assert!(authority.can_write(commit_va));

    let test_data = b"Hello, Carrick!";
    authority
        .write(commit_va, test_data)
        .expect("write to committed page must succeed");

    let mut out_buf = [0u8; 15];
    authority
        .read(commit_va, &mut out_buf)
        .expect("read from committed page must succeed");
    assert_eq!(&out_buf, test_data);

    // Uncommitted portions of the 64 MiB reservation still fault on access.
    let next_page_va = UserVa::new(reserve_va.raw() + 4096);
    assert!(!authority.can_read(next_page_va));
    assert!(!authority.can_write(next_page_va));
    assert!(authority.read(next_page_va, &mut read_buf).is_err());
    assert!(authority.write(next_page_va, b"fail").is_err());

    // 3 & 4. Decommit revokes access (faults), keeps VA reserved, and returns frames to the pool.
    authority
        .decommit_range(commit_va, commit_len)
        .expect("decommit 4 KiB must succeed");

    // Access now faults.
    assert!(!authority.can_read(commit_va));
    assert!(!authority.can_write(commit_va));
    assert!(authority.read(commit_va, &mut out_buf).is_err());
    assert!(authority.write(commit_va, test_data).is_err());

    // VA remains reserved.
    assert!(authority.is_reserved(reserve_va, reserve_len));
    assert!(!authority.is_committed(commit_va, commit_len));

    // Physical frames returned to the pool.
    assert_eq!(authority.allocated_frames(), 0);
    assert_eq!(authority.free_frames(), total_pool_frames);
}

#[test]
fn address_space_commit_rollback_on_frame_exhaustion() {
    let personality = ExamplePersonality::new();
    let pt_manager = test_page_table_manager();

    // Frame pool with only 2 frames capacity.
    let frame_pool_base = FrameGpa::new(0x8000_0000);
    let total_pool_frames = 2;
    let mut authority =
        personality.create_mm_authority(pt_manager, frame_pool_base, total_pool_frames);

    let reserve_va = UserVa::new(LINUX_MMAP_BASE + 0x1000_0000);
    let reserve_len = GuestLen::new(64 * 1024 * 1024);
    authority.reserve_range(reserve_va, reserve_len).unwrap();

    // Commit 1 page (4 KiB) - succeeds.
    let page1_va = reserve_va;
    authority
        .commit_range(page1_va, GuestLen::new(4096), UserLeafAccess::READ_WRITE)
        .unwrap();
    assert_eq!(authority.allocated_frames(), 1);
    assert_eq!(authority.free_frames(), 1);

    // Try committing 2 pages (8 KiB) - should fail because only 1 frame remains, and roll back!
    let page2_va = UserVa::new(reserve_va.raw() + 4096);
    let err = authority.commit_range(page2_va, GuestLen::new(8192), UserLeafAccess::READ_WRITE);
    assert!(err.is_err());

    // Post-rollback state verification:
    // Frame count must be unchanged from before the failed transaction.
    assert_eq!(authority.allocated_frames(), 1);
    assert_eq!(authority.free_frames(), 1);

    // First page is still committed and accessible.
    assert!(authority.can_read(page1_va));
    assert!(authority.can_write(page1_va));

    // Page 2 was never committed.
    assert!(!authority.can_read(page2_va));
    assert!(!authority.can_write(page2_va));
}
