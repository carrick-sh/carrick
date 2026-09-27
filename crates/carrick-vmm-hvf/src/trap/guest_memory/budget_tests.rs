//! Budget test for zero_guest_backing in the HVF backend.
//!
//! A brk shrink (and other backing zeroing) scrubs a range of guest memory.
//! Work must be proportional to the range's distinct backing extents, NOT
//! its 4 KiB pages, with O(1) lock acquisitions across the operation.
//! On unbatched code, scanning scales linearly with the page count (e.g. 256
//! TaskMapping visits and lock round-trips for 256 pages).

use crate::trap::{
    CarrierForeignMmTransport, HotPathScan, HvfSyscallTransport, HvfTaskState, HvfVmState,
    MailboxSlotAllocator, hot_path_rows_scanned, thread_sibling_tests::mapped_region,
};

const PAGE_SIZE: usize = 4096;
const SMALL_PAGES: usize = 1;
const LARGE_PAGES: usize = 256;
const HEAP_START: u64 = 0x2000_0000;
const TASK_ROWS_BUDGET: u64 = 2;

struct MmapBuffer {
    ptr: *mut u8,
    len: usize,
}

impl MmapBuffer {
    fn new(len: usize) -> Self {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED);
        Self {
            ptr: ptr as *mut u8,
            len,
        }
    }
}

impl Drop for MmapBuffer {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
    }
}

fn test_vm_state(task: HvfTaskState) -> HvfVmState {
    HvfVmState {
        _vm: std::mem::ManuallyDrop::new(unsafe { std::mem::zeroed() }),
        task,
        carrier_foreign_mm_transport: std::sync::Arc::new(CarrierForeignMmTransport::new()),
        carrier_mappings: None,
        mailbox_slots: std::sync::Arc::new(MailboxSlotAllocator::new()),
        syscall_transport: HvfSyscallTransport::Mailbox,
        executor_vcpu: None,
        cached_fork_alias_snapshot: parking_lot::Mutex::new(None),
        last_fork_host_mapping_allocations: std::sync::atomic::AtomicU64::new(0),
        last_fork_projection_rows_visited: std::sync::atomic::AtomicU64::new(0),
    }
}

#[test]
fn zero_guest_backing_budget_is_proportional_to_extents_not_pages() {
    let mut task = HvfTaskState::neutral();
    let total_size = LARGE_PAGES * PAGE_SIZE;
    let mmap = MmapBuffer::new(total_size);
    let mut region = mapped_region(HEAP_START, HEAP_START + total_size as u64, HEAP_START);
    region.host_addr = mmap.ptr;
    task.mappings.insert(region);

    let mut vm = test_vm_state(task);

    // 1. Measure zeroing 1 page
    unsafe {
        core::ptr::write_bytes(mmap.ptr, 0xaa, total_size);
    }
    let before_small = hot_path_rows_scanned(HotPathScan::TaskMappings);
    vm.zero_guest_backing(HEAP_START, SMALL_PAGES * PAGE_SIZE)
        .expect("zero small range");
    let scanned_small = hot_path_rows_scanned(HotPathScan::TaskMappings) - before_small;

    // Verify exactly the requested page was zeroed
    assert_eq!(unsafe { *mmap.ptr }, 0);
    assert_eq!(unsafe { *mmap.ptr.add(PAGE_SIZE - 1) }, 0);
    assert_eq!(unsafe { *mmap.ptr.add(PAGE_SIZE) }, 0xaa);

    // 2. Measure zeroing 256 pages (single backing extent)
    unsafe {
        core::ptr::write_bytes(mmap.ptr, 0xbb, total_size);
    }
    let before_large = hot_path_rows_scanned(HotPathScan::TaskMappings);
    vm.zero_guest_backing(HEAP_START, LARGE_PAGES * PAGE_SIZE)
        .expect("zero large range");
    let scanned_large = hot_path_rows_scanned(HotPathScan::TaskMappings) - before_large;

    // Verify all 256 pages were zeroed
    for i in 0..total_size {
        assert_eq!(unsafe { *mmap.ptr.add(i) }, 0);
    }

    assert!(
        scanned_large <= TASK_ROWS_BUDGET,
        "zeroing {LARGE_PAGES} pages visited {scanned_large} task mapping rows \
         (budget {TASK_ROWS_BUDGET}); small scale ({SMALL_PAGES} page) visited {scanned_small}"
    );
}

#[test]
fn zero_guest_backing_multi_extent_budget_is_proportional_to_extents() {
    let mut task = HvfTaskState::neutral();
    let extent1_pages = 128;
    let extent2_pages = 128;
    let total_pages = extent1_pages + extent2_pages;
    let extent1_len = extent1_pages * PAGE_SIZE;
    let extent2_len = extent2_pages * PAGE_SIZE;

    let mmap1 = MmapBuffer::new(extent1_len);
    let mmap2 = MmapBuffer::new(extent2_len);

    let mut region1 = mapped_region(HEAP_START, HEAP_START + extent1_len as u64, HEAP_START);
    region1.host_addr = mmap1.ptr;
    task.mappings.insert(region1);

    let region2_start = HEAP_START + extent1_len as u64;
    let mut region2 = mapped_region(
        region2_start,
        region2_start + extent2_len as u64,
        region2_start,
    );
    region2.host_addr = mmap2.ptr;
    task.mappings.insert(region2);

    let mut vm = test_vm_state(task);

    unsafe {
        core::ptr::write_bytes(mmap1.ptr, 0x11, extent1_len);
        core::ptr::write_bytes(mmap2.ptr, 0x22, extent2_len);
    }

    let before = hot_path_rows_scanned(HotPathScan::TaskMappings);
    vm.zero_guest_backing(HEAP_START, total_pages * PAGE_SIZE)
        .expect("zero multi-extent range");
    let scanned = hot_path_rows_scanned(HotPathScan::TaskMappings) - before;

    // Verify all bytes across both extents are zeroed
    for i in 0..extent1_len {
        assert_eq!(unsafe { *mmap1.ptr.add(i) }, 0);
    }
    for i in 0..extent2_len {
        assert_eq!(unsafe { *mmap2.ptr.add(i) }, 0);
    }

    // Two extents: visited at most 2 * TASK_ROWS_BUDGET rows
    assert!(
        scanned <= 2 * TASK_ROWS_BUDGET,
        "zeroing 2 extents visited {scanned} task mapping rows (budget {})",
        2 * TASK_ROWS_BUDGET
    );
}

#[test]
fn zero_guest_backing_unaligned_partial_range_preserves_surrounding_bytes() {
    let mut task = HvfTaskState::neutral();
    let total_size = 4 * PAGE_SIZE;
    let mmap = MmapBuffer::new(total_size);
    let mut region = mapped_region(HEAP_START, HEAP_START + total_size as u64, HEAP_START);
    region.host_addr = mmap.ptr;
    task.mappings.insert(region);

    let mut vm = test_vm_state(task);

    unsafe {
        core::ptr::write_bytes(mmap.ptr, 0x5a, total_size);
    }

    let zero_offset = 0x123usize;
    let zero_len = 0x1456usize;
    vm.zero_guest_backing(HEAP_START + zero_offset as u64, zero_len)
        .expect("zero unaligned range");

    // Verify bytes before zero_offset are untouched
    for i in 0..zero_offset {
        assert_eq!(
            unsafe { *mmap.ptr.add(i) },
            0x5a,
            "byte at {i} before range modified"
        );
    }
    // Verify bytes inside range are zeroed
    for i in zero_offset..zero_offset + zero_len {
        assert_eq!(
            unsafe { *mmap.ptr.add(i) },
            0,
            "byte at {i} inside range not zeroed"
        );
    }
    // Verify bytes after range are untouched
    for i in zero_offset + zero_len..total_size {
        assert_eq!(
            unsafe { *mmap.ptr.add(i) },
            0x5a,
            "byte at {i} after range modified"
        );
    }
}

#[test]
fn zero_guest_backing_unmapped_hole_leaves_neighbors_zeroed() {
    let mut task = HvfTaskState::neutral();
    let extent1_len = 2 * PAGE_SIZE;
    let hole_len = 2 * PAGE_SIZE;
    let extent2_len = 2 * PAGE_SIZE;

    let mmap1 = MmapBuffer::new(extent1_len);
    let mmap2 = MmapBuffer::new(extent2_len);

    let mut region1 = mapped_region(HEAP_START, HEAP_START + extent1_len as u64, HEAP_START);
    region1.host_addr = mmap1.ptr;
    task.mappings.insert(region1);

    let region2_start = HEAP_START + extent1_len as u64 + hole_len as u64;
    let mut region2 = mapped_region(
        region2_start,
        region2_start + extent2_len as u64,
        region2_start,
    );
    region2.host_addr = mmap2.ptr;
    task.mappings.insert(region2);

    let mut vm = test_vm_state(task);

    unsafe {
        core::ptr::write_bytes(mmap1.ptr, 0x77, extent1_len);
        core::ptr::write_bytes(mmap2.ptr, 0x88, extent2_len);
    }

    let total_len = extent1_len + hole_len + extent2_len;
    vm.zero_guest_backing(HEAP_START, total_len)
        .expect("zero range spanning hole");

    // Extent 1 and Extent 2 should be zeroed
    for i in 0..extent1_len {
        assert_eq!(unsafe { *mmap1.ptr.add(i) }, 0);
    }
    for i in 0..extent2_len {
        assert_eq!(unsafe { *mmap2.ptr.add(i) }, 0);
    }
}
