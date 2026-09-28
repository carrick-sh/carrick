//! Scoped task-row budgets for backing maintenance.
//!
//! The resolver selects and authenticates each Linux page independently.
//! These fixtures measure only TaskMappings rows, bounded per page by the
//! existing kernel.mm.backing-maintenance-lookup contract. They do not measure
//! stage-1 walks, registry visits, locks, write runs, or end-to-end overhead.
//! In particular, there is no extent-proportional total-work claim.

use crate::trap::{
    CarrierForeignMmTransport, HotPathScan, HvfSyscallTransport, HvfTaskState, HvfVmState,
    MailboxSlotAllocator, hot_path_rows_scanned, thread_sibling_tests::mapped_region,
};

const PAGE_SIZE: usize = 4096;
const LARGE_PAGES: usize = 256;
const HEAP_START: u64 = 0x2000_0000;
const TASK_ROWS_PER_PAGE_BUDGET: u64 = 2;

pub(super) struct MmapBuffer {
    pub(super) ptr: *mut u8,
    len: usize,
}

impl MmapBuffer {
    pub(super) fn new(len: usize) -> Self {
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

pub(super) fn test_vm_state(task: HvfTaskState) -> HvfVmState {
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

// Neutral tasks share the default registry scope. Other serial tests may leave
// rows there; exclude that unrelated population from these no-alias fixtures.
fn isolated_alias_registry() -> crate::trap::foreign_mm::tests::ExternalAliasStateRestore {
    let restore = crate::trap::foreign_mm::tests::ExternalAliasStateRestore::capture();
    crate::trap::mutate_external_alias_state(|registry| *registry = Default::default());
    restore
}

#[test]
fn zero_guest_backing_fallback_task_rows_are_bounded_per_page() {
    let _registry = isolated_alias_registry();
    let mut task = HvfTaskState::neutral();
    let total_size = LARGE_PAGES * PAGE_SIZE;
    let mmap = MmapBuffer::new(total_size);
    let mut region = mapped_region(HEAP_START, HEAP_START + total_size as u64, HEAP_START);
    region.host_addr = mmap.ptr;
    task.mappings.insert(region);
    let mut vm = test_vm_state(task);
    for pages in [1, 16, LARGE_PAGES] {
        unsafe {
            core::ptr::write_bytes(mmap.ptr, 0xaa, total_size);
        }
        let before = hot_path_rows_scanned(HotPathScan::TaskMappings);
        vm.zero_guest_backing(HEAP_START, pages * PAGE_SIZE)
            .expect("zero range");
        let scanned = hot_path_rows_scanned(HotPathScan::TaskMappings) - before;
        assert!(
            scanned > 0 && scanned <= pages as u64 * TASK_ROWS_PER_PAGE_BUDGET,
            "{pages} pages visited {scanned} task rows"
        );
        for i in 0..total_size {
            assert_eq!(
                unsafe { *mmap.ptr.add(i) },
                if i < pages * PAGE_SIZE { 0 } else { 0xaa }
            );
        }
    }
}

#[test]
fn zero_guest_backing_two_mappings_task_rows_are_bounded_per_page() {
    // macOS host VM pages are 16 KiB; a one-Linux-page guard would also
    // protect the beginning of the second extent.
    for gap_pages in [0, 4] {
        zero_guest_backing_two_mappings_with_host_gap(gap_pages);
    }
}

fn zero_guest_backing_two_mappings_with_host_gap(gap_pages: usize) {
    let _registry = isolated_alias_registry();
    let mut task = HvfTaskState::neutral();
    let extent1_pages = 128;
    let extent2_pages = 128;
    let total_pages = extent1_pages + extent2_pages;
    let extent1_len = extent1_pages * PAGE_SIZE;
    let extent2_len = extent2_pages * PAGE_SIZE;

    // Reserve both extents together: independent mmap calls may or may not be
    // adjacent, depending on the host allocator's current layout.
    let backing = MmapBuffer::new(extent1_len + gap_pages * PAGE_SIZE + extent2_len);
    let host1 = backing.ptr;
    let host2 = unsafe { backing.ptr.add(extent1_len + gap_pages * PAGE_SIZE) };
    if gap_pages != 0 {
        let result = unsafe {
            libc::mprotect(
                backing.ptr.add(extent1_len).cast(),
                gap_pages * PAGE_SIZE,
                libc::PROT_NONE,
            )
        };
        assert_eq!(result, 0, "protect host guard gap");
    }

    let mut region1 = mapped_region(HEAP_START, HEAP_START + extent1_len as u64, HEAP_START);
    region1.host_addr = host1;
    task.mappings.insert(region1);

    let region2_start = HEAP_START + extent1_len as u64;
    let mut region2 = mapped_region(
        region2_start,
        region2_start + extent2_len as u64,
        region2_start,
    );
    region2.host_addr = host2;
    task.mappings.insert(region2);
    assert_eq!(task.mappings.len(), if gap_pages == 0 { 1 } else { 2 });

    let mut vm = test_vm_state(task);

    unsafe {
        core::ptr::write_bytes(host1, 0x11, extent1_len);
        core::ptr::write_bytes(host2, 0x22, extent2_len);
    }

    let before = hot_path_rows_scanned(HotPathScan::TaskMappings);
    vm.zero_guest_backing(HEAP_START, total_pages * PAGE_SIZE)
        .expect("zero multi-extent range");
    let scanned = hot_path_rows_scanned(HotPathScan::TaskMappings) - before;

    // Verify all bytes across both extents are zeroed
    for i in 0..extent1_len {
        assert_eq!(unsafe { *host1.add(i) }, 0);
    }
    for i in 0..extent2_len {
        assert_eq!(unsafe { *host2.add(i) }, 0);
    }

    // Each page selects its mapping independently; this counts only task rows.
    assert!(
        scanned <= total_pages as u64 * TASK_ROWS_PER_PAGE_BUDGET,
        "zeroing 2 extents with {gap_pages} host gap pages visited {scanned} task mapping rows (budget {})",
        total_pages as u64 * TASK_ROWS_PER_PAGE_BUDGET
    );
    for page in 0..total_pages {
        let before = hot_path_rows_scanned(HotPathScan::TaskMappings);
        vm.zero_guest_backing(HEAP_START + (page * PAGE_SIZE) as u64, PAGE_SIZE)
            .expect("zero one page");
        let scanned = hot_path_rows_scanned(HotPathScan::TaskMappings) - before;
        assert!(
            scanned <= TASK_ROWS_PER_PAGE_BUDGET,
            "page {page} with {gap_pages} host gap pages visited {scanned} task mapping rows"
        );
    }
}

#[test]
fn zero_guest_backing_unaligned_partial_range_preserves_surrounding_bytes() {
    let _registry = isolated_alias_registry();
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
    let _registry = isolated_alias_registry();
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
