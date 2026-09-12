use super::super::tests::{
    CountingMmapMemory, ProtectionTrackingMemory, returned, threaded_memory_call,
};
use super::*;
use crate::memory::LINUX_MMAP_BASE;

struct LazyResidentMemory {
    protect_calls: usize,
}

impl GuestMemory for LazyResidentMemory {
    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        Err(MemoryError::OutOfBounds { address, length })
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        Err(MemoryError::OutOfBounds {
            address,
            length: bytes.len(),
        })
    }

    fn protect_range(&mut self, _address: u64, _len: usize, _prot: u64) -> Result<(), MemoryError> {
        self.protect_calls += 1;
        Ok(())
    }
}

impl CurrentMmMemory for LazyResidentMemory {}

struct GapMemory {
    base: u64,
}

impl GapMemory {
    fn page_is_mapped(&self, address: u64, length: usize) -> bool {
        let Some(end) = address.checked_add(length as u64) else {
            return false;
        };
        let first_start = self.base;
        let first_end = self.base + LINUX_PAGE_SIZE;
        let last_start = self.base + 2 * LINUX_PAGE_SIZE;
        let last_end = self.base + 3 * LINUX_PAGE_SIZE;
        (address >= first_start && end <= first_end) || (address >= last_start && end <= last_end)
    }
}

impl GuestMemory for GapMemory {
    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        if self.page_is_mapped(address, length) {
            Ok(vec![0; length])
        } else {
            Err(MemoryError::OutOfBounds { address, length })
        }
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        if self.page_is_mapped(address, bytes.len()) {
            Ok(())
        } else {
            Err(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            })
        }
    }
}

impl CurrentMmMemory for GapMemory {}

// mincore (syscall 232) failure-arm guards: a guest-controlled `length` must
// never drive the residency-vec allocation past the actual mapping (the
// `vec![1u8; pages]` is uncatchable on alloc failure). Both arms must report
// ENOMEM (errno 12), never panic/abort. The success path is covered by the
// integration test `mm_lock_msync_mincore_stubs_validate_args_and_succeed`.
fn mincore(memory: &mut impl CurrentMmMemory, address: u64, length: u64) -> DispatchOutcome {
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(232, SyscallArgs::from([address, length, address, 0, 0, 0])),
            memory,
            &reporter,
        )
        .expect("mincore dispatch must not be a fatal DispatchError")
}

#[test]
fn mincore_onfault_lock_is_not_resident_until_page_is_touched() {
    let dispatcher = SyscallDispatcher::new();
    let base = LINUX_MMAP_BASE;
    let length = 2 * LINUX_PAGE_SIZE;
    dispatcher.record_dynamic_mapping(
        base,
        length,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Shared,
        String::new(),
    );
    let range =
        crate::vfs::GuestMemoryRange::new(GuestVa(base), GuestVa(base.saturating_add(length)))
            .expect("valid locked range");
    locked_ranges_insert(&mut dispatcher.mem().lock().locked_ranges, range);
    let memory = LinearMemory::new(base, vec![0; length as usize]);

    assert_eq!(
        dispatcher.mincore_residency_vector(&memory, base, 2, LINUX_PAGE_SIZE),
        Some(vec![0, 0]),
        "MLOCK_ONFAULT accounting alone must not make pages resident"
    );

    dispatcher.mark_range_resident(base, LINUX_PAGE_SIZE);
    assert_eq!(
        dispatcher.mincore_residency_vector(&memory, base, 2, LINUX_PAGE_SIZE),
        Some(vec![1, 0]),
        "only the populated page becomes resident"
    );
}

#[test]
fn readonly_private_anonymous_dontneed_retires_populated_residency() {
    const SYS_MMAP: u64 = 222;
    const SYS_MADVISE: u64 = 233;

    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize);
    let reporter = CompatReporter::default();
    let context = dispatcher
        .capture_one_task_context()
        .expect("read-only private-anonymous context");
    let address = returned(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(
                    SYS_MMAP,
                    SyscallArgs([
                        0,
                        LINUX_PAGE_SIZE,
                        LINUX_PROT_READ,
                        LINUX_MAP_PRIVATE
                            | LINUX_MAP_ANONYMOUS
                            | crate::linux_abi::LINUX_MAP_POPULATE,
                        u64::MAX,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .expect("read-only private-anonymous MAP_POPULATE dispatch"),
    ) as u64;
    assert_eq!(
        dispatcher.mincore_residency_vector(&memory, address, 1, LINUX_PAGE_SIZE),
        Some(vec![1]),
        "MAP_POPULATE must begin resident"
    );

    assert_eq!(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(
                    SYS_MADVISE,
                    SyscallArgs([address, LINUX_PAGE_SIZE, LINUX_MADV_DONTNEED, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .expect("read-only private-anonymous MADV_DONTNEED dispatch"),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher.mincore_residency_vector(&memory, address, 1, LINUX_PAGE_SIZE),
        Some(vec![0]),
        "MADV_DONTNEED must retire synthetic residency even when the VMA is read-only"
    );
}

#[test]
fn eager_mlock_uses_committed_vma_metadata_before_lazy_backing_is_resident() {
    const SYS_MLOCK2: u64 = 284;

    let base = LINUX_MMAP_BASE;
    let length = 2 * LINUX_PAGE_SIZE;
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.record_dynamic_mapping(
        base,
        length,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Shared,
        String::new(),
    );
    dispatcher.track_resident_fault_range(
        base,
        length,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
    );
    let reporter = CompatReporter::default();
    let mut memory = LazyResidentMemory { protect_calls: 0 };
    let kernel = dispatcher
        .capture_one_task_context()
        .expect("single task context");

    let outcome = dispatcher
        .dispatch(
            &kernel,
            SyscallRequest::new(SYS_MLOCK2, SyscallArgs([base, length, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .expect("mlock2 dispatch");

    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
    assert_eq!(
        memory.protect_calls, 1,
        "eager mlock must make the lazy range resident"
    );
}

#[test]
fn eager_lock_paths_populate_mincore_residency() {
    let base = LINUX_MMAP_BASE;
    let length = 2 * LINUX_PAGE_SIZE;
    let range =
        crate::vfs::GuestMemoryRange::new(GuestVa(base), GuestVa(base.saturating_add(length)))
            .expect("valid locked range");
    let mut memory = LinearMemory::new(base, vec![0; length as usize]);

    let map_locked = SyscallDispatcher::new();
    map_locked.record_dynamic_mapping(
        base,
        length,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Private,
        String::new(),
    );
    map_locked
        .commit_mmap_locked_range(&mut memory, Some(range))
        .expect("populate MAP_LOCKED range");
    assert_eq!(
        map_locked.mincore_residency_vector(&memory, base, 2, LINUX_PAGE_SIZE),
        Some(vec![1, 1]),
        "MAP_LOCKED must populate the mapping"
    );

    let mlockall = SyscallDispatcher::new();
    mlockall.record_dynamic_mapping(
        base,
        length,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Private,
        String::new(),
    );
    mlockall
        .lock_current_mappings(&mut memory, false)
        .expect("populate MCL_CURRENT mappings");
    assert_eq!(
        mlockall.mincore_residency_vector(&memory, base, 2, LINUX_PAGE_SIZE),
        Some(vec![1, 1]),
        "MCL_CURRENT without MCL_ONFAULT must populate current mappings"
    );

    let alias_locked = SyscallDispatcher::new();
    alias_locked.commit_eager_locked_range(Some(range));
    alias_locked.record_dynamic_mapping(
        base,
        length,
        LinuxProtFlags::READ,
        ProcMapSharing::Shared,
        String::new(),
    );
    assert_eq!(
        alias_locked.mincore_residency_vector(&memory, base, 2, LINUX_PAGE_SIZE),
        Some(vec![1, 1]),
        "deferred host aliases must publish eager MAP_LOCKED residency"
    );
}

#[test]
fn mincore_unmapped_end_page_is_enomem_not_abort() {
    let base = LINUX_MMAP_BASE;
    let mut memory = LinearMemory::new(base, vec![0u8; LINUX_PAGE_SIZE as usize]);
    assert_eq!(
        mincore(&mut memory, base, 2 * LINUX_PAGE_SIZE),
        DispatchOutcome::Errno {
            errno: LinuxErrno::new(12),
        },
        "a range whose end page is unmapped must be ENOMEM"
    );
}

#[test]
fn mincore_mapped_first_and_last_with_hole_is_enomem() {
    let base = LINUX_MMAP_BASE;
    let mut memory = GapMemory { base };
    assert_eq!(
        mincore(&mut memory, base, 3 * LINUX_PAGE_SIZE),
        DispatchOutcome::Errno {
            errno: LinuxErrno::new(12),
        },
        "a range with a mapped first and last page but an unmapped middle page must be ENOMEM"
    );
}

#[test]
fn mincore_overflowing_length_is_enomem_not_abort() {
    let base = LINUX_MMAP_BASE;
    let mut memory = LinearMemory::new(base, vec![0u8; LINUX_PAGE_SIZE as usize]);
    assert_eq!(
        mincore(&mut memory, base, u64::MAX),
        DispatchOutcome::Errno {
            errno: LinuxErrno::new(12),
        },
        "a length that overflows the [address, address+length) range must be ENOMEM"
    );
}

#[test]
fn madvise_reports_vma_rejection_before_unmapped_hole_enomem() {
    const SYS_MMAP: u64 = 222;
    const SYS_MADVISE: u64 = 233;
    const MAPPED_LENGTH: usize = crate::trap::HVF_PAGE_SIZE as usize;

    let map = |flags: u64, thread: i32| {
        let dispatcher = SyscallDispatcher::new();
        let registry = crate::thread::ThreadRegistry::new(
            crate::thread::ThreadId::synthetic_for_tests(thread),
        );
        let reporter = CompatReporter::default();
        let mut memory =
            ProtectionTrackingMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, MAPPED_LENGTH);
        let mapped = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([0, LINUX_PAGE_SIZE, LINUX_PROT_READ, flags, u64::MAX, 0]),
            ),
        )) as u64;
        threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MADVISE,
                SyscallArgs([
                    mapped,
                    16 * LINUX_PAGE_SIZE,
                    carrick_abi::LINUX_MADV_WIPEONFORK,
                    0,
                    0,
                    0,
                ]),
            ),
        )
    };

    assert_eq!(
        map(LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS, 1070),
        DispatchOutcome::errno(LINUX_EINVAL),
        "a visited shared VMA rejects WIPEONFORK ahead of the hole"
    );
    assert_eq!(
        map(LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS, 1071),
        DispatchOutcome::errno(LINUX_ENOMEM),
        "every visited VMA accepts the advice, so the hole reports ENOMEM"
    );
}
