use super::*;
use crate::linux_abi::LINUX_PROT_EXEC;
use crate::memory::{LINUX_HEAP_BASE, LINUX_MMAP_BASE};
use std::cell::{Cell, RefCell};

#[test]
fn vma_snapshot_projects_permissions_and_splits_kernel_hidden_coverage() {
    let mut mem = MemState::new_with_layout(MemoryLayout::hvf_default());
    mem.address_space_regions = Some(vec![ProcMapsEntry {
        start: 0x1000,
        end: 0x5000,
        read: true,
        write: false,
        execute: true,
        sharing: ProcMapSharing::Private,
        path: "/fixture".to_owned(),
    }]);
    locked_ranges_insert(
        &mut mem.secretmem_maps,
        crate::vfs::GuestMemoryRange::new(GuestVa(0x2000), GuestVa(0x3000)).expect("secret range"),
    );

    assert_eq!(
        project_vma_summaries(&mem),
        vec![
            crate::kernel::VmaSummary {
                start: GuestVa(0x1000),
                end: GuestVa(0x2000),
                access: crate::kernel::VmaAccess {
                    readable: true,
                    writable: false,
                    executable: true,
                    kernel_visible: true,
                },
            },
            crate::kernel::VmaSummary {
                start: GuestVa(0x2000),
                end: GuestVa(0x3000),
                access: crate::kernel::VmaAccess {
                    readable: true,
                    writable: false,
                    executable: true,
                    kernel_visible: false,
                },
            },
            crate::kernel::VmaSummary {
                start: GuestVa(0x3000),
                end: GuestVa(0x5000),
                access: crate::kernel::VmaAccess {
                    readable: true,
                    writable: false,
                    executable: true,
                    kernel_visible: true,
                },
            },
        ]
    );
}

/// The Darwin constraint behind [`host_fd_can_back_shared_alias`], asserted
/// against the live host kernel rather than trusted as folklore: a
/// `MAP_SHARED` mapping of an `O_RDONLY` fd is capped at a read-only
/// `max_protection`, so it can never be granted write — which is exactly why
/// `hv_vm_map` refuses such a region with `HV_ERROR` and why that fd must not
/// back a live stage-2 alias. The same file opened `O_RDWR` re-protects fine,
/// so the fd's ACCESS MODE, not the requested protection, is the discriminator.
#[cfg(target_os = "macos")]
/// `locked_ranges_insert` keeps a SORTED, MERGED, non-overlapping set. It used
/// to re-sort and rebuild the whole vector on every insert; it now splices only
/// the run of entries the new range touches. Pin the shape the callers depend
/// on — including the two cases a local splice could plausibly get wrong:
/// inserting BEFORE everything already present, and coalescing a range that
/// merely ABUTS its neighbours rather than overlapping them.
#[test]
fn locked_ranges_insert_keeps_the_set_sorted_and_merged() {
    fn range(start: u64, end: u64) -> crate::vfs::GuestMemoryRange {
        crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(end)).expect("valid range")
    }
    fn pairs(ranges: &[crate::vfs::GuestMemoryRange]) -> Vec<(u64, u64)> {
        ranges
            .iter()
            .map(|r| (r.start().raw(), r.end().raw()))
            .collect()
    }

    // Inserted out of order, disjoint: the set sorts itself.
    let mut ranges = Vec::new();
    for (start, end) in [(0x3000, 0x4000), (0x1000, 0x2000), (0x9000, 0xa000)] {
        locked_ranges_insert(&mut ranges, range(start, end));
    }
    assert_eq!(
        pairs(&ranges),
        vec![(0x1000, 0x2000), (0x3000, 0x4000), (0x9000, 0xa000)]
    );

    // Abutting on BOTH sides coalesces the three into one, even though it
    // overlaps none of them.
    locked_ranges_insert(&mut ranges, range(0x2000, 0x3000));
    assert_eq!(pairs(&ranges), vec![(0x1000, 0x4000), (0x9000, 0xa000)]);

    // A range spanning a gap swallows every entry it now covers.
    locked_ranges_insert(&mut ranges, range(0x3800, 0x9800));
    assert_eq!(pairs(&ranges), vec![(0x1000, 0xa000)]);

    // Wholly contained: no change.
    locked_ranges_insert(&mut ranges, range(0x2000, 0x3000));
    assert_eq!(pairs(&ranges), vec![(0x1000, 0xa000)]);

    // Inserting below everything present keeps the order.
    locked_ranges_insert(&mut ranges, range(0x100, 0x200));
    assert_eq!(pairs(&ranges), vec![(0x100, 0x200), (0x1000, 0xa000)]);

    // And `locked_ranges_remove` still splits an interior hole out of it.
    locked_ranges_remove(&mut ranges, range(0x4000, 0x5000));
    assert_eq!(
        pairs(&ranges),
        vec![(0x100, 0x200), (0x1000, 0x4000), (0x5000, 0xa000)]
    );
}

#[test]
fn readonly_host_fd_cannot_carry_a_writable_shared_file_mapping() {
    use std::io::Write;
    use std::os::fd::AsRawFd;

    let dir = std::env::temp_dir().join(format!("carrick-alias-maxprot-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join("backing");
    {
        let mut file = std::fs::File::create(&path).expect("create backing");
        file.write_all(&[0u8; 16384]).expect("size backing");
    }

    let map_then_grant_write = |file: &std::fs::File| -> (bool, i32) {
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                16384,
                libc::PROT_READ,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(addr, libc::MAP_FAILED, "PROT_READ MAP_SHARED must map");
        let rc = unsafe { libc::mprotect(addr, 16384, libc::PROT_READ | libc::PROT_WRITE) };
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        unsafe { libc::munmap(addr, 16384) };
        (rc == 0, errno)
    };

    let readonly = std::fs::File::open(&path).expect("open O_RDONLY");
    assert!(
        !host_fd_can_back_shared_alias(readonly.as_raw_fd()),
        "an O_RDONLY host fd must be refused as alias backing"
    );
    let (granted, errno) = map_then_grant_write(&readonly);
    assert!(
        !granted && errno == libc::EACCES,
        "Darwin must cap max_protection of an O_RDONLY MAP_SHARED mapping (granted={granted} errno={errno})"
    );

    let readwrite = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("open O_RDWR");
    assert!(
        host_fd_can_back_shared_alias(readwrite.as_raw_fd()),
        "an O_RDWR host fd is valid alias backing"
    );
    let (granted, errno) = map_then_grant_write(&readwrite);
    assert!(
        granted,
        "an O_RDWR-backed MAP_SHARED mapping must accept PROT_WRITE (errno={errno})"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

struct CountingMmapMemory {
    base: u64,
    bytes: Vec<u8>,
    write_calls: Cell<usize>,
    write_bytes_total: Cell<usize>,
    zero_backing_calls: Cell<usize>,
    protect_calls: Cell<usize>,
    protect_log: RefCell<Vec<(u64, usize, u64)>>,
}

#[test]
fn hvpatch_fixed_va_aliases_do_not_consume_the_legacy_monotonic_ipa_cursor() {
    let allocations = Cell::new(0_u64);
    for _ in 0..40_000 {
        let ipa = alloc_alias_ipa_for_publication_with(LINUX_PAGE_SIZE, true, |_| {
            allocations.set(allocations.get() + 1);
            None
        });
        assert_eq!(ipa, Some(crate::memory::LINUX_ALIAS_IPA_BASE));
    }
    assert_eq!(allocations.get(), 0);

    assert_eq!(
        alloc_alias_ipa_for_publication_with(LINUX_PAGE_SIZE, false, |_| {
            allocations.set(allocations.get() + 1);
            Some(0x1234_0000)
        },),
        Some(0x1234_0000)
    );
    assert_eq!(allocations.get(), 1);
}

#[test]
fn backend_mmap_arena_is_not_classified_as_an_alias() {
    let native_layout = MemoryLayout {
        heap_base: 0x8_0000_0000,
        heap_size: 128 * 1024 * 1024,
        mmap_base: 0xa0_0000_0000,
        mmap_size: 32 * 1024 * 1024 * 1024,
    };
    let address = native_layout.mmap_base;

    assert!(!mmap_address_uses_alias(
        address,
        LINUX_PAGE_SIZE,
        native_layout,
    ));
    assert!(mmap_address_uses_alias(
        address,
        LINUX_PAGE_SIZE,
        MemoryLayout::hvf_default(),
    ));
}

#[test]
fn hvpatch_sparse_semantic_arena_stays_identity_while_low_fixed_hole_aliases() {
    assert!(
        !mmap_request_uses_alias(true, false, false, true),
        "an absent sparse page inside the semantic arena must materialize through the identity route"
    );
    assert!(
        mmap_request_uses_alias(true, false, false, false),
        "a true low fixed hole still requires alias backing"
    );
    assert!(
        !mmap_request_uses_alias(true, false, true, false),
        "already-backed identity memory must not acquire a second alias"
    );
}

impl CountingMmapMemory {
    fn new(base: u64, len: usize) -> Self {
        Self {
            base,
            bytes: vec![0u8; len],
            write_calls: Cell::new(0),
            write_bytes_total: Cell::new(0),
            zero_backing_calls: Cell::new(0),
            protect_calls: Cell::new(0),
            protect_log: RefCell::new(Vec::new()),
        }
    }

    fn range_offset(&self, address: u64, length: usize) -> Result<usize, MemoryError> {
        let offset = address
            .checked_sub(self.base)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        let offset =
            usize::try_from(offset).map_err(|_| MemoryError::OutOfBounds { address, length })?;
        let end = offset
            .checked_add(length)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        if end > self.bytes.len() {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        Ok(offset)
    }
}

impl GuestMemory for CountingMmapMemory {
    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let offset = self.range_offset(address, length)?;
        Ok(self.bytes[offset..offset + length].to_vec())
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let offset = self.range_offset(address, bytes.len())?;
        self.write_calls.set(self.write_calls.get() + 1);
        self.write_bytes_total
            .set(self.write_bytes_total.get() + bytes.len());
        self.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        let offset = self.range_offset(address, len)?;
        self.zero_backing_calls
            .set(self.zero_backing_calls.get() + 1);
        self.bytes[offset..offset + len].fill(0);
        Ok(())
    }

    fn protect_range(&mut self, address: u64, len: usize, prot: u64) -> Result<(), MemoryError> {
        self.protect_calls.set(self.protect_calls.get() + 1);
        self.protect_log.borrow_mut().push((address, len, prot));
        Ok(())
    }
}

impl CurrentMmMemory for CountingMmapMemory {}

struct Stage1MmapMemory {
    inner: CountingMmapMemory,
    page_tables: carrick_mem::page_table::PageTableManager,
}

impl Stage1MmapMemory {
    fn new(base: u64, len: usize) -> Self {
        Self {
            inner: CountingMmapMemory::new(base, len),
            page_tables: carrick_mem::page_table::PageTableManager::new(
                carrick_mem::memory::stage1_hvpatch_page_tables(),
                carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
            ),
        }
    }

    fn terminal_descriptor(&self, address: u64) -> u64 {
        carrick_mem::page_table::terminal_descriptor(self.page_tables.debug_walk(address))
    }
}

impl GuestMemory for Stage1MmapMemory {
    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        self.inner.read_bytes_raw(address, length)
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.inner.write_bytes_raw(address, bytes)
    }

    fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.inner.zero_backing(address, len)
    }

    fn protect_range(&mut self, address: u64, len: usize, prot: u64) -> Result<(), MemoryError> {
        let flags = LinuxProtFlags::from_bits_retain(prot);
        let executable = flags.contains(LinuxProtFlags::EXEC);
        let changed = if flags.contains(LinuxProtFlags::WRITE) {
            self.page_tables.set_rw(address, len, executable)
        } else if flags.intersects(LinuxProtFlags::READ | LinuxProtFlags::EXEC) {
            self.page_tables.set_readonly(address, len, executable)
        } else {
            self.page_tables.set_prot_none(address, len)
        };
        changed
            .map(|_| ())
            .map_err(|error| MemoryError::HostMap(format!("stage-1 protection: {error:?}")))
    }
}

impl CurrentMmMemory for Stage1MmapMemory {}

struct ConcurrentExecMemory(CountingMmapMemory);

impl GuestMemory for ConcurrentExecMemory {
    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        self.0.read_bytes_raw(address, length)
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.0.write_bytes_raw(address, bytes)
    }

    fn protect_range(&mut self, address: u64, len: usize, prot: u64) -> Result<(), MemoryError> {
        self.0.protect_range(address, len, prot)
    }

    fn supports_concurrent_exec_protection(&self) -> bool {
        true
    }
}

impl CurrentMmMemory for ConcurrentExecMemory {}

struct ProtectionTrackingMemory {
    inner: CountingMmapMemory,
    protections: carrick_guest_mem::protections::MemoryProtections,
    repoint_calls: usize,
    repoint_payload: Vec<u8>,
    repoint_observed_shared: Vec<bool>,
    restored_shared_identity: Vec<(u64, usize)>,
    repointed_shared_leaves: Vec<(u64, u64, usize)>,
    active_aliases: Vec<(u64, u64, usize)>,
    unmapped_alias_ranges: Vec<(u64, usize)>,
    fail_repoint: bool,
    fail_repoint_indeterminate: bool,
    fail_protect: bool,
}

struct FailingProtectMemory {
    inner: CountingMmapMemory,
}

struct LazyResidentMemory {
    protect_calls: usize,
}

struct DeferredSetterFailureMemory {
    inner: CountingMmapMemory,
    pending_failure: bool,
    protect_calls: usize,
    unmap_calls: usize,
    unmap_failures_remaining: usize,
    concurrent_exec: bool,
    unmapped: carrick_guest_mem::protections::MemoryProtections,
}

impl DeferredSetterFailureMemory {
    fn new(base: u64, len: usize) -> Self {
        Self {
            inner: CountingMmapMemory::new(base, len),
            pending_failure: false,
            protect_calls: 0,
            unmap_calls: 0,
            unmap_failures_remaining: 0,
            concurrent_exec: true,
            unmapped: carrick_guest_mem::protections::MemoryProtections::default(),
        }
    }

    fn fail_unmaps(mut self, count: usize) -> Self {
        self.unmap_failures_remaining = count;
        self
    }

    fn demand_paged(mut self) -> Self {
        self.concurrent_exec = false;
        self
    }
}

impl GuestMemory for DeferredSetterFailureMemory {
    fn protections(&self) -> Option<&carrick_guest_mem::protections::MemoryProtections> {
        Some(&self.unmapped)
    }

    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        self.inner.read_bytes_raw(address, length)
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.inner.write_bytes_raw(address, bytes)
    }

    fn set_mapping_protection(
        &mut self,
        _address: u64,
        _len: usize,
        _no_access: bool,
        _no_write: bool,
    ) {
        self.pending_failure = true;
    }

    fn protect_range(&mut self, _address: u64, _len: usize, _prot: u64) -> Result<(), MemoryError> {
        self.protect_calls += 1;
        if std::mem::take(&mut self.pending_failure) {
            Err(MemoryError::HostMap(
                "deferred eager mapping failure".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    fn unmap_range(&mut self, _address: u64, _len: usize) -> Result<(), MemoryError> {
        self.unmap_calls += 1;
        if self.unmap_failures_remaining != 0 {
            self.unmap_failures_remaining -= 1;
            return Err(MemoryError::HostMap(
                "injected persistent unmap failure".into(),
            ));
        }
        Ok(())
    }

    fn set_unmapped(&mut self, address: u64, len: usize, unmapped: bool) {
        self.unmapped.set_unmapped(address, len, unmapped);
    }

    fn supports_concurrent_exec_protection(&self) -> bool {
        self.concurrent_exec
    }
}

impl CurrentMmMemory for DeferredSetterFailureMemory {}

impl GuestMemory for FailingProtectMemory {
    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        self.inner.read_bytes_raw(address, length)
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.inner.write_bytes_raw(address, bytes)
    }

    fn protect_range(&mut self, _address: u64, _len: usize, _prot: u64) -> Result<(), MemoryError> {
        Err(MemoryError::Unsupported)
    }
}

impl CurrentMmMemory for FailingProtectMemory {}

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

impl ProtectionTrackingMemory {
    fn new(base: u64, len: usize) -> Self {
        Self {
            inner: CountingMmapMemory::new(base, len),
            protections: carrick_guest_mem::protections::MemoryProtections::default(),
            repoint_calls: 0,
            repoint_payload: Vec::new(),
            repoint_observed_shared: Vec::new(),
            restored_shared_identity: Vec::new(),
            repointed_shared_leaves: Vec::new(),
            active_aliases: Vec::new(),
            unmapped_alias_ranges: Vec::new(),
            fail_repoint: false,
            fail_repoint_indeterminate: false,
            fail_protect: false,
        }
    }

    fn translate(&self, address: u64) -> u64 {
        self.active_aliases
            .iter()
            .rev()
            .find(|(va, _, l)| address >= *va && address < *va + *l as u64)
            .map(|(va, target_ipa, _)| target_ipa + (address - va))
            .unwrap_or(address)
    }
}

impl GuestMemory for ProtectionTrackingMemory {
    fn protections(&self) -> Option<&carrick_guest_mem::protections::MemoryProtections> {
        Some(&self.protections)
    }

    fn has_complete_mapping_metadata(&self) -> bool {
        true
    }

    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let translated = self.translate(address);
        self.inner.read_bytes_raw(translated, length)
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let translated = self.translate(address);
        self.inner.write_bytes_raw(translated, bytes)
    }

    fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.inner.zero_backing(address, len)
    }

    fn restore_shared_identity(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.restored_shared_identity.push((address, len));
        Ok(())
    }

    fn unmap_alias_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.unmapped_alias_ranges.push((address, len));
        let unmap_end = address.saturating_add(len as u64);
        self.active_aliases.retain(|(va, _, l)| {
            let end = va.saturating_add(*l as u64);
            end <= address || *va >= unmap_end
        });
        Ok(())
    }

    fn repoint_shared_leaf(
        &mut self,
        va: u64,
        target_ipa: u64,
        len: usize,
    ) -> Result<(), MemoryError> {
        self.repointed_shared_leaves.push((va, target_ipa, len));
        if self.fail_repoint {
            return Err(MemoryError::HostMap(
                "injected repoint shared leaf failure".into(),
            ));
        }
        self.active_aliases.push((va, target_ipa, len));
        Ok(())
    }

    fn translate_va(&self, va: u64) -> Option<u64> {
        self.active_aliases
            .iter()
            .rev()
            .find(|(start, _, l)| va >= *start && va < *start + *l as u64)
            .map(|(start, target_ipa, _)| target_ipa + (va - start))
    }

    fn repoint_private(
        &mut self,
        address: u64,
        _overlay_ipa: u64,
        len: usize,
        content: &[u8],
    ) -> Result<(), carrick_guest_mem::RepointPrivateError> {
        if content.len() != len {
            return Err(carrick_guest_mem::RepointPrivateError::clean(
                MemoryError::OutOfBounds {
                    address,
                    length: content.len(),
                },
            ));
        }
        let offset = self
            .inner
            .range_offset(address, len)
            .map_err(carrick_guest_mem::RepointPrivateError::clean)?;
        self.repoint_observed_shared
            .push(self.protections.range_mutable_shared_backing(address, len));
        self.repoint_calls += 1;
        if self.fail_repoint {
            return Err(carrick_guest_mem::RepointPrivateError::clean(
                MemoryError::HostMap("injected private repoint failure".into()),
            ));
        }
        if self.fail_repoint_indeterminate {
            return Err(carrick_guest_mem::RepointPrivateError::indeterminate(
                MemoryError::HostMap("injected post-publication repoint failure".into()),
            ));
        }
        self.repoint_payload.clear();
        self.repoint_payload.extend_from_slice(content);
        self.inner.bytes[offset..offset + len].copy_from_slice(content);
        Ok(())
    }

    fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
        self.protections.set_no_access(address, len, no_access);
    }

    fn set_no_write(&mut self, address: u64, len: usize, no_write: bool) {
        self.protections.set_no_write(address, len, no_write);
    }

    fn set_unmapped(&mut self, address: u64, len: usize, unmapped: bool) {
        self.protections.set_unmapped(address, len, unmapped);
    }

    fn set_mapping_protection(
        &mut self,
        address: u64,
        len: usize,
        no_access: bool,
        no_write: bool,
    ) {
        self.protections
            .set_mapping_protection(address, len, no_access, no_write);
    }

    fn set_mapping_sharing(
        &mut self,
        address: u64,
        len: usize,
        sharing: carrick_guest_mem::MappingSharing,
    ) {
        self.protections.set_mapping_sharing(address, len, sharing);
    }

    fn set_mapping_protection_and_sharing(
        &mut self,
        address: u64,
        len: usize,
        no_access: bool,
        no_write: bool,
        sharing: carrick_guest_mem::MappingSharing,
    ) {
        self.protections
            .set_mapping_protection_and_sharing(address, len, no_access, no_write, sharing);
    }

    fn protect_range(&mut self, address: u64, len: usize, prot: u64) -> Result<(), MemoryError> {
        if self.fail_protect {
            return Err(MemoryError::HostMap(
                "injected private protection failure".into(),
            ));
        }
        self.protections.set_executable(
            address,
            len,
            carrick_abi::LinuxProtFlags::from_bits_truncate(prot)
                .contains(carrick_abi::LinuxProtFlags::EXEC),
        );
        self.inner.protect_range(address, len, prot)
    }
}

impl CurrentMmMemory for ProtectionTrackingMemory {}

fn returned(outcome: DispatchOutcome) -> i64 {
    match outcome {
        DispatchOutcome::Returned { value } => value,
        other => panic!("expected Returned, got {other:?}"),
    }
}

fn native16k_dispatcher() -> SyscallDispatcher {
    SyscallDispatcher::with_page_geometry(crate::page_profile::PageGeometry {
        host_page_size: 16 * 1024,
        linux_page_size: 16 * 1024,
        native_profile: Some(carrick_spec::NativePageProfile::Native16k),
    })
}

fn threaded_memory_call(
    dispatcher: &SyscallDispatcher,
    memory: &mut impl CurrentMmMemory,
    registry: &crate::thread::ThreadRegistry,
    reporter: &CompatReporter,
    request: SyscallRequest,
) -> DispatchOutcome {
    dispatcher
        .dispatch_threaded_for_test(
            &dispatcher.capture_one_task_context().unwrap(),
            request,
            memory,
            reporter,
            registry.main_tid(),
            registry,
            &crate::thread::FutexTable::new(),
        )
        .expect("threaded memory dispatch")
}

fn assert_partial_reason(reporter: &CompatReporter, syscall: &str, needle: &str) {
    let report = reporter.snapshot();
    assert!(
        report
            .partial_syscalls
            .iter()
            .any(|entry| entry.name == syscall && entry.reason.contains(needle)),
        "missing {syscall} partial-syscall reason containing {needle:?}: {report:?}"
    );
}

fn assert_operation_waits_for_host_alias_idle<F>(label: &'static str, operation: F)
where
    F: FnOnce(std::sync::Arc<SyscallDispatcher>) + Send + 'static,
{
    let dispatcher = std::sync::Arc::new(SyscallDispatcher::new());
    let transaction = dispatcher.with_host_alias_dispatch_for_test(|guard| {
        guard.publish(HostAliasCommit::mmap(HostAliasMmapCommit {
            start: crate::memory::LINUX_HIGH_VA_THRESHOLD,
            len: LINUX_PAGE_SIZE,
            prot: LinuxProtFlags::READ,
            sharing: ProcMapSharing::Private,
            path: String::new(),
            file_page_offset: None,
            droppable: false,
            semantic_vmas: None,
            locked: None,
            resident: false,
            bus_fault: None,
            write_sealed_shared: false,
            read_only_shared_file: false,
            secretmem: false,
            writable_memfd: None,
            shared_file_alias: None,
        }))
    });
    transaction
        .with_claim_for_test(|install| {
            let sibling = std::sync::Arc::clone(&dispatcher);
            let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
            let thread = std::thread::spawn(move || {
                operation(sibling);
                entered_tx.send(()).expect("report blocked operation");
            });
            assert!(
                entered_rx
                    .recv_timeout(std::time::Duration::from_millis(25))
                    .is_err(),
                "{label} raced an installing host alias"
            );
            drop(install);
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("operation admitted after abort");
            thread.join().expect("join blocked operation thread");
        })
        .expect("claim pending host alias install");
}

#[test]
fn native16k_rejects_shared_write_exec_mmap() {
    const SYS_MMAP: u64 = 222;
    const PAGE_SIZE: u64 = 16 * 1024;

    let dispatcher = native16k_dispatcher();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1000));
    let reporter = CompatReporter::default();
    let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, PAGE_SIZE as usize);
    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC,
                LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    );

    assert_eq!(outcome, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
    assert_partial_reason(&reporter, "mmap", "shared write-exec");
}

#[test]
fn shared_anon_deferred_setter_failure_rolls_back_before_commit() {
    const SYS_MMAP: u64 = 222;
    const LENGTH: u64 = 4096;
    const MAPPED_LENGTH: usize = crate::trap::HVF_PAGE_SIZE as usize;

    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1050));
    let reporter = CompatReporter::default();
    let mut memory =
        DeferredSetterFailureMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, MAPPED_LENGTH);
    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                LENGTH,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    );

    assert_eq!(outcome, DispatchOutcome::errno(LINUX_ENOMEM));
    assert_eq!(memory.protect_calls, 1, "setter failure consumed once");
    assert_eq!(memory.unmap_calls, 1, "candidate backing rolled back");
    assert!(
        memory
            .unmapped
            .range_unmapped(crate::memory::LINUX_SHARED_FILE_BASE, MAPPED_LENGTH)
    );
    let mem_authority_101 = dispatcher.mem();
    let mem = mem_authority_101.lock();
    assert!(mem.shared.live().is_empty(), "allocation must not commit");
    assert!(mem.dynamic_maps.is_empty(), "VMA metadata must not commit");
}

#[test]
fn mmap_publishes_shared_rx_and_private_fixed_replacement() {
    const SYS_MMAP: u64 = 222;
    const LENGTH: u64 = 4096;
    const MAPPED_LENGTH: usize = crate::trap::HVF_PAGE_SIZE as usize;

    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1060));
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
            SyscallArgs([
                0,
                LENGTH,
                LINUX_PROT_READ | LINUX_PROT_EXEC,
                LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    assert!(memory.protections.range_executable(mapped, LENGTH as usize));
    assert!(
        memory
            .protections
            .range_mutable_shared_backing(mapped, LENGTH as usize)
    );
    assert!(
        memory
            .protections
            .range_translation_requires_ephemeral(mapped, LENGTH as usize)
    );

    let replaced = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                mapped,
                LENGTH,
                LINUX_PROT_READ | LINUX_PROT_EXEC,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    assert_eq!(replaced, mapped);
    assert!(memory.protections.range_executable(mapped, LENGTH as usize));
    assert!(
        !memory
            .protections
            .range_mutable_shared_backing(mapped, LENGTH as usize)
    );
    assert!(
        !memory
            .protections
            .range_translation_requires_ephemeral(mapped, LENGTH as usize)
    );
}

#[test]
fn file_private_fixed_shared_aperture_repoints_snapshot_and_publishes_map_time_bus_tail() {
    const SYS_MMAP: u64 = 222;
    const SYS_MPROTECT: u64 = 226;
    const LENGTH: u64 = 3 * LINUX_PAGE_SIZE;
    const MAPPED_LENGTH: usize = crate::trap::HVF_PAGE_SIZE as usize;
    const FD: i32 = 9;

    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1061));
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
            SyscallArgs([
                0,
                LENGTH,
                LINUX_PROT_READ | LINUX_PROT_EXEC,
                LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    assert!(
        memory
            .protections
            .range_mutable_shared_backing(mapped, LENGTH as usize)
    );

    let mut file_bytes = vec![0x7d; LINUX_PAGE_SIZE as usize];
    file_bytes.extend_from_slice(&[0x90, 0xc3, 0x4a]);
    dispatcher.captured_file_table().write_open_files().insert(
        FD,
        OpenFile::from_open_description_with_status_flags(
            std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::SyntheticFile {
                base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDONLY),
                path: "private-replacement".into(),
                contents: file_bytes,
                offset: 0,
            })),
            crate::linux_abi::LINUX_O_RDONLY,
            0,
        ),
    );

    let replaced = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                mapped,
                LENGTH,
                LINUX_PROT_READ | LINUX_PROT_EXEC,
                LINUX_MAP_PRIVATE | LINUX_MAP_FIXED,
                FD as u64,
                LINUX_PAGE_SIZE,
            ]),
        ),
    )) as u64;

    assert_eq!(replaced, mapped);
    assert_eq!(memory.repoint_calls, 1);
    assert_eq!(memory.repoint_observed_shared, [true]);
    assert_eq!(memory.repoint_payload.len(), LENGTH as usize);
    assert_eq!(&memory.repoint_payload[..3], &[0x90, 0xc3, 0x4a]);
    assert!(
        memory.repoint_payload[3..LINUX_PAGE_SIZE as usize]
            .iter()
            .all(|byte| *byte == 0),
        "the remainder of the partially backed last page is readable zero-fill"
    );
    assert!(
        memory.repoint_payload[LINUX_PAGE_SIZE as usize..]
            .iter()
            .all(|byte| *byte == 0),
        "materialization bytes stay zeroed even though full pages past EOF fault"
    );
    assert_eq!(
        memory
            .read_bytes(mapped, 3)
            .expect("within-file private snapshot bytes"),
        vec![0x90, 0xc3, 0x4a]
    );
    assert_eq!(
        memory
            .read_bytes(mapped + LINUX_PAGE_SIZE - 1, 1)
            .expect("partial-page EOF zero tail"),
        vec![0]
    );
    assert!(
        memory.read_bytes(mapped + LINUX_PAGE_SIZE, 1).is_err(),
        "the first page wholly beyond map-time EOF is inaccessible"
    );
    assert!(
        !memory.protections.range_bus_fault(mapped, 1)
            && memory
                .protections
                .range_bus_fault(mapped + LINUX_PAGE_SIZE, 1)
    );
    assert!(dispatcher.mmap_fault_is_sigbus(mapped + LINUX_PAGE_SIZE));
    assert!(!dispatcher.mmap_fault_is_sigbus(mapped + LINUX_PAGE_SIZE - 1));

    assert_eq!(
        returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MPROTECT,
                SyscallArgs([mapped, LENGTH, LINUX_PROT_READ | LINUX_PROT_EXEC, 0, 0, 0,]),
            ),
        )),
        0
    );
    assert!(
        memory.read_bytes(mapped + LINUX_PAGE_SIZE - 1, 1).is_ok(),
        "mprotect preserves the readable partial-page zero tail"
    );
    assert!(
        memory.read_bytes(mapped + LINUX_PAGE_SIZE, 1).is_err(),
        "mprotect cannot reopen a full page beyond map-time EOF"
    );
    assert!(
        memory
            .protections
            .range_bus_fault(mapped + LINUX_PAGE_SIZE, 1)
            && memory
                .protections
                .range_no_access(mapped + LINUX_PAGE_SIZE, 1)
    );
    assert_eq!(
        memory.inner.write_calls.get(),
        0,
        "file payload must not be copied through the still-shared VA"
    );
    assert!(
        memory
            .protections
            .range_executable(mapped, LINUX_PAGE_SIZE as usize),
        "the partially backed page remains executable"
    );
    assert!(
        !memory
            .protections
            .range_executable(mapped + LINUX_PAGE_SIZE, 1),
        "the BUS_ADRERR tail cannot remain executable"
    );
    assert!(
        !memory
            .protections
            .range_mutable_shared_backing(mapped, LENGTH as usize)
    );
    assert!(
        !memory
            .protections
            .range_translation_requires_ephemeral(mapped, LENGTH as usize)
    );
    let replacement = dispatcher
        .dynamic_mapping_for_test(mapped)
        .expect("private fixed replacement VMA");
    assert_eq!(replacement.sharing, ProcMapSharing::Private);
    assert!(replacement.execute);
    assert!(
        dispatcher
            .mem()
            .lock()
            .resident_ranges
            .iter()
            .any(|range| { range.start().raw() == mapped && range.end().raw() == mapped + LENGTH })
    );
}

#[test]
fn private_file_snapshot_computes_identical_bus_tail_for_memfd_synthetic_and_host_sources() {
    use std::os::fd::{AsRawFd, IntoRawFd};

    const LENGTH: usize = 3 * LINUX_PAGE_SIZE as usize;
    const FILE_LENGTH: usize = LINUX_PAGE_SIZE as usize + 3;
    let dispatcher = SyscallDispatcher::new();
    let payload = {
        let mut bytes = vec![0x7d; LINUX_PAGE_SIZE as usize];
        bytes.extend_from_slice(&[0x90, 0xc3, 0x4a]);
        bytes
    };
    let metadata = RootFsMetadata {
        path: std::path::PathBuf::from("/memfd:private-eof"),
        kind: RootFsEntryKind::File,
        mode: 0o600,
        size: FILE_LENGTH,
    };
    let memfd_common = std::sync::Arc::new(crate::kernel::DescriptionCommon::new(
        crate::linux_abi::LINUX_O_RDWR,
    ));
    memfd_common.set_seals(Some(0));
    dispatcher.captured_file_table().write_open_files().insert(
        20,
        OpenFile::from_open_description_with_common(
            std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::File {
                base: OpenDescriptionBase::new(0),
                path: "/memfd:private-eof".into(),
                metadata: metadata.clone(),
                contents: FileContents::dense(payload.clone()),
                offset: 0,
                writable: true,
            })),
            memfd_common,
            0,
        ),
    );
    dispatcher.captured_file_table().write_open_files().insert(
        21,
        OpenFile::from_open_description_with_status_flags(
            std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::SyntheticFile {
                base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDONLY),
                path: "/synthetic-private-eof".into(),
                contents: payload.clone(),
                offset: 0,
            })),
            crate::linux_abi::LINUX_O_RDONLY,
            0,
        ),
    );
    let host_file = tempfile::tempfile().expect("temporary host private-map source");
    assert_eq!(
        unsafe {
            libc::pwrite(
                host_file.as_raw_fd(),
                payload.as_ptr().cast(),
                payload.len(),
                0,
            )
        },
        payload.len() as isize
    );
    dispatcher.captured_file_table().write_open_files().insert(
        22,
        OpenFile::from_open_description_with_status_flags(
            std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::HostFile {
                base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDONLY),
                host_fd: HostFdRef::new(host_file.into_raw_fd()),
                metadata,
                writable: false,
            })),
            crate::linux_abi::LINUX_O_RDONLY,
            0,
        ),
    );

    for (fd, source) in [(20, "memfd"), (21, "synthetic"), (22, "host")] {
        let snapshot = dispatcher
            .snapshot_private_mmap_file(Fd(fd), LINUX_PAGE_SIZE, LENGTH)
            .unwrap_or_else(|error| panic!("snapshot {source} source: {error:?}"));
        assert_eq!(
            snapshot.bus_fault_offset,
            Some(LINUX_PAGE_SIZE),
            "{source} first full page beyond EOF"
        );
        assert_eq!(&snapshot.bytes[..3], &[0x90, 0xc3, 0x4a]);
        assert!(
            snapshot.bytes[3..LINUX_PAGE_SIZE as usize]
                .iter()
                .all(|byte| *byte == 0),
            "{source} partial-page tail must be zero-filled"
        );
    }
}

#[test]
fn shared_mmap_refreshes_an_independently_opened_vfs_inode() {
    const SYS_PWRITE64: u64 = 68;
    const SYS_MMAP: u64 = 222;
    const FILE_LEN: u64 = 16 * 1024;
    const WRITER_FD: i32 = 23;
    const MAPPER_FD: i32 = 24;
    const PATH: &str = "/telemetry.count";

    let dispatcher = native16k_dispatcher();
    dispatcher
        .fs
        .rootfs_vfs
        .overlay
        .set_file_contents(PATH, Vec::new())
        .expect("create shared overlay inode");
    let install_snapshot = |fd| {
        dispatcher.captured_file_table().write_open_files().insert(
            fd,
            OpenFile::from_open_description_with_status_flags(
                std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::File {
                    base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDWR),
                    path: PATH.into(),
                    metadata: RootFsMetadata {
                        path: PATH.into(),
                        kind: RootFsEntryKind::File,
                        mode: 0o600,
                        size: 0,
                    },
                    contents: FileContents::dense(Vec::new()),
                    offset: 0,
                    writable: true,
                })),
                crate::linux_abi::LINUX_O_RDWR,
                0,
            ),
        );
    };
    install_snapshot(WRITER_FD);
    install_snapshot(MAPPER_FD);

    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1299));
    let reporter = CompatReporter::default();
    let mut memory = CountingMmapMemory::new(crate::memory::LINUX_MMAP_BASE, 4 * FILE_LEN as usize);
    let header_address = crate::memory::LINUX_MMAP_BASE + 2 * FILE_LEN;
    memory
        .write_bytes(header_address, b"telemetry-header")
        .expect("stage header write payload");
    memory
        .write_bytes(header_address + 32, &[0; 4])
        .expect("stage extension write payload");

    assert_eq!(
        returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_PWRITE64,
                SyscallArgs([
                    WRITER_FD as u64,
                    header_address,
                    b"telemetry-header".len() as u64,
                    0,
                    0,
                    0,
                ]),
            ),
        )),
        b"telemetry-header".len() as i64
    );
    assert_eq!(
        returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_PWRITE64,
                SyscallArgs([WRITER_FD as u64, header_address + 32, 4, FILE_LEN - 4, 0, 0,]),
            ),
        )),
        4
    );
    let mapper = dispatcher.open_file(MAPPER_FD).expect("mapper fd");
    assert_eq!(
        match &*mapper.description.read().expect("mapper open description") {
            OpenDescription::File { contents, .. } => contents.len(),
            other => panic!("expected File, got {other:?}"),
        },
        0,
        "the independently opened description deliberately retains its stale snapshot"
    );

    let mapped = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                FILE_LEN,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_SHARED,
                MAPPER_FD as u64,
                0,
            ]),
        ),
    )) as u64;

    assert_eq!(
        memory
            .read_bytes(mapped, b"telemetry-header".len())
            .expect("mapped header"),
        b"telemetry-header"
    );
    assert!(
        !dispatcher.mmap_fault_is_sigbus(mapped),
        "a live 16 KiB inode must not inherit the stale zero-length description's BUS range"
    );
}

/// Mock backend for the Move-3 E1 lowering: records every
/// `map_private_file_backed` offer and answers with a configured verdict,
/// so the dispatch-side eligibility and fallback are testable without a
/// real identity host mapping.
struct FileBackedLoweringMemory {
    inner: CountingMmapMemory,
    accept: bool,
    offers: std::cell::RefCell<Vec<(u64, usize, u64)>>,
}

impl FileBackedLoweringMemory {
    fn new(base: u64, len: usize, accept: bool) -> Self {
        Self {
            inner: CountingMmapMemory::new(base, len),
            accept,
            offers: std::cell::RefCell::new(Vec::new()),
        }
    }
}

impl GuestMemory for FileBackedLoweringMemory {
    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        self.inner.read_bytes_raw(address, length)
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.inner.write_bytes_raw(address, bytes)
    }

    fn protect_range(&mut self, address: u64, len: usize, prot: u64) -> Result<(), MemoryError> {
        self.inner.protect_range(address, len, prot)
    }

    fn map_private_file_backed(
        &mut self,
        address: u64,
        len: usize,
        _host_fd: std::os::fd::BorrowedFd<'_>,
        offset: u64,
    ) -> Result<bool, MemoryError> {
        self.offers.borrow_mut().push((address, len, offset));
        Ok(self.accept)
    }
}

impl CurrentMmMemory for FileBackedLoweringMemory {}

/// Install a HostFile-backed guest fd whose backing file holds `payload`,
/// returning the guest fd number.
fn install_host_file_fd(dispatcher: &SyscallDispatcher, fd: i32, payload: &[u8]) {
    use std::os::fd::{AsRawFd, IntoRawFd};
    let host_file = tempfile::tempfile().expect("temporary host private-map source");
    assert_eq!(
        unsafe {
            libc::pwrite(
                host_file.as_raw_fd(),
                payload.as_ptr().cast(),
                payload.len(),
                0,
            )
        },
        payload.len() as isize
    );
    dispatcher.captured_file_table().write_open_files().insert(
        fd,
        OpenFile::from_open_description_with_status_flags(
            std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::HostFile {
                base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDONLY),
                host_fd: HostFdRef::new(host_file.into_raw_fd()),
                metadata: RootFsMetadata {
                    path: std::path::PathBuf::from("/host-private-map"),
                    kind: RootFsEntryKind::File,
                    mode: 0o644,
                    size: payload.len(),
                },
                writable: false,
            })),
            crate::linux_abi::LINUX_O_RDONLY,
            0,
        ),
    );
}

#[test]
fn mmap_private_hostfile_lowers_file_backed_and_publishes_bus_tail() {
    const SYS_MMAP: u64 = 222;
    const PAGE_SIZE: u64 = 16 * 1024;
    const LENGTH: u64 = 3 * PAGE_SIZE;

    let dispatcher = native16k_dispatcher();
    // File backs one full page plus 3 bytes: page 1 is the partially
    // backed page (zero tail), page 2 is wholly beyond EOF -> BUS.
    install_host_file_fd(&dispatcher, 30, &vec![0x7d; PAGE_SIZE as usize + 3]);
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1300));
    let reporter = CompatReporter::default();
    let mut memory = FileBackedLoweringMemory::new(LINUX_MMAP_BASE, 4 * PAGE_SIZE as usize, true);
    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                LENGTH,
                LINUX_PROT_READ,
                crate::linux_abi::LINUX_MAP_PRIVATE,
                30,
                0,
            ]),
        ),
    );
    let DispatchOutcome::Returned { value } = outcome else {
        panic!("private host-file mmap must succeed, got {outcome:?}");
    };
    let address = value as u64;
    assert_eq!(
        memory.offers.borrow().as_slice(),
        &[(address, LENGTH as usize, 0)],
        "the backend must be offered exactly the mapped range"
    );
    assert_eq!(
        memory.inner.write_calls.get(),
        0,
        "a lowered mapping must not be eagerly materialized"
    );
    // Map-time EOF contract: the wholly-beyond page is BUS, the partially
    // backed page is not.
    assert!(dispatcher.mmap_fault_is_sigbus(address + 2 * PAGE_SIZE));
    assert!(!dispatcher.mmap_fault_is_sigbus(address + PAGE_SIZE));
}

#[test]
fn mmap_private_hostfile_backend_refusal_falls_back_to_snapshot() {
    const SYS_MMAP: u64 = 222;
    const PAGE_SIZE: u64 = 16 * 1024;
    const LENGTH: u64 = 2 * PAGE_SIZE;

    let dispatcher = native16k_dispatcher();
    install_host_file_fd(&dispatcher, 31, &[0x51u8; 64]);
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1310));
    let reporter = CompatReporter::default();
    let mut memory = FileBackedLoweringMemory::new(LINUX_MMAP_BASE, 4 * PAGE_SIZE as usize, false);
    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                LENGTH,
                LINUX_PROT_READ,
                crate::linux_abi::LINUX_MAP_PRIVATE,
                31,
                0,
            ]),
        ),
    );
    let DispatchOutcome::Returned { value } = outcome else {
        panic!("refused lowering must fall back, got {outcome:?}");
    };
    let address = value as u64;
    assert_eq!(memory.offers.borrow().len(), 1, "the backend was offered");
    assert!(
        memory.inner.write_calls.get() > 0,
        "the fallback must eagerly materialize the snapshot"
    );
    assert_eq!(
        memory.inner.read_bytes_raw(address, 64).expect("content"),
        vec![0x51u8; 64],
        "fallback content must be the file bytes"
    );
    assert!(
        dispatcher.mmap_fault_is_sigbus(address + PAGE_SIZE),
        "a private eager snapshot still faults on pages wholly beyond map-time EOF"
    );
}

#[test]
fn mmap_private_hostfile_refusal_with_unstattable_fd_keeps_legacy_success() {
    const SYS_MMAP: u64 = 222;
    const PAGE_SIZE: u64 = 16 * 1024;

    let dispatcher = native16k_dispatcher();
    // A HostFile description whose backing host fd is already closed:
    // fstat and pread both fail. The pre-E1 eager path SUCCEEDED here
    // (best-effort pread, errors left the zeroed buffer), and mmap
    // failure atomicity demands the candidate path not invent a new
    // errno AFTER the address/scrub steps have run — so a refused
    // candidate must reproduce the legacy zero-filled success exactly.
    let dead = unsafe { libc::dup(0) };
    assert!(dead >= 0);
    assert_eq!(unsafe { libc::close(dead) }, 0);
    dispatcher.captured_file_table().write_open_files().insert(
        34,
        OpenFile::from_open_description_with_status_flags(
            std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::HostFile {
                base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDONLY),
                host_fd: HostFdRef::new(dead),
                metadata: RootFsMetadata {
                    path: std::path::PathBuf::from("/host-private-map-dead"),
                    kind: RootFsEntryKind::File,
                    mode: 0o644,
                    size: 0,
                },
                writable: false,
            })),
            crate::linux_abi::LINUX_O_RDONLY,
            0,
        ),
    );
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1340));
    let reporter = CompatReporter::default();
    let mut memory = FileBackedLoweringMemory::new(LINUX_MMAP_BASE, 4 * PAGE_SIZE as usize, false);
    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                PAGE_SIZE,
                LINUX_PROT_READ,
                crate::linux_abi::LINUX_MAP_PRIVATE,
                34,
                0,
            ]),
        ),
    );
    let DispatchOutcome::Returned { value } = outcome else {
        panic!("legacy contract: unreadable backing still maps zero-filled, got {outcome:?}");
    };
    let address = value as u64;
    assert_eq!(
        memory
            .inner
            .read_bytes_raw(address, 32)
            .expect("mapped range readable"),
        vec![0u8; 32],
        "unreadable backing must surface as zeros, the pre-E1 contract"
    );
    assert!(
        !dispatcher.mmap_fault_is_sigbus(address),
        "no BUS tail may be published without a known file length"
    );
}

#[test]
fn mmap_shared_or_exec_private_is_never_offered_the_lowering() {
    const SYS_MMAP: u64 = 222;
    const PAGE_SIZE: u64 = 16 * 1024;

    let dispatcher = native16k_dispatcher();
    install_host_file_fd(&dispatcher, 32, &[0x11u8; 32]);
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1320));
    let reporter = CompatReporter::default();
    let mut memory = FileBackedLoweringMemory::new(LINUX_MMAP_BASE, 4 * PAGE_SIZE as usize, true);
    for flags_prot in [
        (crate::linux_abi::LINUX_MAP_SHARED, LINUX_PROT_READ),
        (
            crate::linux_abi::LINUX_MAP_PRIVATE,
            LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
        ),
    ] {
        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([0, PAGE_SIZE, flags_prot.1, flags_prot.0, 32, 0]),
            ),
        );
        // A MAP_SHARED file mapping legitimately publishes via the alias
        // transaction; the exec-prot private control returns in place.
        // Either way it must never be OFFERED the lowering.
        assert!(
            matches!(
                outcome,
                DispatchOutcome::Returned { .. } | DispatchOutcome::MapHostAlias { .. }
            ),
            "control mapping must still succeed, got {outcome:?}"
        );
    }
    assert!(
        memory.offers.borrow().is_empty(),
        "shared and exec-prot mappings must keep the snapshot path: {:?}",
        memory.offers.borrow()
    );
}

/// Pin the Darwin primitive the E1 lowering's detachment claim rests on:
/// a `MAP_PRIVATE` file mapping keeps BOTH a COW'd (written) page and a
/// never-touched page readable, with map-time content, across a later
/// `ftruncate` of the backing file. Linux diverges on the untouched page
/// (SIGBUS), so the `mmapprivfile` conformance probe deliberately cannot
/// pin this clause — it is host behaviour and lives here. The faulting-
/// risk reads run in a forked child so a regression reports as a failed
/// assertion, not a dead test harness (`just test` runs this crate
/// single-threaded, the house fork-in-test precondition).
#[test]
#[cfg(target_os = "macos")]
fn darwin_private_file_mapping_detaches_from_truncate() {
    use std::os::fd::AsRawFd;
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let file = tempfile::tempfile().expect("backing file");
    let fd = file.as_raw_fd();
    let content = vec![0xabu8; 2 * page];
    assert_eq!(
        unsafe { libc::pwrite(fd, content.as_ptr().cast(), content.len(), 0) },
        content.len() as isize
    );
    let child = unsafe { libc::fork() };
    if child == 0 {
        let exit = unsafe {
            let p = libc::mmap(
                core::ptr::null_mut(),
                2 * page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE,
                fd,
                0,
            );
            if p == libc::MAP_FAILED {
                10
            } else {
                let p = p.cast::<u8>();
                *p = 0x55; // COW page 0
                if libc::ftruncate(fd, 1) != 0 {
                    11
                } else if *p != 0x55 {
                    12 // written page must survive truncate
                } else if *p.add(page) != 0xab {
                    13 // untouched page must stay readable with map-time content
                } else {
                    0
                }
            }
        };
        unsafe { libc::_exit(exit) };
    }
    assert!(child > 0, "fork failed");
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "Darwin private-file truncate detachment regressed: the E1 \
             file-backed lowering relies on it (status {status:#x}); if this \
             ever fires, the lowering must re-snapshot or be gated off"
    );
}

#[test]
fn mmap_private_hostfile_hatch_zero_keeps_snapshot_path() {
    const SYS_MMAP: u64 = 222;
    const PAGE_SIZE: u64 = 16 * 1024;

    let dispatcher = native16k_dispatcher();
    install_host_file_fd(&dispatcher, 33, &[0x22u8; 16]);
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1330));
    let reporter = CompatReporter::default();
    let mut memory = FileBackedLoweringMemory::new(LINUX_MMAP_BASE, 4 * PAGE_SIZE as usize, true);
    // SAFETY: `just test` runs carrick-runtime single-threaded
    // (RUST_TEST_THREADS=1), the house pattern for env-hatch tests.
    unsafe { std::env::set_var("CARRICK_MMAP_FILE_BACKED", "0") };
    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                PAGE_SIZE,
                LINUX_PROT_READ,
                crate::linux_abi::LINUX_MAP_PRIVATE,
                33,
                0,
            ]),
        ),
    );
    unsafe { std::env::remove_var("CARRICK_MMAP_FILE_BACKED") };
    assert!(
        matches!(outcome, DispatchOutcome::Returned { .. }),
        "hatched mapping must still succeed, got {outcome:?}"
    );
    assert!(
        memory.offers.borrow().is_empty(),
        "CARRICK_MMAP_FILE_BACKED=0 must keep the snapshot path"
    );
    assert!(
        memory.inner.write_calls.get() > 0,
        "the hatched path must eagerly materialize"
    );
}

#[test]
fn private_repoint_failure_preserves_prior_overlay_owner_and_vma() {
    const SYS_MMAP: u64 = 222;
    const LENGTH: u64 = 4096;
    const MAPPED_LENGTH: usize = crate::trap::HVF_PAGE_SIZE as usize;

    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1062));
    let reporter = CompatReporter::default();
    let mut memory =
        ProtectionTrackingMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, MAPPED_LENGTH);
    let shared = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                LENGTH,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    let first = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                shared,
                LENGTH,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    assert_eq!(first, shared);
    let prior_overlay = dispatcher
        .mem()
        .lock()
        .overlay
        .find_by_source(shared)
        .expect("first private overlay owner");
    memory.inner.bytes[0] = 0x5a;
    let prior_map = dispatcher
        .dynamic_mapping_for_test(shared)
        .expect("first private VMA");
    memory.fail_repoint = true;

    let failed = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                shared,
                LENGTH,
                LINUX_PROT_READ,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                u64::MAX,
                0,
            ]),
        ),
    );

    assert_eq!(failed, DispatchOutcome::errno(LINUX_ENOMEM));
    assert_eq!(memory.inner.bytes[0], 0x5a);
    assert_eq!(dispatcher.dynamic_mapping_for_test(shared), Some(prior_map));
    let mem_authority_102 = dispatcher.mem();
    let mut mem = mem_authority_102.lock();
    assert_eq!(mem.overlay.find_by_source(shared), Some(prior_overlay));
    assert_eq!(
        mem.overlay
            .live()
            .iter()
            .filter(|slot| slot.source == Some(shared))
            .count(),
        1,
        "failed candidate must be returned without retiring the prior owner"
    );
    let reused = mem
        .overlay
        .alloc(
            crate::trap::HVF_PAGE_SIZE,
            crate::shared_aperture::BackingObject::PrivateAnon,
        )
        .expect("clean failure candidate is reusable");
    assert_eq!(reused, prior_overlay + crate::trap::HVF_PAGE_SIZE);
}

#[test]
fn indeterminate_repoint_policy_retains_old_and_candidate_storage() {
    const GRANULE: u64 = crate::trap::HVF_PAGE_SIZE;
    let dispatcher = SyscallDispatcher::new();
    let source = crate::memory::LINUX_SHARED_FILE_BASE;
    let (old, candidate) = {
        let mem_authority_103 = dispatcher.mem();
        let mut mem = mem_authority_103.lock();
        let old = mem
            .overlay
            .alloc_sourced(
                GRANULE,
                crate::shared_aperture::BackingObject::PrivateAnon,
                Some(source),
            )
            .expect("old overlay");
        let candidate = mem
            .overlay
            .alloc_sourced(
                GRANULE,
                crate::shared_aperture::BackingObject::PrivateAnon,
                Some(source),
            )
            .expect("candidate overlay");
        (old, candidate)
    };

    let action = dispatcher.recover_private_repoint_failure(
        candidate,
        carrick_guest_mem::RepointPrivateError::indeterminate(MemoryError::HostMap(
            "injected post-publication failure".into(),
        )),
    );
    assert_eq!(action, PrivateRepointRecovery::FailStopRetainingOwners);
    let mem_authority_104 = dispatcher.mem();
    let mut mem = mem_authority_104.lock();
    assert!(mem.overlay.live().iter().any(|slot| slot.guest_addr == old));
    assert!(
        mem.overlay
            .live()
            .iter()
            .any(|slot| slot.guest_addr == candidate)
    );
    let next = mem
        .overlay
        .alloc(GRANULE, crate::shared_aperture::BackingObject::PrivateAnon)
        .expect("retained owners force fresh allocation");
    assert_eq!(next, candidate + GRANULE);
}

#[test]
fn indeterminate_private_repoint_failure_fails_stopped() {
    const SYS_MMAP: u64 = 222;
    const LENGTH: u64 = crate::trap::HVF_PAGE_SIZE;

    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork indeterminate-repoint child failed");
    if child == 0 {
        let no_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) };
        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1165));
        let reporter = CompatReporter::default();
        let mut memory =
            ProtectionTrackingMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, LENGTH as usize);
        let source = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        let _ = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    source,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                    u64::MAX,
                    0,
                ]),
            ),
        ));
        memory.fail_repoint_indeterminate = true;
        let _ = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    source,
                    LENGTH,
                    LINUX_PROT_READ,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                    u64::MAX,
                    0,
                ]),
            ),
        );
        unsafe { libc::_exit(93) };
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(libc::WIFSIGNALED(status), "child status was 0x{status:x}");
    assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
}

fn assert_partial_private_overlay_replacement(replace_offset: u64) {
    const SYS_MMAP: u64 = 222;
    const GRANULE: u64 = crate::trap::HVF_PAGE_SIZE;
    const LENGTH: u64 = 3 * GRANULE;

    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(
            1160 + i32::try_from(replace_offset / GRANULE).unwrap(),
        ));
    let reporter = CompatReporter::default();
    let mut memory =
        ProtectionTrackingMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, LENGTH as usize);
    let source = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                LENGTH,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    let first = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                source,
                LENGTH,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    assert_eq!(first, source);
    let old_overlay = dispatcher
        .mem()
        .lock()
        .overlay
        .translate_source_range(source, LENGTH)
        .expect("whole initial overlay");

    memory.inner.bytes[..GRANULE as usize].fill(0x11);
    memory.inner.bytes[GRANULE as usize..(2 * GRANULE) as usize].fill(0x22);
    memory.inner.bytes[(2 * GRANULE) as usize..].fill(0x33);
    let replaced = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                source + replace_offset,
                GRANULE,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    assert_eq!(replaced, source + replace_offset);

    let replaced_index = usize::try_from(replace_offset).unwrap();
    assert!(
        memory.inner.bytes[replaced_index..replaced_index + GRANULE as usize]
            .iter()
            .all(|byte| *byte == 0),
        "replacement payload must touch only the replaced source interval"
    );
    if replace_offset != 0 {
        assert!(
            memory.inner.bytes[..replaced_index]
                .iter()
                .all(|byte| *byte != 0)
        );
    }
    let replacement_end = replaced_index + GRANULE as usize;
    if replacement_end < LENGTH as usize {
        assert!(
            memory.inner.bytes[replacement_end..]
                .iter()
                .all(|byte| *byte != 0)
        );
    }

    let mem_authority_105 = dispatcher.mem();

    let mut mem = mem_authority_105.lock();
    let replacement_overlay = mem
        .overlay
        .translate_source_range(source + replace_offset, GRANULE)
        .expect("replacement overlay translation");
    assert_ne!(replacement_overlay, old_overlay + replace_offset);
    if replace_offset != 0 {
        assert_eq!(
            mem.overlay.translate_source_range(source, replace_offset),
            Some(old_overlay)
        );
    }
    let suffix_start = replace_offset + GRANULE;
    if suffix_start < LENGTH {
        assert_eq!(
            mem.overlay
                .translate_source_range(source + suffix_start, LENGTH - suffix_start),
            Some(old_overlay + suffix_start)
        );
    }
    let reused = mem
        .overlay
        .alloc(GRANULE, crate::shared_aperture::BackingObject::PrivateAnon)
        .expect("only overwritten overlay storage is reusable");
    assert_eq!(reused, old_overlay + replace_offset);
    let after_reuse = mem
        .overlay
        .alloc(GRANULE, crate::shared_aperture::BackingObject::PrivateAnon)
        .expect("preserved storage remains unavailable");
    assert!(
        after_reuse >= replacement_overlay + GRANULE,
        "preserved prefix/suffix must not be reallocated"
    );
    drop(mem);

    // The mapped bytes survive a real fork snapshot. Child mutations to the
    // private replacement model cannot bleed back into the parent, while the
    // parent retains every preserved prefix/suffix byte.
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork partial-overlay snapshot failed");
    if child == 0 {
        if memory.inner.bytes[replaced_index] != 0 {
            unsafe { libc::_exit(81) };
        }
        memory.inner.bytes.fill(0x7e);
        unsafe { libc::_exit(0) };
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    assert_eq!(memory.inner.bytes[replaced_index], 0);
    if replace_offset != 0 {
        assert_ne!(memory.inner.bytes[0], 0x7e);
    }
    if replacement_end < LENGTH as usize {
        assert_ne!(memory.inner.bytes[replacement_end], 0x7e);
    }
}

fn assert_shared_owner_survives_partial_private_replacement(replace_offset: u64) {
    const SYS_MMAP: u64 = 222;
    const SYS_MUNMAP: u64 = 215;
    const GRANULE: u64 = crate::trap::HVF_PAGE_SIZE;
    const LENGTH: u64 = 3 * GRANULE;

    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(
            1180 + i32::try_from(replace_offset / GRANULE).unwrap(),
        ));
    let reporter = CompatReporter::default();
    let mut memory = ProtectionTrackingMemory::new(
        crate::memory::LINUX_SHARED_FILE_BASE,
        (5 * GRANULE) as usize,
    );
    let source = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                LENGTH,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    memory.inner.bytes[..GRANULE as usize].fill(0x11);
    memory.inner.bytes[GRANULE as usize..(2 * GRANULE) as usize].fill(0x22);
    memory.inner.bytes[(2 * GRANULE) as usize..(3 * GRANULE) as usize].fill(0x33);

    assert_eq!(
        returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    source + replace_offset,
                    GRANULE,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                    u64::MAX,
                    0,
                ]),
            ),
        )),
        (source + replace_offset) as i64
    );
    {
        let mem_authority_106 = dispatcher.mem();
        let mem = mem_authority_106.lock();
        if replace_offset != 0 {
            assert!(mem.shared.guest_range_has_owner(source, replace_offset));
        }
        let suffix_start = replace_offset + GRANULE;
        if suffix_start < LENGTH {
            assert!(
                mem.shared
                    .guest_range_has_owner(source + suffix_start, LENGTH - suffix_start)
            );
        }
        assert!(
            mem.shared
                .guest_range_is_private_reservation(source + replace_offset, GRANULE)
        );
    }

    let blocked = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                GRANULE,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    assert!(
        blocked >= source + LENGTH,
        "live private reservation must keep nonfixed MAP_SHARED away from its source VA"
    );

    assert_eq!(
        threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MUNMAP,
                SyscallArgs([source + replace_offset, GRANULE, 0, 0, 0, 0]),
            ),
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let reused = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                GRANULE,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    assert_eq!(reused, source + replace_offset);
    assert_eq!(
        memory.restored_shared_identity.last(),
        Some(&(source + replace_offset, GRANULE as usize)),
        "reusing the exact private source must restore VA to shared identity backing"
    );

    for (index, expected) in [0x11, 0x22, 0x33].into_iter().enumerate() {
        let offset = (index as u64) * GRANULE;
        if offset != replace_offset {
            let start = usize::try_from(offset).unwrap();
            assert!(
                memory.inner.bytes[start..start + GRANULE as usize]
                    .iter()
                    .all(|byte| *byte == expected),
                "reusing the displaced interval overwrote a live shared fragment"
            );
        }
    }
    let next = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                GRANULE,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    assert!(
        next >= source + LENGTH,
        "a preserved prefix/suffix was returned to the shared allocator"
    );
}

#[test]
fn shared_owner_prefix_replacement_then_unmap_reuses_only_prefix() {
    assert_shared_owner_survives_partial_private_replacement(0);
}

#[test]
fn shared_owner_middle_replacement_then_unmap_reuses_only_middle() {
    assert_shared_owner_survives_partial_private_replacement(crate::trap::HVF_PAGE_SIZE);
}

#[test]
fn shared_owner_suffix_replacement_then_unmap_reuses_only_suffix() {
    assert_shared_owner_survives_partial_private_replacement(2 * crate::trap::HVF_PAGE_SIZE);
}

#[test]
fn partial_shared_file_munmaps_write_exact_fragments_and_close_once() {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    const SYS_MUNMAP: u64 = 215;
    const GRANULE: u64 = crate::trap::HVF_PAGE_SIZE;
    const LENGTH: u64 = 3 * GRANULE;

    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1190));
    let reporter = CompatReporter::default();
    let file = tempfile::tempfile().expect("temporary shared backing");
    file.set_len(LENGTH).expect("size shared backing");
    let dup = unsafe { libc::dup(file.as_raw_fd()) };
    assert!(
        dup >= 0,
        "dup shared backing: {}",
        std::io::Error::last_os_error()
    );
    let owned = unsafe { OwnedFd::from_raw_fd(dup) };
    let owned_raw = owned.as_raw_fd();
    let source = dispatcher
        .mem()
        .lock()
        .shared
        .alloc(
            LENGTH,
            crate::shared_aperture::BackingObject::shared_file(owned, 0),
        )
        .expect("shared file aperture allocation");
    dispatcher.record_dynamic_mapping(
        source,
        LENGTH,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Shared,
        "shared-file".into(),
    );
    let mut memory = ProtectionTrackingMemory::new(source, LENGTH as usize);
    memory.inner.bytes[..GRANULE as usize].fill(0x11);
    memory.inner.bytes[GRANULE as usize..(2 * GRANULE) as usize].fill(0x22);
    memory.inner.bytes[(2 * GRANULE) as usize..].fill(0x33);

    for offset in [GRANULE, 0, 2 * GRANULE] {
        assert_eq!(
            threaded_memory_call(
                &dispatcher,
                &mut memory,
                &registry,
                &reporter,
                SyscallRequest::new(
                    SYS_MUNMAP,
                    SyscallArgs([source + offset, GRANULE, 0, 0, 0, 0]),
                ),
            ),
            DispatchOutcome::Returned { value: 0 }
        );
        if offset != 2 * GRANULE {
            assert_ne!(
                unsafe { libc::fcntl(owned_raw, libc::F_GETFD) },
                -1,
                "a surviving fragment must retain the one fd owner"
            );
        }
    }
    assert_eq!(unsafe { libc::fcntl(owned_raw, libc::F_GETFD) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EBADF)
    );

    let mut actual = vec![0_u8; LENGTH as usize];
    assert_eq!(
        unsafe {
            libc::pread(
                file.as_raw_fd(),
                actual.as_mut_ptr().cast(),
                actual.len(),
                0,
            )
        },
        LENGTH as isize
    );
    assert!(actual[..GRANULE as usize].iter().all(|byte| *byte == 0x11));
    assert!(
        actual[GRANULE as usize..(2 * GRANULE) as usize]
            .iter()
            .all(|byte| *byte == 0x22)
    );
    assert!(
        actual[(2 * GRANULE) as usize..]
            .iter()
            .all(|byte| *byte == 0x33)
    );
}

#[test]
fn clean_private_repoint_failure_does_not_commit_shared_file_writeback() {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    const SYS_MMAP: u64 = 222;
    const SYS_MUNMAP: u64 = 215;
    const LENGTH: u64 = crate::trap::HVF_PAGE_SIZE;

    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1191));
    let reporter = CompatReporter::default();
    let file = tempfile::tempfile().expect("temporary repoint backing");
    file.set_len(LENGTH).expect("size repoint backing");
    let dup = unsafe { libc::dup(file.as_raw_fd()) };
    assert!(dup >= 0, "dup repoint backing");
    let owned = unsafe { OwnedFd::from_raw_fd(dup) };
    let owned_raw = owned.as_raw_fd();
    let source = dispatcher
        .mem()
        .lock()
        .shared
        .alloc(
            LENGTH,
            crate::shared_aperture::BackingObject::shared_file(owned, 0),
        )
        .expect("shared file source");
    dispatcher.record_dynamic_mapping(
        source,
        LENGTH,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Shared,
        "shared-file".into(),
    );
    let mut memory = ProtectionTrackingMemory::new(source, LENGTH as usize);
    memory.inner.bytes.fill(0x61);
    memory.fail_repoint = true;

    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                source,
                LENGTH,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                u64::MAX,
                0,
            ]),
        ),
    );
    assert_eq!(outcome, DispatchOutcome::errno(LINUX_ENOMEM));
    let mut byte = [0xff_u8; 1];
    assert_eq!(
        unsafe { libc::pread(file.as_raw_fd(), byte.as_mut_ptr().cast(), 1, 0) },
        1
    );
    assert_eq!(byte, [0], "clean failure must not commit writeback");
    assert!(
        dispatcher
            .mem()
            .lock()
            .shared
            .guest_range_has_owner(source, LENGTH)
    );
    assert_ne!(unsafe { libc::fcntl(owned_raw, libc::F_GETFD) }, -1);

    assert_eq!(
        threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(SYS_MUNMAP, SyscallArgs([source, LENGTH, 0, 0, 0, 0]),),
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(unsafe { libc::fcntl(owned_raw, libc::F_GETFD) }, -1);
    assert_eq!(
        unsafe { libc::pread(file.as_raw_fd(), byte.as_mut_ptr().cast(), 1, 0) },
        1
    );
    assert_eq!(byte, [0x61]);
}

#[test]
fn private_overlay_prefix_replacement_carves_exact_storage() {
    assert_partial_private_overlay_replacement(0);
}

#[test]
fn private_overlay_middle_replacement_carves_exact_storage() {
    assert_partial_private_overlay_replacement(crate::trap::HVF_PAGE_SIZE);
}

#[test]
fn private_overlay_suffix_replacement_carves_exact_storage() {
    assert_partial_private_overlay_replacement(2 * crate::trap::HVF_PAGE_SIZE);
}

#[test]
fn exact_partial_granule_replacement_splits_owner_without_reusing_live_storage() {
    const SYS_MMAP: u64 = 222;
    const LENGTH: u64 = 2 * crate::trap::HVF_PAGE_SIZE;
    const PARTIAL: u64 = LINUX_PAGE_SIZE;

    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1164));
    let reporter = CompatReporter::default();
    let mut memory =
        ProtectionTrackingMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, LENGTH as usize);
    let source = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                LENGTH,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    let _ = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                source,
                LENGTH,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                u64::MAX,
                0,
            ]),
        ),
    ));
    let prior_calls = memory.repoint_calls;
    let prior_overlay = dispatcher
        .mem()
        .lock()
        .overlay
        .translate_source_range(source, LENGTH)
        .expect("prior overlay");

    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                source,
                PARTIAL,
                LINUX_PROT_READ,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                u64::MAX,
                0,
            ]),
        ),
    );

    assert_eq!(
        outcome,
        DispatchOutcome::Returned {
            value: source as i64
        }
    );
    assert_eq!(memory.repoint_calls, prior_calls + 1);
    let mem_authority_107 = dispatcher.mem();
    let mut mem = mem_authority_107.lock();
    let replacement = mem
        .overlay
        .translate_source_range(source, PARTIAL)
        .expect("exact partial replacement owner");
    assert_ne!(replacement, prior_overlay);
    assert_eq!(
        mem.overlay
            .translate_source_range(source + PARTIAL, LENGTH - PARTIAL),
        Some(prior_overlay + PARTIAL)
    );
    let fresh = mem
        .overlay
        .alloc(
            crate::trap::HVF_PAGE_SIZE,
            crate::shared_aperture::BackingObject::PrivateAnon,
        )
        .expect("partial physical hole is not independently reusable");
    assert!(fresh >= replacement + crate::trap::HVF_PAGE_SIZE);
}

#[test]
fn post_repoint_protection_failure_aborts_instead_of_publishing_split_ownership() {
    const SYS_MMAP: u64 = 222;
    const LENGTH: u64 = 4096;
    const MAPPED_LENGTH: usize = crate::trap::HVF_PAGE_SIZE as usize;

    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork protection-failure child failed");
    if child == 0 {
        let no_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) };
        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1063));
        let reporter = CompatReporter::default();
        let mut memory =
            ProtectionTrackingMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, MAPPED_LENGTH);
        let shared = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        memory.fail_protect = true;
        let _ = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    shared,
                    LENGTH,
                    LINUX_PROT_READ,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                    u64::MAX,
                    0,
                ]),
            ),
        );
        unsafe { libc::_exit(92) };
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(libc::WIFSIGNALED(status), "child status was 0x{status:x}");
    assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
}

#[test]
fn moving_shared_mremap_fails_before_private_copy_or_metadata_mutation() {
    const SYS_MMAP: u64 = 222;
    const SYS_MREMAP: u64 = 216;
    const LENGTH: u64 = LINUX_PAGE_SIZE;

    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1065));
    let reporter = CompatReporter::default();
    let mut memory = ProtectionTrackingMemory::new(LINUX_MMAP_BASE, (8 * LINUX_PAGE_SIZE) as usize);
    let old = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                LENGTH,
                LINUX_PROT_READ | LINUX_PROT_EXEC,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    let _blocker = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                LENGTH,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    ));
    memory.protections.set_mapping_sharing(
        old,
        LENGTH as usize,
        carrick_guest_mem::MappingSharing::Shared,
    );
    dispatcher.record_dynamic_mapping(
        old,
        LENGTH,
        LinuxProtFlags::READ | LinuxProtFlags::EXEC,
        ProcMapSharing::Shared,
        "shared-code".into(),
    );

    let mmap_next_before = dispatcher.mem().lock().mmap_next;
    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MREMAP,
            SyscallArgs([old, LENGTH, 2 * LENGTH, LINUX_MREMAP_MAYMOVE, 0, 0]),
        ),
    );
    assert_eq!(outcome, DispatchOutcome::errno(LINUX_ENOMEM));
    assert_eq!(dispatcher.mem().lock().mmap_next, mmap_next_before);
    assert!(
        memory
            .protections
            .range_mutable_shared_backing(old, LENGTH as usize)
    );
    assert!(!memory.protections.range_unmapped(old, LENGTH as usize));
    let mem_authority_108 = dispatcher.mem();
    let mem = mem_authority_108.lock();
    assert!(mem.dynamic_maps.iter().any(|map| {
        map.start == old
            && map.end == old + LENGTH
            && map.execute
            && map.sharing == ProcMapSharing::Shared
            && map.path == "shared-code"
    }));
    assert_eq!(mem.dynamic_maps.len(), 2, "source plus blocker only");
}

#[test]
fn mixed_rx_and_r_mremap_source_is_rejected_without_broadening_permissions() {
    const SYS_MMAP: u64 = 222;
    const SYS_MPROTECT: u64 = 226;
    const SYS_MREMAP: u64 = 216;
    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1066));
    let reporter = CompatReporter::default();
    let mut memory = ProtectionTrackingMemory::new(LINUX_MMAP_BASE, (8 * LINUX_PAGE_SIZE) as usize);
    let source = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                2 * LINUX_PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_EXEC,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    assert_eq!(
        threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MPROTECT,
                SyscallArgs([
                    source + LINUX_PAGE_SIZE,
                    LINUX_PAGE_SIZE,
                    LINUX_PROT_READ,
                    0,
                    0,
                    0,
                ]),
            ),
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let maps_before = dispatcher.mem().lock().dynamic_maps.clone();
    let mmap_next_before = dispatcher.mem().lock().mmap_next;

    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MREMAP,
            SyscallArgs([
                source,
                2 * LINUX_PAGE_SIZE,
                3 * LINUX_PAGE_SIZE,
                LINUX_MREMAP_MAYMOVE,
                0,
                0,
            ]),
        ),
    );
    assert_eq!(outcome, DispatchOutcome::errno(LINUX_EFAULT));
    assert_eq!(dispatcher.mem().lock().dynamic_maps, maps_before);
    assert_eq!(dispatcher.mem().lock().mmap_next, mmap_next_before);
}

#[test]
fn mremap_shrink_unmap_failure_keeps_source_metadata_and_allocator() {
    const SYS_MREMAP: u64 = 216;
    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1067));
    let reporter = CompatReporter::default();
    let source = LINUX_MMAP_BASE;
    dispatcher.record_dynamic_mapping(
        source,
        2 * LINUX_PAGE_SIZE,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Private,
        "source".into(),
    );
    dispatcher.mem().lock().mmap_next = source + 2 * LINUX_PAGE_SIZE;
    let mut memory =
        DeferredSetterFailureMemory::new(source, (2 * LINUX_PAGE_SIZE) as usize).fail_unmaps(1);
    let maps_before = dispatcher.mem().lock().dynamic_maps.clone();
    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MREMAP,
            SyscallArgs([source, 2 * LINUX_PAGE_SIZE, LINUX_PAGE_SIZE, 0, 0, 0]),
        ),
    );
    assert_eq!(outcome, DispatchOutcome::errno(LINUX_ENOMEM));
    assert_eq!(dispatcher.mem().lock().dynamic_maps, maps_before);
    assert_eq!(
        dispatcher.mem().lock().mmap_next,
        source + 2 * LINUX_PAGE_SIZE
    );
}

#[test]
fn shared_anonymous_mremap_shrink_retains_shared_prefix_metadata() {
    const SYS_MMAP: u64 = 222;
    const SYS_MREMAP: u64 = 216;
    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1068));
    let reporter = CompatReporter::default();
    let base = crate::memory::LINUX_SHARED_FILE_BASE;
    let map_len = crate::trap::HVF_PAGE_SIZE * 2;
    let mut memory = CountingMmapMemory::new(base, map_len as usize);
    let source = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                map_len,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    let shrunk = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MREMAP,
            SyscallArgs([source, map_len, crate::trap::HVF_PAGE_SIZE, 0, 0, 0]),
        ),
    );
    assert_eq!(
        shrunk,
        DispatchOutcome::Returned {
            value: source as i64
        }
    );
    let mem_authority_109 = dispatcher.mem();
    let mem = mem_authority_109.lock();
    assert!(mem.dynamic_maps.iter().any(|map| {
        map.start == source
            && map.end == source + crate::trap::HVF_PAGE_SIZE
            && map.sharing == ProcMapSharing::Shared
    }));
}

#[test]
fn private_overlay_mremap_shrink_carves_source_tail_and_reuses_only_storage() {
    const SYS_MMAP: u64 = 222;
    const SYS_MREMAP: u64 = 216;
    const GRANULE: u64 = crate::trap::HVF_PAGE_SIZE;
    const LENGTH: u64 = 2 * GRANULE;

    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1174));
    let reporter = CompatReporter::default();
    let mut memory =
        ProtectionTrackingMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, LENGTH as usize);
    let source = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                LENGTH,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    assert_eq!(
        returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    source,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                    u64::MAX,
                    0,
                ]),
            ),
        )),
        source as i64
    );
    let old_overlay = dispatcher
        .mem()
        .lock()
        .overlay
        .translate_source_range(source, LENGTH)
        .expect("whole private overlay before shrink");
    memory.inner.bytes[..GRANULE as usize].fill(0x41);
    memory.inner.bytes[GRANULE as usize..].fill(0x52);

    assert_eq!(
        threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(SYS_MREMAP, SyscallArgs([source, LENGTH, GRANULE, 0, 0, 0]),),
        ),
        DispatchOutcome::Returned {
            value: source as i64
        }
    );

    let mem_authority_110 = dispatcher.mem();

    let mut mem = mem_authority_110.lock();
    assert_eq!(
        mem.overlay.translate_source_range(source, GRANULE),
        Some(old_overlay),
        "retained source prefix must keep its physical overlay translation"
    );
    assert_eq!(
        mem.overlay
            .translate_source_range(source + GRANULE, GRANULE),
        None,
        "removed source tail must not retain stale overlay ownership"
    );
    assert!(
        mem.shared
            .guest_range_is_private_reservation(source, GRANULE)
    );
    assert!(!mem.shared.guest_range_has_owner(source + GRANULE, GRANULE));
    assert!(
        mem.shared
            .range_needs_identity_restore(source + GRANULE, GRANULE)
    );
    let reused = mem
        .overlay
        .alloc_sourced(
            GRANULE,
            crate::shared_aperture::BackingObject::PrivateAnon,
            Some(source + (8 * GRANULE)),
        )
        .expect("reuse removed overlay tail for a distinct source");
    assert_eq!(reused, old_overlay + GRANULE);
    assert_eq!(
        mem.overlay
            .translate_source_range(source + (8 * GRANULE), GRANULE),
        Some(old_overlay + GRANULE)
    );
    drop(mem);

    assert!(
        memory
            .protections
            .range_unmapped(source + GRANULE, GRANULE as usize),
        "VMM/identity guest metadata must keep the removed VA inaccessible"
    );
    assert!(
        memory.inner.bytes[..GRANULE as usize]
            .iter()
            .all(|byte| *byte == 0x41)
    );
    let map = dispatcher
        .dynamic_mapping_for_test(source)
        .expect("retained private prefix VMA");
    assert_eq!(map.end, source + GRANULE);
    assert_eq!(map.sharing, ProcMapSharing::Private);
    assert!(
        dispatcher
            .dynamic_mapping_for_test(source + GRANULE)
            .is_none()
    );
}

#[test]
fn mremap_fixed_relocates_to_the_named_destination_and_reclaims_the_source() {
    const SYS_MMAP: u64 = 222;
    const SYS_MREMAP: u64 = 216;
    const MREMAP_MAYMOVE: u64 = 0x01;
    const MREMAP_FIXED: u64 = 0x02;

    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1069));
    let reporter = CompatReporter::default();
    let mut memory = ProtectionTrackingMemory::new(LINUX_MMAP_BASE, (8 * LINUX_PAGE_SIZE) as usize);
    let source = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                LINUX_PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    let destination = source + (2 * LINUX_PAGE_SIZE);
    memory
        .write_bytes(source, b"move")
        .expect("seed source bytes before fixed move");

    // new_size == 0 is EINVAL on real Linux regardless of any other
    // flag bit (confirmed against a real-Linux oracle, 2026-07-23,
    // Linux 6.12.76 — see .superpowers/sdd/mremap-ruling-report.md): it must win
    // over carrick's MREMAP_FIXED-not-yet-implemented refusal, not be
    // masked by it.
    let zero_size = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MREMAP,
            SyscallArgs([u64::MAX, LINUX_PAGE_SIZE, 0, MREMAP_FIXED, 1, 0]),
        ),
    );
    assert_eq!(zero_size, DispatchOutcome::errno(LINUX_EINVAL));
    // An unrecognized flag bit (1 << 63) ORed onto an otherwise-valid
    // MREMAP_FIXED request is EINVAL on real Linux, not EOPNOTSUPP:
    // real Linux actually implements MREMAP_FIXED (confirmed by the
    // same oracle run — MREMAP_FIXED|MREMAP_MAYMOVE with the garbage
    // bit removed succeeds), so an unknown bit is what makes this
    // request invalid, and that check must run before carrick's
    // "not yet implemented" refusal for the FIXED shape itself.
    let invalid_combo = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MREMAP,
            SyscallArgs([u64::MAX, u64::MAX, u64::MAX, MREMAP_FIXED | (1 << 63), 3, 0]),
        ),
    );
    assert_eq!(invalid_combo, DispatchOutcome::errno(LINUX_EINVAL));

    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MREMAP,
            SyscallArgs([
                source,
                LINUX_PAGE_SIZE,
                LINUX_PAGE_SIZE,
                MREMAP_MAYMOVE | MREMAP_FIXED,
                destination,
                0,
            ]),
        ),
    );
    // MREMAP_FIXED relocates to the address the guest named: the bytes are at
    // the destination, the source is unmapped, and the call returns the
    // destination (Linux never returns the old address for a fixed move).
    assert_eq!(
        outcome,
        DispatchOutcome::Returned {
            value: destination as i64
        }
    );
    assert_eq!(memory.read_bytes(destination, 4).unwrap(), b"move");
    assert!(
        memory
            .protections
            .range_unmapped(source, LINUX_PAGE_SIZE as usize)
    );
    let mem_authority_111 = dispatcher.mem();
    let mem = mem_authority_111.lock();
    assert!(!mem.dynamic_maps.iter().any(|map| map.start == source));
    assert!(mem.dynamic_maps.iter().any(|map| map.start == destination));
}

#[test]
fn mremap_dontunmap_moves_contents_and_leaves_the_source_zeroed() {
    const SYS_MMAP: u64 = 222;
    const SYS_MREMAP: u64 = 216;
    const MREMAP_MAYMOVE: u64 = 0x01;
    const MREMAP_DONTUNMAP: u64 = 0x04;

    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1070));
    let reporter = CompatReporter::default();
    let mut memory = ProtectionTrackingMemory::new(LINUX_MMAP_BASE, (8 * LINUX_PAGE_SIZE) as usize);
    let source = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                LINUX_PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    memory
        .write_bytes(source, b"keep")
        .expect("seed source bytes before dontunmap move");

    // new_size == 0 (and, independently, the unrecognized 1 << 63 bit)
    // is EINVAL on real Linux, not EOPNOTSUPP: confirmed against a
    // real-Linux oracle, 2026-07-23, Linux 6.12.76 — see
    // .superpowers/sdd/mremap-ruling-report.md. Either well-formedness check must
    // win over carrick's MREMAP_DONTUNMAP-not-yet-implemented refusal.
    let invalid_precedence = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MREMAP,
            SyscallArgs([u64::MAX, 0, 0, MREMAP_DONTUNMAP | (1 << 63), 0, 0]),
        ),
    );
    assert_eq!(invalid_precedence, DispatchOutcome::errno(LINUX_EINVAL));

    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MREMAP,
            SyscallArgs([
                source,
                LINUX_PAGE_SIZE,
                LINUX_PAGE_SIZE,
                MREMAP_MAYMOVE | MREMAP_DONTUNMAP,
                0,
                0,
            ]),
        ),
    );
    // MREMAP_DONTUNMAP moves the contents and KEEPS the source mapped, as
    // fresh zero-filled anonymous memory: two live mappings afterwards, the
    // bytes at the destination, and the old address reading back zero rather
    // than faulting.
    let destination = returned(outcome) as u64;
    assert_ne!(destination, source);
    assert_eq!(memory.read_bytes(destination, 4).unwrap(), b"keep");
    assert_eq!(memory.read_bytes(source, 4).unwrap(), &[0; 4]);
    let mem_authority_112 = dispatcher.mem();
    let mem = mem_authority_112.lock();
    assert!(mem.dynamic_maps.iter().any(|map| map.start == source));
    assert!(mem.dynamic_maps.iter().any(|map| map.start == destination));
}

#[test]
fn shared_fixed_mremap_move_fails_before_source_mutation() {
    const SYS_MMAP: u64 = 222;
    const SYS_MREMAP: u64 = 216;
    const MREMAP_MAYMOVE: u64 = 0x01;
    const MREMAP_FIXED: u64 = 0x02;

    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1071));
    let reporter = CompatReporter::default();
    let mut memory = ProtectionTrackingMemory::new(LINUX_MMAP_BASE, (8 * LINUX_PAGE_SIZE) as usize);
    let source = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                LINUX_PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_EXEC,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    memory.protections.set_mapping_sharing(
        source,
        LINUX_PAGE_SIZE as usize,
        carrick_guest_mem::MappingSharing::Shared,
    );
    dispatcher.record_dynamic_mapping(
        source,
        LINUX_PAGE_SIZE,
        LinuxProtFlags::READ | LinuxProtFlags::EXEC,
        ProcMapSharing::Shared,
        "shared-fixed".into(),
    );
    let before = dispatcher.mem().lock().dynamic_maps.clone();

    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MREMAP,
            SyscallArgs([
                source,
                LINUX_PAGE_SIZE,
                LINUX_PAGE_SIZE,
                MREMAP_MAYMOVE | MREMAP_FIXED,
                source + (2 * LINUX_PAGE_SIZE),
                0,
            ]),
        ),
    );
    assert_eq!(outcome, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
    assert_eq!(dispatcher.mem().lock().dynamic_maps, before);
    assert!(
        !memory
            .protections
            .range_unmapped(source, LINUX_PAGE_SIZE as usize)
    );
}

#[test]
fn shared_fixed_mremap_shrink_fails_before_source_tail_mutation() {
    const SYS_MMAP: u64 = 222;
    const SYS_MREMAP: u64 = 216;
    const MREMAP_MAYMOVE: u64 = 0x01;
    const MREMAP_FIXED: u64 = 0x02;

    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1073));
    let reporter = CompatReporter::default();
    let mut memory = ProtectionTrackingMemory::new(LINUX_MMAP_BASE, (8 * LINUX_PAGE_SIZE) as usize);
    let source = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                2 * LINUX_PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    memory.protections.set_mapping_sharing(
        source,
        (2 * LINUX_PAGE_SIZE) as usize,
        carrick_guest_mem::MappingSharing::Shared,
    );
    dispatcher.record_dynamic_mapping(
        source,
        2 * LINUX_PAGE_SIZE,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Shared,
        "shared-fixed-shrink".into(),
    );
    let before = dispatcher.mem().lock().dynamic_maps.clone();

    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MREMAP,
            SyscallArgs([
                source,
                2 * LINUX_PAGE_SIZE,
                LINUX_PAGE_SIZE,
                MREMAP_MAYMOVE | MREMAP_FIXED,
                source + (3 * LINUX_PAGE_SIZE),
                0,
            ]),
        ),
    );

    assert_eq!(outcome, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
    assert_eq!(dispatcher.mem().lock().dynamic_maps, before);
    assert!(
        !memory
            .protections
            .range_unmapped(source + LINUX_PAGE_SIZE, LINUX_PAGE_SIZE as usize),
        "fixed shared shrink must not unmap the source tail before rejection"
    );
}

#[test]
fn mremap_boot_region_metadata_fallback_preserves_exact_properties() {
    const SYS_MREMAP: u64 = 216;
    const BOOT_VMA: u64 = LINUX_MMAP_BASE - (8 * LINUX_PAGE_SIZE);
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_address_space_regions(vec![ProcMapsEntry {
        start: BOOT_VMA,
        end: BOOT_VMA + (2 * LINUX_PAGE_SIZE),
        read: true,
        write: true,
        execute: false,
        sharing: ProcMapSharing::Private,
        path: "boot-region".into(),
    }]);
    let reporter = CompatReporter::default();
    let mut memory = ProtectionTrackingMemory::new(BOOT_VMA, (4 * LINUX_PAGE_SIZE) as usize);

    let outcome = dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(
                SYS_MREMAP,
                SyscallArgs([BOOT_VMA, 2 * LINUX_PAGE_SIZE, LINUX_PAGE_SIZE, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .expect("boot-region shrink dispatch");
    assert_eq!(
        outcome,
        DispatchOutcome::Returned {
            value: BOOT_VMA as i64
        }
    );
    let map = dispatcher
        .dynamic_mapping_for_test(BOOT_VMA)
        .expect("fallback should publish exact boot-region metadata");
    assert_eq!(map.end, BOOT_VMA + LINUX_PAGE_SIZE);
    assert!((map.read, map.write, map.execute) == (true, true, false));
    assert_eq!(map.sharing, ProcMapSharing::Private);
    assert_eq!(map.path, "boot-region");
}

#[test]
fn mremap_rejects_boot_region_source_spanning_multiple_regions() {
    const SYS_MREMAP: u64 = 216;
    const BOOT_VMA: u64 = LINUX_MMAP_BASE - (8 * LINUX_PAGE_SIZE);
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_address_space_regions(vec![
        ProcMapsEntry {
            start: BOOT_VMA,
            end: BOOT_VMA + LINUX_PAGE_SIZE,
            read: true,
            write: true,
            execute: false,
            sharing: ProcMapSharing::Private,
            path: "boot-left".into(),
        },
        ProcMapsEntry {
            start: BOOT_VMA + LINUX_PAGE_SIZE,
            end: BOOT_VMA + (2 * LINUX_PAGE_SIZE),
            read: true,
            write: false,
            execute: false,
            sharing: ProcMapSharing::Private,
            path: "boot-right".into(),
        },
    ]);
    let reporter = CompatReporter::default();
    let mut memory = ProtectionTrackingMemory::new(BOOT_VMA, (4 * LINUX_PAGE_SIZE) as usize);

    let outcome = dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(
                SYS_MREMAP,
                SyscallArgs([
                    BOOT_VMA,
                    2 * LINUX_PAGE_SIZE,
                    3 * LINUX_PAGE_SIZE,
                    LINUX_MREMAP_MAYMOVE,
                    0,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
        )
        .expect("mixed boot-span shrink dispatch");
    assert_eq!(outcome, DispatchOutcome::errno(LINUX_EFAULT));
    assert!(dispatcher.mem().lock().dynamic_maps.is_empty());
}

#[test]
fn mremap_rejects_hidden_mmap_backing_boot_region() {
    const SYS_MREMAP: u64 = 216;
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_address_space_regions(vec![ProcMapsEntry {
        start: LINUX_MMAP_BASE,
        end: LINUX_MMAP_BASE + crate::memory::LINUX_MMAP_SIZE,
        read: true,
        write: true,
        execute: false,
        sharing: ProcMapSharing::Private,
        path: "hidden-mmap-backing".into(),
    }]);
    let mut memory = ProtectionTrackingMemory::new(LINUX_MMAP_BASE, (2 * LINUX_PAGE_SIZE) as usize);
    let outcome = dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(
                SYS_MREMAP,
                SyscallArgs([LINUX_MMAP_BASE, LINUX_PAGE_SIZE, LINUX_PAGE_SIZE, 0, 0, 0]),
            ),
            &mut memory,
            &CompatReporter::default(),
        )
        .expect("hidden backing mremap dispatch");
    assert_eq!(outcome, DispatchOutcome::errno(LINUX_EFAULT));
    assert!(dispatcher.mem().lock().dynamic_maps.is_empty());
}

#[test]
fn mremap_rejects_hidden_shared_and_private_aperture_boot_regions() {
    const SYS_MREMAP: u64 = 216;
    for (base, size, label) in [
        (
            crate::memory::LINUX_SHARED_FILE_BASE,
            crate::memory::LINUX_SHARED_FILE_SIZE,
            "hidden-shared-aperture",
        ),
        (
            crate::memory::LINUX_PRIVATE_OVERLAY_BASE,
            crate::memory::LINUX_PRIVATE_OVERLAY_SIZE,
            "hidden-private-overlay",
        ),
    ] {
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_address_space_regions(vec![ProcMapsEntry {
            start: base,
            end: base + size,
            read: true,
            write: true,
            execute: false,
            sharing: ProcMapSharing::Private,
            path: label.into(),
        }]);
        let mut memory = ProtectionTrackingMemory::new(base, LINUX_PAGE_SIZE as usize);
        let outcome = dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    SYS_MREMAP,
                    SyscallArgs([base, LINUX_PAGE_SIZE, LINUX_PAGE_SIZE, 0, 0, 0]),
                ),
                &mut memory,
                &CompatReporter::default(),
            )
            .expect("hidden aperture mremap dispatch");
        assert_eq!(outcome, DispatchOutcome::errno(LINUX_EFAULT), "{label}");
        assert!(dispatcher.mem().lock().dynamic_maps.is_empty(), "{label}");
    }
}

#[test]
fn mremap_boot_heap_fallback_accepts_live_prefix_and_rejects_hidden_suffix() {
    const SYS_MREMAP: u64 = 216;
    let mut dispatcher = SyscallDispatcher::new();
    let layout = dispatcher.mem().lock().layout;
    // Boot publication derives the canonical semantic heap VMA from the live
    // break. Set the fixture's break first instead of mutating `brk_current`
    // behind that authority after publication.
    dispatcher.mem().lock().brk_current = layout.heap_base + (2 * LINUX_PAGE_SIZE);
    dispatcher.set_address_space_regions(vec![ProcMapsEntry {
        start: layout.heap_base,
        end: layout.heap_base + layout.heap_size,
        read: true,
        write: true,
        execute: false,
        sharing: ProcMapSharing::Private,
        path: "hidden-heap-backing".into(),
    }]);
    let mut memory =
        ProtectionTrackingMemory::new(layout.heap_base, (4 * LINUX_PAGE_SIZE) as usize);
    let reporter = CompatReporter::default();

    let live = dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(
                SYS_MREMAP,
                SyscallArgs([layout.heap_base, LINUX_PAGE_SIZE, LINUX_PAGE_SIZE, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .expect("live heap-prefix mremap");
    assert_eq!(
        live,
        DispatchOutcome::Returned {
            value: layout.heap_base as i64
        }
    );

    let hidden = dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(
                SYS_MREMAP,
                SyscallArgs([
                    layout.heap_base + (2 * LINUX_PAGE_SIZE),
                    LINUX_PAGE_SIZE,
                    LINUX_PAGE_SIZE,
                    0,
                    0,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
        )
        .expect("hidden heap-suffix mremap");
    assert_eq!(hidden, DispatchOutcome::errno(LINUX_EFAULT));
    assert!(
        dispatcher
            .dynamic_mapping_for_test(layout.heap_base)
            .is_some()
    );
    assert!(
        dispatcher
            .dynamic_mapping_for_test(layout.heap_base + (2 * LINUX_PAGE_SIZE))
            .is_none()
    );
}

#[test]
fn munmap_hole_cannot_fall_back_to_boot_metadata_during_mremap() {
    const SYS_MMAP: u64 = 222;
    const SYS_MUNMAP: u64 = 215;
    const SYS_MREMAP: u64 = 216;
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_address_space_regions(vec![ProcMapsEntry {
        start: LINUX_MMAP_BASE,
        end: LINUX_MMAP_BASE + (4 * LINUX_PAGE_SIZE),
        read: true,
        write: true,
        execute: false,
        sharing: ProcMapSharing::Private,
        path: "hidden-mmap-backing".into(),
    }]);
    let mut memory = ProtectionTrackingMemory::new(LINUX_MMAP_BASE, (4 * LINUX_PAGE_SIZE) as usize);
    let reporter = CompatReporter::default();
    let mapped = dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LINUX_PAGE_SIZE,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
        )
        .expect("mmap before hole regression");
    assert_eq!(returned(mapped), LINUX_MMAP_BASE as i64);
    let unmapped = dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(
                SYS_MUNMAP,
                SyscallArgs([LINUX_MMAP_BASE, LINUX_PAGE_SIZE, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .expect("munmap before hole regression");
    assert_eq!(unmapped, DispatchOutcome::Returned { value: 0 });

    let remapped = dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(
                SYS_MREMAP,
                SyscallArgs([LINUX_MMAP_BASE, LINUX_PAGE_SIZE, LINUX_PAGE_SIZE, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .expect("mremap of munmap hole");
    assert_eq!(remapped, DispatchOutcome::errno(LINUX_EFAULT));
    assert!(dispatcher.mem().lock().dynamic_maps.is_empty());
    assert!(
        memory
            .protections
            .range_unmapped(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize)
    );
}

#[test]
fn shared_aperture_partial_and_shifted_sources_reject_before_backend_mutation() {
    const SYS_MMAP: u64 = 222;
    const SYS_MREMAP: u64 = 216;
    const OLD_LEN: u64 = 32 * 1024;
    const PREFIX_LEN: u64 = 16 * 1024;
    const NEW_LEN: u64 = 8 * 1024;

    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1073));
    let reporter = CompatReporter::default();
    let mut memory = ProtectionTrackingMemory::new(
        crate::memory::LINUX_SHARED_FILE_BASE,
        (OLD_LEN + LINUX_PAGE_SIZE) as usize,
    );
    let source = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                OLD_LEN,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MREMAP,
            SyscallArgs([source, PREFIX_LEN, NEW_LEN, 0, 0, 0]),
        ),
    );
    assert_eq!(outcome, DispatchOutcome::errno(LINUX_EFAULT));
    let suffix_outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MREMAP,
            SyscallArgs([source + PREFIX_LEN, PREFIX_LEN, NEW_LEN, 0, 0, 0]),
        ),
    );
    assert_eq!(suffix_outcome, DispatchOutcome::errno(LINUX_EFAULT));

    // Fabricate an exact VMA that starts inside the allocation and has the
    // same length as its owner. Without an explicit allocation-start check,
    // this shape passed the live_len test and released pages it did not own.
    dispatcher.remove_mapping_metadata(source, OLD_LEN);
    dispatcher.record_dynamic_mapping(
        source + LINUX_PAGE_SIZE,
        OLD_LEN,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Shared,
        "shifted-shared-vma".into(),
    );
    let shifted_outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MREMAP,
            SyscallArgs([source + LINUX_PAGE_SIZE, OLD_LEN, PREFIX_LEN, 0, 0, 0]),
        ),
    );
    assert_eq!(shifted_outcome, DispatchOutcome::errno(LINUX_EFAULT));
    let mem_authority_113 = dispatcher.mem();
    let mem = mem_authority_113.lock();
    let alloc = mem
        .shared
        .live()
        .iter()
        .find(|alloc| alloc.guest_addr == source)
        .expect("whole shared allocation retained");
    assert_eq!(alloc.live_len, OLD_LEN);
    assert_eq!(alloc.len, OLD_LEN);
    assert!(!memory.protections.range_unmapped(source + NEW_LEN, 1));
}

#[test]
fn odd_shared_mmap_tracks_logical_length_and_granule_reservation() {
    const SYS_MMAP: u64 = 222;
    const REQUESTED: u64 = 4097;
    const LOGICAL: u64 = 8192;
    const RESERVED: u64 = 16 * 1024;
    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1074));
    let mut memory =
        ProtectionTrackingMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, RESERVED as usize);
    let source = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &CompatReporter::default(),
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                REQUESTED,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;
    let mem_authority_114 = dispatcher.mem();
    let mem = mem_authority_114.lock();
    let alloc = mem
        .shared
        .live()
        .iter()
        .find(|alloc| alloc.guest_addr == source)
        .expect("odd shared allocation");
    assert_eq!(alloc.live_len, LOGICAL);
    assert_eq!(alloc.len, RESERVED);
    let map = mem
        .dynamic_maps
        .iter()
        .find(|map| map.start == source)
        .expect("odd logical VMA");
    assert_eq!(map.end - map.start, LOGICAL);
}

#[test]
fn shared_mremap_shrink_unmap_failure_keeps_live_length_and_tail_accounting() {
    const SYS_MMAP: u64 = 222;
    const SYS_MREMAP: u64 = 216;

    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1072));
    let reporter = CompatReporter::default();
    let map_len = crate::trap::HVF_PAGE_SIZE * 2;
    let mut memory =
        DeferredSetterFailureMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, map_len as usize)
            .demand_paged()
            .fail_unmaps(1);
    let source = returned(threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                map_len,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    )) as u64;

    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MREMAP,
            SyscallArgs([source, map_len, crate::trap::HVF_PAGE_SIZE, 0, 0, 0]),
        ),
    );
    assert_eq!(outcome, DispatchOutcome::errno(LINUX_ENOMEM));
    {
        let mem_authority_115 = dispatcher.mem();
        let mem = mem_authority_115.lock();
        let alloc = mem
            .shared
            .live()
            .iter()
            .find(|alloc| alloc.guest_addr == source)
            .unwrap();
        assert_eq!(alloc.live_len, map_len);
        assert_eq!(alloc.len, map_len);
    }
    let next = {
        let mem_authority_116 = dispatcher.mem();
        let mut mem = mem_authority_116.lock();
        mem.shared
            .alloc(
                crate::trap::HVF_PAGE_SIZE,
                crate::shared_aperture::BackingObject::SharedAnon,
            )
            .expect("failed shrink must not free the tail for reuse")
    };
    assert_eq!(next, source + map_len);
}

#[test]
fn demand_paged_shared_anon_keeps_best_effort_mapping_on_protection_failure() {
    const SYS_MMAP: u64 = 222;
    const LENGTH: u64 = 4096;
    const MAPPED_LENGTH: usize = crate::trap::HVF_PAGE_SIZE as usize;

    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1070));
    let reporter = CompatReporter::default();
    let mut memory =
        DeferredSetterFailureMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, MAPPED_LENGTH)
            .demand_paged();
    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                LENGTH,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    );

    assert!(matches!(outcome, DispatchOutcome::Returned { .. }));
    assert_eq!(memory.protect_calls, 1);
    assert_eq!(
        memory.unmap_calls, 0,
        "demand-paged backend keeps reservation"
    );
    assert_eq!(dispatcher.mem().lock().dynamic_maps.len(), 1);
}

#[test]
fn concurrent_exec_mmap_does_not_commit_consumed_protection_failure_outside_arena() {
    const SYS_MMAP: u64 = 222;
    const ADDRESS: u64 = 0x2000_0000;
    const LENGTH: u64 = 4096;

    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1075));
    let reporter = CompatReporter::default();
    let mut memory = DeferredSetterFailureMemory::new(ADDRESS, LENGTH as usize);
    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                ADDRESS,
                LENGTH,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                u64::MAX,
                0,
            ]),
        ),
    );

    assert_eq!(outcome, DispatchOutcome::errno(LINUX_ENOMEM));
    assert_eq!(
        memory.protect_calls, 1,
        "deferred failure consumed exactly once"
    );
    assert!(dispatcher.mem().lock().dynamic_maps.is_empty());
}

#[test]
fn shared_anon_persistent_rollback_failure_aborts_concurrent_exec_backend() {
    const SYS_MMAP: u64 = 222;
    const LENGTH: u64 = 4096;
    const MAPPED_LENGTH: usize = crate::trap::HVF_PAGE_SIZE as usize;

    // SAFETY: the child owns an isolated dispatcher and intentionally takes
    // the fail-stop abort after two injected host-unmap failures.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
    if pid == 0 {
        let no_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) };
        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1080));
        let reporter = CompatReporter::default();
        let mut memory =
            DeferredSetterFailureMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, MAPPED_LENGTH)
                .fail_unmaps(2);
        let _ = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        );
        unsafe { libc::_exit(92) };
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
}

#[test]
fn native16k_rejects_multithreaded_write_exec_mmap() {
    const SYS_MMAP: u64 = 222;
    const PAGE_SIZE: u64 = 16 * 1024;

    let dispatcher = native16k_dispatcher();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1100));
    registry.register_child(0);
    let reporter = CompatReporter::default();
    let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, PAGE_SIZE as usize);
    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    );

    assert_eq!(outcome, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
    assert_partial_reason(&reporter, "mmap", "multiple live guest threads");
}

#[test]
fn native16k_rejects_write_exec_alias_mmap() {
    const SYS_MMAP: u64 = 222;
    const PAGE_SIZE: u64 = 16 * 1024;

    let dispatcher = native16k_dispatcher();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1150));
    let reporter = CompatReporter::default();
    let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, PAGE_SIZE as usize);
    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                crate::memory::LINUX_HIGH_VA_THRESHOLD,
                PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC,
                LINUX_MAP_FIXED | LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        ),
    );

    assert_eq!(outcome, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
    assert_partial_reason(&reporter, "mmap", "alias write-exec");
}

#[test]
fn native16k_rejects_write_exec_alias_mprotect() {
    const SYS_MPROTECT: u64 = 226;
    const PAGE_SIZE: u64 = 16 * 1024;
    let address = crate::memory::LINUX_HIGH_VA_THRESHOLD;

    let dispatcher = native16k_dispatcher();
    // Model a completed high-VA alias transaction, not merely a reserved
    // VMA.  The authoritative backing inventory is published only at
    // commit, after the backend mapping has succeeded.
    dispatcher.commit_host_alias_mmap(HostAliasMmapCommit {
        start: address,
        len: PAGE_SIZE,
        prot: LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        sharing: ProcMapSharing::Private,
        path: String::new(),
        file_page_offset: None,
        droppable: false,
        semantic_vmas: None,
        locked: None,
        resident: false,
        bus_fault: None,
        write_sealed_shared: false,
        read_only_shared_file: false,
        secretmem: false,
        writable_memfd: None,
        shared_file_alias: None,
    });
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1160));
    let reporter = CompatReporter::default();
    let mut memory = CountingMmapMemory::new(address, PAGE_SIZE as usize);
    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MPROTECT,
            SyscallArgs([
                address,
                PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC,
                0,
                0,
                0,
            ]),
        ),
    );

    assert_eq!(outcome, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
    assert_partial_reason(&reporter, "mprotect", "alias write-exec");
    assert_eq!(memory.protect_calls.get(), 0);
}

#[test]
fn committed_high_alias_mprotect_readonly_edits_guest_page_tables() {
    const SYS_MPROTECT: u64 = 226;
    const PAGE_SIZE: u64 = 4 * 1024;
    let address = crate::memory::LINUX_HIGH_VA_THRESHOLD;

    let dispatcher = SyscallDispatcher::new();
    dispatcher.commit_host_alias_mmap(HostAliasMmapCommit {
        start: address,
        len: PAGE_SIZE,
        prot: LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        sharing: ProcMapSharing::Shared,
        path: "/tmp/mprotect03".to_owned(),
        file_page_offset: Some(0),
        droppable: false,
        semantic_vmas: None,
        locked: None,
        resident: true,
        bus_fault: None,
        write_sealed_shared: false,
        read_only_shared_file: false,
        secretmem: false,
        writable_memfd: None,
        shared_file_alias: None,
    });
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1161));
    let reporter = CompatReporter::default();
    let mut memory = CountingMmapMemory::new(address, PAGE_SIZE as usize);

    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MPROTECT,
            SyscallArgs([address, PAGE_SIZE, LINUX_PROT_READ, 0, 0, 0]),
        ),
    );

    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
    assert_eq!(
        memory.protect_calls.get(),
        1,
        "a committed high alias must publish its read-only stage-1 permission"
    );
}

#[test]
fn committed_high_alias_mprotect_reports_backend_edit_failure() {
    const SYS_MPROTECT: u64 = 226;
    const PAGE_SIZE: u64 = 4 * 1024;
    let address = crate::memory::LINUX_HIGH_VA_THRESHOLD;

    let dispatcher = SyscallDispatcher::new();
    dispatcher.commit_host_alias_mmap(HostAliasMmapCommit {
        start: address,
        len: PAGE_SIZE,
        prot: LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        sharing: ProcMapSharing::Shared,
        path: "/tmp/mprotect03-failure".to_owned(),
        file_page_offset: Some(0),
        droppable: false,
        semantic_vmas: None,
        locked: None,
        resident: true,
        bus_fault: None,
        write_sealed_shared: false,
        read_only_shared_file: false,
        secretmem: false,
        writable_memfd: None,
        shared_file_alias: None,
    });
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1162));
    let reporter = CompatReporter::default();
    let mut memory = FailingProtectMemory {
        inner: CountingMmapMemory::new(address, PAGE_SIZE as usize),
    };

    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MPROTECT,
            SyscallArgs([address, PAGE_SIZE, LINUX_PROT_READ, 0, 0, 0]),
        ),
    );

    assert_eq!(outcome, DispatchOutcome::errno(LINUX_ENOMEM));
}

#[test]
fn native16k_shared_provenance_survives_partial_mprotect() {
    const SYS_MPROTECT: u64 = 226;
    const PAGE_SIZE: u64 = 16 * 1024;
    const MAP_LEN: u64 = 3 * PAGE_SIZE;

    let dispatcher = native16k_dispatcher();
    dispatcher.record_dynamic_mapping(
        LINUX_MMAP_BASE,
        MAP_LEN,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Shared,
        String::new(),
    );
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1175));
    let reporter = CompatReporter::default();
    let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, MAP_LEN as usize);

    let middle = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MPROTECT,
            SyscallArgs([
                LINUX_MMAP_BASE + PAGE_SIZE,
                PAGE_SIZE,
                LINUX_PROT_READ,
                0,
                0,
                0,
            ]),
        ),
    );
    assert_eq!(middle, DispatchOutcome::Returned { value: 0 });
    let maps = dispatcher.mem().lock().dynamic_maps.clone();
    assert_eq!(
        maps.len(),
        3,
        "partial mprotect must preserve VMA fragments"
    );
    assert!(
        maps.iter().all(|map| map.sharing == ProcMapSharing::Shared),
        "all fragments must retain shared provenance: {maps:?}"
    );

    let left_write_exec = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MPROTECT,
            SyscallArgs([
                LINUX_MMAP_BASE,
                PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC,
                0,
                0,
                0,
            ]),
        ),
    );
    assert_eq!(left_write_exec, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
    assert_partial_reason(&reporter, "mprotect", "shared write-exec");
}

#[test]
fn native16k_rejects_multithreaded_exec_mprotect() {
    const SYS_MPROTECT: u64 = 226;
    const PAGE_SIZE: u64 = 16 * 1024;

    let dispatcher = native16k_dispatcher();
    dispatcher.record_dynamic_mapping(
        LINUX_MMAP_BASE,
        PAGE_SIZE,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Private,
        String::new(),
    );
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1185));
    registry.register_child(0);
    let reporter = CompatReporter::default();
    let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, PAGE_SIZE as usize);
    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MPROTECT,
            SyscallArgs([
                LINUX_MMAP_BASE,
                PAGE_SIZE,
                LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
                0,
                0,
                0,
            ]),
        ),
    );

    assert_eq!(outcome, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
    assert_partial_reason(&reporter, "mprotect", "executable protection transition");
    assert_eq!(memory.protect_calls.get(), 0);
}

#[test]
fn native16k_allows_multithreaded_exec_mprotect_for_translation_backend() {
    const SYS_MPROTECT: u64 = 226;
    const PAGE_SIZE: u64 = 16 * 1024;

    let dispatcher = native16k_dispatcher();
    dispatcher.record_dynamic_mapping(
        LINUX_MMAP_BASE,
        PAGE_SIZE,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Private,
        String::new(),
    );
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1186));
    registry.register_child(0);
    let reporter = CompatReporter::default();
    let mut memory =
        ConcurrentExecMemory(CountingMmapMemory::new(LINUX_MMAP_BASE, PAGE_SIZE as usize));
    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MPROTECT,
            SyscallArgs([
                LINUX_MMAP_BASE,
                PAGE_SIZE,
                LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
                0,
                0,
                0,
            ]),
        ),
    );

    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
    assert_eq!(memory.0.protect_calls.get(), 1);
}

#[test]
fn native16k_allows_private_alias_write_exec_for_translation_backend() {
    const SYS_MPROTECT: u64 = 226;
    const PAGE_SIZE: u64 = 16 * 1024;
    let address = crate::memory::LINUX_HIGH_VA_THRESHOLD;

    let dispatcher = native16k_dispatcher();
    // Model a completed high-VA alias transaction, not merely a reserved
    // VMA.  The authoritative backing inventory is published only at
    // commit, after the backend mapping has succeeded.
    dispatcher.commit_host_alias_mmap(HostAliasMmapCommit {
        start: address,
        len: PAGE_SIZE,
        prot: LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        sharing: ProcMapSharing::Private,
        path: String::new(),
        file_page_offset: None,
        droppable: false,
        semantic_vmas: None,
        locked: None,
        resident: false,
        bus_fault: None,
        write_sealed_shared: false,
        read_only_shared_file: false,
        secretmem: false,
        writable_memfd: None,
        shared_file_alias: None,
    });
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1187));
    registry.register_child(0);
    let reporter = CompatReporter::default();
    let mut memory = ConcurrentExecMemory(CountingMmapMemory::new(address, PAGE_SIZE as usize));
    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MPROTECT,
            SyscallArgs([
                address,
                PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC,
                0,
                0,
                0,
            ]),
        ),
    );

    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
    assert_eq!(memory.0.protect_calls.get(), 1);
}

#[test]
fn native16k_identity_mprotect_propagates_backend_failure() {
    const SYS_MPROTECT: u64 = 226;
    const PAGE_SIZE: u64 = 16 * 1024;

    let mut dispatcher = native16k_dispatcher();
    let reporter = CompatReporter::default();
    let mut memory = FailingProtectMemory {
        inner: CountingMmapMemory::new(LINUX_HEAP_BASE, PAGE_SIZE as usize),
    };
    let outcome = dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(
                SYS_MPROTECT,
                SyscallArgs([LINUX_HEAP_BASE, PAGE_SIZE, LINUX_PROT_READ, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .expect("identity mprotect dispatch");

    assert_eq!(outcome, DispatchOutcome::errno(LINUX_ENOMEM));
    assert_partial_reason(&reporter, "mprotect", "backend protection failure");
}

#[test]
fn native16k_rejects_shared_write_exec_mprotect() {
    const SYS_MPROTECT: u64 = 226;
    const PAGE_SIZE: u64 = 16 * 1024;

    let dispatcher = native16k_dispatcher();
    dispatcher.record_dynamic_mapping(
        LINUX_MMAP_BASE,
        PAGE_SIZE,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Shared,
        String::new(),
    );
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1200));
    let reporter = CompatReporter::default();
    let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, PAGE_SIZE as usize);
    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MPROTECT,
            SyscallArgs([
                LINUX_MMAP_BASE,
                PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC,
                0,
                0,
                0,
            ]),
        ),
    );

    assert_eq!(outcome, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
    assert_partial_reason(&reporter, "mprotect", "shared write-exec");
    assert_eq!(memory.protect_calls.get(), 0);
}

#[test]
fn native16k_rejects_multithreaded_write_exec_mprotect() {
    const SYS_MPROTECT: u64 = 226;
    const PAGE_SIZE: u64 = 16 * 1024;

    let dispatcher = native16k_dispatcher();
    dispatcher.record_dynamic_mapping(
        LINUX_MMAP_BASE,
        PAGE_SIZE,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Private,
        String::new(),
    );
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1300));
    registry.register_child(0);
    let reporter = CompatReporter::default();
    let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, PAGE_SIZE as usize);
    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MPROTECT,
            SyscallArgs([
                LINUX_MMAP_BASE,
                PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC,
                0,
                0,
                0,
            ]),
        ),
    );

    assert_eq!(outcome, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
    assert_partial_reason(&reporter, "mprotect", "multiple live guest threads");
    assert_eq!(memory.protect_calls.get(), 0);
}

#[test]
fn munmap_clears_read_only_tracking_before_writable_reuse() {
    const SYS_MMAP: u64 = 222;
    const SYS_MUNMAP: u64 = 215;
    const SYS_MPROTECT: u64 = 226;

    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = ProtectionTrackingMemory::new(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize);
    let reporter = CompatReporter::default();
    let read_only = SyscallRequest::new(
        SYS_MMAP,
        SyscallArgs([
            0,
            LINUX_PAGE_SIZE,
            LINUX_PROT_READ,
            LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
            u64::MAX,
            0,
        ]),
    );

    assert_eq!(
        returned(
            dispatcher
                .dispatch(
                    &dispatcher.capture_one_task_context().unwrap(),
                    read_only,
                    &mut memory,
                    &reporter
                )
                .expect("read-only mmap dispatch")
        ),
        LINUX_MMAP_BASE as i64
    );
    assert!(
        memory
            .protections
            .range_no_write(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize)
    );

    let unmap = SyscallRequest::new(
        SYS_MUNMAP,
        SyscallArgs([LINUX_MMAP_BASE, LINUX_PAGE_SIZE, 0, 0, 0, 0]),
    );
    assert_eq!(
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                unmap,
                &mut memory,
                &reporter
            )
            .expect("munmap dispatch"),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(
        memory
            .protections
            .range_no_access(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize)
    );
    assert!(
        !memory
            .protections
            .range_no_write(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize),
        "an unmapped VA must not retain stale read-only VMA evidence"
    );
    assert_eq!(
        crate::vcpu_loop::upgrade_protection_si_code(
            &memory,
            crate::linux_abi::LINUX_SIGSEGV,
            1,
            LINUX_MMAP_BASE,
        ),
        1,
        "a post-munmap translation fault is SEGV_MAPERR, not a permission fault"
    );

    let protect_hole = SyscallRequest::new(
        SYS_MPROTECT,
        SyscallArgs([LINUX_MMAP_BASE, LINUX_PAGE_SIZE, LINUX_PROT_READ, 0, 0, 0]),
    );
    assert_eq!(
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                protect_hole,
                &mut memory,
                &reporter
            )
            .expect("mprotect post-munmap hole dispatch"),
        DispatchOutcome::errno(LINUX_ENOMEM),
        "retained host backing must not let mprotect resurrect an unmapped VMA"
    );
    assert!(
        memory
            .protections
            .range_unmapped(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize)
    );

    let writable = SyscallRequest::new(
        SYS_MMAP,
        SyscallArgs([
            0,
            LINUX_PAGE_SIZE,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
            u64::MAX,
            0,
        ]),
    );
    assert_eq!(
        returned(
            dispatcher
                .dispatch(
                    &dispatcher.capture_one_task_context().unwrap(),
                    writable,
                    &mut memory,
                    &reporter
                )
                .expect("writable reuse mmap dispatch")
        ),
        LINUX_MMAP_BASE as i64
    );
    assert!(
        !memory
            .protections
            .range_no_access(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize)
    );
    assert!(
        !memory
            .protections
            .range_no_write(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize)
    );
}

#[test]
fn free_regions_coalesce_adjacent() {
    let mut r = vec![];
    free_regions_insert(&mut r, 0x1000, 0x1000); // [0x1000,0x2000)
    free_regions_insert(&mut r, 0x3000, 0x1000); // [0x3000,0x4000)
    free_regions_insert(&mut r, 0x2000, 0x1000); // bridges → one [0x1000,0x4000)
    assert_eq!(r, vec![(0x1000, 0x3000)]);
}

#[test]
fn lowering_the_cursor_drops_free_regions_left_above_it() {
    // The superset-munmap shape: an interior hole exists, then a munmap that
    // ends at the cursor lowers it PAST that hole. The absorb loop only takes
    // regions contiguous below, so the hole would survive above the cursor —
    // and the free list would then hand out a VA the bump path also hands out.
    let mut next = 0x4000;
    let mut regions = vec![(0x1000_u64, 0x1000_u64)]; // [0x1000,0x2000)
    lower_mmap_next(&mut next, &mut regions, 0x0);
    assert_eq!(next, 0x0);
    assert!(
        regions.is_empty(),
        "a region above the lowered cursor must not survive: {regions:x?}"
    );
}

#[test]
fn lowering_the_cursor_truncates_a_region_that_straddles_it() {
    let mut next = 0x4000;
    let mut regions = vec![(0x1000_u64, 0x2000_u64)]; // [0x1000,0x3000)
    lower_mmap_next(&mut next, &mut regions, 0x2000);
    assert_eq!(next, 0x2000);
    assert_eq!(
        regions,
        vec![(0x1000, 0x1000)],
        "only the part below survives"
    );
}

#[test]
fn lowering_the_cursor_still_absorbs_regions_contiguous_below() {
    let mut next = 0x4000;
    let mut regions = vec![(0x1000_u64, 0x1000_u64), (0x2000_u64, 0x1000_u64)];
    lower_mmap_next(&mut next, &mut regions, 0x3000);
    assert_eq!(next, 0x1000, "both contiguous regions fold into the cursor");
    assert!(regions.is_empty());
}

#[test]
fn removing_a_fixed_range_splits_the_region_it_lands_inside() {
    // MAP_FIXED inside the arena allocates VA the free list may still hold.
    let mut regions = vec![(0x1000_u64, 0x4000_u64)]; // [0x1000,0x5000)
    free_regions_remove_range(&mut regions, 0x2000, 0x1000);
    assert_eq!(regions, vec![(0x1000, 0x1000), (0x3000, 0x2000)]);

    let mut exact = vec![(0x1000_u64, 0x1000_u64)];
    free_regions_remove_range(&mut exact, 0x1000, 0x1000);
    assert!(exact.is_empty());

    let mut untouched = vec![(0x1000_u64, 0x1000_u64)];
    free_regions_remove_range(&mut untouched, 0x9000, 0x1000);
    assert_eq!(untouched, vec![(0x1000, 0x1000)]);
}

#[test]
fn guest_vma_occupancy_excludes_hidden_arenas_but_includes_live_ranges() {
    let dispatcher = SyscallDispatcher::new();
    let layout = dispatcher.mem().lock().layout;
    const BOOT: u64 = 0x20_0000_0000;
    dispatcher.mem().lock().brk_current = layout.heap_base + LINUX_PAGE_SIZE;
    dispatcher.set_address_space_regions(vec![
        ProcMapsEntry {
            start: layout.heap_base,
            end: layout.heap_base + layout.heap_size,
            read: true,
            write: true,
            execute: false,
            sharing: ProcMapSharing::Private,
            path: "heap-backing".into(),
        },
        ProcMapsEntry {
            start: layout.mmap_base,
            end: layout.mmap_base + layout.mmap_size,
            read: true,
            write: true,
            execute: true,
            sharing: ProcMapSharing::Private,
            path: "mmap-backing".into(),
        },
        ProcMapsEntry {
            start: BOOT,
            end: BOOT + LINUX_PAGE_SIZE,
            read: true,
            write: false,
            execute: true,
            sharing: ProcMapSharing::Private,
            path: "boot-text".into(),
        },
    ]);
    dispatcher.record_dynamic_mapping(
        layout.mmap_base + (2 * LINUX_PAGE_SIZE),
        LINUX_PAGE_SIZE,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Private,
        String::new(),
    );

    assert!(dispatcher.guest_vma_overlaps(layout.heap_base, LINUX_PAGE_SIZE));
    assert!(!dispatcher.guest_vma_overlaps(layout.heap_base + LINUX_PAGE_SIZE, LINUX_PAGE_SIZE));
    assert!(
        dispatcher.guest_vma_overlaps(layout.mmap_base + (2 * LINUX_PAGE_SIZE), LINUX_PAGE_SIZE)
    );
    assert!(!dispatcher.guest_vma_overlaps(layout.mmap_base, LINUX_PAGE_SIZE));
    assert!(dispatcher.guest_vma_overlaps(BOOT, LINUX_PAGE_SIZE));

    let snapshot = dispatcher
        .mem()
        .snapshot_until(std::time::Instant::now() + std::time::Duration::from_secs(1))
        .expect("VMA authority snapshot");
    assert!(snapshot.vmas.contains(&crate::kernel::VmaSummary {
        start: GuestVa(layout.heap_base),
        end: GuestVa(layout.heap_base + LINUX_PAGE_SIZE),
        access: crate::kernel::VmaAccess {
            readable: true,
            writable: true,
            executable: false,
            kernel_visible: true,
        },
    }));
    assert!(snapshot.vmas.contains(&crate::kernel::VmaSummary {
        start: GuestVa(layout.mmap_base + (2 * LINUX_PAGE_SIZE)),
        end: GuestVa(layout.mmap_base + (3 * LINUX_PAGE_SIZE)),
        access: crate::kernel::VmaAccess {
            readable: true,
            writable: true,
            executable: false,
            kernel_visible: true,
        },
    }));
    assert!(snapshot.vmas.contains(&crate::kernel::VmaSummary {
        start: GuestVa(BOOT),
        end: GuestVa(BOOT + LINUX_PAGE_SIZE),
        access: crate::kernel::VmaAccess {
            readable: true,
            writable: false,
            executable: true,
            kernel_visible: true,
        },
    }));
    assert!(!snapshot.vmas.iter().any(|vma| {
        vma.start == GuestVa(layout.mmap_base)
            || vma.end == GuestVa(layout.heap_base + layout.heap_size)
    }));
    assert!(
        snapshot
            .vmas
            .windows(2)
            .all(|rows| rows[0].end.raw() < rows[1].start.raw())
    );
}

#[test]
fn core_vma_projection_subtracts_map_fixed_replacement_from_live_heap() {
    let dispatcher = SyscallDispatcher::new();
    let layout = dispatcher.mem().lock().layout;
    dispatcher.mem().lock().brk_current = layout.heap_base + (2 * LINUX_PAGE_SIZE);
    dispatcher.set_address_space_regions(vec![ProcMapsEntry {
        start: layout.heap_base,
        end: layout.heap_base + layout.heap_size,
        read: true,
        write: true,
        execute: false,
        sharing: ProcMapSharing::Private,
        path: "heap-backing".into(),
    }]);
    dispatcher.record_dynamic_mapping(
        layout.heap_base,
        LINUX_PAGE_SIZE,
        LinuxProtFlags::READ,
        ProcMapSharing::Private,
        "fixed-replacement".into(),
    );

    let maps = project_core_maps(&dispatcher.mem().lock());
    assert_eq!(maps.len(), 2);
    assert_eq!(
        (
            maps[0].start,
            maps[0].end,
            maps[0].write,
            maps[0].path.as_str()
        ),
        (
            layout.heap_base,
            layout.heap_base + LINUX_PAGE_SIZE,
            false,
            "fixed-replacement",
        )
    );
    assert_eq!(
        (
            maps[1].start,
            maps[1].end,
            maps[1].write,
            maps[1].path.as_str()
        ),
        (
            layout.heap_base + LINUX_PAGE_SIZE,
            layout.heap_base + (2 * LINUX_PAGE_SIZE),
            true,
            "heap-backing",
        )
    );
    assert!(maps.windows(2).all(|pair| pair[0].end <= pair[1].start));
}

#[test]
fn vma_projection_preserves_adjacency_and_removes_unmapped_boot_ranges() {
    let dispatcher = SyscallDispatcher::new();
    dispatcher.set_address_space_regions(vec![
        ProcMapsEntry {
            start: 0x1000,
            end: 0x2000,
            read: true,
            write: false,
            execute: true,
            sharing: ProcMapSharing::Private,
            path: "text".to_owned(),
        },
        ProcMapsEntry {
            start: 0x2000,
            end: 0x3000,
            read: true,
            write: false,
            execute: false,
            sharing: ProcMapSharing::Private,
            path: "rodata".to_owned(),
        },
    ]);
    let before = dispatcher
        .mem()
        .snapshot_until(std::time::Instant::now() + std::time::Duration::from_secs(1))
        .expect("adjacent VMA snapshot");
    assert_eq!(before.vmas.len(), 2);

    dispatcher.with_vma_dispatch_for_test(|_vma_dispatch| {
        dispatcher.remove_mapping_metadata(0x1000, 0x1000);
    });
    let after = dispatcher
        .mem()
        .snapshot_until(std::time::Instant::now() + std::time::Duration::from_secs(1))
        .expect("trimmed VMA snapshot");
    assert_eq!(
        after.vmas,
        vec![crate::kernel::VmaSummary {
            start: GuestVa(0x2000),
            end: GuestVa(0x3000),
            access: crate::kernel::VmaAccess {
                readable: true,
                writable: false,
                executable: false,
                kernel_visible: true,
            },
        }]
    );
}

#[test]
fn mem_authority_revises_once_per_published_vma_transaction() {
    let dispatcher = SyscallDispatcher::new();
    let initial = dispatcher.mem().vma_revision();

    let _layout = dispatcher.mem().lock().layout;
    dispatcher.mem().lock().linux_auxv_image.push(1);
    assert_eq!(dispatcher.mem().vma_revision(), initial);

    // Failed/no-op mapping paths take exclusion but never arm publication.
    dispatcher.with_conditional_vma_dispatch_for_test(|guard| drop(guard));
    assert_eq!(dispatcher.mem().vma_revision(), initial);

    dispatcher.with_vma_dispatch_for_test(|_vma_dispatch| {
        dispatcher.mem().lock().brk_current += LINUX_PAGE_SIZE;
    });
    assert_eq!(
        dispatcher.mem().vma_revision(),
        initial.next().expect("revision")
    );

    dispatcher.with_conditional_vma_dispatch_for_test(|mut conditional| {
        dispatcher.mark_vma_dispatch(&mut conditional);
    });
    assert_eq!(
        dispatcher.mem().vma_revision(),
        initial
            .next()
            .and_then(crate::kernel::VmaRevision::next)
            .expect("second revision")
    );
}

#[test]
fn revision_checked_publication_excludes_concurrent_vma_mutation() {
    let dispatcher = std::sync::Arc::new(SyscallDispatcher::new());
    let source = dispatcher.vma_snapshot_source();
    let expected = source.revision();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let acquired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (attempting_tx, attempting_rx) = std::sync::mpsc::sync_channel(0);
    let worker_dispatcher = std::sync::Arc::clone(&dispatcher);
    let worker_barrier = std::sync::Arc::clone(&barrier);
    let worker_acquired = std::sync::Arc::clone(&acquired);
    let worker = std::thread::spawn(move || {
        worker_barrier.wait();
        attempting_tx.send(()).expect("announce mutation attempt");
        worker_dispatcher.with_conditional_vma_dispatch_for_test(|_guard| {
            worker_acquired.store(true, std::sync::atomic::Ordering::Release);
        });
    });

    source
        .publish_if_revision(
            expected,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            &mut || {
                barrier.wait();
                attempting_rx
                    .recv_timeout(std::time::Duration::from_secs(1))
                    .expect("mutation waiter reached acquisition");
                let waiter_deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
                while dispatcher.mm_mutation_coordinator().alias_waiters() == 0 {
                    assert!(
                        std::time::Instant::now() < waiter_deadline,
                        "mutation thread never blocked on VMA exclusion"
                    );
                    std::thread::yield_now();
                }
                assert!(!acquired.load(std::sync::atomic::Ordering::Acquire));
                Ok(())
            },
        )
        .expect("revision-checked publication");
    worker.join().expect("mutation waiter");
    assert!(acquired.load(std::sync::atomic::Ordering::Acquire));
}

#[test]
fn growdown_metadata_is_trimmed_with_mapping_teardown() {
    let dispatcher = SyscallDispatcher::new();
    let page = dispatcher.linux_page_size();
    let start = 0x10_000;
    dispatcher.record_dynamic_mapping(
        start,
        page * 4,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Private,
        "stack".to_owned(),
    );
    dispatcher.record_growdown_mapping(start, page * 4);
    dispatcher
        .with_mmap_growdown_fault_plan_for_test(start - page, |plan| {
            dispatcher.commit_mmap_growdown(plan);
        })
        .expect("grow-down plan");

    dispatcher.with_vma_dispatch_for_test(|_vma_dispatch| {
        dispatcher.remove_mapping_metadata(start + page, page);
    });
    let split = dispatcher
        .vma_snapshot_source()
        .snapshot(std::time::Instant::now() + std::time::Duration::from_secs(1))
        .expect("split grow-down snapshot");
    assert_eq!(
        split.vmas,
        vec![
            crate::kernel::VmaSummary {
                start: GuestVa(start - page),
                end: GuestVa(start + page),
                access: crate::kernel::VmaAccess {
                    readable: true,
                    writable: true,
                    executable: false,
                    kernel_visible: true,
                },
            },
            crate::kernel::VmaSummary {
                start: GuestVa(start + page * 2),
                end: GuestVa(start + page * 4),
                access: crate::kernel::VmaAccess {
                    readable: true,
                    writable: true,
                    executable: false,
                    kernel_visible: true,
                },
            },
        ]
    );

    dispatcher.with_vma_dispatch_for_test(|_vma_dispatch| {
        dispatcher.remove_mapping_metadata(start - page, page * 2);
    });
    assert!(
        dispatcher
            .with_mmap_growdown_fault_plan_for_test(start - page * 2, |plan| drop(plan))
            .is_none()
    );
    let retired = dispatcher
        .vma_snapshot_source()
        .snapshot(std::time::Instant::now() + std::time::Duration::from_secs(1))
        .expect("retired grow-down snapshot");
    assert_eq!(
        retired.vmas,
        vec![crate::kernel::VmaSummary {
            start: GuestVa(start + page * 2),
            end: GuestVa(start + page * 4),
            access: crate::kernel::VmaAccess {
                readable: true,
                writable: true,
                executable: false,
                kernel_visible: true,
            },
        }]
    );
}

/// Two guest threads first-touch the same armed page. The winner commits the
/// page under MM mutation authority and retires its fault range; the loser's
/// fault was already taken against the invalid leaf, so its read-only
/// classification runs AFTER the commit. It must still route to the mutation
/// authority (where the live leaf is authenticated and the access retried),
/// never straight to `SIGSEGV` (go-crypto_md5 under 4-way load: 3/12 SEGV).
#[test]
fn committed_first_touch_page_still_routes_to_mutation_authority() {
    let dispatcher = SyscallDispatcher::new();
    let page = dispatcher.linux_page_size();
    let base = LINUX_MMAP_BASE;
    dispatcher.record_dynamic_mapping(
        base,
        page * 2,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Private,
        String::new(),
    );
    dispatcher.track_resident_fault_range(
        base,
        page * 2,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
    );
    assert!(dispatcher.fault_requires_mm_mutation(base + 16));

    dispatcher
        .with_resident_fault_plan_for_test(base + 16, |plan| {
            assert_eq!(plan.page(), base);
            dispatcher.commit_resident_fault(plan);
        })
        .expect("first-touch plan");
    assert!(
        dispatcher
            .with_resident_fault_plan_for_test(base + 16, |plan| drop(plan))
            .is_none(),
        "a committed page has no pending stage-1 edit"
    );

    assert!(
        dispatcher.fault_requires_mm_mutation(base + 16),
        "the losing sibling's fault on the committed page must reach the authority"
    );
    assert!(dispatcher.fault_requires_mm_mutation(base + page));

    dispatcher.with_vma_dispatch_for_test(|_vma_dispatch| {
        dispatcher.remove_mapping_metadata(base, page * 2);
    });
    assert!(
        !dispatcher.fault_requires_mm_mutation(base + 16),
        "unmapping retires the tracked extent"
    );
}

/// `mprotect` over an armed first-touch range must not silently make the
/// pending pages accessible: the leaf stays invalid (so the first touch is
/// still observed for `mincore`) and the recorded protection follows the new
/// VMA permission, so the eventual fault installs what the guest asked for
/// last -- never the stale arming-time protection.
#[test]
fn mprotect_over_armed_first_touch_page_keeps_the_leaf_invalid_with_new_prot() {
    const SYS_MPROTECT: u64 = 226;
    let dispatcher = SyscallDispatcher::new();
    let page = dispatcher.linux_page_size();
    let base = LINUX_MMAP_BASE;
    let rw = LinuxProtFlags::READ | LinuxProtFlags::WRITE;
    dispatcher.record_dynamic_mapping(base, page * 2, rw, ProcMapSharing::Private, String::new());
    dispatcher.track_resident_fault_range(base, page * 2, rw);
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1171));
    let reporter = CompatReporter::default();
    let mut memory = CountingMmapMemory::new(base, (page * 2) as usize);

    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MPROTECT,
            SyscallArgs([base, page, LINUX_PROT_READ, 0, 0, 0]),
        ),
    );
    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });

    let prot = dispatcher
        .with_resident_fault_plan_for_test(base + 16, |plan| plan.prot())
        .expect("the untouched page stays armed");
    assert_eq!(
        prot, LINUX_PROT_READ,
        "the pending edit carries the NEW protection"
    );
    let sibling = dispatcher
        .with_resident_fault_plan_for_test(base + page + 16, |plan| plan.prot())
        .expect("the page outside the mprotect range stays armed");
    assert_eq!(sibling, rw.bits());
    let log = memory.protect_log.borrow();
    assert_eq!(
        log.last().copied(),
        Some((base, page as usize, 0)),
        "the armed page must be re-protected to an invalid leaf after the VMA edit: {log:?}"
    );
}

/// `MADV_DONTNEED` turns a private-anonymous page back into a first-touch
/// fault. The protection restored by that fault is the VMA's complete live
/// R/W/X permission, not a reconstruction from only its writable bit. V8 uses
/// this exact RWX reserve/discard/publish sequence for generated code.
#[test]
fn dontneed_first_touch_restores_an_executable_leaf() {
    const SYS_MADVISE: u64 = 233;
    let dispatcher = SyscallDispatcher::new();
    let page = dispatcher.linux_page_size();
    let base = LINUX_MMAP_BASE;
    let rwx = LinuxProtFlags::READ | LinuxProtFlags::WRITE | LinuxProtFlags::EXEC;
    dispatcher.record_dynamic_mapping(base, page, rwx, ProcMapSharing::Private, String::new());

    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1174));
    let reporter = CompatReporter::default();
    let mut memory = Stage1MmapMemory::new(base, page as usize);
    memory
        .protect_range(base, page as usize, rwx.bits())
        .expect("publish the live RWX VMA");

    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MADVISE,
            SyscallArgs([base, page, carrick_abi::LINUX_MADV_DONTNEED, 0, 0, 0]),
        ),
    );
    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });

    let restored_prot = dispatcher
        .with_resident_fault_plan_for_test(base + 16, |plan| {
            let prot = plan.prot();
            memory
                .protect_range(plan.page(), page as usize, prot)
                .expect("publish first-touch leaf");
            prot
        })
        .expect("MADV_DONTNEED re-arms the discarded page");
    let leaf = memory.terminal_descriptor(base);
    assert_eq!(
        restored_prot,
        rwx.bits(),
        "the pending edit preserves PROT_EXEC"
    );
    assert!(
        carrick_mem::page_table::terminal_descriptor_permits_el0(
            leaf,
            carrick_mem::page_table::LeafAccess::Execute,
        ),
        "the exact first-touch leaf must remain executable: {leaf:#x}"
    );
}

/// `mprotect(PROT_NONE)` over an armed page retires its pending edit: a later
/// fault must be delivered as SIGSEGV, not resolved by installing the
/// arming-time RW leaf. The extent stays routed to the authority so a fault
/// there still asks the live stage-1 leaf before delivery, and a later
/// accessible `mprotect` re-arms the still-untouched page.
#[test]
fn mprotect_none_over_armed_first_touch_page_retires_and_rearms_the_pending_edit() {
    const SYS_MPROTECT: u64 = 226;
    let dispatcher = SyscallDispatcher::new();
    let page = dispatcher.linux_page_size();
    let base = LINUX_MMAP_BASE;
    let rw = LinuxProtFlags::READ | LinuxProtFlags::WRITE;
    dispatcher.record_dynamic_mapping(base, page * 2, rw, ProcMapSharing::Private, String::new());
    dispatcher.track_resident_fault_range(base, page * 2, rw);
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1172));
    let reporter = CompatReporter::default();
    let mut memory = CountingMmapMemory::new(base, (page * 2) as usize);

    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(SYS_MPROTECT, SyscallArgs([base, page, 0, 0, 0, 0])),
    );
    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
    assert!(
        dispatcher
            .with_resident_fault_plan_for_test(base + 16, |plan| drop(plan))
            .is_none(),
        "a PROT_NONE page has no pending accessible edit to install"
    );
    assert!(
        dispatcher.fault_requires_mm_mutation(base + 16),
        "the tracked extent still routes to the authority"
    );
    assert!(
        dispatcher
            .with_resident_fault_plan_for_test(base + page + 16, |plan| drop(plan))
            .is_some(),
        "the neighbouring page keeps its pending edit"
    );

    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MPROTECT,
            SyscallArgs([base, page, LINUX_PROT_READ, 0, 0, 0]),
        ),
    );
    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
    let prot = dispatcher
        .with_resident_fault_plan_for_test(base + 16, |plan| plan.prot())
        .expect("an accessible mprotect re-arms the still-untouched page");
    assert_eq!(prot, LINUX_PROT_READ);
    let log = memory.protect_log.borrow();
    assert_eq!(
        log.last().copied(),
        Some((base, page as usize, 0)),
        "{log:?}"
    );
}

/// A page the guest has already touched is resident; `mprotect` over it must
/// publish the new leaf and leave it valid -- only the untouched remainder
/// of the tracked extent is re-armed.
#[test]
fn mprotect_over_committed_first_touch_page_does_not_rearm_it() {
    const SYS_MPROTECT: u64 = 226;
    let dispatcher = SyscallDispatcher::new();
    let page = dispatcher.linux_page_size();
    let base = LINUX_MMAP_BASE;
    let rw = LinuxProtFlags::READ | LinuxProtFlags::WRITE;
    dispatcher.record_dynamic_mapping(base, page * 2, rw, ProcMapSharing::Private, String::new());
    dispatcher.track_resident_fault_range(base, page * 2, rw);
    dispatcher
        .with_resident_fault_plan_for_test(base + 16, |plan| dispatcher.commit_resident_fault(plan))
        .expect("first-touch plan");
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1173));
    let reporter = CompatReporter::default();
    let mut memory = CountingMmapMemory::new(base, (page * 2) as usize);

    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MPROTECT,
            SyscallArgs([base, page * 2, LINUX_PROT_READ, 0, 0, 0]),
        ),
    );
    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
    assert!(
        dispatcher
            .with_resident_fault_plan_for_test(base + 16, |plan| drop(plan))
            .is_none(),
        "a resident page is never re-armed"
    );
    let prot = dispatcher
        .with_resident_fault_plan_for_test(base + page + 16, |plan| plan.prot())
        .expect("the untouched page stays armed");
    assert_eq!(prot, LINUX_PROT_READ);
    let log = memory.protect_log.borrow().clone();
    assert_eq!(
        log,
        vec![
            (base, (page * 2) as usize, LINUX_PROT_READ),
            (base + page, page as usize, 0),
        ],
        "only the untouched page returns to an invalid leaf"
    );
}

/// Same race on the grow-down stack: the winner lowers `current` to its page,
/// so the loser's page no longer satisfies `page < current`. The whole
/// grow-down extent stays routed to the authority.
#[test]
fn committed_growdown_page_still_routes_to_mutation_authority() {
    let dispatcher = SyscallDispatcher::new();
    let page = dispatcher.linux_page_size();
    let start = 0x10_000;
    dispatcher.record_dynamic_mapping(
        start,
        page * 4,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Private,
        "stack".to_owned(),
    );
    dispatcher.record_growdown_mapping(start, page * 4);
    assert!(dispatcher.fault_requires_mm_mutation(start - page * 2 + 8));
    dispatcher
        .with_mmap_growdown_fault_plan_for_test(start - page * 2, |plan| {
            dispatcher.commit_mmap_growdown(plan);
        })
        .expect("grow-down plan");
    assert!(
        dispatcher
            .with_mmap_growdown_fault_plan_for_test(start - page, |plan| drop(plan))
            .is_none(),
        "the committed extent has no pending grow-down edit"
    );
    assert!(
        dispatcher.fault_requires_mm_mutation(start - page + 8),
        "the losing sibling's fault inside the committed extent must reach the authority"
    );
    assert!(dispatcher.fault_requires_mm_mutation(start + page * 3));
    assert!(!dispatcher.fault_requires_mm_mutation(start + page * 4));
}

#[test]
fn mem_authority_fork_is_independent_after_one_existing_state_clone() {
    let parent = SyscallDispatcher::new();
    let layout = parent.mem().lock().layout;
    parent.with_vma_dispatch_for_test(|_parent_vma_dispatch| {
        parent.mem().lock().brk_current = layout.heap_base + LINUX_PAGE_SIZE;
    });
    let parent_revision = parent.mem().vma_revision();
    let child = parent.fork_clone_in_process(
        crate::thread::ThreadId::synthetic_for_tests(71),
        crate::thread::ThreadId::synthetic_for_tests(72),
        71,
        72,
    );

    assert!(!std::sync::Arc::ptr_eq(&parent.mem(), &child.mem()));
    assert_eq!(child.mem().vma_revision(), parent_revision);
    child.with_vma_dispatch_for_test(|_child_vma_dispatch| {
        child.mem().lock().brk_current += LINUX_PAGE_SIZE;
    });
    assert_eq!(
        parent.mem().lock().brk_current,
        layout.heap_base + LINUX_PAGE_SIZE
    );
    assert_eq!(parent.mem().vma_revision(), parent_revision);
    assert_eq!(
        child.mem().vma_revision(),
        parent_revision.next().expect("child revision")
    );
}

#[test]
fn mem_authority_snapshot_honors_deadline_contention() {
    let dispatcher = std::sync::Arc::new(SyscallDispatcher::new());
    let source = dispatcher.vma_snapshot_source();
    let held = std::sync::Arc::clone(&dispatcher);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let worker_barrier = std::sync::Arc::clone(&barrier);
    let worker = std::thread::spawn(move || {
        held.with_vma_dispatch_for_test(|_dispatch| {
            worker_barrier.wait();
            std::thread::sleep(std::time::Duration::from_millis(40));
        });
    });
    barrier.wait();

    assert_eq!(
        source.snapshot(std::time::Instant::now() + std::time::Duration::from_millis(5)),
        Err(crate::kernel::SnapshotError::TimedOut)
    );
    worker.join().expect("authority lock worker");
}

#[test]
fn dynamic_mapping_overlap_uses_sorted_boundaries() {
    let maps = vec![
        ProcMapsEntry {
            start: 0x1000,
            end: 0x2000,
            read: true,
            write: false,
            execute: false,
            sharing: ProcMapSharing::Private,
            path: String::new(),
        },
        ProcMapsEntry {
            start: 0x4000,
            end: 0x5000,
            read: true,
            write: false,
            execute: false,
            sharing: ProcMapSharing::Private,
            path: String::new(),
        },
    ];

    assert!(!dynamic_mapping_overlaps_sorted(&maps, 0x2000, 0x2000));
    assert!(dynamic_mapping_overlaps_sorted(&maps, 0x1fff, 1));
    assert!(dynamic_mapping_overlaps_sorted(&maps, 0x3000, 0x1001));
}

#[test]
fn committed_vma_coverage_rejects_holes_and_accepts_adjacent_mappings() {
    let dispatcher = SyscallDispatcher::new();
    let base = LINUX_MMAP_BASE;
    for start in [base, base + 2 * LINUX_PAGE_SIZE] {
        dispatcher.record_dynamic_mapping(
            start,
            LINUX_PAGE_SIZE,
            LinuxProtFlags::READ,
            ProcMapSharing::Private,
            String::new(),
        );
    }
    assert!(!guest_vma_covers_locked(
        &dispatcher.mem().lock(),
        base,
        3 * LINUX_PAGE_SIZE,
    ));

    dispatcher.record_dynamic_mapping(
        base + LINUX_PAGE_SIZE,
        LINUX_PAGE_SIZE,
        LinuxProtFlags::READ,
        ProcMapSharing::Private,
        String::new(),
    );
    assert!(guest_vma_covers_locked(
        &dispatcher.mem().lock(),
        base,
        3 * LINUX_PAGE_SIZE,
    ));
}

#[test]
fn trim_dynamic_maps_preserves_sorted_order_without_full_resort() {
    let mut maps = vec![
        ProcMapsEntry {
            start: 0x1000,
            end: 0x5000,
            read: true,
            write: true,
            execute: false,
            sharing: ProcMapSharing::Private,
            path: String::new(),
        },
        ProcMapsEntry {
            start: 0x8000,
            end: 0x9000,
            read: true,
            write: false,
            execute: false,
            sharing: ProcMapSharing::Private,
            path: String::new(),
        },
    ];

    trim_dynamic_maps_for_range(&mut maps, 0x2000, 0x2000);

    let ranges: Vec<(u64, u64)> = maps.iter().map(|map| (map.start, map.end)).collect();
    assert_eq!(
        ranges,
        vec![(0x1000, 0x2000), (0x4000, 0x5000), (0x8000, 0x9000)]
    );
}

#[test]
fn secretmem_range_registry_records_queries_and_splits() {
    let dispatcher = SyscallDispatcher::new();
    let base = LINUX_MMAP_BASE;
    let page = LINUX_PAGE_SIZE;

    // Nothing recorded -> nothing touches.
    assert!(!dispatcher.range_touches_secretmem(base, page));

    dispatcher.record_secretmem_map(base, 4 * page);
    // Inside, at both edges, and spanning the start from below.
    assert!(dispatcher.range_touches_secretmem(base, 1));
    assert!(dispatcher.range_touches_secretmem(base + 4 * page - 1, 1));
    assert!(dispatcher.range_touches_secretmem(base - page, 2 * page));
    // Adjacent-but-outside on both sides.
    assert!(!dispatcher.range_touches_secretmem(base - page, page));
    assert!(!dispatcher.range_touches_secretmem(base + 4 * page, page));

    // A partial munmap splits the range: the middle stops matching, the
    // outer halves keep matching.
    dispatcher.remove_secretmem_map(base + page, page);
    assert!(dispatcher.range_touches_secretmem(base, page));
    assert!(!dispatcher.range_touches_secretmem(base + page, page));
    assert!(dispatcher.range_touches_secretmem(base + 2 * page, 2 * page));

    // Removing the rest clears the registry.
    dispatcher.remove_secretmem_map(base, 4 * page);
    assert!(!dispatcher.range_touches_secretmem(base, 4 * page));
}

/// The shared mmap-teardown path (`munmap`, and SysV `shmdt`) must retire
/// secretmem ranges along with every other range classification, so a later
/// mapping at the same VA is not spuriously hidden from `/proc/<pid>/mem`.
#[test]
fn secretmem_range_is_retired_by_mapping_metadata_removal() {
    let dispatcher = SyscallDispatcher::new();
    let base = LINUX_MMAP_BASE;
    let page = LINUX_PAGE_SIZE;

    dispatcher.record_secretmem_map(base, 2 * page);
    assert!(dispatcher.range_touches_secretmem(base, 2 * page));

    dispatcher.remove_mapping_metadata(base, 2 * page);
    assert!(
        !dispatcher.range_touches_secretmem(base, 2 * page),
        "remove_mapping_metadata must retire the secretmem classification"
    );
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
fn mmap_shared_validate_rejects_anonymous_but_keeps_file_and_unknown_flag_rules() {
    const SYS_MMAP: u64 = 222;
    const SHARED_VALIDATE: u64 = LINUX_MAP_SHARED | LINUX_MAP_PRIVATE;
    const UNKNOWN_FLAG: u64 = 1 << 63;
    const FILE_FD: i32 = 40;

    let mut anonymous_dispatcher = SyscallDispatcher::new();
    let mut anonymous_memory = CountingMmapMemory::new(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize);
    let reporter = CompatReporter::default();
    let anonymous = anonymous_dispatcher
        .dispatch(
            &anonymous_dispatcher
                .capture_one_task_context()
                .expect("anonymous context"),
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LINUX_PAGE_SIZE,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    SHARED_VALIDATE | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
            &mut anonymous_memory,
            &reporter,
        )
        .expect("anonymous MAP_SHARED_VALIDATE dispatch");
    assert_eq!(anonymous, DispatchOutcome::errno(LINUX_EINVAL));

    let install_file = |dispatcher: &SyscallDispatcher| {
        install_host_file_fd(dispatcher, FILE_FD, &[0x5a; LINUX_PAGE_SIZE as usize]);
    };

    let mut file_dispatcher = SyscallDispatcher::new();
    install_file(&file_dispatcher);
    let mut file_memory = CountingMmapMemory::new(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize);
    let file_backed = file_dispatcher
        .dispatch(
            &file_dispatcher
                .capture_one_task_context()
                .expect("file context"),
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LINUX_PAGE_SIZE,
                    LINUX_PROT_READ,
                    SHARED_VALIDATE,
                    FILE_FD as u64,
                    0,
                ]),
            ),
            &mut file_memory,
            &reporter,
        )
        .expect("file-backed MAP_SHARED_VALIDATE dispatch");
    assert!(
        matches!(
            file_backed,
            DispatchOutcome::Returned { .. } | DispatchOutcome::MapHostAlias { .. }
        ),
        "file-backed MAP_SHARED_VALIDATE must remain valid: {file_backed:?}"
    );

    let mut unknown_dispatcher = SyscallDispatcher::new();
    install_file(&unknown_dispatcher);
    let mut unknown_memory = CountingMmapMemory::new(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize);
    let unknown = unknown_dispatcher
        .dispatch(
            &unknown_dispatcher
                .capture_one_task_context()
                .expect("unknown-flag context"),
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LINUX_PAGE_SIZE,
                    LINUX_PROT_READ,
                    SHARED_VALIDATE | UNKNOWN_FLAG,
                    FILE_FD as u64,
                    0,
                ]),
            ),
            &mut unknown_memory,
            &reporter,
        )
        .expect("unknown MAP_SHARED_VALIDATE flag dispatch");
    assert_eq!(unknown, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
}

#[test]
fn anonymous_mmap_residency_tracks_populate_first_touch_and_dontneed() {
    const SYS_MMAP: u64 = 222;
    const SYS_MADVISE: u64 = 233;

    let mut private_dispatcher = SyscallDispatcher::new();
    let mut private_memory = CountingMmapMemory::new(LINUX_MMAP_BASE, 4 * LINUX_PAGE_SIZE as usize);
    let reporter = CompatReporter::default();
    let private_context = private_dispatcher
        .capture_one_task_context()
        .expect("private map context");
    let private_mmap = |dispatcher: &mut SyscallDispatcher,
                        memory: &mut CountingMmapMemory,
                        prot: u64,
                        flags: u64| {
        returned(
            dispatcher
                .dispatch(
                    &private_context,
                    SyscallRequest::new(
                        SYS_MMAP,
                        SyscallArgs([0, LINUX_PAGE_SIZE, prot, flags, u64::MAX, 0]),
                    ),
                    memory,
                    &reporter,
                )
                .expect("private anonymous map dispatch"),
        ) as u64
    };

    let untouched = private_mmap(
        &mut private_dispatcher,
        &mut private_memory,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
    );
    assert_eq!(
        private_dispatcher
            .mincore_residency_vector(&private_memory, untouched, 1, LINUX_PAGE_SIZE,),
        Some(vec![0]),
        "untouched anonymous memory must not be resident"
    );

    let populated = private_mmap(
        &mut private_dispatcher,
        &mut private_memory,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | crate::linux_abi::LINUX_MAP_POPULATE,
    );
    assert_eq!(
        private_dispatcher
            .mincore_residency_vector(&private_memory, populated, 1, LINUX_PAGE_SIZE,),
        Some(vec![1]),
        "MAP_POPULATE must publish private-anonymous residency before return"
    );

    let populated_prot_none = private_mmap(
        &mut private_dispatcher,
        &mut private_memory,
        0,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | crate::linux_abi::LINUX_MAP_POPULATE,
    );
    assert_eq!(
        private_dispatcher.mincore_residency_vector(
            &private_memory,
            populated_prot_none,
            1,
            LINUX_PAGE_SIZE,
        ),
        Some(vec![1]),
        "MAP_POPULATE must publish PROT_NONE private-anonymous residency before return"
    );

    private_dispatcher.mark_range_resident(untouched, LINUX_PAGE_SIZE);
    assert_eq!(
        private_dispatcher
            .mincore_residency_vector(&private_memory, untouched, 1, LINUX_PAGE_SIZE,),
        Some(vec![1]),
        "the first-touch publication must make the page resident"
    );
    assert_eq!(
        private_dispatcher
            .dispatch(
                &private_context,
                SyscallRequest::new(
                    SYS_MADVISE,
                    SyscallArgs([untouched, LINUX_PAGE_SIZE, LINUX_MADV_DONTNEED, 0, 0, 0]),
                ),
                &mut private_memory,
                &reporter,
            )
            .expect("MADV_DONTNEED dispatch"),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        private_dispatcher
            .mincore_residency_vector(&private_memory, untouched, 1, LINUX_PAGE_SIZE,),
        Some(vec![0]),
        "MADV_DONTNEED must retire private-anonymous residency"
    );

    for sharing in [LINUX_MAP_PRIVATE, LINUX_MAP_SHARED] {
        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize);
        let context = dispatcher
            .capture_one_task_context()
            .expect("anonymous populate context");
        let outcome = dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(
                    SYS_MMAP,
                    SyscallArgs([
                        0,
                        LINUX_PAGE_SIZE,
                        LINUX_PROT_READ | LINUX_PROT_WRITE,
                        sharing | LINUX_MAP_ANONYMOUS | crate::linux_abi::LINUX_MAP_POPULATE,
                        u64::MAX,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .expect("anonymous MAP_POPULATE dispatch");
        let address = returned(outcome) as u64;
        assert_eq!(
            dispatcher.mincore_residency_vector(&memory, address, 1, LINUX_PAGE_SIZE),
            Some(vec![1]),
            "MAP_POPULATE must publish residency for sharing={sharing:#x}"
        );
    }
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

#[test]
fn mincore_unmapped_end_page_is_enomem_not_abort() {
    // One mapped page at the base; a length that spans into the unmapped next
    // page must be ENOMEM — Linux requires the WHOLE range mapped, and the
    // unmapped end caps the residency-vec bound.
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
    // address + length overflows u64: the bound guard must turn this into
    // ENOMEM rather than computing a u64::MAX-page residency vec (an
    // uncatchable allocation abort).
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
fn free_regions_coalesce_overlap_and_keep_disjoint() {
    let mut r = vec![];
    free_regions_insert(&mut r, 0x1000, 0x2000); // [0x1000,0x3000)
    free_regions_insert(&mut r, 0x2000, 0x2000); // overlaps → [0x1000,0x4000)
    free_regions_insert(&mut r, 0x9000, 0x1000); // disjoint
    assert_eq!(r, vec![(0x1000, 0x3000), (0x9000, 0x1000)]);
}

#[test]
fn next_mmap_address_reuses_freed_arena_region() {
    let dispatcher = SyscallDispatcher::new();
    let freed = LINUX_MMAP_BASE + (4 * LINUX_PAGE_SIZE);
    {
        let mem_authority_117 = dispatcher.mem();
        let mut mem = mem_authority_117.lock();
        free_regions_insert(&mut mem.free_regions, freed, 2 * LINUX_PAGE_SIZE);
    }

    let first = dispatcher.next_mmap_address(0, LINUX_PAGE_SIZE, 0, 0, MmapGrantCongruence::Any);
    assert_eq!(first, Some((freed, true)));

    let second = dispatcher.next_mmap_address(0, LINUX_PAGE_SIZE, 0, 0, MmapGrantCongruence::Any);
    assert_eq!(second, Some((freed + LINUX_PAGE_SIZE, true)));

    assert!(dispatcher.mem().lock().free_regions.is_empty());
}

/// A page-cache view of a file needs `address ≡ offset (mod host page)`,
/// so an eligible hint-less `mmap(MAP_PRIVATE, fd, offset)` grant must land
/// on a congruent address — on both the bump path and the freed-region
/// path — and the skipped prefix must be parked for reuse, not stranded.
/// Linux only promises page alignment for a hint-less grant, so choosing
/// the residue is ABI-legal.
#[test]
fn next_mmap_address_honours_file_offset_congruence() {
    let host_page = crate::page_profile::host_page_size();
    if host_page <= LINUX_PAGE_SIZE {
        // A 4K host has nothing to be congruent to; `for_file_offset` is `Any`.
        assert!(matches!(
            MmapGrantCongruence::for_file_offset(3 * LINUX_PAGE_SIZE, LINUX_PAGE_SIZE),
            MmapGrantCongruence::Any
        ));
        return;
    }
    let residue = 3 * LINUX_PAGE_SIZE % host_page;
    assert_ne!(
        residue, 0,
        "fixture offset must not already be host-page aligned"
    );
    let congruence = MmapGrantCongruence::for_file_offset(3 * LINUX_PAGE_SIZE, LINUX_PAGE_SIZE);

    // Bump path: the arena base is host-page aligned, so the grant skips
    // `residue` bytes, which are parked as a free region.
    let dispatcher = SyscallDispatcher::new();
    let (address, reused) = dispatcher
        .next_mmap_address(0, LINUX_PAGE_SIZE, 0, 0, congruence)
        .expect("bump grant");
    assert_eq!(address % host_page, residue);
    assert_eq!(address, LINUX_MMAP_BASE + residue);
    assert!(!reused);
    assert_eq!(
        dispatcher.mem().lock().free_regions,
        vec![(LINUX_MMAP_BASE, residue)],
        "the skipped congruence prefix is parked, not stranded"
    );

    // Freed-region path: a hole that starts host-page aligned is entered at
    // its first congruent address; the prefix and the tail both survive.
    let dispatcher = SyscallDispatcher::new();
    let hole = LINUX_MMAP_BASE + 8 * host_page;
    let hole_len = 2 * host_page;
    {
        let mem_authority = dispatcher.mem();
        let mut mem = mem_authority.lock();
        free_regions_insert(&mut mem.free_regions, hole, hole_len);
    }
    let (address, reused) = dispatcher
        .next_mmap_address(0, LINUX_PAGE_SIZE, 0, 0, congruence)
        .expect("free-region grant");
    assert_eq!(address, hole + residue);
    assert!(reused);
    assert_eq!(
        dispatcher.mem().lock().free_regions,
        vec![
            (hole, residue),
            (
                hole + residue + LINUX_PAGE_SIZE,
                hole_len - residue - LINUX_PAGE_SIZE
            ),
        ]
    );

    // A hole too short to hold a congruent fit is skipped rather than
    // misplaced: the grant falls through to the bump cursor.
    let dispatcher = SyscallDispatcher::new();
    {
        let mem_authority = dispatcher.mem();
        let mut mem = mem_authority.lock();
        free_regions_insert(&mut mem.free_regions, hole, residue);
    }
    let (address, reused) = dispatcher
        .next_mmap_address(0, LINUX_PAGE_SIZE, 0, 0, congruence)
        .expect("bump fallback");
    assert_eq!(address, LINUX_MMAP_BASE + residue);
    assert!(!reused);
}

/// A `PROT_NONE` reservation cannot hold a guest-written byte, so it must
/// NOT raise the writable watermark — and a later allocation that lands
/// under it must therefore be handed back WITHOUT a scrub.
///
/// This is the dominant shape on a build: Go's allocator reserves by the
/// gigabyte and commits sub-ranges, and raising the watermark on every
/// hand-out regardless of protection is what made carrick memset 2.38 GB
/// for a workload whose real touched set is ~226 MB
/// (`docs/perf-results/2026-08-13-hvpatch-kf-scrub-ceiling.md`).
#[test]
fn a_prot_none_reserve_does_not_raise_the_writable_watermark() {
    let dispatcher = SyscallDispatcher::new();
    let base = dispatcher.mem().lock().mmap_writable_high;

    // A large PROT_NONE reserve: allocated, never writable.
    let reserve = dispatcher
        .next_mmap_address(0, 16 * LINUX_PAGE_SIZE, 0, 0, MmapGrantCongruence::Any)
        .expect("reserve");
    assert!(!reserve.1, "a fresh bump allocation is never reused");
    assert_eq!(
        dispatcher.mem().lock().mmap_writable_high,
        base,
        "a PROT_NONE reservation must not move the writable watermark"
    );

    // Rewind the cursor the way `munmap` of the top region does, then take
    // the same span again. Nothing could have written it, so no scrub.
    dispatcher.mem().lock().mmap_next = reserve.0;
    let again = dispatcher
        .next_mmap_address(0, 16 * LINUX_PAGE_SIZE, 0, 0, MmapGrantCongruence::Any)
        .expect("re-allocate");
    assert_eq!(again.0, reserve.0);
    assert!(
        !again.1,
        "re-handing out never-writable memory must not force a scrub"
    );
}

/// The other half of the same invariant: a WRITABLE hand-out does raise the
/// watermark, so re-handing that span out later DOES force a scrub. Without
/// this the previous test would be satisfied by never raising it at all,
/// which is the stale-bytes bug the watermark exists to prevent.
#[test]
fn a_writable_mapping_raises_the_watermark_and_forces_a_later_scrub() {
    let dispatcher = SyscallDispatcher::new();

    let writable = dispatcher
        .next_mmap_address(
            0,
            16 * LINUX_PAGE_SIZE,
            LINUX_PROT_WRITE,
            0,
            MmapGrantCongruence::Any,
        )
        .expect("writable mapping");
    assert!(!writable.1, "a fresh bump allocation is never reused");
    assert!(
        dispatcher.mem().lock().mmap_writable_high >= writable.0 + 16 * LINUX_PAGE_SIZE,
        "a writable hand-out must move the watermark past its end"
    );

    dispatcher.mem().lock().mmap_next = writable.0;
    let again = dispatcher
        .next_mmap_address(
            0,
            16 * LINUX_PAGE_SIZE,
            LINUX_PROT_WRITE,
            0,
            MmapGrantCongruence::Any,
        )
        .expect("re-allocate");
    assert_eq!(again.0, writable.0);
    assert!(
        again.1,
        "re-handing out memory the guest could have written MUST force a scrub"
    );
}

#[test]
fn reset_memory_state_on_execve_resets_arenas_and_preserves_auxv_snapshot() {
    let dispatcher = SyscallDispatcher::new();
    dispatcher.set_auxv_image(vec![1, 2, 3, 4]);
    {
        let mem_authority_118 = dispatcher.mem();
        let mut mem = mem_authority_118.lock();
        mem.brk_current = LINUX_HEAP_BASE + 0x21000;
        mem.mmap_next = LINUX_MMAP_BASE + 0x8000;
        mem.mmap_writable_high = LINUX_MMAP_BASE + 0x9000;
        free_regions_insert(&mut mem.free_regions, LINUX_MMAP_BASE + 0x1000, 0x1000);
    }

    dispatcher.reset_memory_state_on_execve();

    {
        let mem_authority_119 = dispatcher.mem();
        let mem = mem_authority_119.lock();
        assert_eq!(mem.brk_current, LINUX_HEAP_BASE);
        assert_eq!(mem.mmap_next, LINUX_MMAP_BASE);
        assert_eq!(mem.mmap_writable_high, LINUX_MMAP_BASE);
        assert!(mem.free_regions.is_empty());
        assert_eq!(mem.linux_auxv_image, vec![1, 2, 3, 4]);
    }
    assert_eq!(
        dispatcher.next_mmap_address(0, LINUX_PAGE_SIZE, 0, 0, MmapGrantCongruence::Any),
        Some((LINUX_MMAP_BASE, false))
    );
}

#[test]
fn brk_shrink_scrubs_backing_before_regrowth() {
    const SYS_BRK: u64 = 214;
    const PAGES: u64 = 3;

    let mut dispatcher = SyscallDispatcher::new();
    let initial = dispatcher.mem().lock().layout.heap_base;
    let grown = initial + PAGES * LINUX_PAGE_SIZE;
    dispatcher.mem().lock().brk_current = grown;

    let mut memory = CountingMmapMemory::new(initial, (PAGES * LINUX_PAGE_SIZE) as usize);
    memory.bytes.fill(0xa5);
    let reporter = CompatReporter::default();
    let shrink = SyscallRequest::new(SYS_BRK, SyscallArgs([initial, 0, 0, 0, 0, 0]));

    let outcome = dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            shrink,
            &mut memory,
            &reporter,
        )
        .expect("brk shrink dispatch should succeed");

    assert_eq!(returned(outcome), initial as i64);
    assert_eq!(memory.zero_backing_calls.get(), 1);
    assert!(
        memory.bytes.iter().all(|byte| *byte == 0),
        "a later brk growth must not re-expose stale heap bytes"
    );
}

struct HeapVmaTrackingMemory {
    base: u64,
    bytes: Vec<u8>,
    protections: carrick_guest_mem::protections::MemoryProtections,
    event_log: std::cell::RefCell<Vec<String>>,
}

impl HeapVmaTrackingMemory {
    fn new(base: u64, len: usize) -> Self {
        let protections = carrick_guest_mem::protections::MemoryProtections::default();
        protections.set_unmapped(base, len, true);
        Self {
            base,
            bytes: vec![0u8; len],
            protections,
            event_log: std::cell::RefCell::new(Vec::new()),
        }
    }

    fn offset(&self, address: u64, length: usize) -> Result<usize, MemoryError> {
        let offset = address
            .checked_sub(self.base)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        let offset =
            usize::try_from(offset).map_err(|_| MemoryError::OutOfBounds { address, length })?;
        let end = offset
            .checked_add(length)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        if end > self.bytes.len() {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        Ok(offset)
    }
}

impl GuestMemory for HeapVmaTrackingMemory {
    fn protections(&self) -> Option<&carrick_guest_mem::protections::MemoryProtections> {
        Some(&self.protections)
    }

    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let off = self.offset(address, length)?;
        Ok(self.bytes[off..off + length].to_vec())
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let off = self.offset(address, bytes.len())?;
        self.bytes[off..off + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.event_log
            .borrow_mut()
            .push(format!("zero_backing({address:#x}, {len:#x})"));
        let off = self.offset(address, len)?;
        self.bytes[off..off + len].fill(0);
        Ok(())
    }

    fn protect_range(&mut self, address: u64, len: usize, prot: u64) -> Result<(), MemoryError> {
        self.event_log.borrow_mut().push(format!(
            "protect_range({address:#x}, {len:#x}, prot={prot})"
        ));
        Ok(())
    }

    fn set_unmapped(&mut self, address: u64, len: usize, unmapped: bool) {
        self.event_log.borrow_mut().push(format!(
            "set_unmapped({address:#x}, {len:#x}, unmapped={unmapped})"
        ));
        self.protections.set_unmapped(address, len, unmapped);
    }

    fn set_mapping_protection(
        &mut self,
        address: u64,
        len: usize,
        no_access: bool,
        no_write: bool,
    ) {
        self.event_log.borrow_mut().push(format!(
            "set_mapping_protection({address:#x}, {len:#x}, no_acc={no_access}, no_wr={no_write})"
        ));
        self.protections
            .set_mapping_protection(address, len, no_access, no_write);
    }
}

impl CurrentMmMemory for HeapVmaTrackingMemory {}

#[test]
fn brk_heap_real_vma_page_transitions() {
    const SYS_BRK: u64 = 214;
    let mut dispatcher = SyscallDispatcher::new();
    let heap_base = dispatcher.mem().lock().layout.heap_base;
    let heap_size = dispatcher.mem().lock().layout.heap_size as usize;
    let mut memory = HeapVmaTrackingMemory::new(heap_base, heap_size);
    let reporter = CompatReporter::default();

    let call_brk = |dispatcher: &mut SyscallDispatcher,
                    memory: &mut HeapVmaTrackingMemory,
                    target: u64|
     -> i64 {
        let req = SyscallRequest::new(SYS_BRK, SyscallArgs([target, 0, 0, 0, 0, 0]));
        let outcome = dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                req,
                memory,
                &reporter,
            )
            .expect("brk dispatch");
        returned(outcome)
    };

    // 0. Initial state: brk is at heap_base, memory is unmapped
    assert_eq!(call_brk(&mut dispatcher, &mut memory, 0), heap_base as i64);
    assert!(
        memory.read_bytes(heap_base, 1).is_err(),
        "initial heap must reject syscall reads before growth"
    );

    // 1. Grow 1 page (0x1000)
    memory.event_log.borrow_mut().clear();
    let ret = call_brk(&mut dispatcher, &mut memory, heap_base + LINUX_PAGE_SIZE);
    assert_eq!(ret, (heap_base + LINUX_PAGE_SIZE) as i64);
    // Verified grow ordering: stage-1 protect_range RW then set_mapping_protection (clearing unmapped)
    let log = memory.event_log.borrow().clone();
    let prot_idx = log
        .iter()
        .position(|e| e.starts_with("protect_range") && e.contains("prot=3"));
    let set_map_idx = log.iter().position(|e| {
        e.starts_with("set_mapping_protection") && e.contains("no_acc=false, no_wr=false")
    });
    assert!(
        prot_idx.is_some() && set_map_idx.is_some(),
        "grow must call protect_range(RW) then set_mapping_protection: {log:?}"
    );
    assert!(
        prot_idx.unwrap() < set_map_idx.unwrap(),
        "grow ordering must be stage1-RW -> set_mapping_protection: {log:?}"
    );
    assert!(
        !memory.protections.range_unmapped(heap_base, 0x1000),
        "grown page must no longer be unmapped in MemoryProtections"
    );
    assert!(
        !memory.protections.range_no_access(heap_base, 0x1000),
        "grown page must no longer be no_access in MemoryProtections"
    );
    assert!(
        memory
            .protections
            .range_unmapped(heap_base + LINUX_PAGE_SIZE, 0x1000),
        "ungrown tail must remain unmapped"
    );
    // Grown page is readable and writable
    assert!(memory.write_bytes(heap_base, &[0xa5; 0x1000]).is_ok());
    let read_back = memory
        .read_bytes(heap_base, 0x1000)
        .expect("read back grown page");
    assert_eq!(read_back, vec![0xa5; 0x1000]);
    // Next page is still unmapped
    assert!(memory.read_bytes(heap_base + LINUX_PAGE_SIZE, 1).is_err());

    // 2. Unaligned break move within live page (e.g. heap_base + 0x800)
    memory.event_log.borrow_mut().clear();
    let ret2 = call_brk(&mut dispatcher, &mut memory, heap_base + 0x800);
    assert_eq!(ret2, (heap_base + 0x800) as i64);
    assert!(
        memory.event_log.borrow().is_empty(),
        "same-page move must not edit page tables or protections: {:?}",
        memory.event_log.borrow()
    );
    // Page remains accessible
    assert!(memory.read_bytes(heap_base, 0x1000).is_ok());

    // 3. Shrink to heap base
    memory.event_log.borrow_mut().clear();
    let ret3 = call_brk(&mut dispatcher, &mut memory, heap_base);
    assert_eq!(ret3, heap_base as i64);
    let shrink_log = memory.event_log.borrow().clone();
    // Verify restrictive ordering: protect_range PROT_NONE -> set_unmapped true -> zero_backing
    let prot_idx = shrink_log
        .iter()
        .position(|e| e.starts_with("protect_range") && e.contains("prot=0"));
    let unmap_idx = shrink_log.iter().position(|e| e.contains("unmapped=true"));
    let zero_idx = shrink_log
        .iter()
        .position(|e| e.starts_with("zero_backing"));
    assert!(
        prot_idx.is_some() && unmap_idx.is_some() && zero_idx.is_some(),
        "shrink must perform protect_range(0), set_unmapped(true), and zero_backing: {shrink_log:?}"
    );
    assert!(
        prot_idx.unwrap() < unmap_idx.unwrap() && unmap_idx.unwrap() < zero_idx.unwrap(),
        "shrink ordering must be stage1-invalid -> unmapped -> zero_backing: {shrink_log:?}"
    );
    // Now syscall read to heap_base fails
    assert!(memory.read_bytes(heap_base, 1).is_err());

    // 4. Re-grow 1 page: must be zeroed
    let ret4 = call_brk(&mut dispatcher, &mut memory, heap_base + LINUX_PAGE_SIZE);
    assert_eq!(ret4, (heap_base + LINUX_PAGE_SIZE) as i64);
    let regrown_bytes = memory
        .read_bytes(heap_base, 0x1000)
        .expect("read regrown page");
    assert!(
        regrown_bytes.iter().all(|&b| b == 0),
        "re-grown heap page must be zeroed"
    );
}

#[test]
fn fresh_private_anonymous_mmap_skips_zero_write() {
    const SYS_MMAP: u64 = 222;

    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize);
    let reporter = CompatReporter::default();
    let request = SyscallRequest::new(
        SYS_MMAP,
        SyscallArgs([
            0,
            LINUX_PAGE_SIZE,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
            u64::MAX,
            0,
        ]),
    );

    let outcome = dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            request,
            &mut memory,
            &reporter,
        )
        .expect("mmap dispatch should succeed");

    assert_eq!(returned(outcome), LINUX_MMAP_BASE as i64);
    assert_eq!(
        memory.write_calls.get(),
        0,
        "fresh anonymous mmap should rely on lazy-zero backing, not write a zero buffer"
    );
    assert_eq!(memory.write_bytes_total.get(), 0);
    assert_eq!(memory.zero_backing_calls.get(), 0);
    assert_eq!(
        memory.protect_calls.get(),
        2,
        "fresh mapping installs the requested guest protection, then arms the \
         first-touch residency fault (the second call, PROT_NONE) so `mincore` \
         can tell a written page from an untouched one"
    );
}

#[test]
fn reused_private_anonymous_mmap_zeroes_backing_without_zero_write() {
    const SYS_MMAP: u64 = 222;

    let mut dispatcher = SyscallDispatcher::new();
    {
        let mem_authority_120 = dispatcher.mem();
        let mut mem = mem_authority_120.lock();
        free_regions_insert(&mut mem.free_regions, LINUX_MMAP_BASE, LINUX_PAGE_SIZE);
    }
    let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize);
    memory.bytes.fill(0x5a);
    let reporter = CompatReporter::default();
    let request = SyscallRequest::new(
        SYS_MMAP,
        SyscallArgs([
            0,
            LINUX_PAGE_SIZE,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
            u64::MAX,
            0,
        ]),
    );

    let outcome = dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            request,
            &mut memory,
            &reporter,
        )
        .expect("mmap dispatch should succeed");

    assert_eq!(returned(outcome), LINUX_MMAP_BASE as i64);
    assert_eq!(
        memory.zero_backing_calls.get(),
        1,
        "reused anonymous mmap must scrub stale physical backing"
    );
    assert_eq!(
        memory.write_calls.get(),
        0,
        "zero_backing should be the only scrub path for reused anonymous mmap"
    );
    assert!(
        memory
            .read_bytes(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize)
            .unwrap()
            .iter()
            .all(|byte| *byte == 0),
        "stale bytes must not remain visible after reuse"
    );
    assert_eq!(
        memory.protect_calls.get(),
        2,
        "reused mapping installs the requested guest protection, then arms the \
         first-touch residency fault (the second call, PROT_NONE)"
    );
}

#[test]
fn range_owned_metadata_removal_clears_every_mmap_classification() {
    let dispatcher = SyscallDispatcher::new();
    let start = crate::memory::LINUX_HIGH_VA_THRESHOLD;
    let len = 2 * LINUX_PAGE_SIZE;
    let range = crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start + len))
        .expect("metadata range");
    let writable_memfd = kernel_file_description(
        std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::SyntheticFile {
            base: OpenDescriptionBase::new(0),
            path: "memfd:metadata-remove".into(),
            contents: Vec::new(),
            offset: 0,
        })),
        crate::linux_abi::LINUX_O_RDWR,
    );
    dispatcher.record_dynamic_mapping(
        start,
        len,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Shared,
        String::new(),
    );
    {
        let mem_authority_121 = dispatcher.mem();
        let mut mem = mem_authority_121.lock();
        mem.remap_snapshots.insert(start, vec![0; len as usize]);
        mem.bus_fault_ranges.push((start, len));
        locked_ranges_insert(&mut mem.locked_ranges, range);
        locked_ranges_insert(&mut mem.resident_ranges, range);
        locked_ranges_insert(&mut mem.resident_tracked_ranges, range);
        mem.resident_fault_ranges.push(ResidentFaultRange {
            range,
            prot: LinuxProtFlags::READ,
        });
        locked_ranges_insert(&mut mem.write_sealed_shared_maps, range);
        mem.writable_memfd_maps.push((range, writable_memfd));
    }
    assert!(dispatcher.range_has_mapping_metadata_for_test(start, len));

    dispatcher.remove_mapping_metadata(start, len);

    assert!(!dispatcher.range_has_mapping_metadata_for_test(start, len));
}

#[test]
fn replacement_commit_trims_every_predecessor_classification_to_prefix_and_suffix() {
    let dispatcher = SyscallDispatcher::new();
    let start = crate::memory::LINUX_HIGH_VA_THRESHOLD;
    let page = LINUX_PAGE_SIZE;
    let len = 3 * page;
    let middle = start + page;
    let whole = crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start + len))
        .expect("whole predecessor range");
    let writable_memfd = kernel_file_description(
        std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::SyntheticFile {
            base: OpenDescriptionBase::new(0),
            path: "memfd:split-predecessor".into(),
            contents: Vec::new(),
            offset: 0,
        })),
        crate::linux_abi::LINUX_O_RDWR,
    );
    dispatcher.record_dynamic_mapping(
        start,
        len,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Shared,
        "predecessor".into(),
    );
    {
        let mem_authority_122 = dispatcher.mem();
        let mut mem = mem_authority_122.lock();
        let mut snapshot = vec![0x11; page as usize];
        snapshot.extend(std::iter::repeat_n(0x22, page as usize));
        snapshot.extend(std::iter::repeat_n(0x33, page as usize));
        mem.remap_snapshots.insert(start, snapshot);
        mem.bus_fault_ranges.push((start, len));
        locked_ranges_insert(&mut mem.locked_ranges, whole);
        locked_ranges_insert(&mut mem.resident_ranges, whole);
        locked_ranges_insert(&mut mem.resident_tracked_ranges, whole);
        mem.resident_fault_ranges.push(ResidentFaultRange {
            range: whole,
            prot: LinuxProtFlags::READ,
        });
        locked_ranges_insert(&mut mem.write_sealed_shared_maps, whole);
        mem.writable_memfd_maps
            .push((whole, std::sync::Arc::clone(&writable_memfd)));
    }

    dispatcher.commit_host_alias_mmap(HostAliasMmapCommit {
        start: middle,
        len: page,
        prot: LinuxProtFlags::READ | LinuxProtFlags::EXEC,
        sharing: ProcMapSharing::Private,
        path: "replacement".into(),
        file_page_offset: None,
        droppable: false,
        semantic_vmas: None,
        locked: None,
        resident: false,
        bus_fault: None,
        write_sealed_shared: false,
        read_only_shared_file: false,
        secretmem: false,
        writable_memfd: None,
        shared_file_alias: None,
    });

    let mem_authority_123 = dispatcher.mem();

    let mem = mem_authority_123.lock();
    assert_eq!(mem.dynamic_maps.len(), 3);
    assert_eq!(
        mem.dynamic_maps
            .iter()
            .map(|map| (map.start, map.end, map.path.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (start, middle, "predecessor"),
            (middle, middle + page, "replacement"),
            (middle + page, start + len, "predecessor"),
        ]
    );
    assert_eq!(
        mem.bus_fault_ranges,
        vec![(start, page), (middle + page, page)]
    );
    let expected_ranges = vec![
        crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(middle)).expect("prefix"),
        crate::vfs::GuestMemoryRange::new(GuestVa(middle + page), GuestVa(start + len))
            .expect("suffix"),
    ];
    assert_eq!(mem.locked_ranges, expected_ranges);
    assert_eq!(mem.resident_ranges, expected_ranges);
    assert_eq!(mem.resident_tracked_ranges, expected_ranges);
    assert_eq!(mem.write_sealed_shared_maps, expected_ranges);
    assert_eq!(mem.resident_fault_ranges.len(), 2);
    assert_eq!(mem.resident_fault_ranges[0].range, expected_ranges[0]);
    assert_eq!(mem.resident_fault_ranges[1].range, expected_ranges[1]);
    assert!(
        mem.resident_fault_ranges
            .iter()
            .all(|fault| fault.prot == LinuxProtFlags::READ)
    );
    assert_eq!(mem.writable_memfd_maps.len(), 2);
    assert_eq!(mem.writable_memfd_maps[0].0, expected_ranges[0]);
    assert_eq!(mem.writable_memfd_maps[1].0, expected_ranges[1]);
    assert!(
        mem.writable_memfd_maps
            .iter()
            .all(|(_, description)| std::sync::Arc::ptr_eq(description, &writable_memfd))
    );
    assert_eq!(mem.remap_snapshots.len(), 2);
    assert_eq!(
        mem.remap_snapshots.get(&start).map(Vec::as_slice),
        Some(vec![0x11; page as usize].as_slice())
    );
    assert_eq!(
        mem.remap_snapshots.get(&(middle + page)).map(Vec::as_slice),
        Some(vec![0x33; page as usize].as_slice())
    );
}

#[test]
fn core_file_provenance_keeps_mmap_offset_and_excludes_anonymous_exec() {
    let dispatcher = SyscallDispatcher::new();
    dispatcher.commit_host_alias_mmap(HostAliasMmapCommit {
        start: 0x7000_0000,
        len: 0x2000,
        prot: LinuxProtFlags::READ | LinuxProtFlags::EXEC,
        sharing: ProcMapSharing::Private,
        path: "/tmp/nonzero-map".to_owned(),
        file_page_offset: Some(3),
        droppable: false,
        semantic_vmas: None,
        locked: None,
        resident: true,
        bus_fault: None,
        write_sealed_shared: false,
        read_only_shared_file: false,
        secretmem: false,
        writable_memfd: None,
        shared_file_alias: None,
    });
    dispatcher.commit_host_alias_mmap(HostAliasMmapCommit {
        start: 0x7100_0000,
        len: 0x1000,
        prot: LinuxProtFlags::READ | LinuxProtFlags::EXEC,
        sharing: ProcMapSharing::Private,
        path: String::new(),
        file_page_offset: None,
        droppable: false,
        semantic_vmas: None,
        locked: None,
        resident: true,
        bus_fault: None,
        write_sealed_shared: false,
        read_only_shared_file: false,
        secretmem: false,
        writable_memfd: None,
        shared_file_alias: None,
    });

    assert_eq!(
        dispatcher.mem().lock().core_file_mappings,
        vec![crate::core_dump::FileMapping {
            start: 0x7000_0000,
            end: 0x7000_2000,
            file_page_offset: 3,
            path: "/tmp/nonzero-map".to_owned(),
        }]
    );
}

#[test]
fn host_alias_inventory_commits_trims_and_fork_clones_exact_ranges() {
    let parent = SyscallDispatcher::new();
    let start = crate::memory::LINUX_HIGH_VA_THRESHOLD;
    let page = LINUX_PAGE_SIZE;
    let len = 3 * page;
    let transaction = parent.with_host_alias_dispatch_for_test(|guard| {
        guard.publish(HostAliasCommit::mmap(HostAliasMmapCommit {
            start,
            len,
            prot: LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            sharing: ProcMapSharing::Shared,
            path: String::new(),
            file_page_offset: None,
            droppable: false,
            semantic_vmas: None,
            locked: None,
            resident: false,
            bus_fault: None,
            write_sealed_shared: false,
            read_only_shared_file: false,
            secretmem: false,
            writable_memfd: None,
            shared_file_alias: None,
        }))
    });
    assert!(
        !parent.range_has_host_alias_backing(start, len),
        "a pending transaction must not predict physical backing"
    );
    transaction
        .with_claim_for_test(|install| {
            assert!(
                !parent.range_has_host_alias_backing(start, len),
                "an installing transaction must not publish before backend success"
            );
            parent
                .commit_host_alias_install(install)
                .expect("publish successful host-alias install");
        })
        .expect("claim host-alias install");
    assert!(parent.range_has_host_alias_backing(start, len));

    let child = parent.fork_clone_in_process(
        crate::thread::ThreadId::synthetic_for_tests(73),
        crate::thread::ThreadId::synthetic_for_tests(74),
        73,
        74,
    );
    assert!(
        child.range_has_host_alias_backing(start, len),
        "fork inherits the fact that its explicit child descriptor reuses the alias backing"
    );

    parent.remove_mapping_metadata(start + page, page);
    assert!(parent.range_has_host_alias_backing(start, page));
    assert!(!parent.range_has_host_alias_backing(start, len));
    assert!(!parent.range_has_host_alias_backing(start + page, page));
    assert!(parent.range_has_host_alias_backing(start + 2 * page, page));
    assert!(
        child.range_has_host_alias_backing(start, len),
        "the child's copied inventory is not mutated by a parent-only unmap"
    );
}

#[test]
fn host_alias_abort_preserves_replaced_vma_lock_residency_bus_and_seal_metadata() {
    let dispatcher = SyscallDispatcher::new();
    let start = crate::memory::LINUX_HIGH_VA_THRESHOLD;
    let len = LINUX_PAGE_SIZE * 2;
    let replacement = crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start + len))
        .expect("replacement range");
    dispatcher.record_dynamic_mapping(
        start,
        len,
        LinuxProtFlags::READ | LinuxProtFlags::EXEC,
        ProcMapSharing::Private,
        "prior".to_string(),
    );
    let writable_memfd = kernel_file_description(
        std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::SyntheticFile {
            base: OpenDescriptionBase::new(0),
            path: "memfd:test".into(),
            contents: Vec::new(),
            offset: 0,
        })),
        crate::linux_abi::LINUX_O_RDWR,
    );
    {
        let mem_authority_124 = dispatcher.mem();
        let mut mem = mem_authority_124.lock();
        locked_ranges_insert(&mut mem.locked_ranges, replacement);
        locked_ranges_insert(&mut mem.resident_ranges, replacement);
        locked_ranges_insert(&mut mem.write_sealed_shared_maps, replacement);
        mem.writable_memfd_maps
            .push((replacement, std::sync::Arc::clone(&writable_memfd)));
        mem.bus_fault_ranges
            .push((start + LINUX_PAGE_SIZE, LINUX_PAGE_SIZE));
    }
    let before = dispatcher.mem().lock().clone();
    assert!(!dispatcher.range_has_host_alias_backing(start, len));
    let vma_source = dispatcher.vma_snapshot_source();
    let transaction = dispatcher.with_host_alias_dispatch_for_test(|guard| {
        guard.publish(HostAliasCommit::mmap(HostAliasMmapCommit {
            start,
            len,
            prot: LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            sharing: ProcMapSharing::Shared,
            path: "replacement".to_string(),
            file_page_offset: None,
            droppable: false,
            semantic_vmas: None,
            locked: None,
            resident: false,
            bus_fault: None,
            write_sealed_shared: false,
            read_only_shared_file: false,
            secretmem: false,
            writable_memfd: None,
            shared_file_alias: None,
        }))
    });

    assert!(
        vma_source
            .snapshot(std::time::Instant::now() + std::time::Duration::from_millis(50))
            .is_ok(),
        "a pending outcome owns no alias phase and exposes the old coherent generation"
    );
    let pending = dispatcher.mem().lock().clone();
    assert!(!dispatcher.range_has_host_alias_backing(start, len));
    assert_eq!(pending.dynamic_maps, before.dynamic_maps);
    assert_eq!(pending.locked_ranges, before.locked_ranges);
    assert_eq!(pending.resident_ranges, before.resident_ranges);
    assert_eq!(pending.bus_fault_ranges, before.bus_fault_ranges);
    assert_eq!(
        pending.write_sealed_shared_maps,
        before.write_sealed_shared_maps
    );
    assert_eq!(pending.writable_memfd_maps.len(), 1);
    assert!(std::sync::Arc::ptr_eq(
        &pending.writable_memfd_maps[0].1,
        &writable_memfd
    ));
    transaction
        .with_claim_for_test(|install| drop(install))
        .expect("claim pending host alias install");

    let after = dispatcher.mem().lock().clone();
    assert!(
        !dispatcher.range_has_host_alias_backing(start, len),
        "an aborted backend install must not publish backing presence"
    );
    assert_eq!(after.dynamic_maps, before.dynamic_maps);
    assert_eq!(after.locked_ranges, before.locked_ranges);
    assert_eq!(after.resident_ranges, before.resident_ranges);
    assert_eq!(after.bus_fault_ranges, before.bus_fault_ranges);
    assert_eq!(
        after.write_sealed_shared_maps,
        before.write_sealed_shared_maps
    );
    assert_eq!(after.writable_memfd_maps.len(), 1);
    assert!(std::sync::Arc::ptr_eq(
        &after.writable_memfd_maps[0].1,
        &writable_memfd
    ));
}

#[test]
fn pending_host_alias_transaction_drop_aborts_and_notifies_waiters() {
    let dispatcher = std::sync::Arc::new(SyscallDispatcher::new());
    let transaction = dispatcher.with_host_alias_dispatch_for_test(|guard| {
        guard.publish(HostAliasCommit::mmap(HostAliasMmapCommit {
            start: crate::memory::LINUX_HIGH_VA_THRESHOLD,
            len: LINUX_PAGE_SIZE,
            prot: LinuxProtFlags::READ,
            sharing: ProcMapSharing::Private,
            path: String::new(),
            file_page_offset: None,
            droppable: false,
            semantic_vmas: None,
            locked: None,
            resident: false,
            bus_fault: None,
            write_sealed_shared: false,
            read_only_shared_file: false,
            secretmem: false,
            writable_memfd: None,
            shared_file_alias: None,
        }))
    });
    let sibling = std::sync::Arc::clone(&dispatcher);
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        started_tx.send(()).expect("report pending waiter start");
        sibling.with_host_alias_dispatch_for_test(|_guard| {
            entered_tx
                .send(())
                .expect("report pending waiter admission");
        });
    });
    started_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("pending waiter reached exclusion");
    assert!(
        entered_rx
            .recv_timeout(std::time::Duration::from_millis(25))
            .is_err(),
        "pending transaction did not exclude a sibling"
    );
    drop(transaction);
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("pending transaction Drop notified sibling");
    thread.join().expect("join pending transaction waiter");
}

#[test]
fn proc_mem_snapshot_waits_for_install_and_returns_one_coherent_generation() {
    let dispatcher = std::sync::Arc::new(SyscallDispatcher::new());
    dispatcher.mem().lock().brk_current = 0x1111_0000;
    let transaction = dispatcher.with_host_alias_dispatch_for_test(|guard| {
        guard.publish(HostAliasCommit::mmap(HostAliasMmapCommit {
            start: crate::memory::LINUX_HIGH_VA_THRESHOLD,
            len: LINUX_PAGE_SIZE,
            prot: LinuxProtFlags::READ,
            sharing: ProcMapSharing::Private,
            path: String::new(),
            file_page_offset: None,
            droppable: false,
            semantic_vmas: None,
            locked: None,
            resident: false,
            bus_fault: None,
            write_sealed_shared: false,
            read_only_shared_file: false,
            secretmem: false,
            writable_memfd: None,
            shared_file_alias: None,
        }))
    });
    transaction
        .with_claim_for_test(|install| {
            let (tx, rx) = std::sync::mpsc::channel();
            let worker = std::sync::Arc::clone(&dispatcher);
            let thread = std::thread::spawn(move || {
                let snapshot = worker
                    .mem_snapshot_until(
                        std::time::Instant::now() + std::time::Duration::from_secs(1),
                    )
                    .expect("snapshot after install phase");
                tx.send(snapshot.brk_current).expect("publish snapshot");
            });

            assert_eq!(
                rx.recv_timeout(std::time::Duration::from_millis(20)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout),
                "proc snapshot must not clone MemState during Installing"
            );
            drop(install);
            assert_eq!(
                rx.recv_timeout(std::time::Duration::from_secs(1)),
                Ok(0x1111_0000)
            );
            thread.join().expect("snapshot worker exits");
        })
        .expect("claim host-alias install");
}

#[test]
fn dropping_unconsumed_host_alias_outcome_closes_fd_and_aborts_transaction() {
    let dispatcher = SyscallDispatcher::new();
    let transaction = dispatcher.with_host_alias_dispatch_for_test(|guard| {
        guard.publish(HostAliasCommit::mmap(HostAliasMmapCommit {
            start: crate::memory::LINUX_HIGH_VA_THRESHOLD,
            len: LINUX_PAGE_SIZE,
            prot: LinuxProtFlags::READ,
            sharing: ProcMapSharing::Shared,
            path: String::new(),
            file_page_offset: None,
            droppable: false,
            semantic_vmas: None,
            locked: None,
            resident: false,
            bus_fault: None,
            write_sealed_shared: false,
            read_only_shared_file: false,
            secretmem: false,
            writable_memfd: None,
            shared_file_alias: None,
        }))
    });
    let mut pipe = [-1; 2];
    assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
    let read_fd = pipe[0];
    let outcome = DispatchOutcome::MapHostAlias {
        success_retval: 0,
        transaction,
        va: GuestVa(crate::memory::LINUX_HIGH_VA_THRESHOLD),
        ipa: Gpa(crate::memory::LINUX_ALIAS_IPA_BASE),
        len: LINUX_PAGE_SIZE,
        payload: Vec::new(),
        backing: HostAliasBacking::File {
            // SAFETY: the successful pipe read end is uniquely transferred.
            fd: HostAliasOwnedFd::from(unsafe { std::os::fd::OwnedFd::from_raw_fd(read_fd) }),
            offset: 0,
            host_prot: libc::PROT_READ,
            sharing: HostAliasSharing::Shared,
        },
        prot: crate::linux_abi::LINUX_PROT_READ,
        prot_none: false,
    };

    drop(outcome);
    assert_eq!(unsafe { libc::fcntl(read_fd, libc::F_GETFD) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EBADF)
    );
    assert_eq!(unsafe { libc::close(pipe[1]) }, 0);
    // Drop of the transaction handle also returned the exclusion to Idle.
    dispatcher.with_host_alias_dispatch_for_test(|guard| drop(guard));
}

#[test]
fn installing_host_alias_blocks_sibling_mapping_dispatch_until_resolution() {
    let dispatcher = std::sync::Arc::new(SyscallDispatcher::new());
    let transaction = dispatcher.with_host_alias_dispatch_for_test(|guard| {
        guard.publish(HostAliasCommit::mmap(HostAliasMmapCommit {
            start: crate::memory::LINUX_HIGH_VA_THRESHOLD,
            len: LINUX_PAGE_SIZE,
            prot: LinuxProtFlags::READ,
            sharing: ProcMapSharing::Private,
            path: String::new(),
            file_page_offset: None,
            droppable: false,
            semantic_vmas: None,
            locked: None,
            resident: false,
            bus_fault: None,
            write_sealed_shared: false,
            read_only_shared_file: false,
            secretmem: false,
            writable_memfd: None,
            shared_file_alias: None,
        }))
    });
    transaction
        .with_claim_for_test(|install| {
            let sibling = std::sync::Arc::clone(&dispatcher);
            let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
            let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
            let thread = std::thread::spawn(move || {
                started_tx.send(()).expect("report install waiter start");
                sibling.with_host_alias_dispatch_for_test(|_guard| {
                    entered_tx.send(()).expect("report mapping admission");
                });
            });
            started_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("install waiter reached exclusion");
            assert!(
                entered_rx
                    .recv_timeout(std::time::Duration::from_millis(25))
                    .is_err(),
                "sibling mapping dispatch raced an installing host alias"
            );
            drop(install);
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("sibling admitted after abort");
            thread.join().expect("join sibling mapping dispatch");
        })
        .expect("claim pending host alias install");
}

#[test]
fn brk_waits_for_host_alias_idle() {
    const SYS_BRK: u64 = 214;
    assert_operation_waits_for_host_alias_idle("brk", move |dispatcher| {
        let reporter = CompatReporter::default();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1300));
        let mut memory = LinearMemory::new(LINUX_HEAP_BASE, vec![0; LINUX_PAGE_SIZE as usize]);
        dispatcher
            .dispatch_threaded_for_test(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(SYS_BRK, SyscallArgs([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
                registry.main_tid(),
                &registry,
                &crate::thread::FutexTable::new(),
            )
            .expect("brk dispatch while alias install is pending");
    });
}

#[test]
fn msync_waits_for_host_alias_idle() {
    const SYS_MSYNC: u64 = 227;
    assert_operation_waits_for_host_alias_idle("msync", move |dispatcher| {
        let reporter = CompatReporter::default();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1301));
        let mut memory = LinearMemory::new(LINUX_MMAP_BASE, vec![0; LINUX_PAGE_SIZE as usize]);
        dispatcher
            .dispatch_threaded_for_test(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    SYS_MSYNC,
                    SyscallArgs([LINUX_MMAP_BASE, LINUX_PAGE_SIZE, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
                registry.main_tid(),
                &registry,
                &crate::thread::FutexTable::new(),
            )
            .expect("msync dispatch while alias install is pending");
    });
}

#[test]
fn mincore_waits_for_host_alias_idle() {
    const SYS_MINCORE: u64 = 232;
    assert_operation_waits_for_host_alias_idle("mincore", move |dispatcher| {
        let reporter = CompatReporter::default();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1302));
        let mut memory =
            LinearMemory::new(LINUX_MMAP_BASE, vec![0; (2 * LINUX_PAGE_SIZE) as usize]);
        dispatcher
            .dispatch_threaded_for_test(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    SYS_MINCORE,
                    SyscallArgs([
                        LINUX_MMAP_BASE,
                        LINUX_PAGE_SIZE,
                        LINUX_MMAP_BASE + LINUX_PAGE_SIZE,
                        0,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
                registry.main_tid(),
                &registry,
                &crate::thread::FutexTable::new(),
            )
            .expect("mincore dispatch while alias install is pending");
    });
}

#[test]
fn high_va_private_anonymous_mmap_returns_empty_alias_payload() {
    const SYS_MMAP: u64 = 222;

    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize);
    let reporter = CompatReporter::default();
    let va = crate::memory::LINUX_HIGH_VA_THRESHOLD;
    let request = SyscallRequest::new(
        SYS_MMAP,
        SyscallArgs([
            va,
            LINUX_PAGE_SIZE,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            LINUX_MAP_FIXED | LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
            u64::MAX,
            0,
        ]),
    );

    let outcome = dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            request,
            &mut memory,
            &reporter,
        )
        .expect("mmap dispatch should succeed");

    let DispatchOutcome::MapHostAlias {
        va: mapped_va,
        len,
        payload,
        backing,
        ..
    } = outcome
    else {
        panic!("expected high-VA alias outcome, got {outcome:?}");
    };
    assert_eq!(mapped_va, GuestVa(va));
    assert_eq!(len, LINUX_PAGE_SIZE);
    assert!(
        !backing.is_file(),
        "anonymous alias should not carry a file"
    );
    assert!(
        payload.is_empty(),
        "fresh high-VA anonymous mmap should use the zeroed host anon alias without carrying a zero payload"
    );
    assert_eq!(memory.write_calls.get(), 0);
    assert_eq!(memory.zero_backing_calls.get(), 0);
    assert_eq!(memory.protect_calls.get(), 0);
}

#[test]
fn hvpatch_low_fixed_hole_maps_a_host_alias() {
    const SYS_MMAP: u64 = 222;
    const VA: u64 = 0x1_0000_0000;

    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize);
    let reporter = CompatReporter::default();
    let request = SyscallRequest::new(
        SYS_MMAP,
        SyscallArgs([
            VA,
            LINUX_PAGE_SIZE,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            LINUX_MAP_FIXED | LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
            u64::MAX,
            0,
        ]),
    );

    let outcome = dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            request,
            &mut memory,
            &reporter,
        )
        .expect("low fixed HVPatch mmap dispatch");

    let DispatchOutcome::MapHostAlias {
        va, len, payload, ..
    } = outcome
    else {
        panic!("expected low fixed hole to use an alias, got {outcome:?}");
    };
    assert_eq!(va, GuestVa(VA));
    assert_eq!(len, LINUX_PAGE_SIZE);
    assert!(payload.is_empty());
    assert_eq!(memory.zero_backing_calls.get(), 0);
    assert_eq!(memory.protect_calls.get(), 0);
}

#[test]
fn alias_window_advisory_hint_is_honored_without_consuming_low_arena() {
    const SYS_MMAP: u64 = 222;
    const SYS_MUNMAP: u64 = 215;

    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize);
    let reporter = CompatReporter::default();
    let va = 0xc000000000;
    let len = 0x4000000;
    let request = SyscallRequest::new(
        SYS_MMAP,
        SyscallArgs([
            va,
            len,
            0,
            LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
            u64::MAX,
            0,
        ]),
    );

    let outcome = dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            request,
            &mut memory,
            &reporter,
        )
        .expect("mmap dispatch should succeed");

    assert_eq!(outcome, DispatchOutcome::Returned { value: va as i64 });
    let unmap = SyscallRequest::new(SYS_MUNMAP, SyscallArgs([va, len, 0, 0, 0, 0]));
    let unmap_outcome = dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            unmap,
            &mut memory,
            &reporter,
        )
        .expect("munmap dispatch should succeed");
    assert_eq!(unmap_outcome, DispatchOutcome::Returned { value: 0 });
    assert_eq!(
        dispatcher.next_mmap_address(0, LINUX_PAGE_SIZE, 0, 0, MmapGrantCongruence::Any),
        Some((LINUX_MMAP_BASE, false)),
        "alias-window advisory reservations must not consume the low mmap arena"
    );
}

#[test]
fn alias_window_advisory_hint_with_protection_maps_alias() {
    const SYS_MMAP: u64 = 222;

    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize);
    let reporter = CompatReporter::default();
    let va = 0xc000000000;
    let len = LINUX_PAGE_SIZE;
    let request = SyscallRequest::new(
        SYS_MMAP,
        SyscallArgs([
            va,
            len,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
            u64::MAX,
            0,
        ]),
    );

    let outcome = dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            request,
            &mut memory,
            &reporter,
        )
        .expect("mmap dispatch should succeed");

    let DispatchOutcome::MapHostAlias {
        va: mapped_va,
        len: mapped_len,
        payload,
        backing,
        ..
    } = outcome
    else {
        panic!("expected protected high advisory hint to map an alias, got {outcome:?}");
    };
    assert_eq!(mapped_va, GuestVa(va));
    assert_eq!(mapped_len, len);
    assert!(payload.is_empty());
    assert!(!backing.is_file());
    assert_eq!(
        dispatcher.next_mmap_address(0, LINUX_PAGE_SIZE, 0, 0, MmapGrantCongruence::Any),
        Some((LINUX_MMAP_BASE, false)),
        "alias-window advisory aliases must not consume the low mmap arena"
    );
}

#[test]
fn lazy_high_va_commit_preserves_shared_reservation_provenance() {
    const SYS_MPROTECT: u64 = 226;
    let address = crate::memory::LINUX_HIGH_VA_THRESHOLD;
    let mut dispatcher = SyscallDispatcher::new();
    // HVPatch advertises complete VMA metadata even though a PROT_NONE
    // high-VA reservation deliberately has no alias backing yet. Model that
    // exact split: metadata is complete, while the only readable backing is
    // the unrelated low mmap arena.
    let mut memory = ProtectionTrackingMemory::new(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize);
    let reporter = CompatReporter::default();

    // Model the original high-VA MAP_SHARED|MAP_ANONYMOUS|PROT_NONE
    // reservation. Its backing is absent until mprotect commits it, but
    // its VMA sharing classification is already authoritative.
    dispatcher.record_dynamic_mapping(
        address,
        LINUX_PAGE_SIZE,
        LinuxProtFlags::empty(),
        ProcMapSharing::Shared,
        String::new(),
    );
    let outcome = dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(
                SYS_MPROTECT,
                SyscallArgs([
                    address,
                    LINUX_PAGE_SIZE,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    0,
                    0,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
        )
        .expect("mprotect dispatch should complete");

    let DispatchOutcome::MapHostAlias {
        success_retval,
        backing,
        transaction,
        ..
    } = outcome
    else {
        panic!("shared high-VA reservation must commit through MapHostAlias: {outcome:?}");
    };
    assert_eq!(
        success_retval, 0,
        "mprotect must return success, not an address"
    );
    assert!(
        backing.is_shared(),
        "lazy commit must retain MAP_SHARED provenance"
    );
    assert!(
        !dispatcher.range_has_host_alias_backing(address, LINUX_PAGE_SIZE),
        "dispatch alone must not predict backend publication"
    );
    transaction
        .with_claim_for_test(|install| {
            dispatcher
                .commit_host_alias_install(install)
                .expect("publish successful lazy host-alias install");
        })
        .expect("claim lazy host-alias install");
    assert!(dispatcher.range_has_host_alias_backing(address, LINUX_PAGE_SIZE));
}

#[test]
fn committed_low_vma_can_materialize_before_raw_backing_exists() {
    const SYS_MPROTECT: u64 = 226;
    let address = LINUX_MMAP_BASE + 0x20_0000;
    let mut dispatcher = SyscallDispatcher::new();
    // Model HVPatch's sparse low arena: the kernel VMA is committed, while
    // the backend raw read correctly fails until protect_range performs the
    // demand materialization.
    dispatcher.record_dynamic_mapping(
        address,
        LINUX_PAGE_SIZE,
        LinuxProtFlags::empty(),
        ProcMapSharing::Private,
        String::new(),
    );
    let mut memory = CountingMmapMemory::new(LINUX_HEAP_BASE, LINUX_PAGE_SIZE as usize);
    let reporter = CompatReporter::default();

    let outcome = dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(
                SYS_MPROTECT,
                SyscallArgs([
                    address,
                    LINUX_PAGE_SIZE,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    0,
                    0,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
        )
        .expect("mprotect dispatch");

    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
    assert_eq!(
        memory.protect_calls.get(),
        1,
        "committed VMA authority must reach sparse backend materialization"
    );
}

#[test]
fn shared_anonymous_high_advisory_hint_is_selected_then_committed_lazily() {
    const SYS_MMAP: u64 = 222;
    const SYS_MPROTECT: u64 = 226;
    let address = 0x1382_8ed0_0000;
    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = ProtectionTrackingMemory::new(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize);
    let reporter = CompatReporter::default();
    let context = dispatcher.capture_one_task_context().unwrap();

    let reserve = dispatcher
        .dispatch(
            &context,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    address,
                    LINUX_PAGE_SIZE,
                    0,
                    LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
        )
        .expect("high advisory reservation");
    assert_eq!(
        reserve,
        DispatchOutcome::Returned {
            value: address as i64
        }
    );

    let commit = dispatcher
        .dispatch(
            &context,
            SyscallRequest::new(
                SYS_MPROTECT,
                SyscallArgs([
                    address,
                    LINUX_PAGE_SIZE,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    0,
                    0,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
        )
        .expect("lazy high advisory commit");
    let DispatchOutcome::MapHostAlias { va, backing, .. } = commit else {
        panic!("shared high advisory hint must commit through a host alias: {commit:?}");
    };
    assert_eq!(va, GuestVa(address));
    assert!(backing.is_shared());
}

/// The `mmap` handler must not be able to hand the guest a `MAP_FAILED` it
/// cannot explain.
///
/// Ten CPython suites produced zero assertions for as long as CPython had been
/// run on the HVPatch lane, because a `dlopen` segment mapping was refused with
/// `ENOMEM` and carrick logged nothing at all — glibc renders every such
/// failure as the same opaque "failed to map segment from shared object".
/// Every error return in the handler now goes through
/// [`MmapRequest::refused`], which names the refusal. This test is the
/// mechanical guard on that: a new branch reaching for a bare
/// `DispatchOutcome::errno` reintroduces the diagnostic hole and fails here,
/// rather than months later inside a workload.
#[test]
fn every_mmap_refusal_names_itself() {
    const SOURCE: &str = include_str!("../mem.rs");
    let start = SOURCE
        .find("fn mmap(this, cx, requested: GuestPtr,")
        .expect("mmap handler header");
    let end = SOURCE
        .find("fn munmap(this, cx, address: GuestPtr,")
        .expect("munmap handler header");
    let body = &SOURCE[start..end];
    assert!(
        !body.contains("DispatchOutcome::errno("),
        "the mmap handler contains a bare DispatchOutcome::errno; every refusal \
         must go through MmapRequest::refused/refused_by so it names itself"
    );
    assert!(
        body.contains("request.refused("),
        "the mmap handler no longer routes refusals through MmapRequest::refused"
    );
}

/// A core is a Linux artifact: it may only contain VMAs the guest itself can
/// see. Carrick's kernel hole is `AP=00` (EL1-only) — the EL0 trampoline, the
/// EL1 vectors, the stage-1 page tables, the maintenance trampoline, the
/// per-process identity page and the syscall mailbox arena — so Linux has no
/// such VMA and neither may the core.
///
/// This is not cosmetic. The identity page at `LINUX_IDENTITY_PAGE_BASE` has a
/// live stage-1 leaf pointing into a reusable global frame that the host-side
/// guest-memory reader cannot authenticate, so dumping it failed the WHOLE
/// core closed with `live core read has no current backing:
/// va=0x2d001e4000` — observed on `ltp-mmap18` and `ltp-munmap04`.
#[test]
fn core_maps_exclude_carricks_el1_only_kernel_hole() {
    let mut mem = MemState::new();
    let kernel_hole = |start: u64, size: u64| ProcMapsEntry {
        start,
        end: start + size,
        read: true,
        write: true,
        execute: false,
        sharing: crate::vfs::ProcMapSharing::Private,
        path: String::new(),
    };
    let guest_text = ProcMapsEntry {
        start: 0x1_0000_0000,
        end: 0x1_0001_0000,
        read: true,
        write: false,
        execute: true,
        sharing: crate::vfs::ProcMapSharing::Private,
        path: String::new(),
    };
    mem.address_space_regions = Some(vec![
        guest_text.clone(),
        kernel_hole(crate::memory::LINUX_EL0_TRAMPOLINE_BASE, 0x4000),
        kernel_hole(crate::memory::LINUX_EL1_VECTORS_BASE, 0x4000),
        kernel_hole(
            crate::memory::LINUX_PAGE_TABLES_BASE,
            crate::memory::LINUX_PAGE_TABLES_SIZE,
        ),
        kernel_hole(
            crate::memory::LINUX_IDENTITY_PAGE_BASE,
            crate::memory::LINUX_IDENTITY_PAGE_SIZE,
        ),
        kernel_hole(
            crate::memory::LINUX_SYSCALL_MAILBOX_BASE,
            crate::memory::LINUX_SYSCALL_MAILBOX_ARENA_SIZE,
        ),
    ]);

    let maps = project_core_maps(&mem);
    assert_eq!(
        maps.iter().map(|map| map.start).collect::<Vec<_>>(),
        vec![guest_text.start],
        "only the guest's own VMA belongs in a core"
    );
}

/// The guest-visible neighbours of the kernel hole must NOT be swept up with
/// it: the vvar/vDSO pair and the rt_sigreturn trampoline are mapped for EL0
/// and a real Linux core carries their equivalents.
#[test]
fn core_maps_keep_guest_visible_neighbours_of_the_kernel_hole() {
    let mut mem = MemState::new();
    let region = |start: u64, size: u64| ProcMapsEntry {
        start,
        end: start + size,
        read: true,
        write: false,
        execute: true,
        sharing: crate::vfs::ProcMapSharing::Private,
        path: String::new(),
    };
    mem.address_space_regions = Some(vec![
        region(crate::memory::LINUX_SIGRETURN_TRAMPOLINE_BASE, 0x4000),
        region(
            crate::memory::LINUX_KERNEL_REGION_BASE + crate::memory::LINUX_KERNEL_REGION_SIZE,
            0x1000,
        ),
        region(crate::memory::LINUX_KERNEL_REGION_BASE - 0x10000, 0x1000),
    ]);

    let maps = project_core_maps(&mem);
    assert_eq!(maps.len(), 3, "nothing outside the kernel hole is dropped");
}

fn test_semantic_vma(
    start: u64,
    end: u64,
    fork_policy: carrick_abi::VmaForkPolicy,
    droppable: bool,
) -> SemanticVma {
    SemanticVma {
        start,
        end,
        read: true,
        write: true,
        execute: false,
        provenance: VmaBackingProvenance::PrivateAnonymous,
        fork_policy,
        dump_policy: carrick_abi::VmaDumpPolicy::Include,
        droppable,
        path: "[mremap-policy]".to_owned(),
        file_page_offset: None,
    }
}

fn dontfork_policy() -> carrick_abi::VmaForkPolicy {
    carrick_abi::VmaForkPolicy {
        copy: carrick_abi::VmaForkCopyPolicy::Omit,
        child_contents: carrick_abi::VmaForkChildPolicy::Preserve,
    }
}

fn wipeonfork_policy() -> carrick_abi::VmaForkPolicy {
    carrick_abi::VmaForkPolicy {
        copy: carrick_abi::VmaForkCopyPolicy::Inherit,
        child_contents: carrick_abi::VmaForkChildPolicy::ZeroInChild,
    }
}

#[test]
fn mremap_fork_semantics_preserve_splits_across_move_and_grow() {
    let source = [
        test_semantic_vma(0x1000, 0x2000, carrick_abi::VmaForkPolicy::DEFAULT, false),
        test_semantic_vma(0x2000, 0x3000, dontfork_policy(), true),
        test_semantic_vma(0x3000, 0x5000, wipeonfork_policy(), false),
    ];
    let semantics =
        MremapForkSemantics::capture(&source, 0x1000, 0x4000).expect("source is totally covered");

    let moved = semantics
        .project(0x9000, 0x6000)
        .expect("move and grow are representable");
    assert_eq!(
        moved
            .iter()
            .map(|vma| (vma.start, vma.end, vma.fork_policy, vma.droppable))
            .collect::<Vec<_>>(),
        vec![
            (0x9000, 0xa000, carrick_abi::VmaForkPolicy::DEFAULT, false),
            (0xa000, 0xb000, dontfork_policy(), true),
            (0xb000, 0xf000, wipeonfork_policy(), false),
        ]
    );
}

#[test]
fn mremap_fork_semantics_preserve_splits_across_shrink() {
    let source = [
        test_semantic_vma(0x1000, 0x3000, dontfork_policy(), true),
        test_semantic_vma(0x3000, 0x5000, wipeonfork_policy(), false),
    ];
    let semantics =
        MremapForkSemantics::capture(&source, 0x1000, 0x4000).expect("source is totally covered");

    let shrunk = semantics
        .project(0x1000, 0x3000)
        .expect("shrink is representable");
    assert_eq!(
        shrunk
            .iter()
            .map(|vma| (vma.start, vma.end, vma.fork_policy, vma.droppable))
            .collect::<Vec<_>>(),
        vec![
            (0x1000, 0x3000, dontfork_policy(), true),
            (0x3000, 0x4000, wipeonfork_policy(), false),
        ]
    );
}

#[test]
fn host_alias_map_droppable_reaches_keeponfork_rejection_metadata() {
    let dispatcher = SyscallDispatcher::new();
    dispatcher.commit_host_alias_mmap(HostAliasMmapCommit {
        start: 0x9000,
        len: 0x1000,
        prot: LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        sharing: ProcMapSharing::Private,
        path: String::new(),
        file_page_offset: None,
        droppable: true,
        semantic_vmas: None,
        locked: None,
        resident: false,
        bus_fault: None,
        write_sealed_shared: false,
        read_only_shared_file: false,
        secretmem: false,
        writable_memfd: None,
        shared_file_alias: None,
    });

    let metadata = dispatcher.madvise_range_meta(0x9000, 0xa000);
    assert!(metadata.fully_mapped);
    assert!(metadata.any_droppable);
}

/// madvise(2) walks the VMAs it visits and reports a per-VMA rejection
/// (EINVAL) ahead of the unmapped-hole ENOMEM: LTP `madvise02` maps ONE
/// shared-anonymous page and advises 16 pages `MADV_WIPEONFORK`, expecting
/// EINVAL because the visited VMA is not private anonymous — carrick answered
/// ENOMEM for the hole first. The hole still wins when every visited VMA
/// accepts the advice (the private-anonymous twin).
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

/// `RLIMIT_DATA` (proc(5) `VmData`) charges the brk heap and private
/// writable mappings only; `RLIMIT_AS` charges the union of every VMA.
#[test]
fn data_va_bytes_counts_only_private_writable_mappings_and_the_heap() {
    let mut mem = MemState::new();
    let entry = |start: u64, end: u64, write: bool, sharing: ProcMapSharing| ProcMapsEntry {
        start,
        end,
        read: true,
        write,
        execute: false,
        sharing,
        path: String::new(),
    };
    mem.dynamic_maps.push(entry(
        LINUX_MMAP_BASE,
        LINUX_MMAP_BASE + 3 * LINUX_PAGE_SIZE,
        true,
        ProcMapSharing::Private,
    ));
    mem.dynamic_maps.push(entry(
        LINUX_MMAP_BASE + 0x10_0000,
        LINUX_MMAP_BASE + 0x10_0000 + LINUX_PAGE_SIZE,
        true,
        ProcMapSharing::Shared,
    ));
    mem.dynamic_maps.push(entry(
        LINUX_MMAP_BASE + 0x20_0000,
        LINUX_MMAP_BASE + 0x20_0000 + LINUX_PAGE_SIZE,
        false,
        ProcMapSharing::Private,
    ));
    mem.brk_current = mem.layout.heap_base + 2 * LINUX_PAGE_SIZE;

    assert_eq!(data_va_bytes(&mem), 5 * LINUX_PAGE_SIZE);
    assert_eq!(committed_va_bytes(&mem), 7 * LINUX_PAGE_SIZE);
    assert_eq!(
        mapped_overlap_bytes(&mem, LINUX_MMAP_BASE + LINUX_PAGE_SIZE, 4 * LINUX_PAGE_SIZE),
        2 * LINUX_PAGE_SIZE
    );
}

/// `mmap` past the `RLIMIT_AS` soft limit is ENOMEM before any allocator or
/// VMA mutation: the arena cursor must not move.
#[test]
fn mmap_refuses_growth_past_rlimit_as_with_enomem() {
    const SYS_MMAP: u64 = 222;
    let mut dispatcher = SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().unwrap();
    let baseline = committed_va_bytes(&dispatcher.mem().lock());
    context
        .task()
        .replace_rlimit(carrick_abi::LinuxResource::As, |_| {
            Ok::<_, std::convert::Infallible>(carrick_abi::LinuxRlimit::new(
                baseline + 2 * LINUX_PAGE_SIZE,
                LINUX_RLIM_INFINITY,
            ))
        })
        .expect("set RLIMIT_AS");
    let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, (4 * LINUX_PAGE_SIZE) as usize);
    let reporter = CompatReporter::default();
    let map = |len: u64| {
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                len,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        )
    };

    let first = dispatcher
        .dispatch(&context, map(2 * LINUX_PAGE_SIZE), &mut memory, &reporter)
        .expect("mmap dispatch");
    assert_eq!(returned(first), LINUX_MMAP_BASE as i64);

    let cursor = dispatcher.mem().lock().mmap_next;
    let second = dispatcher
        .dispatch(&context, map(LINUX_PAGE_SIZE), &mut memory, &reporter)
        .expect("mmap dispatch");
    assert_eq!(second, DispatchOutcome::errno(LINUX_ENOMEM));
    assert_eq!(dispatcher.mem().lock().mmap_next, cursor);
}

/// `brk` past the `RLIMIT_DATA` soft limit reports ENOMEM the way Linux does:
/// by returning the UNCHANGED break.
#[test]
fn brk_growth_past_rlimit_data_returns_the_unchanged_break() {
    const SYS_BRK: u64 = 214;
    let mut dispatcher = SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().unwrap();
    let initial = dispatcher.mem().lock().layout.heap_base;
    let data_now = data_va_bytes(&dispatcher.mem().lock());
    context
        .task()
        .replace_rlimit(carrick_abi::LinuxResource::Data, |_| {
            Ok::<_, std::convert::Infallible>(carrick_abi::LinuxRlimit::new(
                data_now + LINUX_PAGE_SIZE,
                LINUX_RLIM_INFINITY,
            ))
        })
        .expect("set RLIMIT_DATA");
    let mut memory = CountingMmapMemory::new(initial, (2 * LINUX_PAGE_SIZE) as usize);
    let reporter = CompatReporter::default();
    let grow = |to: u64| SyscallRequest::new(SYS_BRK, SyscallArgs([to, 0, 0, 0, 0, 0]));

    let one = dispatcher
        .dispatch(
            &context,
            grow(initial + LINUX_PAGE_SIZE),
            &mut memory,
            &reporter,
        )
        .expect("brk dispatch");
    assert_eq!(returned(one), (initial + LINUX_PAGE_SIZE) as i64);

    let two = dispatcher
        .dispatch(
            &context,
            grow(initial + 2 * LINUX_PAGE_SIZE),
            &mut memory,
            &reporter,
        )
        .expect("brk dispatch");
    assert_eq!(
        returned(two),
        (initial + LINUX_PAGE_SIZE) as i64,
        "brk past RLIMIT_DATA must report the unchanged break"
    );
    assert_eq!(
        dispatcher.mem().lock().brk_current,
        initial + LINUX_PAGE_SIZE
    );
}

/// When `RLIMIT_AS` and `RLIMIT_DATA` are infinite (carrick defaults),
/// `address_space_limits_apply` returns `None` lock-free, and
/// `check_address_space_limits` bypasses `MemState` locking and VMA projection entirely.
#[test]
fn disabled_rlimits_bypass_vma_projection_and_locks() {
    let dispatcher = SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().unwrap();

    // Default state: both limits are infinite.
    assert_eq!(dispatcher.address_space_limits_apply(false), None);
    assert_eq!(dispatcher.address_space_limits_apply(true), None);

    // With no limit applying, production skips the locked check entirely —
    // that `None` IS the disabled path. When a limit does apply, the locked
    // check is what runs, so exercise the real pair rather than a wrapper
    // that only a test would call.

    // Set RLIMIT_AS: now limits apply to both data and non-data mappings.
    context
        .task()
        .replace_rlimit(carrick_abi::LinuxResource::As, |_| {
            Ok::<_, std::convert::Infallible>(carrick_abi::LinuxRlimit::new(
                512 * 1024 * 1024,
                LINUX_RLIM_INFINITY,
            ))
        })
        .expect("set RLIMIT_AS");
    assert_eq!(
        dispatcher.address_space_limits_apply(false),
        Some((512 * 1024 * 1024, LINUX_RLIM_INFINITY))
    );
    assert_eq!(
        dispatcher.address_space_limits_apply(true),
        Some((512 * 1024 * 1024, LINUX_RLIM_INFINITY))
    );

    // Reset RLIMIT_AS to infinite, set RLIMIT_DATA: applies to data mappings only.
    context
        .task()
        .replace_rlimit(carrick_abi::LinuxResource::As, |_| {
            Ok::<_, std::convert::Infallible>(carrick_abi::LinuxRlimit::new(
                LINUX_RLIM_INFINITY,
                LINUX_RLIM_INFINITY,
            ))
        })
        .expect("reset RLIMIT_AS");
    context
        .task()
        .replace_rlimit(carrick_abi::LinuxResource::Data, |_| {
            Ok::<_, std::convert::Infallible>(carrick_abi::LinuxRlimit::new(
                64 * 1024 * 1024,
                LINUX_RLIM_INFINITY,
            ))
        })
        .expect("set RLIMIT_DATA");
    assert_eq!(dispatcher.address_space_limits_apply(false), None);
    assert_eq!(
        dispatcher.address_space_limits_apply(true),
        Some((LINUX_RLIM_INFINITY, 64 * 1024 * 1024))
    );
}

#[test]
fn shared_file_fixed_mremap_moves_page_and_preserves_file_offset() {
    const SYS_MREMAP: u64 = 216;
    const MREMAP_MAYMOVE: u64 = 0x01;
    const MREMAP_FIXED: u64 = 0x02;
    const PAGE: u64 = LINUX_PAGE_SIZE;
    let base = crate::memory::LINUX_HIGH_VA_THRESHOLD;

    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1080));
    let reporter = CompatReporter::default();
    let mut memory = ProtectionTrackingMemory::new(base, (4 * PAGE) as usize);

    use std::os::fd::{AsRawFd, IntoRawFd};

    let host_file = tempfile::tempfile().expect("create tempfile");
    let raw_fd = host_file.as_raw_fd();
    unsafe {
        assert_eq!(libc::ftruncate(raw_fd, (4 * PAGE) as libc::off_t), 0);
        for i in 0..4 {
            let page_data = vec![0x10 + i as u8; PAGE as usize];
            assert_eq!(
                libc::pwrite(
                    raw_fd,
                    page_data.as_ptr().cast(),
                    PAGE as usize,
                    (i * PAGE) as libc::off_t,
                ),
                PAGE as isize,
            );
        }
    }
    for i in 0..4 {
        memory.inner.bytes[(i * PAGE as usize)..((i + 1) * PAGE as usize)].fill(0x10 + i as u8);
    }
    let metadata = RootFsMetadata {
        path: std::path::PathBuf::from("/tmp/test_shared_fixed.dat"),
        kind: RootFsEntryKind::File,
        mode: 0o644,
        size: (4 * PAGE) as usize,
    };
    let open_desc = std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::HostFile {
        base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDWR),
        host_fd: HostFdRef::new(host_file.into_raw_fd()),
        metadata,
        writable: true,
    }));
    let description = OpenFile::from_open_description_with_status_flags(
        open_desc,
        crate::linux_abi::LINUX_O_RDWR,
        0,
    )
    .description();

    dispatcher.commit_host_alias_mmap(HostAliasMmapCommit {
        start: base,
        len: 4 * PAGE,
        prot: LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        sharing: ProcMapSharing::Shared,
        path: "/tmp/test_shared_fixed.dat".into(),
        file_page_offset: Some(0),
        droppable: false,
        semantic_vmas: None,
        locked: None,
        resident: true,
        bus_fault: None,
        write_sealed_shared: false,
        read_only_shared_file: false,
        secretmem: false,
        writable_memfd: None,
        shared_file_alias: Some(SharedFileAliasCommit {
            description: Arc::clone(&description),
            extent_base: carrick_guest_mem::Gpa(base),
            row_file_offset: 0,
        }),
    });
    memory.active_aliases.push((base, base, 4 * PAGE as usize));

    let src = base + PAGE;
    let dst = base + 3 * PAGE;

    // Move page 1 to page 3.
    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MREMAP,
            SyscallArgs([src, PAGE, PAGE, MREMAP_MAYMOVE | MREMAP_FIXED, dst, 0]),
        ),
    );

    assert_eq!(outcome, DispatchOutcome::Returned { value: dst as i64 });
    assert_eq!(
        memory.repointed_shared_leaves,
        vec![(dst, base + PAGE, PAGE as usize)]
    );
    assert!(
        memory.unmapped_alias_ranges.contains(&(src, PAGE as usize)),
        "source range must be unmapped via unmap_alias_range"
    );

    // Verify reading dst sees page 1's content.
    assert_eq!(memory.read_bytes(dst, 1).unwrap(), vec![0x11]);

    // Write through dst and verify writeback to file at page 1's offset.
    memory.write_bytes(dst, &[0x77]).unwrap();
    {
        let mem_authority = dispatcher.mem();
        let mem = mem_authority.lock();
        let alias = mem
            .shared_file_alias_maps
            .iter()
            .find(|entry| entry.range.start().raw() == dst)
            .expect("dst shared file alias map entry");
        assert_eq!(alias.row_file_offset, PAGE);
        assert_eq!(alias.extent_base, carrick_guest_mem::Gpa(base));
    }
    let dirty = memory.read_bytes(dst, 1).unwrap();
    assert_eq!(dirty[0], 0x77);
    unsafe {
        assert_eq!(
            libc::pwrite(raw_fd, dirty.as_ptr().cast(), 1, PAGE as libc::off_t),
            1
        );
    }
    let mut b = [0u8; 1];
    unsafe {
        assert_eq!(
            libc::pread(raw_fd, b.as_mut_ptr().cast(), 1, PAGE as libc::off_t),
            1
        );
    }
    assert_eq!(b[0], 0x77);

    // Verify metadata after move:
    // Destination dst has file_page_offset == Some(1).
    // Source src is unmapped.
    {
        let mem_authority = dispatcher.mem();
        let mem = mem_authority.lock();
        let dst_mapping = mem
            .core_file_mappings
            .iter()
            .find(|m| m.start == dst && m.end == dst + PAGE)
            .expect("dst core file entry");
        assert_eq!(dst_mapping.file_page_offset, 1);

        assert!(
            !mem.core_file_mappings
                .iter()
                .any(|m| m.start < src + PAGE && m.end > src),
            "source range must be unmapped from core_file_mappings"
        );
        assert!(
            !mem.shared_file_alias_maps.iter().any(
                |entry| entry.range.start().raw() < src + PAGE && entry.range.end().raw() > src
            ),
            "source range must be unmapped from shared_file_alias_maps"
        );
    }

    // Reverse move: move page from dst back to src.
    let back_outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MREMAP,
            SyscallArgs([dst, PAGE, PAGE, MREMAP_MAYMOVE | MREMAP_FIXED, src, 0]),
        ),
    );

    assert_eq!(
        back_outcome,
        DispatchOutcome::Returned { value: src as i64 }
    );
    assert_eq!(
        memory.repointed_shared_leaves,
        vec![
            (dst, base + PAGE, PAGE as usize),
            (src, base + PAGE, PAGE as usize),
        ]
    );
    assert!(
        memory.unmapped_alias_ranges.contains(&(dst, PAGE as usize)),
        "destination range must be unmapped via unmap_alias_range on reverse move"
    );

    // Verify reading src after reverse move sees 0x77.
    assert_eq!(memory.read_bytes(src, 1).unwrap(), vec![0x77]);

    {
        let mem_authority = dispatcher.mem();
        let mem = mem_authority.lock();
        let src_mapping = mem
            .core_file_mappings
            .iter()
            .find(|m| m.start == src && m.end == src + PAGE)
            .expect("src core file entry");
        assert_eq!(src_mapping.file_page_offset, 1);
    }
}

#[test]
fn shared_file_fixed_mremap_repoint_failure_lowers_to_enomem() {
    const SYS_MREMAP: u64 = 216;
    const MREMAP_MAYMOVE: u64 = 0x01;
    const MREMAP_FIXED: u64 = 0x02;
    const PAGE: u64 = LINUX_PAGE_SIZE;
    let base = crate::memory::LINUX_HIGH_VA_THRESHOLD;

    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1082));
    let reporter = CompatReporter::default();
    let mut memory = ProtectionTrackingMemory::new(base, (4 * PAGE) as usize);
    memory.fail_repoint = true;

    use std::os::fd::IntoRawFd;

    let host_file = tempfile::tempfile().expect("create tempfile");
    let metadata = RootFsMetadata {
        path: std::path::PathBuf::from("/tmp/test_shared_fixed_fail.dat"),
        kind: RootFsEntryKind::File,
        mode: 0o644,
        size: (4 * PAGE) as usize,
    };
    let open_desc = std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::HostFile {
        base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDWR),
        host_fd: HostFdRef::new(host_file.into_raw_fd()),
        metadata,
        writable: true,
    }));
    let description = OpenFile::from_open_description_with_status_flags(
        open_desc,
        crate::linux_abi::LINUX_O_RDWR,
        0,
    )
    .description();

    dispatcher.commit_host_alias_mmap(HostAliasMmapCommit {
        start: base,
        len: 4 * PAGE,
        prot: LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        sharing: ProcMapSharing::Shared,
        path: "/tmp/test_shared_fixed_fail.dat".into(),
        file_page_offset: Some(0),
        droppable: false,
        semantic_vmas: None,
        locked: None,
        resident: true,
        bus_fault: None,
        write_sealed_shared: false,
        read_only_shared_file: false,
        secretmem: false,
        writable_memfd: None,
        shared_file_alias: Some(SharedFileAliasCommit {
            description: Arc::clone(&description),
            extent_base: carrick_guest_mem::Gpa(base),
            row_file_offset: 0,
        }),
    });
    memory.active_aliases.push((base, base, 4 * PAGE as usize));

    let src = base + PAGE;
    let dst = base + 3 * PAGE;

    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MREMAP,
            SyscallArgs([src, PAGE, PAGE, MREMAP_MAYMOVE | MREMAP_FIXED, dst, 0]),
        ),
    );

    assert_eq!(outcome, DispatchOutcome::errno(LINUX_ENOMEM));
}

#[test]
fn shared_file_fixed_mremap_rejects_missing_maymove_or_overlapping_ranges() {
    const SYS_MREMAP: u64 = 216;
    const MREMAP_MAYMOVE: u64 = 0x01;
    const MREMAP_FIXED: u64 = 0x02;
    const PAGE: u64 = LINUX_PAGE_SIZE;
    let base = crate::memory::LINUX_HIGH_VA_THRESHOLD;

    let dispatcher = SyscallDispatcher::new();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1081));
    let reporter = CompatReporter::default();
    let mut memory = ProtectionTrackingMemory::new(base, (4 * PAGE) as usize);

    use std::os::fd::IntoRawFd;

    let host_file = tempfile::tempfile().expect("create tempfile");
    let metadata = RootFsMetadata {
        path: std::path::PathBuf::from("/tmp/test_shared_fixed_err.dat"),
        kind: RootFsEntryKind::File,
        mode: 0o644,
        size: (4 * PAGE) as usize,
    };
    let open_desc = std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::HostFile {
        base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDWR),
        host_fd: HostFdRef::new(host_file.into_raw_fd()),
        metadata,
        writable: true,
    }));
    let description = OpenFile::from_open_description_with_status_flags(
        open_desc,
        crate::linux_abi::LINUX_O_RDWR,
        0,
    )
    .description();

    dispatcher.commit_host_alias_mmap(HostAliasMmapCommit {
        start: base,
        len: 4 * PAGE,
        prot: LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        sharing: ProcMapSharing::Shared,
        path: "/tmp/test_shared_fixed_err.dat".into(),
        file_page_offset: Some(0),
        droppable: false,
        semantic_vmas: None,
        locked: None,
        resident: true,
        bus_fault: None,
        write_sealed_shared: false,
        read_only_shared_file: false,
        secretmem: false,
        writable_memfd: None,
        shared_file_alias: Some(SharedFileAliasCommit {
            description: Arc::clone(&description),
            extent_base: carrick_guest_mem::Gpa(base),
            row_file_offset: 0,
        }),
    });

    let src = base + PAGE;
    let dst = base + 3 * PAGE;

    // MREMAP_FIXED without MREMAP_MAYMOVE returns EINVAL.
    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MREMAP,
            SyscallArgs([src, PAGE, PAGE, MREMAP_FIXED, dst, 0]),
        ),
    );
    assert_eq!(outcome, DispatchOutcome::errno(LINUX_EINVAL));

    // Overlapping ranges return EINVAL.
    let outcome_overlap = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MREMAP,
            SyscallArgs([
                src,
                2 * PAGE,
                PAGE,
                MREMAP_MAYMOVE | MREMAP_FIXED,
                src + PAGE,
                0,
            ]),
        ),
    );
    assert_eq!(outcome_overlap, DispatchOutcome::errno(LINUX_EINVAL));
}
