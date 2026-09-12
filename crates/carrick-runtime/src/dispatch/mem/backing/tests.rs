use super::super::tests::{
    CountingMmapMemory, ProtectionTrackingMemory, install_host_file_fd,
    install_host_file_fd_with_source, native16k_dispatcher, returned, threaded_memory_call,
};
use super::*;
use crate::compat::CompatReporter;
use crate::dispatch::OpenFile;
use crate::dispatch::SyscallDispatcher;
use crate::dispatch::fd_table::kernel_file_description;
use crate::dispatch::host_alias::HostAliasCommit;
use crate::dispatch::outcome::DispatchOutcome;
use crate::dispatch::outcome::LinearMemory;
use crate::dispatch::{OpenDescription, OpenDescriptionBase};
use crate::dispatch::{SyscallArgs, SyscallRequest};
use crate::memory::{LINUX_HEAP_BASE, LINUX_MMAP_BASE};
use crate::rootfs::{RootFsEntryKind, RootFsMetadata};
use carrick_abi::LINUX_PAGE_SIZE;
use carrick_guest_mem::{Gpa, GuestVa};
use carrick_hal::trap::{HostAliasBacking, HostAliasOwnedFd, HostAliasSharing};
use std::cell::Cell;
use std::os::fd::FromRawFd;

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

fn assert_operation_waits_for_host_alias_idle<F>(label: &'static str, operation: F)
where
    F: FnOnce(std::sync::Arc<SyscallDispatcher>) + Send + 'static,
{
    let dispatcher = std::sync::Arc::new(SyscallDispatcher::new());
    let transaction = dispatcher.with_host_alias_dispatch_for_test(|guard| {
        guard
            .publish(HostAliasCommit::mmap(HostAliasMmapCommit {
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
                private_file: None,
                shared_file_alias: None,
            }))
            .expect("publish")
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

/// Mock backend for the Move-3 E1 lowering: records every
/// `map_private_file_backed` offer and answers with a configured verdict,
/// so the dispatch-side eligibility and fallback are testable without a
/// real identity host mapping.
struct FileBackedLoweringMemory {
    inner: CountingMmapMemory,
    accept: bool,
    defer: bool,
    offers: std::cell::RefCell<Vec<(u64, usize, u64)>>,
    deferred_offers:
        std::cell::RefCell<Vec<(u64, usize, u64, carrick_guest_mem::PrivateFileSource)>>,
}

impl FileBackedLoweringMemory {
    fn new(base: u64, len: usize, accept: bool) -> Self {
        Self {
            inner: CountingMmapMemory::new(base, len),
            accept,
            defer: false,
            offers: std::cell::RefCell::new(Vec::new()),
            deferred_offers: std::cell::RefCell::new(Vec::new()),
        }
    }

    fn deferred(mut self) -> Self {
        self.defer = true;
        self
    }
}

impl GuestMemory for FileBackedLoweringMemory {
    fn supports_lazy_private_file_mmap(&self) -> bool {
        self.defer
    }

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
        _source: carrick_guest_mem::PrivateFileSource,
    ) -> Result<bool, MemoryError> {
        self.offers.borrow_mut().push((address, len, offset));
        Ok(self.accept)
    }

    fn defer_private_file_backed(
        &mut self,
        address: u64,
        len: usize,
        _host_fd: std::os::fd::BorrowedFd<'_>,
        offset: u64,
        source: carrick_guest_mem::PrivateFileSource,
    ) -> Result<bool, MemoryError> {
        self.deferred_offers
            .borrow_mut()
            .push((address, len, offset, source));
        Ok(self.accept)
    }
}

impl CurrentMmMemory for FileBackedLoweringMemory {}

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
fn mmap_private_hostfile_lazy_backend_does_not_publish_backing_at_map_time() {
    const SYS_MMAP: u64 = 222;
    const PAGE_SIZE: u64 = 4096;
    const LENGTH: u64 = 2 * PAGE_SIZE;

    let dispatcher = SyscallDispatcher::new();
    install_host_file_fd_with_source(
        &dispatcher,
        35,
        &vec![0x63; LENGTH as usize],
        carrick_guest_mem::PrivateFileSource::ImmutableLower,
    );
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1305));
    let reporter = CompatReporter::default();
    let mut memory =
        FileBackedLoweringMemory::new(LINUX_MMAP_BASE, 4 * LENGTH as usize, true).deferred();
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
                35,
                0,
            ]),
        ),
    );
    let DispatchOutcome::Returned { value } = outcome else {
        panic!("lazy private host-file mmap must succeed, got {outcome:?}");
    };
    let address = value as u64;
    assert!(
        memory.offers.borrow().is_empty(),
        "mmap must retain the file recipe without invoking backing publication"
    );
    assert_eq!(
        memory.deferred_offers.borrow().as_slice(),
        &[(
            address,
            LENGTH as usize,
            0,
            carrick_guest_mem::PrivateFileSource::ImmutableLower,
        )],
        "mmap must retain exactly one deferred file recipe"
    );
    assert_eq!(
        memory.inner.protect_log.borrow().as_slice(),
        &[(address, LENGTH as usize, 0)],
        "mmap must leave the semantic file view stage-1-invalid until first access"
    );
    assert!(
        dispatcher
            .with_resident_fault_plan_for_test(address, |_| ())
            .is_some(),
        "the first permitted access needs an MM-owned fault plan"
    );
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
    // Handing an already-closed fd to an owner is an I/O-safety violation by
    // construction (production never does it; `OwnedFd`'s drop asserts
    // liveness under debug UB checks). This test wants exactly that
    // impossible state, so it keeps a clone of the description alive for the
    // life of the test binary: the owner is never dropped, the dead fd is
    // never closed twice, and the lie stays confined to this test.
    let dead_description =
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
        }));
    std::mem::forget(std::sync::Arc::clone(&dead_description));
    dispatcher.captured_file_table().write_open_files().insert(
        34,
        OpenFile::from_open_description_with_status_flags(
            dead_description,
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
fn mmap_shared_is_never_offered_the_lowering_and_exec_private_is_admitted() {
    const SYS_MMAP: u64 = 222;
    const PAGE_SIZE: u64 = 16 * 1024;

    let dispatcher = native16k_dispatcher();
    install_host_file_fd(&dispatcher, 32, &[0x11u8; 32]);
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1320));
    let reporter = CompatReporter::default();
    let mut memory = FileBackedLoweringMemory::new(LINUX_MMAP_BASE, 4 * PAGE_SIZE as usize, true);

    // MAP_SHARED file mapping legitimately publishes via the alias transaction
    // and is never offered the private lowering.
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
                crate::linux_abi::LINUX_MAP_SHARED,
                32,
                0,
            ]),
        ),
    );
    assert!(
        matches!(outcome, DispatchOutcome::MapHostAlias { .. }),
        "control mapping must still succeed, got {outcome:?}"
    );
    assert!(
        memory.offers.borrow().is_empty(),
        "shared allocation must never be offered the private lowering: {:?}",
        memory.offers.borrow()
    );
    drop(outcome);

    // Private executable allocation IS admitted and offered the lowering.
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
                LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
                crate::linux_abi::LINUX_MAP_PRIVATE,
                32,
                0,
            ]),
        ),
    );
    assert!(
        matches!(outcome, DispatchOutcome::Returned { .. }),
        "executable private allocation must succeed, got {outcome:?}"
    );
    assert_eq!(
        memory.offers.borrow().len(),
        1,
        "executable private allocation must be offered the lowering"
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

    assert_eq!(Ok(outcome), DispatchOutcome::returned_u64(source));
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
        mem.resident_fault_ranges.arm(range, LinuxProtFlags::READ);
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
        mem.resident_fault_ranges.arm(whole, LinuxProtFlags::READ);
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
        private_file: None,
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
    assert_eq!(
        mem.resident_fault_ranges
            .iter()
            .map(|fault| fault.range)
            .collect::<Vec<_>>(),
        expected_ranges
    );
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
        private_file: None,
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
        private_file: None,
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
        guard
            .publish(HostAliasCommit::mmap(HostAliasMmapCommit {
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
                private_file: None,
                shared_file_alias: None,
            }))
            .expect("publish")
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
        guard
            .publish(HostAliasCommit::mmap(HostAliasMmapCommit {
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
                private_file: None,
                shared_file_alias: None,
            }))
            .expect("publish")
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
        guard
            .publish(HostAliasCommit::mmap(HostAliasMmapCommit {
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
                private_file: None,
                shared_file_alias: None,
            }))
            .expect("publish")
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
        guard
            .publish(HostAliasCommit::mmap(HostAliasMmapCommit {
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
                private_file: None,
                shared_file_alias: None,
            }))
            .expect("publish")
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
        guard
            .publish(HostAliasCommit::mmap(HostAliasMmapCommit {
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
                private_file: None,
                shared_file_alias: None,
            }))
            .expect("publish")
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
        guard
            .publish(HostAliasCommit::mmap(HostAliasMmapCommit {
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
                private_file: None,
                shared_file_alias: None,
            }))
            .expect("publish")
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
                crate::dispatch::ThreadCtx::new(
                    registry.main_tid(),
                    &registry,
                    &crate::thread::FutexTable::new(),
                ),
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
                crate::dispatch::ThreadCtx::new(
                    registry.main_tid(),
                    &registry,
                    &crate::thread::FutexTable::new(),
                ),
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
                crate::dispatch::ThreadCtx::new(
                    registry.main_tid(),
                    &registry,
                    &crate::thread::FutexTable::new(),
                ),
            )
            .expect("mincore dispatch while alias install is pending");
    });
}
