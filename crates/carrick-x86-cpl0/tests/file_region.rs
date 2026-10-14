//! F2 storage/authority witnesses. These exercise production file-table
//! operations, not FileService or regular-file open acceptance.
#![allow(clippy::expect_used)]

use carrick_el1::personality::file_table::{
    admit_host_fd, admit_stdio, close_host_binding, dup_host_binding, fork_fd_map, retire_fd_map,
};
use carrick_el1_abi::*;
use carrick_guest_arch::{FrameGpa, GuestLen, KernelVa};
use carrick_test_support::TestEl1Region;
use core::{num::NonZeroU64, ptr::NonNull, sync::atomic::Ordering};
use std::os::fd::AsRawFd;

struct Fixture {
    registration: FileRegionRegistration,
    _storage: Box<TestEl1Region>,
}

fn binding(identity: u64) -> FileRegionBinding {
    FileRegionBinding::new(
        FileRegionId::from_carrier(NonZeroU64::new(identity).expect("issued identity")),
        KernelVa::new(X86_CPL0_REGION_BASE),
        FrameGpa::new(0x1_0000_0000),
        GuestLen::new(EL1_REGION_SIZE),
    )
    .expect("shared layout")
}

impl Fixture {
    fn new(identity: u64) -> Self {
        let mut storage = TestEl1Region::zeroed();
        let mapped = NonNull::new(storage.as_mut_ptr()).expect("aligned storage");
        // SAFETY: exclusive aligned full extent; storage remains owned here
        // until after registration drop, with no guest CPUs.
        let registration = unsafe { FileRegionRegistration::initialize(mapped, binding(identity)) }
            .expect("publication");
        Self {
            registration,
            _storage: storage,
        }
    }
    fn tables(&self) -> FileTables<'_> {
        self.registration
            .tables(self.registration.binding())
            .expect("live own region")
    }
}

#[test]
fn file_region_layout_alignment_capacity_and_extent() {
    let fixture = Fixture::new(1);
    let tables = fixture.tables();
    let base = fixture._storage.as_ptr() as usize;
    assert_eq!(
        tables.objects().as_ptr() as usize - base,
        EL1_OBJECT_TABLE_OFFSET as usize
    );
    assert_eq!(
        tables.opens().as_ptr() as usize - base,
        EL1_OPEN_FILE_TABLE_OFFSET as usize
    );
    assert_eq!(
        tables.fd_map().as_ptr() as usize - base,
        EL1_FD_MAP_OFFSET as usize
    );
    assert_eq!(
        core::ptr::from_ref(tables.names()) as usize - base,
        EL1_NAME_CACHE_OFFSET as usize
    );
    assert_eq!(tables.objects().len(), MAX_DELEGATED_FILES);
    assert_eq!(tables.opens().len(), MAX_ZONE_OPEN_FILES);
    assert_eq!(tables.fd_map().len(), FD_MAP_CAPACITY);
    for handle in [1, 16, MAX_DELEGATED_FILES as u32] {
        assert_eq!(
            tables.cache(handle).expect("bounded cache").as_ptr() as usize - base,
            EL1_CACHE_OFFSET as usize + (handle as usize - 1) * DELEGATED_FILE_MAX_SIZE as usize
        );
    }
    assert!(tables.cache(0).is_none());
    assert!(tables.cache(MAX_DELEGATED_FILES as u32 + 1).is_none());
    for (guest, physical, len) in [
        (X86_CPL0_REGION_BASE, 0x1_0000_0000, EL1_REGION_SIZE - 1),
        (X86_CPL0_REGION_BASE + 1, 0x1_0000_0000, EL1_REGION_SIZE),
        (X86_CPL0_REGION_BASE, 0x1_0000_0001, EL1_REGION_SIZE),
        (u64::MAX - 4095, 0x1_0000_0000, EL1_REGION_SIZE),
        (X86_CPL0_REGION_BASE, u64::MAX - 4095, EL1_REGION_SIZE),
    ] {
        assert_eq!(
            FileRegionBinding::new(
                FileRegionId::from_carrier(NonZeroU64::MIN),
                KernelVa::new(guest),
                FrameGpa::new(physical),
                GuestLen::new(len)
            ),
            Err(FileRegionError::Layout)
        );
    }
    let mut storage = TestEl1Region::zeroed();
    // SAFETY: deliberately misaligned pointer to otherwise retained writable
    // storage. The constructor must refuse before touching any record.
    let result = unsafe {
        FileRegionRegistration::initialize(
            NonNull::new(storage.as_mut_ptr().add(1)).expect("nonnull"),
            binding(2),
        )
    };
    assert!(matches!(result, Err(FileRegionError::Layout)));
}

#[test]
fn file_region_stdio_parity_and_closed_descriptor_stays_closed() {
    let fixture = Fixture::new(2);
    let tables = fixture.tables();
    admit_stdio(
        tables.fd_map(),
        tables.opens(),
        tables.objects(),
        51,
        [true; 3],
    );
    for (fd, expected) in [
        HostObjectBinding::STDIN,
        HostObjectBinding::STDOUT,
        HostObjectBinding::STDERR,
    ]
    .into_iter()
    .enumerate()
    {
        let (handle, _) = fd_map_lookup(tables.fd_map(), 51, fd as i32).expect("stdio");
        let open = &tables.opens()[handle as usize - 1];
        assert_eq!(open.host_object(), Some(expected));
        assert!(open.is_bound_to(&tables.objects()[handle as usize - 1]));
        assert_eq!(
            open.flags.load(Ordering::Acquire),
            if fd == 0 {
                DELEGATED_FLAG_READABLE
            } else {
                DELEGATED_FLAG_WRITABLE
            }
        );
    }
    let change = close_host_binding(tables.fd_map(), 51, 1).expect("close stdout");
    assert!(change.release.is_some());
    admit_stdio(
        tables.fd_map(),
        tables.opens(),
        tables.objects(),
        51,
        [true; 3],
    );
    assert!(fd_map_lookup(tables.fd_map(), 51, 1).is_none());
    assert!(fd_map_lookup(tables.fd_map(), 51, 2).is_some());
}

#[test]
fn file_region_record_beyond_fifteen_uses_shared_capacity() {
    let fixture = Fixture::new(3);
    let tables = fixture.tables();
    let host = std::fs::File::open("/dev/null").expect("real host crossing object");
    admit_stdio(
        tables.fd_map(),
        tables.opens(),
        tables.objects(),
        51,
        [true; 3],
    );
    for index in 3..20 {
        let handle = admit_host_fd(
            tables.fd_map(),
            tables.opens(),
            tables.objects(),
            51,
            index,
            host.as_raw_fd(),
            DELEGATED_FLAG_READABLE,
        )
        .expect("ABI capacity");
        assert_eq!(handle, index as u32 + 1);
        let open = &tables.opens()[index as usize];
        assert_eq!(
            open.host_fd().expect("real host binding").raw(),
            host.as_raw_fd()
        );
        assert!(open.is_bound_to(&tables.objects()[index as usize]));
    }
    assert!(
        close_host_binding(tables.fd_map(), 51, 19)
            .expect("close beyond 15")
            .release
            .is_some()
    );
}

#[test]
fn file_region_foreign_retired_and_two_carriers() {
    let mut a = Fixture::new(4);
    let b = Fixture::new(5);
    assert!(matches!(
        a.registration.tables(b.registration.binding()),
        Err(FileRegionError::Foreign)
    ));
    for (fixture, size) in [(&a, 17), (&b, 29)] {
        fixture.tables().objects()[17]
            .size
            .store(size, Ordering::Release);
    }
    assert_eq!(a.tables().objects()[17].size.load(Ordering::Acquire), 17);
    assert_eq!(b.tables().objects()[17].size.load(Ordering::Acquire), 29);
    let stale = a.registration.binding();
    a.registration.retire();
    assert!(matches!(
        a.registration.tables(stale),
        Err(FileRegionError::Retired)
    ));
    assert_eq!(b.tables().objects()[17].size.load(Ordering::Acquire), 29);
    drop(a);
    assert_eq!(b.tables().objects()[17].size.load(Ordering::Acquire), 29);
}

#[test]
fn file_region_fork_dup_lookup_and_retire_preserve_live_parent() {
    let fixture = Fixture::new(6);
    let tables = fixture.tables();
    admit_stdio(
        tables.fd_map(),
        tables.opens(),
        tables.objects(),
        51,
        [true; 3],
    );
    assert!(fork_fd_map(tables.fd_map(), 51, 52));
    for table in [51, 52] {
        assert_eq!(
            dup_host_binding(tables.fd_map(), table, 1, 0, 1024, false)
                .expect("dup stdout")
                .fd,
            3
        );
    }
    let parent = fd_map_lookup(tables.fd_map(), 51, 3).expect("parent dup");
    let child = fd_map_lookup(tables.fd_map(), 52, 3).expect("child dup");
    assert_ne!(parent.1, child.1);
    assert_eq!(parent.0, child.0);
    let open = &tables.opens()[parent.0 as usize - 1];
    assert!(
        open.is_bound_to(&tables.objects()[open.inode_handle.load(Ordering::Acquire) as usize - 1])
    );
    retire_fd_map(tables.fd_map(), 52);
    assert_eq!(
        tables.fd_map()[child.1].incarnation.load(Ordering::Acquire),
        0
    );
    for fd in 0..=3 {
        assert!(fd_map_lookup(tables.fd_map(), 51, fd).is_some());
        assert!(fd_map_lookup(tables.fd_map(), 52, fd).is_none());
    }
}

#[test]
fn file_region_unpublished_is_distinct_from_retired() {
    let mut fixture = Fixture::new(7);
    let published = fixture.registration.binding();
    assert!(matches!(
        FileRegionBinding::new(
            FileRegionBinding::UNPUBLISHED.identity(),
            published.guest(),
            published.physical(),
            published.bytes()
        ),
        Err(FileRegionError::Unpublished)
    ));
    assert!(matches!(
        fixture.registration.tables(FileRegionBinding::UNPUBLISHED),
        Err(FileRegionError::Unpublished)
    ));
    fixture.registration.retire();
    assert!(matches!(
        fixture.registration.tables(published),
        Err(FileRegionError::Retired)
    ));
    assert_ne!(
        FileRegionError::Unpublished.fatal_payload(),
        FileRegionError::Retired.fatal_payload()
    );
}
