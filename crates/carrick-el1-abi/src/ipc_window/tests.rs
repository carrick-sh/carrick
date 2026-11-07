//! IPC address-domain admission before any mapped-memory access.
#![allow(clippy::unwrap_used)]

extern crate std;

use crate::{
    EL1_IPC_DIRECTORY_SPAN, EL1_IPC_POOL_SPAN, EL1_REGION_SIZE, FileRegionBinding, FileRegionError,
    FileRegionId, IpcWindowBinding, X86_CPL0_REGION_BASE,
};
use carrick_guest_arch::{FrameGpa, GuestLen, KernelLayout, KernelVa};
use core::num::NonZeroU64;

fn region() -> FileRegionBinding {
    FileRegionBinding::new(
        FileRegionId::from_carrier(NonZeroU64::MIN),
        KernelVa::new(X86_CPL0_REGION_BASE),
        FrameGpa::new(0x1_0000_0000),
        GuestLen::new(EL1_REGION_SIZE),
    )
    .unwrap()
}

fn bind(
    region: FileRegionBinding,
    directory_va: u64,
    directory_gpa: u64,
    directory_len: u64,
    pool_va: u64,
    pool_gpa: u64,
    pool_len: u64,
) -> Result<IpcWindowBinding, FileRegionError> {
    IpcWindowBinding::new(
        region,
        KernelVa::new(directory_va),
        FrameGpa::new(directory_gpa),
        GuestLen::new(directory_len),
        KernelVa::new(pool_va),
        FrameGpa::new(pool_gpa),
        GuestLen::new(pool_len),
    )
}

const DIRECTORY: u64 = 0x4_0000_0000;
const POOL: u64 = DIRECTORY + EL1_IPC_DIRECTORY_SPAN;

#[test]
fn ipc_binding_refuses_zero_carrier_identity() {
    assert_eq!(
        bind(
            FileRegionBinding::UNPUBLISHED,
            DIRECTORY,
            DIRECTORY,
            EL1_IPC_DIRECTORY_SPAN,
            POOL,
            POOL,
            EL1_IPC_POOL_SPAN,
        ),
        Err(FileRegionError::Unpublished),
    );
}

#[test]
fn ipc_binding_refuses_each_unaligned_address_and_wrong_length() {
    for lane in 0..6 {
        let mut geometry = [
            DIRECTORY,
            DIRECTORY,
            EL1_IPC_DIRECTORY_SPAN,
            POOL,
            POOL,
            EL1_IPC_POOL_SPAN,
        ];
        // A page-aligned address still cannot name a 2 MiB mapping.
        geometry[lane] += if lane == 2 || lane == 5 { 1 } else { 4096 };
        assert_eq!(
            bind(
                region(),
                geometry[0],
                geometry[1],
                geometry[2],
                geometry[3],
                geometry[4],
                geometry[5],
            ),
            Err(FileRegionError::Layout),
            "geometry lane {lane}",
        );
    }
}

#[test]
fn ipc_binding_derives_x86_table_map_from_its_region() {
    let binding = bind(
        region(),
        DIRECTORY,
        DIRECTORY,
        EL1_IPC_DIRECTORY_SPAN,
        POOL,
        POOL,
        EL1_IPC_POOL_SPAN,
    )
    .unwrap();
    let layout = KernelLayout {
        region: region().guest(),
        zone: KernelVa::new(0),
        portal: KernelVa::new(0),
        dynamic_metadata: KernelVa::new(0),
    };
    assert_eq!(
        binding.table_map_address(layout).unwrap().raw(),
        X86_CPL0_REGION_BASE + crate::EL1_IPC_TABLE_MAP_OFFSET,
    );
    let foreign = KernelLayout {
        region: KernelVa::new(0x2D_0400_0000),
        ..layout
    };
    assert_eq!(
        binding.table_map_address(foreign),
        Err(FileRegionError::Foreign)
    );
}

#[test]
fn ipc_binding_refuses_overflow_zero_va_and_overlapping_domains() {
    let valid = [
        DIRECTORY,
        DIRECTORY,
        EL1_IPC_DIRECTORY_SPAN,
        POOL,
        POOL,
        EL1_IPC_POOL_SPAN,
    ];
    let mut cases = std::vec::Vec::new();
    for lane in [0, 1, 3, 4] {
        let mut geometry = valid;
        geometry[lane] = !0x1f_ffff_u64;
        cases.push(geometry);
    }
    for lane in [0, 3] {
        let mut geometry = valid;
        geometry[lane] = 0;
        cases.push(geometry);
    }
    // Neither address domain can alias another IPC range or the file region.
    for (lane, address) in [
        (3, DIRECTORY),
        (4, DIRECTORY),
        (0, region().guest().raw()),
        (3, region().guest().raw()),
        (1, region().physical().raw()),
        (4, region().physical().raw()),
    ] {
        let mut geometry = valid;
        geometry[lane] = address;
        cases.push(geometry);
    }
    for geometry in cases {
        assert_eq!(
            bind(
                region(),
                geometry[0],
                geometry[1],
                geometry[2],
                geometry[3],
                geometry[4],
                geometry[5],
            ),
            Err(FileRegionError::Layout),
            "{geometry:x?}",
        );
    }
}

#[test]
fn ipc_binding_keeps_guest_virtual_and_physical_ranges_distinct() {
    let binding = bind(
        region(),
        DIRECTORY,
        DIRECTORY + 0x1_0000_0000,
        EL1_IPC_DIRECTORY_SPAN,
        POOL,
        POOL + 0x1_0000_0000,
        EL1_IPC_POOL_SPAN,
    )
    .unwrap();
    assert_eq!(binding.region(), region());
    assert_eq!(binding.directory(), KernelVa::new(DIRECTORY));
    assert_eq!(
        binding.directory_physical(),
        FrameGpa::new(DIRECTORY + 0x1_0000_0000)
    );
    assert_eq!(
        binding.directory_bytes(),
        GuestLen::new(EL1_IPC_DIRECTORY_SPAN)
    );
    assert_eq!(binding.pool(), KernelVa::new(POOL));
    assert_eq!(binding.pool_physical(), FrameGpa::new(POOL + 0x1_0000_0000));
    assert_eq!(binding.pool_bytes(), GuestLen::new(EL1_IPC_POOL_SPAN));
}

#[test]
fn ipc_host_window_keeps_host_addresses_typed() {
    use carrick_guest_arch::HostVa;
    let directory = HostVa::new(0x200_0000);
    let pool = HostVa::new(0x400_0000);
    // SAFETY: validation only; no attachment or memory access in this witness.
    let window = unsafe {
        crate::HostIpcWindow::new(
            directory,
            GuestLen::new(EL1_IPC_DIRECTORY_SPAN),
            pool,
            GuestLen::new(EL1_IPC_POOL_SPAN),
        )
    }
    .unwrap();
    assert_eq!(window.directory(), directory);
    assert_eq!(window.pool(), pool);
    assert_eq!(
        window.directory_bytes(),
        GuestLen::new(EL1_IPC_DIRECTORY_SPAN)
    );
    assert_eq!(window.pool_bytes(), GuestLen::new(EL1_IPC_POOL_SPAN));
}
