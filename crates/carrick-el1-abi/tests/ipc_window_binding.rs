//! IPC address-domain admission before any mapped-memory access.
#![allow(clippy::unwrap_used)]

use carrick_el1_abi::{
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
        X86_CPL0_REGION_BASE + carrick_el1_abi::EL1_IPC_TABLE_MAP_OFFSET,
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
