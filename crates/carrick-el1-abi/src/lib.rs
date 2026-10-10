//! ABI contracts, memory layouts, and definitions shared between the host
//! runtime and the bare-metal in-guest EL1 kernel (`carrick-el1`).
//!
//! # Region Layout
//!
//! The EL1 kernel occupies a 64 MiB window starting at [`EL1_REGION_BASE`].
//! This region is mapped kernel-only (`AP=00`, `UXN=1`, `PXN=0`) in stage-1
//! page tables: EL0 userspace code cannot read, write, or execute within it.
//!
//! Within this 64 MiB region:
//! - `0x0000_0000..0x0010_0000` (1 MiB): Image ([`EL1_IMAGE_OFFSET`]), starting with [`ImageHeader`].
//! - `0x0010_0000..0x0020_0000` (1 MiB): Counters ([`EL1_COUNTERS_OFFSET`]), holding [`Counters`].
//! - `0x0020_0000..0x0060_0000` (4 MiB): Per-vCPU kernel stacks ([`EL1_STACKS_OFFSET`]),
//!   256 slots of [`EL1_STACK_SIZE`] (16 KiB) each.
//! - `0x0100_0000..0x0400_0000` (48 MiB): Dynamic heap ([`EL1_HEAP_OFFSET`]).
//!
//! A separate kernel-only window at [`EL1_IPC_BASE`] (after the dynamic
//! metadata aperture) maps the host IPC authority's [`ipc::IpcDirectory`] and
//! byte pool; the [`ipc_tables::IpcTableMap`] lives in this region.

#![no_std]

mod cow_grants;
pub use cow_grants::*;
mod descriptor_txn;
pub use descriptor_txn::*;
mod guest_mmu_publication;
pub use guest_mmu_publication::*;
mod x86_initial_boot;
pub use x86_initial_boot::*;
mod native_run_failure;
pub use native_run_failure::*;
mod fork_stock;
pub use fork_stock::*;
mod x86_prepare_stock;
pub use x86_prepare_stock::*;
mod delegated_notification;
pub use delegated_notification::*;
mod mm_portal;
mod mm_portal_executable;
mod mm_portal_fork;
mod mm_portal_grant;
pub use carrick_core_abi::*;
pub use carrick_personality_linux::abi::entry::{
    LinuxTaskMetadata, LinuxTaskState, SERVED_COMMIT_OWED, SERVED_WAKES_OWED, ServedBoundary,
};
pub use mm_portal::*;
pub use mm_portal_executable::*;
pub use mm_portal_fork::*;
pub use mm_portal_grant::*;

mod reservations;
pub use reservations::*;
mod thread_lifecycle;
pub use thread_lifecycle::*;
mod service_copy;
pub use service_copy::*;
mod internal_read;
pub use internal_read::*;
mod kernel_fault_venues;
pub use kernel_fault_venues::*;

use core::cell::UnsafeCell;

pub mod ipc;
pub mod ipc_tables;

/// Guest VA/IPA base of the 64 MiB EL1 kernel region.
/// Placed at 180 GiB + 64 MiB, cleanly within the 180..181 GiB L2 block table (L2_B)
/// and disjoint from all other guest memory ranges.
pub const EL1_REGION_BASE: u64 = 0x2D_0400_0000;

/// Total size of the EL1 kernel region: 64 MiB.
pub const EL1_REGION_SIZE: u64 = 64 * 1024 * 1024;

/// Byte offset of the executable EL1 image within the region.
pub const EL1_IMAGE_OFFSET: u64 = 0x0;

/// Byte offset of the per-syscall counters within the region.
pub const EL1_COUNTERS_OFFSET: u64 = 0x10_0000;

/// Base guest virtual address of the per-syscall counters page.
pub const EL1_COUNTERS_BASE: u64 = EL1_REGION_BASE + EL1_COUNTERS_OFFSET;

/// Explicit ARM opt-out bit. A zero control word enforces strict admission.
pub const APERTURE_CONTROL_ARM_RING_FIRST_OPT_OUT: u64 = 1 << 3;

/// Byte offset of the aperture control word within the region.
pub const EL1_APERTURE_CONTROL_OFFSET: u64 =
    EL1_SERVICE_COPY_TABLE_OFFSET + core::mem::size_of::<ServiceCopyTable>() as u64;

/// Base guest virtual address of the aperture control word.
pub const EL1_APERTURE_CONTROL_BASE: u64 = EL1_REGION_BASE + EL1_APERTURE_CONTROL_OFFSET;

/// Byte offset of the per-vCPU stack arena within the region.
pub const EL1_STACKS_OFFSET: u64 = 0x20_0000;

/// Base guest virtual address of the per-vCPU stack arena.
pub const EL1_STACKS_BASE: u64 = EL1_REGION_BASE + EL1_STACKS_OFFSET;

/// Size of each vCPU's EL1 kernel stack: 16 KiB.
pub const EL1_STACK_SIZE: u64 = 0x4000;
/// The first 4 KiB of every EL1 stack slot has no stage-1 translation.
pub const EL1_STACK_GUARD_SIZE: u64 = 0x1000;

/// Number of vCPU stack slots supported in the stack arena (matches mailbox slots).
pub const EL1_STACK_SLOTS: u64 = 256;

/// Byte offset of the per-vCPU current-task array within the region.
pub const EL1_CURRENT_TASKS_OFFSET: u64 = 0x60_0000;

/// Base guest virtual address of the per-vCPU current-task array.
pub const EL1_CURRENT_TASKS_BASE: u64 = EL1_REGION_BASE + EL1_CURRENT_TASKS_OFFSET;

/// Size of the per-vCPU current-task array area (1 MiB).
pub const EL1_CURRENT_TASKS_SIZE: u64 = 0x10_0000;

/// Shared single-flight metadata request mailbox. The guest publishes only
/// bounded request data here, then unwinds to the ordinary pending-host-work
/// boundary; the host never services a metadata grant on the guest's EL1
/// allocator stack.
pub const EL1_METADATA_MAILBOX_OFFSET: u64 = EL1_CURRENT_TASKS_OFFSET + 0x10_000;
pub const EL1_METADATA_MAILBOX_BASE: u64 = EL1_REGION_BASE + EL1_METADATA_MAILBOX_OFFSET;

/// Dedicated metadata readiness queue, outside guest IPC queue admission.
pub const METADATA_WAIT_QUEUE_INDEX: u32 = carrick_sched_core::ZONE_RECORDS as u32;

pub const METADATA_MAILBOX_IDLE: u32 = 0;
pub const METADATA_MAILBOX_GUEST_WRITING: u32 = 1;
pub const METADATA_MAILBOX_REQUESTED: u32 = 2;
pub const METADATA_MAILBOX_HOST_WORKING: u32 = 3;
pub const METADATA_MAILBOX_RESPONSE: u32 = 4;
pub const METADATA_MAILBOX_GUEST_CONSUMING: u32 = 5;

/// Per-vCPU single-flight anonymous-frame grant mailboxes. EL1 publishes a
/// fault request in the current slot and leaves through the ordinary host
/// boundary. The host may publish a successful response only after the named
/// stage-2 owner and frame inventory mapping are live and authenticated.
pub const EL1_FRAME_GRANT_MAILBOX_OFFSET: u64 = EL1_CURRENT_TASKS_OFFSET + 0x20_000;
pub const EL1_FRAME_GRANT_MAILBOX_BASE: u64 = EL1_REGION_BASE + EL1_FRAME_GRANT_MAILBOX_OFFSET;

/// Shared residency journal for up to 4096 live bulk grants. It occupies the
/// otherwise unused tail of the current-task area, after the mailboxes.
pub const EL1_FRAME_GRANT_RESIDENCY_OFFSET: u64 = EL1_CURRENT_TASKS_OFFSET + 0x30_000;
pub const EL1_FRAME_GRANT_RESIDENCY_BASE: u64 = EL1_REGION_BASE + EL1_FRAME_GRANT_RESIDENCY_OFFSET;

/// Guest VA/IPA base of the 2 MiB AArch64 kernel control window (L1 index 180).
pub const AARCH64_KERNEL_CONTROL_BASE: u64 =
    carrick_mmu_core::aarch64::owner_fork::KERNEL_CONTROL_BASE;

/// Span of the AArch64 kernel control window (exactly one 2 MiB Level-2 block).
pub const AARCH64_KERNEL_CONTROL_SIZE: u64 =
    carrick_mmu_core::aarch64::owner_fork::KERNEL_CONTROL_SPAN;

/// EL1-only virtual alias of the current MM's primary AArch64 stage-1 table
/// arena. Every published address space maps its own arena at this fixed VA.
pub const AARCH64_STAGE1_TABLES_ALIAS_BASE: u64 =
    carrick_mmu_core::aarch64::owner_fork::STAGE1_TABLES_ALIAS_BASE;

/// Bytes available through [`AARCH64_STAGE1_TABLES_ALIAS_BASE`]. Guest leaf
/// publication must reject every descriptor outside this primary arena.
pub const AARCH64_STAGE1_TABLES_PRIMARY_SIZE: u64 =
    carrick_mmu_core::aarch64::owner_fork::STAGE1_TABLES_PRIMARY_SIZE;
/// The carrier FD control backing occupies the last free aligned window before
/// the EL1 maintenance trampoline.
pub const AARCH64_FD_CEILING_CONTROL_BASE: u64 =
    AARCH64_STAGE1_TABLES_ALIAS_BASE + AARCH64_STAGE1_TABLES_PRIMARY_SIZE;
pub const AARCH64_FD_CEILING_CONTROL_SIZE: u64 = 0x4000;

/// Guest-physical base of the carrier's dense pool of 2 MiB stage-1 table
/// arenas: every MM's primary arena (its root slot) and every extension arena
/// it grows into are slots of this pool. Every HVPatch image maps the whole
/// pool EL1-only at its own address (VA == IPA, EL0 no access, never
/// executable), so EL1 reaches every table of every arena the host grants it
/// and the guest lane's table supply grows exactly like the host lane's.
pub const AARCH64_STAGE1_TABLE_POOL_BASE: u64 = 0x9A_0000_0000;

/// Bytes of [`AARCH64_STAGE1_TABLE_POOL_BASE`]'s pool (2048 arenas).
pub const AARCH64_STAGE1_TABLE_POOL_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// EL1's window over every stage-1 table arena of the pool (each MM's
/// extension arenas, and its primary arena when that is a pool slot). The
/// MM's primary arena is also reachable through
/// [`AARCH64_STAGE1_TABLES_ALIAS_BASE`]. Only meaningful on the guest (EL1),
/// where the pool is mapped.
#[must_use]
pub const fn stage1_table_pool_window() -> carrick_mmu_core::aarch64::descriptor_txn::TableWindow {
    carrick_mmu_core::aarch64::descriptor_txn::TableWindow {
        words: AARCH64_STAGE1_TABLE_POOL_BASE as *mut core::sync::atomic::AtomicU64,
        physical_base: AARCH64_STAGE1_TABLE_POOL_BASE,
        byte_len: AARCH64_STAGE1_TABLE_POOL_SIZE as usize,
    }
}

/// Canonical accessible user address used when adopting a live AArch64 table
/// image and detecting its ASID-scoped construction mode.
pub const AARCH64_USER_LEAF_CHECK_VA: u64 = 0x1_0000;

/// Guest-physical window reserved for the in-kernel GIC implementation.
/// A stage-1 publication must never expose this range as ordinary memory.
pub const AARCH64_GIC_WINDOW_BASE: u64 = 0x2F_0000_0000;
pub const AARCH64_GIC_WINDOW_SIZE: u64 = 0x1000_0000;

/// Byte offset of the EL1 bootstrap metadata allocator arena within the region.
pub const EL1_BOOTSTRAP_METADATA_OFFSET: u64 = 0x70_0000;

/// Base guest virtual address of the EL1 bootstrap metadata allocator arena.
pub const EL1_BOOTSTRAP_METADATA_BASE: u64 = EL1_REGION_BASE + EL1_BOOTSTRAP_METADATA_OFFSET;

/// Base guest virtual address of the x86 CPL0 bootstrap metadata allocator arena.
pub const X86_CPL0_BOOTSTRAP_METADATA_BASE: u64 = 0xffff_ffff_a800_0000;
/// Checked extent shared by the CPL0 linker and host ELF admission.
pub const X86_CPL0_SUPERVISOR_IMAGE_BASE: u64 = 0xffff_ffff_8000_0000;
/// Guest-physical base shared by the CPL0 image loader and fixture table grant.
pub const X86_CPL0_SUPERVISOR_IMAGE_GPA: u64 = 0x10_0000;
pub const X86_CPL0_SUPERVISOR_IMAGE_SIZE: u64 = 0x12_0000;
/// CPL0's one upper-half supervisor window for retained physical pages.
pub const X86_CPL0_DIRECT_VA: u64 = 0xffff_ffff_9000_0000;
/// Retained initial-image frames use their own supervisor alias, never the
/// short bootstrap direct window. The full 512 MiB budget fits here.
pub const X86_CPL0_INITIAL_EXTENT_VA: u64 = 0xffff_fffe_0000_0000;
pub const X86_CPL0_INITIAL_EXTENT_GPA: u64 = 0x40_00000;
pub const X86_CPL0_INITIAL_EXTENT_MAX_SIZE: u64 = 0x2000_0000;
pub const X86_CPL0_REGION_BASE: u64 = 0xffff_ffff_c000_0000;
/// MM-private temporary supervisor copy pair.
pub const X86_CPL0_COW_COPY_BASE: u64 = carrick_mmu_core::x86::copy_window::COW_COPY_WINDOW_BASE;
pub const X86_CPL0_COW_COPY_SIZE: u64 = carrick_mmu_core::x86::copy_window::COW_COPY_WINDOW_LEN;
/// Retained CPL0 root arena reachable through the supervisor direct window.
pub const X86_CPL0_TABLE_ARENA_BYTES: u64 = 448 * 4096;

/// Size of the EL1 bootstrap metadata allocator arena (9 MiB).
pub const EL1_BOOTSTRAP_METADATA_SIZE: u64 = 0x90_0000;

/// Base guest virtual address of the dynamic metadata grant aperture (64 MiB window).
pub const X86_CPL0_DYNAMIC_METADATA_BASE: u64 = 0xffff_ffff_a000_0000;
pub const EL1_DYNAMIC_METADATA_BASE: u64 = 0x2D_0800_0000;

const fn disjoint(a: u64, a_size: u64, b: u64, b_size: u64) -> bool {
    a + a_size <= b || b + b_size <= a
}

const _: () = {
    // Every fixed x86 supervisor alias, including the full initial-image
    // capacity, must be disjoint. This is checked at compile time for both
    // guest and host builds so a new map cannot silently replace another PTE.
    const WINDOWS: [(u64, u64); 9] = [
        (
            X86_CPL0_SUPERVISOR_IMAGE_BASE,
            X86_CPL0_SUPERVISOR_IMAGE_SIZE,
        ),
        (X86_CPL0_COW_COPY_BASE, X86_CPL0_COW_COPY_SIZE),
        (X86_CPL0_DIRECT_VA, 0x0200_0000), // bootstrap direct window
        (X86_CPL0_DYNAMIC_METADATA_BASE, 0x0400_0000),
        (
            X86_CPL0_BOOTSTRAP_METADATA_BASE,
            EL1_BOOTSTRAP_METADATA_SIZE,
        ),
        (0xffff_ffff_b000_0000, 0x100_0000), // progress aliases
        (X86_CPL0_REGION_BASE, EL1_REGION_SIZE),
        (0xffff_ffff_d000_0000, 0x1000), // local APIC
        (X86_CPL0_INITIAL_EXTENT_VA, X86_CPL0_INITIAL_EXTENT_MAX_SIZE),
    ];
    let mut i = 0;
    while i < WINDOWS.len() {
        let mut j = i + 1;
        while j < WINDOWS.len() {
            assert!(disjoint(
                WINDOWS[i].0,
                WINDOWS[i].1,
                WINDOWS[j].0,
                WINDOWS[j].1
            ));
            j += 1;
        }
        i += 1;
    }
};

/// Total size of the dynamic metadata grant aperture (64 MiB).
pub const EL1_DYNAMIC_METADATA_SIZE: u64 = 0x0400_0000;

/// Standard quantum size of a dynamic metadata extent granted by the host (512 KiB).
pub use carrick_core_abi::EL1_DYNAMIC_METADATA_EXTENT_SIZE;

/// The exact mapped boot-stock extent containing a loaned table root.
pub fn fork_stock_table_window(
    loaned_root: u64,
) -> Option<carrick_mmu_core::aarch64::descriptor_txn::TableWindow> {
    let offset = loaned_root.checked_sub(EL1_DYNAMIC_METADATA_BASE)?;
    if offset >= EL1_DYNAMIC_METADATA_SIZE {
        return None;
    }
    let extent = EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64;
    let base = EL1_DYNAMIC_METADATA_BASE + offset / extent * extent;
    Some(carrick_mmu_core::aarch64::descriptor_txn::TableWindow {
        words: base as *mut core::sync::atomic::AtomicU64,
        physical_base: base,
        byte_len: EL1_DYNAMIC_METADATA_EXTENT_SIZE,
    })
}

/// Operation code for requesting an extent grant from the host (HVC #6).
pub const METADATA_GRANT_OP_ALLOC: u64 = 1;

/// Operation code for returning an unused extent to the host (HVC #6).
pub const METADATA_GRANT_OP_FREE: u64 = 2;

/// Operation code for physical page-table stock loans and settlements (HVC #6).
pub const GRANT_OP_FORK_STOCK: u64 = 3;

/// Operation code for root container exit notification (HVC #6).
pub const GRANT_OP_ROOT_EXIT: u64 = 4;

/// Operation code for quarantining a retired child MM (HVC #6).
pub const GRANT_OP_CHILD_RETIRE: u64 = 5;

/// Metadata grant hypercall outcome: successful extent allocation or return.
pub const METADATA_GRANT_SUCCESS: u64 = 0;

/// Metadata grant hypercall outcome: host denied allocation request.
pub const METADATA_GRANT_ERR_DENIED: u64 = 1;

/// Metadata grant hypercall outcome: invalid arguments or parameters.
pub const METADATA_GRANT_ERR_INVALID: u64 = 2;

/// Metadata grant hypercall outcome: extent not found in active grant registry.
pub const METADATA_GRANT_ERR_NOT_FOUND: u64 = 3;

/// Metadata grant hypercall outcome: extent overlaps existing allocation or region.
pub const METADATA_GRANT_ERR_OVERLAP: u64 = 4;

/// Metadata grant hypercall outcome: extent alignment violation.
pub const METADATA_GRANT_ERR_ALIGNMENT: u64 = 5;

/// Test/control return used only to ask the caller to cross an EL0 host-work
/// boundary and retry after an asynchronous metadata request completes.
pub const METADATA_GRANT_PENDING: u64 = u64::MAX - 1;

/// Unaliased Carrick-private test and diagnostic control syscall number (outside Linux 0..500 space).
pub const SYS_CARRICK_EL1_CONTROL: u64 = 0xCA88_0001;

/// Byte offset of the EL1 kernel heap within the region.
pub const EL1_HEAP_OFFSET: u64 = 0x100_0000;

/// Base guest virtual address of the EL1 kernel heap.
pub const EL1_HEAP_BASE: u64 = EL1_REGION_BASE + EL1_HEAP_OFFSET;

/// Size of the EL1 kernel heap (48 MiB).
pub const EL1_HEAP_SIZE: u64 = EL1_REGION_SIZE - EL1_HEAP_OFFSET;

/// Guest VA/IPA of the shared IPC window (kernel-only, identity mapped).
/// The host's IPC authority owns the memory (directory and pool, two host
/// allocations); the runtime maps the directory at [`EL1_IPC_BASE`] and the
/// pool at [`EL1_IPC_POOL_BASE`]. EL1 attaches only once the directory is
/// published, so an unmapped or unpublished window fails closed.
pub const EL1_IPC_BASE: u64 = EL1_DYNAMIC_METADATA_BASE + EL1_DYNAMIC_METADATA_SIZE;
/// IPA span reserved for the directory mapping: the fixed directory head
/// and the reservations of its elastic stores
/// ([`ipc::IPC_DIRECTORY_BYTES`] must fit). Address space only: the host
/// commits a store's pages as it publishes segments.
pub const EL1_IPC_DIRECTORY_SPAN: u64 = 0x800_0000;
/// Guest VA/IPA of the IPC byte pool.
pub const EL1_IPC_POOL_BASE: u64 = EL1_IPC_BASE + EL1_IPC_DIRECTORY_SPAN;
/// Length of the IPC byte pool (the authority's pool is exactly this long):
/// descriptor-table extents and the rings of pipes that hold (or held)
/// data; a pipe's ring is allocated at its first write.
pub const EL1_IPC_POOL_SPAN: u64 = 0x2000_0000;
/// The whole kernel-only IPC window.
pub const EL1_IPC_SIZE: u64 = EL1_IPC_DIRECTORY_SPAN + EL1_IPC_POOL_SPAN;
/// Offset, within the EL1 region, of the [`ipc_tables::IpcTableMap`]
/// (region memory the carrier owns, so it exists before any IPC authority).
pub const EL1_IPC_TABLE_MAP_OFFSET: u64 = EL1_OPEN_FILE_TABLE_OFFSET + EL1_OPEN_FILE_TABLE_SIZE;

const _: () = assert!(ipc::IPC_DIRECTORY_BYTES as u64 <= EL1_IPC_DIRECTORY_SPAN);
const _: () = assert!(
    EL1_IPC_TABLE_MAP_OFFSET + core::mem::size_of::<ipc_tables::IpcTableMap>() as u64
        <= EL1_CACHE_OFFSET
);
const _: () = assert!(EL1_IPC_TABLE_MAP_OFFSET.is_multiple_of(64));
const _: () = assert!(EL1_IPC_BASE.is_multiple_of(0x20_0000));
const _: () = assert!(EL1_IPC_POOL_BASE.is_multiple_of(0x20_0000));
const _: () = assert!(EL1_IPC_BASE + EL1_IPC_SIZE <= 0x2D_4000_0000);

/// Byte offset of the object table within the region (at start of heap).
pub const EL1_OBJECT_TABLE_OFFSET: u64 = EL1_HEAP_OFFSET;

/// Base guest virtual address of the object table.
pub const EL1_OBJECT_TABLE_BASE: u64 = EL1_REGION_BASE + EL1_OBJECT_TABLE_OFFSET;

/// Size of the object table area (64 KiB).
pub const EL1_OBJECT_TABLE_SIZE: u64 = 0x1_0000;

/// Byte offset of the fd map within the region.
pub const EL1_FD_MAP_OFFSET: u64 = EL1_OBJECT_TABLE_OFFSET + EL1_OBJECT_TABLE_SIZE;

/// Base guest virtual address of the fd map.
pub const EL1_FD_MAP_BASE: u64 = EL1_REGION_BASE + EL1_FD_MAP_OFFSET;

/// Size of the fd map area (64 KiB).
pub const EL1_FD_MAP_SIZE: u64 = 0x1_0000;

/// Offset of the in-zone open-file table (one record per open description of
/// an in-zone inode), right after the fd map.
pub const EL1_OPEN_FILE_TABLE_OFFSET: u64 = EL1_FD_MAP_OFFSET + EL1_FD_MAP_SIZE;

/// Guest virtual base of the in-zone open-file table.
pub const EL1_OPEN_FILE_TABLE_BASE: u64 = EL1_REGION_BASE + EL1_OPEN_FILE_TABLE_OFFSET;

/// Size of the in-zone open-file table.
pub const EL1_OPEN_FILE_TABLE_SIZE: u64 = 0x1_0000;

/// Maximum open-file records (open descriptions of in-zone inodes).
pub const MAX_ZONE_OPEN_FILES: usize = 512;

/// Dedicated supervisor crossing for host-bound poll readiness. It is not a
/// Linux syscall number and cannot alias an allowed guest forward.
pub struct HostReadinessCrossing;

/// Result carried beside the x86 CPL0 fault record, before the carrier
/// applies the unresolved-fault policy.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum X86FaultDisposition {
    PolicyDeclined,
}

impl X86FaultDisposition {
    pub const fn raw(self) -> u64 {
        match self {
            Self::PolicyDeclined => 6,
        }
    }

    pub const fn from_raw(raw: u64) -> Option<Self> {
        match raw {
            6 => Some(Self::PolicyDeclined),
            _ => None,
        }
    }
}

/// Millisecond timeout carried by the private readiness request. Negative
/// values mean no deadline, matching Linux `poll`.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct HostReadinessTimeout(i32);

impl HostReadinessTimeout {
    pub const fn from_wire(raw: u64) -> Option<Self> {
        let millis = raw as i32;
        if millis as i64 as u64 == raw {
            Some(Self(millis))
        } else {
            None
        }
    }

    pub const fn millis(self) -> i32 {
        self.0
    }
}

impl HostReadinessCrossing {
    pub const NUMBER: u64 = u64::MAX - 0x100;
    pub const MASK_NONE: u64 = 0;
    pub const MASK_REPLACE: u64 = 1;
    /// `SYSCALL` captures the user return PC in RCX before EL1 writes this
    /// supervisor-only tag. The adapter restores RCX before returning.
    pub const FRAME_TAG: u64 = u64::MAX - 1;

    pub const fn is_crossing(tag: u64) -> bool {
        tag == Self::FRAME_TAG
    }
}

/// One host-bound description in a readiness request. The guest file owner
/// supplies `host_fd`; the carrier fills `revents` without changing identity
/// or interest. `poll_index` keeps duplicate guest entries independent.
#[repr(C)]
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct HostReadinessEntry {
    pub binding: HostObjectBinding,
    pub events: i16,
    pub revents: i16,
    pub poll_index: u32,
}

/// Typed write of an in-ring descriptor's host-bound object. The object id
/// travels in RDI, byte address in RSI, length in RDX; the saved native frame
/// is restored by the guest after this synchronous crossing completes.
pub struct HostObjectWriteCrossing;
impl HostObjectWriteCrossing {
    pub const NUMBER: u64 = 0x4341_5252_574f_424a;
    pub const FRAME_TAG: u64 = 0x574f_424a_4543_5431;
}

/// Last guest reference to one host object description. RDI carries the
/// binding, RSI the description handle, RDX its incarnation.
pub struct HostObjectReleaseCrossing;
impl HostObjectReleaseCrossing {
    pub const NUMBER: u64 = 0x4341_5252_5245_4c53;
    pub const FRAME_TAG: u64 = 0x5245_4c45_4153_4531;
}

const _: () = assert!(core::mem::size_of::<HostReadinessEntry>() == 12);

/// Byte offset of the file page cache arena within the region.
pub const EL1_CACHE_OFFSET: u64 = EL1_HEAP_OFFSET + 0x10_0000; // 1 MiB into heap

/// Base guest virtual address of the file page cache arena.
pub const EL1_CACHE_BASE: u64 = EL1_REGION_BASE + EL1_CACHE_OFFSET;

/// Size of the file page cache arena (32 MiB).
pub const EL1_CACHE_SIZE: u64 = (MAX_DELEGATED_FILES as u64) * DELEGATED_FILE_MAX_SIZE;

/// GIC INTID of the kick a vCPU owes at its next EL0 boundary: an SGI the
/// HVF host makes pending in the vCPU's redistributor when a host kick stops
/// the vCPU inside Carrick's EL1 code (EL1 plan 1a).
pub const GIC_KICK_INTID: u32 = 15;
/// GIC INTID of the EL1 virtual timer (Hypervisor.framework
/// `HV_GIC_INT_EL1_VIRTUAL_TIMER`, checked at every GIC creation).
pub const GIC_VTIMER_INTID: u32 = 27;
/// What `ICC_IAR1_EL1` returns when no interrupt is pending.
pub const GIC_SPURIOUS_INTID: u32 = 1023;
/// GIC INTID of the reschedule SGI one vCPU's EL1 sends another when it
/// queues a thread there (EL1 plan 1c): it ends the target's WFI, or makes
/// a running target look at its run queue.
pub const GIC_RESCHED_INTID: u32 = 14;

/// Magic bytes at offset 0 of the EL1 image header: `CEL1`.
pub const IMAGE_MAGIC: [u8; 4] = *b"CEL1";

/// Current version of the EL1 image format. Version 2 adds the ABI layout
/// hash ([`ImageHeader::abi_hash_offset`]).
pub const IMAGE_VERSION: u32 = 2;

/// Why an EL1 image cannot be used with this host.
#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub enum ImageAbiError {
    /// No complete header, or the wrong magic.
    NotAnImage,
    /// An image format this host does not read.
    Version { found: u32 },
    /// The hash offset lies outside the image.
    HashOutOfBounds,
    /// The image was built against a different layout of the shared records.
    LayoutMismatch { expected: u64, found: u64 },
}

/// Check that `image` was built against this crate's shared-record layout
/// (a stale image once served nothing, silently).
pub fn check_image_abi(image: &[u8]) -> Result<ImageHeader, ImageAbiError> {
    let header = ImageHeader::read_from_prefix(image).ok_or(ImageAbiError::NotAnImage)?;
    if header.magic != IMAGE_MAGIC {
        return Err(ImageAbiError::NotAnImage);
    }
    if header.version != IMAGE_VERSION {
        return Err(ImageAbiError::Version {
            found: header.version,
        });
    }
    let at = usize::try_from(header.abi_hash_offset).map_err(|_| ImageAbiError::HashOutOfBounds)?;
    let bytes = image
        .get(at..at.checked_add(8).ok_or(ImageAbiError::HashOutOfBounds)?)
        .ok_or(ImageAbiError::HashOutOfBounds)?;
    let mut word = [0u8; 8];
    word.copy_from_slice(bytes);
    let found = u64::from_le_bytes(word);
    if found != EL1_ABI_LAYOUT_HASH {
        return Err(ImageAbiError::LayoutMismatch {
            expected: EL1_ABI_LAYOUT_HASH,
            found,
        });
    }
    Ok(header)
}

/// FNV-1a over the layout facts both sides depend on: every shared record's
/// size, alignment and field offsets, and the region layout. Computed at
/// compile time; the EL1 image embeds its copy and the host refuses an image
/// whose copy differs.
pub const EL1_ABI_LAYOUT_HASH: u64 = {
    let facts: &[u64] = &[
        EL1_REGION_BASE,
        EL1_REGION_SIZE,
        EL1_COUNTERS_OFFSET,
        EL1_SERVICE_COPY_TABLE_OFFSET,
        core::mem::size_of::<ServiceCopyTable>() as u64,
        EL1_SERVICE_COPY_BASE,
        EL1_SERVICE_COPY_SIZE,
        EL1_CARRIER_MAINT_ROOT_BASE,
        EL1_CARRIER_MAINT_ROOT_SIZE,
        AARCH64_STAGE1_TABLES_PRIMARY_SIZE,
        AARCH64_FD_CEILING_CONTROL_BASE,
        AARCH64_FD_CEILING_CONTROL_SIZE,
        EL1_RESERVATIONS_OFFSET,
        EL1_RESERVATIONS_END,
        RESERVATION_PROTOCOL_VERSION,
        MM_PORTAL_PROTOCOL,
        MM_TRANSFER_LAYOUT_HASH,
        MM_PORTAL_BIND_ESR,
        MM_PORTAL_SELECT_ESR,
        MM_PORTAL_SERVICE_ESR,
        MM_PORTAL_GRANT_ESR,
        MM_PORTAL_MAINTENANCE_ESR,
        core::mem::size_of::<PortalGrantSlot>() as u64,
        core::mem::size_of::<PortalExecutableSlot>() as u64,
        core::mem::size_of::<PortalExecutablePublication>() as u64,
        MM_PORTAL_MAX_BYTES,
        EL1_MM_PORTAL_OFFSET,
        core::mem::size_of::<PortalTransferSlot>() as u64,
        core::mem::size_of::<MmPortalSlots>() as u64,
        core::mem::align_of::<MmPortalSlots>() as u64,
        core::mem::size_of::<ReservationRequest>() as u64,
        core::mem::size_of::<ReservationCompletion>() as u64,
        ReservationNodeFlags::ATTRIBUTES.bits() as u64,
        EL1_STACKS_OFFSET,
        EL1_STACK_SIZE,
        EL1_STACK_GUARD_SIZE,
        EL1_CURRENT_TASKS_OFFSET,
        EL1_METADATA_MAILBOX_OFFSET,
        EL1_FRAME_GRANT_MAILBOX_OFFSET,
        EL1_FRAME_GRANT_RESIDENCY_OFFSET,
        FRAME_GRANT_RESIDENCY_SLOTS as u64,
        EL1_FRAME_GRANT_TARGET_SIZE,
        EL1_BOOTSTRAP_METADATA_OFFSET,
        EL1_BOOTSTRAP_METADATA_SIZE,
        EL1_DYNAMIC_METADATA_BASE,
        EL1_DYNAMIC_METADATA_SIZE,
        METADATA_GRANT_OP_ALLOC,
        METADATA_GRANT_OP_FREE,
        SYS_CARRICK_EL1_CONTROL,
        EL1_OBJECT_TABLE_OFFSET,
        EL1_FD_MAP_OFFSET,
        EL1_OPEN_FILE_TABLE_OFFSET,
        EL1_CACHE_OFFSET,
        EL1_INOTIFY_TABLE_OFFSET,
        EL1_NAME_CACHE_OFFSET,
        EL1_IPC_BASE,
        EL1_IPC_DIRECTORY_SPAN,
        EL1_IPC_POOL_BASE,
        EL1_IPC_POOL_SPAN,
        EL1_IPC_TABLE_MAP_OFFSET,
        ipc::IPC_LAYOUT_HASH,
        core::mem::size_of::<ipc_tables::IpcTableMap>() as u64,
        MAX_DELEGATED_FILES as u64,
        MAX_ZONE_OPEN_FILES as u64,
        MAX_DELEGATED_INOTIFY as u64,
        MAX_DELEGATED_WATCHES as u64,
        MAX_DELEGATED_MARKS_PER_FILE as u64,
        FD_MAP_CAPACITY as u64,
        DELEGATED_FILE_MAX_SIZE,
        DELEGATED_PAGE_SIZE,
        INOTIFY_QUEUE_BYTES as u64,
        FD_HANDLE_INOTIFY_TAG as u64,
        core::mem::size_of::<TrapFrame>() as u64,
        core::mem::size_of::<Counters>() as u64,
        core::mem::offset_of!(Counters, irq_taken) as u64,
        core::mem::offset_of!(Counters, fault_taken) as u64,
        core::mem::offset_of!(Counters, ipc_leaves) as u64,
        core::mem::offset_of!(Counters, anonymous_leaves) as u64,
        core::mem::offset_of!(Counters, refused) as u64,
        core::mem::size_of::<CurrentTask>() as u64,
        core::mem::offset_of!(CurrentTask, linux.file_table) as u64,
        core::mem::offset_of!(CurrentTask, linux.pending_host_work) as u64,
        core::mem::offset_of!(CurrentTask, linux.served_with_work) as u64,
        core::mem::offset_of!(CurrentTask, mm.key) as u64,
        core::mem::offset_of!(CurrentTask, mm.thread_generation) as u64,
        core::mem::offset_of!(CurrentTask, metadata.lifecycle_page) as u64,
        core::mem::offset_of!(CurrentTask, metadata.control_slot) as u64,
        core::mem::size_of::<MetadataGrantMailbox>() as u64,
        core::mem::align_of::<MetadataGrantMailbox>() as u64,
        core::mem::offset_of!(MetadataGrantMailbox, request_generation) as u64,
        carrick_sched_core::object_wait::OBJECT_WAIT_QUEUES as u64,
        FRAME_GRANT_PROTOCOL_VERSION,
        core::mem::size_of::<FrameGrantMailbox>() as u64,
        core::mem::align_of::<FrameGrantMailbox>() as u64,
        core::mem::size_of::<FrameGrantMailboxes>() as u64,
        core::mem::align_of::<FrameGrantMailboxes>() as u64,
        FrameGrantMailbox::STATE_OFFSET as u64,
        FrameGrantMailbox::STATUS_OFFSET as u64,
        FrameGrantMailbox::MM_KEY_OFFSET as u64,
        FrameGrantMailbox::REQUEST_GENERATION_OFFSET as u64,
        FrameGrantMailbox::FAULT_VA_OFFSET as u64,
        FrameGrantMailbox::REQUESTED_LEN_OFFSET as u64,
        FrameGrantMailbox::ACCESS_OFFSET as u64,
        FrameGrantMailbox::SEMANTIC_BASE_OFFSET as u64,
        FrameGrantMailbox::PHYSICAL_IPA_OFFSET as u64,
        FrameGrantMailbox::GRANTED_LEN_OFFSET as u64,
        FrameGrantMailbox::PERMISSIONS_OFFSET as u64,
        FrameGrantMailbox::FRAME_ID_OFFSET as u64,
        FrameGrantMailbox::MAPPING_ID_OFFSET as u64,
        FrameGrantMailbox::OWNER_GENERATION_OFFSET as u64,
        FrameGrantMailbox::INVENTORY_REVISION_OFFSET as u64,
        core::mem::size_of::<FrameGrantResidencyRecord>() as u64,
        core::mem::align_of::<FrameGrantResidencyRecord>() as u64,
        core::mem::size_of::<FrameGrantResidencyTable>() as u64,
        FrameGrantResidencyRecord::COMMITTED_OFFSET as u64,
        FrameGrantResidencyRecord::TRANSFER_PINS_OFFSET as u64,
        TRANSFER_PIN_RETIRED,
        EL1_ZONE_OFFSET,
        carrick_sched_core::HOST_REQUEST_PROTOCOL,
        carrick_sched_core::Claim::OnCpuRequested {
            slot: SlotId::new(0),
            seq: 0,
        }
        .encode(),
        // Claim protocol semantics participate even when record layout is
        // unchanged: older images must not decode a transfer as Free.
        carrick_sched_core::Claim::Transferring {
            seq: 0,
            cancelled: false,
            host_requested: false,
        }
        .encode(),
        carrick_sched_core::Claim::Transferring {
            seq: 0,
            cancelled: false,
            host_requested: true,
        }
        .encode(),
        carrick_sched_core::Claim::Transferring {
            seq: 0,
            cancelled: true,
            host_requested: false,
        }
        .encode(),
        carrick_sched_core::object_wait::OBJECT_WAIT_LAYOUT_HASH,
        core::mem::size_of::<ZoneTables>() as u64,
        core::mem::align_of::<ZoneTables>() as u64,
        core::mem::size_of::<ZoneRecord>() as u64,
        core::mem::size_of::<carrick_sched_core::ZoneSlot>() as u64,
        GIC_RESCHED_INTID as u64,
        GIC_KICK_INTID as u64,
        GIC_VTIMER_INTID as u64,
        core::mem::size_of::<ThreadCtx>() as u64,
        carrick_sched_core::THREAD_CTX_V_OFFSET as u64,
        carrick_sched_core::THREAD_CTX_FPSR_OFFSET as u64,
        carrick_sched_core::ZONE_RECORDS as u64,
        carrick_sched_core::ZONE_ENTRIES as u64,
        carrick_sched_core::ZONE_BUCKETS as u64,
        carrick_sched_core::ZONE_SLOTS as u64,
        carrick_sched_core::ZONE_SLOT_WORDS as u64,
        core::mem::size_of::<carrick_sched_core::ZoneCounters>() as u64,
        core::mem::offset_of!(ZoneTables, occupancy) as u64,
        core::mem::offset_of!(ZoneTables, spaces) as u64,
        core::mem::size_of::<carrick_sched_core::Occupancy>() as u64,
        core::mem::size_of::<carrick_sched_core::AddressSpaces>() as u64,
        core::mem::size_of::<carrick_sched_core::spaces::SpaceEntry>() as u64,
        core::mem::offset_of!(carrick_sched_core::spaces::SpaceEntry, mmap_next) as u64,
        core::mem::offset_of!(carrick_sched_core::spaces::SpaceEntry, brk_current) as u64,
        carrick_sched_core::ADDRESS_SPACES as u64,
        carrick_sched_core::EXECUTION_SLOTS as u64,
        carrick_sched_core::GATE_CLOSED,
        EL1_STACK_SLOTS,
        core::mem::size_of::<FdMapSlot>() as u64,
        core::mem::offset_of!(FdMapSlot, handle) as u64,
        core::mem::offset_of!(FdMapSlot, incarnation) as u64,
        core::mem::size_of::<DelegatedFile>() as u64,
        core::mem::align_of::<DelegatedFile>() as u64,
        core::mem::offset_of!(DelegatedFile, size) as u64,
        core::mem::offset_of!(DelegatedFile, dirty_mask) as u64,
        core::mem::offset_of!(DelegatedFile, notification_generation) as u64,
        core::mem::offset_of!(DelegatedFile, host_recall_generation) as u64,
        core::mem::offset_of!(DelegatedFile, host_recall_owed) as u64,
        core::mem::offset_of!(DelegatedFile, marks) as u64,
        core::mem::size_of::<DelegatedOpenFile>() as u64,
        core::mem::offset_of!(DelegatedOpenFile, inode_handle) as u64,
        core::mem::offset_of!(DelegatedOpenFile, host_fd) as u64,
        core::mem::offset_of!(DelegatedOpenFile, inode_generation) as u64,
        core::mem::offset_of!(DelegatedOpenFile, offset) as u64,
        core::mem::size_of::<DelegatedMark>() as u64,
        core::mem::size_of::<DelegatedWatch>() as u64,
        core::mem::size_of::<DelegatedInotify>() as u64,
        core::mem::offset_of!(DelegatedInotify, queued_bytes) as u64,
        core::mem::offset_of!(DelegatedInotify, host_observed) as u64,
        core::mem::offset_of!(DelegatedInotify, wake_owed) as u64,
        core::mem::offset_of!(DelegatedInotify, watches) as u64,
        core::mem::offset_of!(DelegatedInotify, queue) as u64,
        core::mem::size_of::<InotifyNameCache>() as u64,
    ];
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut i = 0;
    let txn_end = facts.len() + DESCRIPTOR_TXN_LAYOUT_FACTS.len();
    let cow_end = txn_end + COW_GRANT_LAYOUT_FACTS.len();
    while i < cow_end + THREAD_LIFECYCLE_LAYOUT_FACTS.len() {
        let mut word = if i < facts.len() {
            facts[i]
        } else if i < txn_end {
            DESCRIPTOR_TXN_LAYOUT_FACTS[i - facts.len()]
        } else if i < cow_end {
            COW_GRANT_LAYOUT_FACTS[i - txn_end]
        } else {
            THREAD_LIFECYCLE_LAYOUT_FACTS[i - cow_end]
        };
        let mut b = 0;
        while b < 8 {
            hash ^= word & 0xff;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            word >>= 8;
            b += 1;
        }
        i += 1;
    }
    let aperture_facts = [
        EL1_APERTURE_CONTROL_OFFSET,
        core::mem::size_of::<ApertureControl>() as u64,
        core::mem::align_of::<ApertureControl>() as u64,
        core::mem::offset_of!(ApertureControl, control) as u64,
        APERTURE_CONTROL_ARM_RING_FIRST_OPT_OUT,
        2, // control encoding: zero is strict; bit 3 opts out.
    ];
    let mut a = 0;
    while a < aperture_facts.len() {
        let mut word = aperture_facts[a];
        let mut b = 0;
        while b < 8 {
            hash ^= word & 0xff;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            word >>= 8;
            b += 1;
        }
        a += 1;
    }
    hash
};

/// Fixed header placed at the beginning of the `carrick-el1` binary image.
#[repr(C)]
#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub struct ImageHeader {
    /// Magic identifier (`b"CEL1"`).
    pub magic: [u8; 4],
    /// Header / ABI version (currently 1).
    pub version: u32,
    /// Offset from the start of the image to the `carrick_el1_syscall` entry point.
    pub entry_offset: u64,
    /// Total binary size of the loaded image in bytes.
    pub image_size: u64,
    /// Offset from the start of the image to the `u64` layout hash the
    /// image was built against ([`EL1_ABI_LAYOUT_HASH`]).
    pub abi_hash_offset: u64,
}

impl ImageHeader {
    /// Read and parse an [`ImageHeader`] from the beginning of a byte slice,
    /// safely handling any alignment.
    pub fn read_from_prefix(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[0..4]);
        let version = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
        let entry_offset = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
        let image_size = u64::from_le_bytes(bytes[16..24].try_into().ok()?);
        let abi_hash_offset = u64::from_le_bytes(bytes[24..32].try_into().ok()?);
        Some(Self {
            magic,
            version,
            entry_offset,
            image_size,
            abi_hash_offset,
        })
    }
}

/// Action returned by the EL1 kernel syscall dispatcher to the exception vector.
#[repr(u64)]
#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub enum Action {
    /// Sycall was serviced entirely at EL1 in-guest; restore registers and `eret` to EL0.
    Served = 0,
    /// Syscall was not handled at EL1; restore registers and fall through to host mailbox capture.
    Forward = 1,
    /// Syscall was serviced at EL1, but return-to-user host work is pending; take the forward path
    /// with the completed result in frame.x0 to deliver to the host without replaying the syscall.
    ServedWithWork = 2,
    /// The syscall parked its thread, nothing else was runnable, and host
    /// work arrived while the vCPU idled in EL1: leave through the host with
    /// no thread on the vCPU (`hvc #5`). The parked thread's context is in its
    /// zone record.
    Idle = 3,
}

/// Register trap frame saved by the exception vector before calling `carrick_el1_syscall`.
#[repr(C)]
#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
    ::core::default::Default,
)]
pub struct TrapFrame {
    /// General-purpose registers x0 through x30.
    pub x: [u64; 31],
    /// Exception Link Register (PC where the exception was taken).
    pub elr: u64,
    /// Saved Program Status Register.
    pub spsr: u64,
    /// Exception Syndrome Register.
    pub esr: u64,
    /// Syscall mailbox / vCPU slot index derived from SP_EL1.
    pub slot: u64,
    /// Fault Address Register (FAR_EL1) for data/instruction aborts.
    pub far: u64,
}
impl carrick_guest_arch::SyscallFrame for TrapFrame {
    fn canonical_ordinal(&self) -> carrick_guest_arch::CanonicalNr {
        carrick_guest_arch::CanonicalNr::new(self.x[8])
    }
    fn argument(&self, index: usize) -> Option<u64> {
        self.x.get(index).copied()
    }
    fn result(&self) -> carrick_guest_arch::NativeReturnWord {
        carrick_guest_arch::NativeReturnWord(self.x[0])
    }
    fn set_result(&mut self, result: carrick_guest_arch::NativeReturnWord) {
        self.x[0] = result.0;
    }
    fn slot(&self) -> Option<carrick_guest_arch::SlotId> {
        usize::try_from(self.slot)
            .ok()
            .and_then(carrick_guest_arch::SlotId::from_index)
    }
    fn user_sp(&self) -> Option<carrick_guest_arch::UserVa> {
        None
    }
}
const _: () = {
    assert!(core::mem::offset_of!(TrapFrame, x) == 0);
    assert!(core::mem::offset_of!(TrapFrame, elr) == 248);
    assert!(core::mem::offset_of!(TrapFrame, spsr) == 256);
    assert!(core::mem::offset_of!(TrapFrame, esr) == 264);
    assert!(core::mem::offset_of!(TrapFrame, slot) == 272);
    assert!(core::mem::offset_of!(TrapFrame, far) == 280);
    assert!(core::mem::size_of::<TrapFrame>() == 288);
};

pub use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Linux thread identity as published into a [`CurrentTask`] record.
///
/// The record stores a `u64` word; this newtype is the only way to produce or
/// compare that word, so a bare `tid as u64` (which sign-extends) can never
/// cross the host/EL1 boundary. `NONE` (0) means no task is bound.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
    ::core::fmt::Debug,
    ::core::default::Default,
)]
#[repr(transparent)]
pub struct El1TaskId(u64);

impl From<carrick_sched_core::process::TaskId> for El1TaskId {
    fn from(id: carrick_sched_core::process::TaskId) -> Self {
        Self::from_linux_tid(id.raw())
    }
}

impl El1TaskId {
    /// No task bound to the slot.
    pub const NONE: Self = Self(0);

    /// Zero-extend a Linux tid (always positive) into the record word.
    pub const fn from_linux_tid(tid: i32) -> Self {
        Self(tid as u32 as u64)
    }

    /// The record word.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Per-vCPU slot task record published by the host runtime before running
/// a vCPU and cleared when unloaded.
#[repr(C, align(8))]
#[derive(::core::fmt::Debug)]
pub struct CurrentTask {
    pub execution: ExecutionIdentity,
    pub linux: LinuxTaskState,
    pub mm: ExecutionMm,
    pub metadata: LinuxTaskMetadata,
    _stride_padding: [u64; 5],
}

pub const CURRENT_TASK_STRIDE_SHIFT: u32 = 7;
const _: () = assert!(core::mem::size_of::<CurrentTask>() == 1 << CURRENT_TASK_STRIDE_SHIFT);

const _: () = {
    assert!(core::mem::align_of::<CurrentTask>() == 8);
    assert!(core::mem::offset_of!(CurrentTask, execution.generation) == 0);
    assert!(core::mem::offset_of!(CurrentTask, execution.task) == 8);
    assert!(core::mem::offset_of!(CurrentTask, linux.file_table) == 16);
    assert!(core::mem::offset_of!(CurrentTask, linux.fixup_pc) == 24);
    assert!(core::mem::offset_of!(CurrentTask, linux.orig_arg0) == 32);
    assert!(core::mem::offset_of!(CurrentTask, linux.pending_host_work) == 40);
    assert!(core::mem::offset_of!(CurrentTask, linux.served_with_work) == 44);
    assert!(core::mem::offset_of!(CurrentTask, mm.key) == 48);
    assert!(core::mem::offset_of!(CurrentTask, mm.thread_generation) == 56);
    assert!(core::mem::offset_of!(CurrentTask, metadata.lifecycle_page) == 64);
    assert!(core::mem::offset_of!(CurrentTask, metadata.control_slot) == 72);
    assert!(core::mem::offset_of!(CurrentTask, metadata.visible_pid) == 80);
};

impl CurrentTask {
    pub const fn new() -> Self {
        Self {
            execution: ExecutionIdentity::new(),
            linux: LinuxTaskState::new(),
            mm: ExecutionMm::new(),
            metadata: LinuxTaskMetadata::new(),
            _stride_padding: [0; 5],
        }
    }

    /// The lifecycle page and control slot published for the running task.
    ///
    /// Both addresses live in the retained EL1 metadata window. Keeping the
    /// validation here gives substrate schedulers and Linux-personality code
    /// one typed boundary for the host-published addresses.
    pub fn lifecycle_refs(&self) -> Option<(&ThreadLifecyclePage, &ThreadControlSlot)> {
        let page = self.metadata.lifecycle_page.load(Ordering::Acquire);
        let slot = self.metadata.control_slot.load(Ordering::Acquire);
        let expected_base = {
            #[cfg(all(target_os = "none", target_arch = "x86_64"))]
            {
                X86_CPL0_DYNAMIC_METADATA_BASE
            }
            #[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
            {
                EL1_DYNAMIC_METADATA_BASE
            }
        };
        let contains = |address: u64, len: usize| {
            address >= expected_base
                && address
                    .checked_add(len as u64)
                    .is_some_and(|end| end <= expected_base + EL1_DYNAMIC_METADATA_SIZE)
        };
        if !page.is_multiple_of(16384)
            || !slot.is_multiple_of(core::mem::align_of::<ThreadControlSlot>() as u64)
            || !contains(page, core::mem::size_of::<ThreadLifecyclePage>())
            || !contains(slot, core::mem::size_of::<ThreadControlSlot>())
        {
            return None;
        }
        // SAFETY: only the runtime publishes these EL1-only addresses; its
        // carrier owner pins both allocations while this task is runnable.
        Some(unsafe {
            (
                &*(page as *const ThreadLifecyclePage),
                &*(slot as *const ThreadControlSlot),
            )
        })
    }

    /// Publication belongs to the loaded task, never to the executor itself.
    pub fn publish_lifecycle(&self, page: u64, slot: u64) {
        self.metadata.control_slot.store(slot, Ordering::Relaxed);
        self.metadata.lifecycle_page.store(page, Ordering::Release);
    }

    /// The process leader's namespace PID, shared by every thread in its
    /// process and cleared before a task slot is reused.
    pub fn publish_visible_pid(&self, pid: u32) {
        self.metadata.visible_pid.store(pid, Ordering::Release);
    }

    pub fn visible_pid(&self) -> Option<u32> {
        let pid = self.metadata.visible_pid.load(Ordering::Acquire);
        (pid != 0).then_some(pid)
    }

    #[inline]
    pub fn clear(&self) {
        self.linux.file_table.store(0, Ordering::Release);
        self.execution.generation.store(0, Ordering::Release);
        self.execution.task.store(0, Ordering::Release);
        self.linux.fixup_pc.store(0, Ordering::Relaxed);
        self.linux.orig_arg0.store(0, Ordering::Relaxed);
        self.linux.pending_host_work.store(0, Ordering::Release);
        self.linux.served_with_work.store(0, Ordering::Release);
        self.mm.key.store(0, Ordering::Release);
        self.mm.thread_generation.store(0, Ordering::Release);
        self.publish_lifecycle(0, 0);
        self.publish_visible_pid(0);
    }

    #[inline]
    pub fn set(&self, task_id: El1TaskId, generation: u64, file_table: u64) {
        self.execution.task.store(task_id.raw(), Ordering::Relaxed);
        self.execution
            .generation
            .store(generation, Ordering::Release);
        self.linux.file_table.store(file_table, Ordering::Release);
    }
}

impl Default for CurrentTask {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub struct MetadataGrantRequest {
    pub op: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub cookie: u64,
}

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub struct MetadataGrantResponse {
    pub op: u64,
    pub status: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub cookie: u64,
}

/// One carrier-wide single-flight request. The allocator lock serializes guest
/// publication/consumption; the state word transfers ownership to and from the
/// host with release/acquire ordering. Host service happens only after EL1 has
/// unwound to its normal pending-host-work boundary.
#[repr(C, align(64))]
#[derive(::core::fmt::Debug)]
pub struct MetadataGrantMailbox {
    pub state: AtomicU32,
    op: AtomicU32,
    status: AtomicU64,
    arg1: AtomicU64,
    arg2: AtomicU64,
    arg3: AtomicU64,
    cookie: AtomicU64,
    request_generation: AtomicU64,
}

impl MetadataGrantMailbox {
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(METADATA_MAILBOX_IDLE),
            op: AtomicU32::new(0),
            status: AtomicU64::new(METADATA_GRANT_ERR_INVALID),
            arg1: AtomicU64::new(0),
            arg2: AtomicU64::new(0),
            arg3: AtomicU64::new(0),
            cookie: AtomicU64::new(0),
            request_generation: AtomicU64::new(0),
        }
    }

    pub fn request_generation(&self) -> u64 {
        self.request_generation.load(Ordering::Acquire)
    }

    pub fn try_publish_request(&self, request: MetadataGrantRequest) -> bool {
        self.try_publish_request_prepared(request, |_| true)
    }

    /// Bind the wait queue before the host can claim this incarnation.
    pub fn try_publish_request_prepared(
        &self,
        request: MetadataGrantRequest,
        prepare: impl FnOnce(u64) -> bool,
    ) -> bool {
        let Ok(op) = u32::try_from(request.op) else {
            return false;
        };
        if self
            .state
            .compare_exchange(
                METADATA_MAILBOX_IDLE,
                METADATA_MAILBOX_GUEST_WRITING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        let Some(generation) = self
            .request_generation
            .load(Ordering::Relaxed)
            .checked_add(1)
        else {
            self.state.store(METADATA_MAILBOX_IDLE, Ordering::Release);
            return false;
        };
        if !prepare(generation) {
            self.state.store(METADATA_MAILBOX_IDLE, Ordering::Release);
            return false;
        }
        self.request_generation.store(generation, Ordering::Relaxed);
        self.op.store(op, Ordering::Relaxed);
        self.status
            .store(METADATA_GRANT_ERR_INVALID, Ordering::Relaxed);
        self.arg1.store(request.arg1, Ordering::Relaxed);
        self.arg2.store(request.arg2, Ordering::Relaxed);
        self.arg3.store(request.arg3, Ordering::Relaxed);
        self.cookie.store(request.cookie, Ordering::Relaxed);
        self.state
            .store(METADATA_MAILBOX_REQUESTED, Ordering::Release);
        true
    }

    pub fn claim_request(&self) -> Option<MetadataGrantRequest> {
        self.state
            .compare_exchange(
                METADATA_MAILBOX_REQUESTED,
                METADATA_MAILBOX_HOST_WORKING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;
        Some(MetadataGrantRequest {
            op: self.op.load(Ordering::Relaxed) as u64,
            arg1: self.arg1.load(Ordering::Relaxed),
            arg2: self.arg2.load(Ordering::Relaxed),
            arg3: self.arg3.load(Ordering::Relaxed),
            cookie: self.cookie.load(Ordering::Relaxed),
        })
    }

    pub fn publish_response(&self, status: u64, arg1: u64, arg2: u64, arg3: u64) {
        debug_assert_eq!(
            self.state.load(Ordering::Acquire),
            METADATA_MAILBOX_HOST_WORKING
        );
        self.status.store(status, Ordering::Relaxed);
        // FREE completion preserves the exact request identity. Backend
        // status carries no authority to substitute a successor extent.
        if self.op.load(Ordering::Relaxed) as u64 != METADATA_GRANT_OP_FREE {
            self.arg1.store(arg1, Ordering::Relaxed);
            self.arg2.store(arg2, Ordering::Relaxed);
            self.arg3.store(arg3, Ordering::Relaxed);
        }
        self.state
            .store(METADATA_MAILBOX_RESPONSE, Ordering::Release);
    }

    pub fn claim_response(&self) -> Option<MetadataGrantResponse> {
        self.state
            .compare_exchange(
                METADATA_MAILBOX_RESPONSE,
                METADATA_MAILBOX_GUEST_CONSUMING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;
        Some(MetadataGrantResponse {
            op: self.op.load(Ordering::Relaxed) as u64,
            status: self.status.load(Ordering::Relaxed),
            arg1: self.arg1.load(Ordering::Relaxed),
            arg2: self.arg2.load(Ordering::Relaxed),
            arg3: self.arg3.load(Ordering::Relaxed),
            cookie: self.cookie.load(Ordering::Relaxed),
        })
    }

    pub fn finish_response(&self) {
        debug_assert_eq!(
            self.state.load(Ordering::Acquire),
            METADATA_MAILBOX_GUEST_CONSUMING
        );
        self.state.store(METADATA_MAILBOX_IDLE, Ordering::Release);
    }

    pub fn has_guest_work(&self) -> bool {
        self.state.load(Ordering::Acquire) != METADATA_MAILBOX_IDLE
    }
}

/// Host completion publishes under the exact request's waiter queue lock.
/// The implementation delivers record wakes only after that lock is released.
pub trait MetadataCompletionWake: Send + Sync + core::fmt::Debug {
    fn publish_and_wake(&self, mailbox: &MetadataGrantMailbox, generation: u64, response: [u64; 4]);
}

impl Default for MetadataGrantMailbox {
    fn default() -> Self {
        Self::new()
    }
}

/// Lifecycle state of a delegated file object in the EL1 object table: Dead.
pub const DELEGATED_STATE_DEAD: u32 = 0;
/// Lifecycle state of a delegated file object in the EL1 object table: Guest-owned.
pub const DELEGATED_STATE_GUEST: u32 = 1;
/// Lifecycle state of a delegated file object in the EL1 object table: Being recalled by host.
pub const DELEGATED_STATE_RECALLING: u32 = 2;

/// File access flag: Readable.
pub const DELEGATED_FLAG_READABLE: u32 = 1 << 0;
/// File access flag: Writable.
pub const DELEGATED_FLAG_WRITABLE: u32 = 1 << 1;
/// File access flag: Append.
pub const DELEGATED_FLAG_APPEND: u32 = 1 << 2;

/// Maximum number of simultaneously delegated files.
pub const MAX_DELEGATED_FILES: usize = carrick_sched_core::object_wait::DELEGATED_FILE_WAIT_QUEUES;

/// Maximum size of a delegated regular file (256 KiB).
pub const DELEGATED_FILE_MAX_SIZE: u64 = 256 * 1024;

/// Page size used for delegated cache pages (4 KiB).
pub const DELEGATED_PAGE_SIZE: u64 = 4096;

/// Number of 4 KiB pages per delegated file cache (64 pages).
pub const DELEGATED_MAX_PAGES: usize = 64;

/// Capacity of the EL1 fd map (512 slots).
pub const FD_MAP_CAPACITY: usize = 512;

/// Inode identity of a delegated file matching the host inotify model.
#[repr(C)]
#[derive(::core::fmt::Debug, ::core::default::Default)]
pub struct DelegatedInodeIdentity {
    pub dev: AtomicU64,
    pub ino: AtomicU64,
}

impl DelegatedInodeIdentity {
    pub const fn new(dev: u64, ino: u64) -> Self {
        Self {
            dev: AtomicU64::new(dev),
            ino: AtomicU64::new(ino),
        }
    }

    #[inline]
    pub fn get(&self) -> (u64, u64) {
        (
            self.dev.load(Ordering::Relaxed),
            self.ino.load(Ordering::Relaxed),
        )
    }

    #[inline]
    pub fn set(&self, dev: u64, ino: u64) {
        self.dev.store(dev, Ordering::Relaxed);
        self.ino.store(ino, Ordering::Relaxed);
    }
}

/// In-guest notification mark attached to a delegated file.
#[repr(C)]
#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
    ::core::default::Default,
)]
pub struct DelegatedMark {
    pub inotify_handle: u32,
    pub wd: i32,
    pub mask: u32,
    pub _pad: u32,
}

/// Maximum in-guest notification marks attached to a single delegated file.
pub const MAX_DELEGATED_MARKS_PER_FILE: usize = 8;

/// EL1 object table entry representing a delegated regular file.
#[repr(C)]
#[repr(align(64))]
pub struct DelegatedFile {
    /// Object lifecycle state: Dead (0), Guest (1), Recalling (2).
    pub state: AtomicU32,
    /// Spinlock word usable by both host and guest: 0 = unlocked, 1 = locked.
    pub lock: AtomicU32,
    /// Owner generation word.
    pub generation: AtomicU64,
    /// Formerly the offset: offsets belong to each open file
    /// ([`DelegatedOpenFile`]), never to the inode.
    pub _reserved_offset: u64,
    /// Current file size in bytes.
    pub size: AtomicU64,
    /// Formerly the access flags: they belong to each open file.
    pub _reserved_flags: u32,
    pub _reserved0: u32,
    /// 64-bit dirty page mask (bit i indicates 4 KiB page i is dirty).
    pub dirty_mask: AtomicU64,
    /// 64-bit zero-filled gap page mask (bit i indicates 4 KiB page i was zero-filled on extension and never written).
    pub zero_filled_mask: AtomicU64,
    /// Exact incarnation of the detached notification source base pin.
    /// Admission and retirement are protected by this inode's lock.
    pub(crate) notification_generation: AtomicU64,
    /// Exact host inode identity for inotify correspondence.
    pub inode: DelegatedInodeIdentity,
    /// Count of active marks currently attached.
    pub num_marks: AtomicU32,
    pub _reserved1: u32,
    /// Fixed table of active marks attached to this file.
    pub marks: UnsafeCell<[DelegatedMark; MAX_DELEGATED_MARKS_PER_FILE]>,
    /// Exact owner-only recall subscription and its owed release edge.
    pub(crate) host_recall_generation: AtomicU64,
    pub(crate) host_recall_owed: AtomicU64,
    pub _pad: [u8; 24],
}

unsafe impl Sync for DelegatedFile {}

/// A descriptor in the carrier's host file table, distinct from a guest fd
/// and from a delegated inode identity.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
#[repr(transparent)]
pub struct HostBoundFd(i32);

impl HostBoundFd {
    pub const STDOUT: Self = Self(1);
    pub const STDERR: Self = Self(2);

    pub const fn new(raw: i32) -> Option<Self> {
        if raw < 0 { None } else { Some(Self(raw)) }
    }

    pub const fn raw(self) -> i32 {
        self.0
    }
}

/// Host-owned object identity. Stdio streams keep the dispatcher's chosen
/// Captured/Piped/Inherit route; they are not carrier descriptor numbers.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
#[repr(transparent)]
pub struct HostObjectBinding(u32);

impl HostObjectBinding {
    pub const STDIN: Self = Self(1);
    pub const STDOUT: Self = Self(2);
    pub const STDERR: Self = Self(3);

    pub const fn from_encoded(encoded: u32) -> Option<Self> {
        if encoded == 0 {
            None
        } else {
            Some(Self(encoded))
        }
    }

    pub const fn from_host_fd(fd: HostBoundFd) -> Self {
        Self(fd.raw() as u32 + 4)
    }

    pub const fn encoded(self) -> u32 {
        self.0
    }

    pub const fn stdio_fd(self) -> Option<i32> {
        if self.0 >= 1 && self.0 <= 3 {
            Some(self.0 as i32 - 1)
        } else {
            None
        }
    }

    pub const fn host_fd(self) -> Option<HostBoundFd> {
        if self.0 < 4 {
            None
        } else {
            HostBoundFd::new((self.0 - 4) as i32)
        }
    }
}

/// One open description of an in-zone inode (open(2): an open file
/// description has its own offset and status flags; every description of an
/// inode shares its bytes). Guarded by its inode's lock.
#[repr(C, align(64))]
#[derive(::core::fmt::Debug)]
pub struct DelegatedOpenFile {
    /// Dead (0) or Guest (1).
    pub state: AtomicU32,
    /// Access flags (`DELEGATED_FLAG_*`).
    pub flags: AtomicU32,
    /// This record's incarnation; the fd map publishes it.
    pub generation: AtomicU64,
    /// 1-based handle of the inode record ([`DelegatedFile`]).
    pub inode_handle: AtomicU32,
    /// Host object binding: 1..3 are the dispatcher's stdio routes, and
    /// values >= 4 name explicit host descriptors as fd + 4.
    host_fd: AtomicU32,
    /// The inode's generation when this record joined it: an inode handle
    /// reused by another inode never matches.
    pub inode_generation: AtomicU64,
    /// Current file offset of this description.
    pub offset: AtomicU64,
    pub _pad: [u64; 3],
}

impl DelegatedOpenFile {
    pub fn bind_host_fd(&self, fd: HostBoundFd) {
        self.host_fd.store(fd.raw() as u32 + 4, Ordering::Release);
    }

    pub fn bind_host_object(&self, binding: HostObjectBinding) {
        self.host_fd.store(binding.encoded(), Ordering::Release);
    }

    pub fn host_object(&self) -> Option<HostObjectBinding> {
        HostObjectBinding::from_encoded(self.host_fd.load(Ordering::Acquire))
    }

    pub fn host_fd(&self) -> Option<HostBoundFd> {
        let encoded = self.host_fd.load(Ordering::Acquire);
        if encoded < 4 {
            None
        } else {
            HostBoundFd::new((encoded - 4) as i32)
        }
    }

    /// Clear the binding before publishing a reused description as live.
    pub fn clear_host_fd(&self) {
        self.host_fd.store(0, Ordering::Release);
    }

    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(DELEGATED_STATE_DEAD),
            flags: AtomicU32::new(0),
            generation: AtomicU64::new(0),
            inode_handle: AtomicU32::new(0),
            host_fd: AtomicU32::new(0),
            inode_generation: AtomicU64::new(0),
            offset: AtomicU64::new(0),
            _pad: [0; 3],
        }
    }

    /// Whether this record is live and still bound to `inode`'s current
    /// incarnation. The caller holds `inode`'s lock.
    #[inline]
    pub fn is_bound_to(&self, inode: &DelegatedFile) -> bool {
        self.state.load(Ordering::Acquire) == DELEGATED_STATE_GUEST
            && inode.state.load(Ordering::Acquire) == DELEGATED_STATE_GUEST
            && self.inode_generation.load(Ordering::Acquire)
                == inode.generation.load(Ordering::Acquire)
    }
}

impl Default for DelegatedOpenFile {
    fn default() -> Self {
        Self::new()
    }
}

const _: () = assert!(core::mem::size_of::<DelegatedOpenFile>() == 64);
const _: () = assert!(
    MAX_ZONE_OPEN_FILES as u64 * core::mem::size_of::<DelegatedOpenFile>() as u64
        <= EL1_OPEN_FILE_TABLE_SIZE
);
const _: () = assert!(EL1_OPEN_FILE_TABLE_OFFSET + EL1_OPEN_FILE_TABLE_SIZE <= EL1_CACHE_OFFSET);

impl DelegatedFile {
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(DELEGATED_STATE_DEAD),
            lock: AtomicU32::new(0),
            generation: AtomicU64::new(0),
            _reserved_offset: 0,
            size: AtomicU64::new(0),
            _reserved_flags: 0,
            _reserved0: 0,
            dirty_mask: AtomicU64::new(0),
            zero_filled_mask: AtomicU64::new(0),
            notification_generation: AtomicU64::new(0),
            inode: DelegatedInodeIdentity::new(0, 0),
            num_marks: AtomicU32::new(0),
            _reserved1: 0,
            marks: UnsafeCell::new(
                [const {
                    DelegatedMark {
                        inotify_handle: 0,
                        wd: 0,
                        mask: 0,
                        _pad: 0,
                    }
                }; MAX_DELEGATED_MARKS_PER_FILE],
            ),
            host_recall_generation: AtomicU64::new(0),
            host_recall_owed: AtomicU64::new(0),
            _pad: [0; 24],
        }
    }

    /// Clear all marks from this file.
    pub fn clear_marks(&self) {
        let marks = unsafe { &mut *self.marks.get() };
        for m in marks.iter_mut() {
            *m = DelegatedMark::default();
        }
        self.num_marks.store(0, Ordering::Release);
    }

    /// Remove all marks belonging to a specific inotify handle.
    pub fn remove_marks_for_inotify(&self, inotify_handle: u32) {
        let marks = unsafe { &mut *self.marks.get() };
        let mut count = 0;
        for m in marks.iter_mut() {
            if m.inotify_handle == inotify_handle {
                *m = DelegatedMark::default();
                count += 1;
            }
        }
        if count > 0 {
            self.num_marks.fetch_sub(count, Ordering::Release);
        }
    }

    /// Attach a mark to this delegated file.
    pub fn add_mark(&self, mark: DelegatedMark) -> bool {
        let marks = unsafe { &mut *self.marks.get() };
        for m in marks.iter() {
            if m.inotify_handle == mark.inotify_handle && m.wd == mark.wd {
                return true;
            }
        }
        for m in marks.iter_mut() {
            if m.inotify_handle == 0 {
                *m = mark;
                self.num_marks.fetch_add(1, Ordering::Release);
                return true;
            }
        }
        false
    }

    /// Detach a mark from this delegated file.
    pub fn remove_mark(&self, inotify_handle: u32, wd: i32) -> bool {
        let marks = unsafe { &mut *self.marks.get() };
        for m in marks.iter_mut() {
            if m.inotify_handle == inotify_handle && m.wd == wd {
                *m = DelegatedMark::default();
                self.num_marks.fetch_sub(1, Ordering::Release);
                return true;
            }
        }
        false
    }

    /// Iterate over active marks.
    pub fn for_each_mark<F: FnMut(&DelegatedMark)>(&self, mut f: F) {
        let marks = unsafe { &*self.marks.get() };
        for m in marks.iter() {
            if m.inotify_handle != 0 {
                f(m);
            }
        }
    }

    /// Whether any marks are currently attached.
    #[inline]
    pub fn has_marks(&self) -> bool {
        self.num_marks.load(Ordering::Acquire) > 0
    }

    /// Try to acquire the spinlock without blocking.
    /// Guest calls this; if it returns `false`, guest must FORWARD.
    #[inline]
    pub fn try_lock(&self) -> bool {
        // Strong: a spurious LL/SC failure must not look like contention.
        self.lock
            .compare_exchange(0, LOCK_GUEST, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// EL1 acquire: wait a bounded while only for another vCPU's in-guest
    /// critical section (short, and completed even across kicks); a host
    /// holder may be a long recall, so forward at once. Bounded, so a lock
    /// order inversion between vCPUs costs a forward, never a deadlock.
    #[inline]
    pub fn lock_guest_bounded(&self, max_spins: u32) -> bool {
        for _ in 0..max_spins {
            match self
                .lock
                .compare_exchange(0, LOCK_GUEST, Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(LOCK_HOST) => return false,
                Err(_) => core::hint::spin_loop(),
            }
        }
        false
    }

    /// Release the spinlock.
    #[inline]
    pub fn unlock(&self) {
        assert_eq!(
            self.notification_generation.load(Ordering::Acquire),
            0,
            "admitted delegated inode requires owned release custody"
        );
        self.lock.store(0, Ordering::Release);
    }

    /// Check if the lock is currently held.
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.lock.load(Ordering::Relaxed) != 0
    }

    /// Host spin-waits until the lock is acquired, up to a bounded spin limit.
    /// Returns true if locked, false if timed out / exceeded max spins.
    pub fn host_lock_bounded(&self, max_spins: u64) -> bool {
        for _ in 0..max_spins {
            if self
                .lock
                .compare_exchange(0, LOCK_HOST, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }
}

impl Default for DelegatedFile {
    fn default() -> Self {
        Self::new()
    }
}

/// Mapping from `(file_table, fd)` to a 1-based delegated file `handle` and its host incarnation.
#[repr(C)]
#[derive(::core::fmt::Debug)]
pub struct FdMapSlot {
    /// Owning FileTableId (0 = empty).
    pub file_table: AtomicU64,
    /// Guest file descriptor number.
    pub fd: AtomicU32,
    /// 1-based delegated file handle (0 = empty).
    pub handle: AtomicU32,
    /// Host-assigned incarnation of the delegated file.
    pub incarnation: AtomicU64,
    /// Per-descriptor flags; these are not open-description status flags.
    pub fd_flags: AtomicU32,
}

impl FdMapSlot {
    /// Reserved while a publisher fills a vacant slot; never a live incarnation.
    pub const CLAIMED: u64 = u64::MAX;

    #[inline]
    pub fn try_claim(&self) -> bool {
        self.incarnation
            .compare_exchange(0, Self::CLAIMED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
    pub const fn new() -> Self {
        Self {
            file_table: AtomicU64::new(0),
            fd: AtomicU32::new(0),
            handle: AtomicU32::new(0),
            incarnation: AtomicU64::new(0),
            fd_flags: AtomicU32::new(0),
        }
    }

    #[inline]
    pub fn clear(&self) {
        self.incarnation.store(Self::CLAIMED, Ordering::Release);
        self.handle.store(0, Ordering::Relaxed);
        self.fd.store(0, Ordering::Relaxed);
        self.file_table.store(0, Ordering::Relaxed);
        self.fd_flags.store(0, Ordering::Relaxed);
        self.incarnation.store(0, Ordering::Release);
    }

    #[inline]
    pub fn set(&self, file_table: u64, fd: u32, handle: u32, incarnation: u64) {
        self.set_with_flags(file_table, fd, handle, incarnation, 0);
    }

    #[inline]
    pub fn set_with_flags(
        &self,
        file_table: u64,
        fd: u32,
        handle: u32,
        incarnation: u64,
        fd_flags: u32,
    ) {
        self.file_table.store(file_table, Ordering::Relaxed);
        self.fd.store(fd, Ordering::Relaxed);
        self.handle.store(handle, Ordering::Relaxed);
        self.fd_flags.store(fd_flags, Ordering::Relaxed);
        self.incarnation.store(incarnation, Ordering::Release);
    }
}

impl Default for FdMapSlot {
    fn default() -> Self {
        Self::new()
    }
}

/// Flag set on `handle` indicating the slot references a delegated inotify instance.
pub const FD_HANDLE_INOTIFY_TAG: u32 = 0x8000_0000;

/// Kind of delegated object bound to an fd-map slot.
#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub enum FdSlotKind {
    File(u32),
    Inotify(u32),
}

/// Lookup a delegated file handle and slot index for a given `(file_table, fd)`.
pub fn fd_map_lookup(map: &[FdMapSlot], file_table: u64, fd: i32) -> Option<(u32, usize)> {
    if file_table == 0 || fd < 0 {
        return None;
    }
    let ufd = fd as u32;
    for (idx, slot) in map.iter().take(FD_MAP_CAPACITY).enumerate() {
        let inc = slot.incarnation.load(Ordering::Acquire);
        if inc != 0
            && inc != FdMapSlot::CLAIMED
            && slot.fd.load(Ordering::Relaxed) == ufd
            && slot.file_table.load(Ordering::Relaxed) == file_table
        {
            let h = slot.handle.load(Ordering::Relaxed);
            if h != 0 && (h & FD_HANDLE_INOTIFY_TAG) == 0 {
                return Some((h, idx));
            }
        }
    }
    None
}

/// Lookup a delegated inotify handle and slot index for a given `(file_table, fd)`.
pub fn fd_map_lookup_inotify(map: &[FdMapSlot], file_table: u64, fd: i32) -> Option<(u32, usize)> {
    if file_table == 0 || fd < 0 {
        return None;
    }
    let ufd = fd as u32;
    for (idx, slot) in map.iter().take(FD_MAP_CAPACITY).enumerate() {
        let inc = slot.incarnation.load(Ordering::Acquire);
        if inc != 0
            && inc != FdMapSlot::CLAIMED
            && slot.fd.load(Ordering::Relaxed) == ufd
            && slot.file_table.load(Ordering::Relaxed) == file_table
        {
            let h = slot.handle.load(Ordering::Relaxed);
            if (h & FD_HANDLE_INOTIFY_TAG) != 0 {
                return Some((h & !FD_HANDLE_INOTIFY_TAG, idx));
            }
        }
    }
    None
}

/// Lookup either kind of delegated descriptor handle.
pub fn fd_map_lookup_kind(
    map: &[FdMapSlot],
    file_table: u64,
    fd: i32,
) -> Option<(FdSlotKind, usize)> {
    if file_table == 0 || fd < 0 {
        return None;
    }
    let ufd = fd as u32;
    for (idx, slot) in map.iter().take(FD_MAP_CAPACITY).enumerate() {
        let inc = slot.incarnation.load(Ordering::Acquire);
        if inc != 0
            && inc != FdMapSlot::CLAIMED
            && slot.fd.load(Ordering::Relaxed) == ufd
            && slot.file_table.load(Ordering::Relaxed) == file_table
        {
            let h = slot.handle.load(Ordering::Relaxed);
            if h != 0 {
                let kind = if (h & FD_HANDLE_INOTIFY_TAG) != 0 {
                    FdSlotKind::Inotify(h & !FD_HANDLE_INOTIFY_TAG)
                } else {
                    FdSlotKind::File(h)
                };
                return Some((kind, idx));
            }
        }
    }
    None
}

/// Calculate the guest virtual address of a delegated file's cache.
#[inline]
pub const fn delegated_file_cache_va(handle: u32) -> u64 {
    EL1_CACHE_BASE + ((handle - 1) as u64) * DELEGATED_FILE_MAX_SIZE
}

/// Total size of the EL1 kernel image area (1 MiB).
pub const EL1_IMAGE_SIZE: u64 = 0x10_0000;

/// Total size of the EL1 kernel counters area (1 MiB).
pub const EL1_COUNTERS_SIZE: u64 = 0x10_0000;

/// Total size of the EL1 kernel stacks area (4 MiB).
pub const EL1_STACKS_SIZE: u64 = 0x40_0000;

/// Sentinel value written by `carrick-el1` panic handler into [`Counters`] before spinning.
pub const PANIC_SENTINEL: u64 = 0xDEAD_CAFE_DEAD_BEEF;

/// Syscall counter index used by the panic handler to store the sentinel.
pub const PANIC_SENTINEL_SYSCALL_NR: usize = 511;

/// Stable classes for one `hv_vcpu_run` return. The host increments exactly
/// one class at the return boundary, including exits it resumes internally.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
#[repr(usize)]
pub enum HostExitClass {
    Canceled,
    Idle,
    Kick,
    Syscall,
    Metadata,
    Maintenance,
    Fault,
    Other,
}

impl HostExitClass {
    pub const COUNT: usize = 8;

    /// Every class in ordinal order: `ALL[c.ordinal() as usize] == c`. The
    /// ordinal is the wire value of the `vcpu-run-exit` USDT probe, so a
    /// trace reader decodes it here instead of keeping its own copy.
    pub const ALL: [Self; Self::COUNT] = [
        Self::Canceled,
        Self::Idle,
        Self::Kick,
        Self::Syscall,
        Self::Metadata,
        Self::Maintenance,
        Self::Fault,
        Self::Other,
    ];

    /// The stable wire ordinal (also the index of the exit counters).
    pub const fn ordinal(self) -> u32 {
        self as u32
    }

    /// Decode a wire ordinal; `None` for a value no class carries.
    pub const fn from_ordinal(ordinal: u32) -> Option<Self> {
        if (ordinal as usize) < Self::COUNT {
            Some(Self::ALL[ordinal as usize])
        } else {
            None
        }
    }

    /// Stable kebab-case name used in trace summaries.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Canceled => "canceled",
            Self::Idle => "idle",
            Self::Kick => "kick",
            Self::Syscall => "syscall",
            Self::Metadata => "metadata",
            Self::Maintenance => "maintenance",
            Self::Fault => "fault",
            Self::Other => "other",
        }
    }

    /// `exception` means HVF reported EXCEPTION; `canceled` means CANCELED.
    /// The syndrome is authoritative only for EXCEPTION. Keep every unknown
    /// exception in `Fault` so the accounting remains exhaustive.
    pub const fn from_hvf(canceled: bool, exception: bool, syndrome: u64) -> Self {
        if canceled {
            return Self::Canceled;
        }
        if !exception {
            return Self::Other;
        }
        match ((syndrome >> 26) & 0x3f, syndrome & 0xffff) {
            (0x16, 5) => Self::Idle,
            (0x16, 4) => Self::Kick,
            (0x16, 2) | (0x15, _) => Self::Syscall,
            (0x16, 6) => Self::Metadata,
            (0x16, 1) => Self::Maintenance,
            _ => Self::Fault,
        }
    }
}

/// Saved ESR_EL1 reason behind an HVC #2 vector trampoline. The HVF HVC
/// immediate is always 2; the exception class and fault status distinguish
/// the underlying EL0 exception from an actual forwarded syscall.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct HvcNotSvcReason {
    pub ec: u8,
    pub fault_status: Option<u8>,
}

impl HvcNotSvcReason {
    pub const COUNT: usize = 64;

    pub const fn from_esr(esr: u64) -> Self {
        let ec = ((esr >> 26) & 0x3f) as u8;
        let fault_status = if matches!(ec, 0x20 | 0x21 | 0x24 | 0x25) {
            Some((esr & 0x3f) as u8)
        } else {
            None
        };
        Self { ec, fault_status }
    }
}

/// Process-lifetime HVC #2 returns that were not SVC, grouped by the saved
/// ESR_EL1 exception class and (for aborts) fault status code.
#[derive(::core::clone::Clone, ::core::fmt::Debug, ::core::cmp::Eq, ::core::cmp::PartialEq)]
pub struct HvcNotSvcCounts {
    pub by_ec: [u64; HvcNotSvcReason::COUNT],
    pub fault_status: [u64; HvcNotSvcReason::COUNT],
    pub sysreg: [u64; HvcSysregKind::COUNT],
    pub emulated_sys64: u64,
}

/// A SYS64 MRS register behind the EL1 HVC #2 vector trampoline.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
#[repr(usize)]
pub enum HvcSysregKind {
    Cntfrq,
    Cntvct,
    Ctr,
    Dczid,
    FeatureId,
    Other,
}

impl HvcSysregKind {
    pub const COUNT: usize = 6;
}

/// Decode the register fields of ESR_EL1 for EC=0x18 (SYS64).
pub const fn sys64_sysreg_kind(esr: u64) -> HvcSysregKind {
    if esr & 1 == 0 {
        return HvcSysregKind::Other;
    }
    let op0 = (esr >> 20) & 0x3;
    let op1 = (esr >> 14) & 0x7;
    let crn = (esr >> 10) & 0xf;
    let crm = (esr >> 1) & 0xf;
    let op2 = (esr >> 17) & 0x7;
    let enc = (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2;
    match enc {
        0xdf00 => HvcSysregKind::Cntfrq,
        0xdf02 => HvcSysregKind::Cntvct,
        0xd801 => HvcSysregKind::Ctr,
        0xd807 => HvcSysregKind::Dczid,
        _ if op0 == 3 && op1 == 0 && crn == 0 => HvcSysregKind::FeatureId,
        _ => HvcSysregKind::Other,
    }
}

/// EL1's reason for an `Idle` or `Kick` HVC. These counters complement the
/// HVF class: an HVC can be attributed to host work, a service queue, or a
/// failed address-space switch without guessing from total exit counts.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
#[repr(usize)]
pub enum El1ExitReason {
    IdleHostWork,
    IdleEntryHostWork,
    Service,
    InterruptHostWork,
}

impl El1ExitReason {
    pub const COUNT: usize = 4;
}

/// Why the EL1 pipe/eventfd adapter left a read or write for the host:
/// forwarded unchanged before any effect, or its owned operation handed
/// back. The normal routing of a host-backed description is not counted.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
#[repr(usize)]
pub enum IpcLeave {
    /// The task's descriptor table is not published to EL1.
    NoTable,
    /// The table lock stayed contended past EL1's bounded spin (lookup).
    TableContended,
    /// The table lookup was refused otherwise (stale table), not EBADF.
    TableRefused,
    /// The table lock stayed contended past EL1's bounded spin (pin).
    PinContended,
    /// The description could not be pinned otherwise (stale table).
    PinRefused,
    /// No operation record was free (or one could not be taken back).
    NoOperationRecord,
    /// An eventfd write's value could not be copied in.
    CopyInFault,
    /// A resumed operation's token or record did not resolve.
    StaleOperation,
    /// A resumed operation belongs to another task or address space.
    ForeignOperation,
    /// The pinned description's flags could not be read.
    FlagsRefused,
    /// The object lock stayed contended past EL1's bounded spin (and was
    /// free again when EL1 looked at its holder).
    ObjectBusy,
    /// ... held by a host thread.
    ObjectBusyHost,
    /// ... held by EL1 on another vCPU.
    ObjectBusyEl1,
    /// The object refused the transfer (e.g. a pipe with no ring).
    TransferRefused,
    /// A would-block call could not be parked.
    ParkRefused,
    /// EPIPE with no progress: the host re-runs the call (SIGPIPE).
    BrokenFirst,
    /// A first copy faulted: the host resolves it.
    FaultFirst,
    /// A broken pipe after progress: handed back for SIGPIPE.
    SigpipeHandback,
    /// A description replaced by a host-backed one since the snapshot.
    Restart,
    /// `epoll_pwait` with a signal mask: the host swaps the mask.
    EpollSigmask,
    /// `epoll_pwait` on a set with host-half items: the host harvests both.
    EpollHostItems,
    /// `epoll_pwait` with a finite timeout and nothing ready: the host waits
    /// with its deadline.
    EpollTimedWait,
    /// The harvested events could not be copied out: the items are
    /// restored and the host resolves the fault.
    EpollCopyOut,
}

impl IpcLeave {
    pub const COUNT: usize = 23;
}

/// Why EL1 left a delegated-MM anonymous `brk`/`mmap`/`munmap`/`mprotect`
/// (an MM with an admitted reservation root) for the host, counted beside
/// `forwarded[nr]` so a signed run names each remaining forward cause.
/// Append only: the embed witnesses read the ordinals.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
#[repr(usize)]
pub enum AnonymousLeave {
    /// Host work was pending at entry (a kick, a signal, an owed wake).
    PendingHostWork,
    /// The root guard was held (by the host venue, or EL1 on another vCPU).
    RootBusy,
    /// The root model could not decide now (`Busy`, `Stale`,
    /// `MetadataRequired` from the decision itself).
    RootUnavailable,
    /// The root model routed the call to the host (a host-owned node, a
    /// shape EL1 does not serve).
    RootDeclined,
    /// The MM's address space has no grant (gate closed) or no owner.
    NoGrant,
    /// Another EL1 editor holds the MM's descriptor editor.
    EditorBusy,
    /// The range's backing has a terminal the host owns (a leaf without
    /// EL1 tags).
    BackingHostOwnedLeaf,
    /// The range's backing has an L1/L2 block terminal.
    BackingBlock,
    /// The range's backing is split into more backed runs than one step.
    BackingMultiRun,
    /// The range's backing has a malformed terminal, or a table outside
    /// the primary arena.
    BackingMalformed,
    /// The range's backing has a retired terminal whose return is owed.
    BackingRetired,
    /// The descriptor step refused (permission or retirement edit).
    EditRefused,
    /// No owed-return journal slot was free.
    JournalFull,
}

impl AnonymousLeave {
    pub const COUNT: usize = 13;
}

/// Exact gate that refused an owner-routed process syscall.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
#[repr(usize)]
pub enum ProcessRefusal {
    MissingEntry,
    Admission,
    Service,
    RegisteredEntry,
    RootExit,
    Forwarded,
}

impl ProcessRefusal {
    pub const COUNT: usize = 6;
}

/// First failing stage of an ARM native fork attempt. Zero means no error.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
#[repr(u64)]
pub enum NativeForkFailureStage {
    MappingCount = 1,
    SpaceAccess = 2,
    Root = 3,
    ObserveMappings = 4,
    TransferSequence = 5,
    Census = 6,
    RootPublication = 7,
    Scratch = 8,
    Prepare = 9,
    Publish = 10,
    Commit = 11,
    Abort = 12,
    BornSpaceAccess = 13,
    PrepareInvalid = 14,
    PrepareStale = 15,
    PrepareBusy = 16,
    PrepareNoMemory = 17,
    PrepareMetadataRequired = 18,
    PrepareFault = 19,
    PrepareCore = 20,
    PrepareTable = 21,
    PrepareReservation = 22,
    PrepareWait = 23,
    PrepareUnsupportedExecutableCow = 24,
    PrepareMappingCapacity = 25,
    PrepareReadCapacity = 26,
    PrepareChildCapacity = 27,
    PrepareParentCapacity = 28,
    PrepareCustodyCapacity = 29,
    PrepareUnclassifiedCapacity = 30,
    PrepareEditCapacity = 31,
    PublishRevalidateWords = 32,
    PublishAuthenticateParent = 33,
    PublishCheckReadiness = 34,
    PublishReserveCertificate = 35,
    PublishStoreChildTables = 36,
    PublishStoreParentTables = 37,
    PublishEditParent = 38,
    PublishSetChildOrigin = 39,
    PublishCloneReservations = 40,
    PublishPublishParent = 41,
    PublishPublishChild = 42,
    PublishInvalid = 43,
    PublishStale = 44,
    PublishBusy = 45,
    PublishNoMemory = 46,
    PublishMetadataRequired = 47,
    PublishFault = 48,
    PublishCore = 49,
    PublishTable = 50,
    PublishReservation = 51,
    PublishWait = 52,
    PublishUnsupportedExecutableCow = 53,
    ReleaseBirth = 54,
    SettleCustody = 55,
    SettleRecord = 56,
    SettleCrossing = 57,
    SettleReply = 58,
    SettlePortal = 59,
    SettleSpace = 60,
    RegisterChild = 61,
}

impl NativeForkFailureStage {
    pub fn from_raw(raw: u64) -> Option<Self> {
        Some(match raw {
            1 => Self::MappingCount,
            2 => Self::SpaceAccess,
            3 => Self::Root,
            4 => Self::ObserveMappings,
            5 => Self::TransferSequence,
            6 => Self::Census,
            7 => Self::RootPublication,
            8 => Self::Scratch,
            9 => Self::Prepare,
            10 => Self::Publish,
            11 => Self::Commit,
            12 => Self::Abort,
            13 => Self::BornSpaceAccess,
            14 => Self::PrepareInvalid,
            15 => Self::PrepareStale,
            16 => Self::PrepareBusy,
            17 => Self::PrepareNoMemory,
            18 => Self::PrepareMetadataRequired,
            19 => Self::PrepareFault,
            20 => Self::PrepareCore,
            21 => Self::PrepareTable,
            22 => Self::PrepareReservation,
            23 => Self::PrepareWait,
            24 => Self::PrepareUnsupportedExecutableCow,
            25 => Self::PrepareMappingCapacity,
            26 => Self::PrepareReadCapacity,
            27 => Self::PrepareChildCapacity,
            28 => Self::PrepareParentCapacity,
            29 => Self::PrepareCustodyCapacity,
            30 => Self::PrepareUnclassifiedCapacity,
            31 => Self::PrepareEditCapacity,
            32 => Self::PublishRevalidateWords,
            33 => Self::PublishAuthenticateParent,
            34 => Self::PublishCheckReadiness,
            35 => Self::PublishReserveCertificate,
            36 => Self::PublishStoreChildTables,
            37 => Self::PublishStoreParentTables,
            38 => Self::PublishEditParent,
            39 => Self::PublishSetChildOrigin,
            40 => Self::PublishCloneReservations,
            41 => Self::PublishPublishParent,
            42 => Self::PublishPublishChild,
            43 => Self::PublishInvalid,
            44 => Self::PublishStale,
            45 => Self::PublishBusy,
            46 => Self::PublishNoMemory,
            47 => Self::PublishMetadataRequired,
            48 => Self::PublishFault,
            49 => Self::PublishCore,
            50 => Self::PublishTable,
            51 => Self::PublishReservation,
            52 => Self::PublishWait,
            53 => Self::PublishUnsupportedExecutableCow,
            54 => Self::ReleaseBirth,
            55 => Self::SettleCustody,
            56 => Self::SettleRecord,
            57 => Self::SettleCrossing,
            58 => Self::SettleReply,
            59 => Self::SettlePortal,
            60 => Self::SettleSpace,
            61 => Self::RegisterChild,
            _ => return None,
        })
    }
}

/// Completed ARM fork milestones. Counts preserve progress across multiple
/// children, including a child that exits before its parent resumes.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
#[repr(usize)]
pub enum NativeForkProgress {
    Prepare = 0,
    Publish = 1,
    Commit = 2,
    Settle = 3,
    ChildRegistered = 4,
    ParentResumed = 5,
    ChildEntered = 6,
    WaitEntered = 7,
    WaitReturned = 8,
    ChildExit = 9,
    ChildRetired = 10,
}

impl NativeForkProgress {
    pub const COUNT: usize = 11;
}

/// Per-syscall accounting counters maintained by the EL1 kernel in the shared aperture.
#[repr(C)]
pub struct Counters {
    /// Number of times syscall nr was serviced at EL1 without VM exit.
    pub served: [AtomicU64; 512],
    /// Number of times syscall nr was forwarded to the host.
    pub forwarded: [AtomicU64; 512],
    /// GIC interrupts EL1 took and completed, by INTID (SGIs 0-15, PPIs
    /// 16-31); written by the vector page's IRQ hook.
    pub irq_taken: [AtomicU64; 32],
    /// Data/memory abort exceptions taken into EL1.
    pub fault_taken: AtomicU64,
    /// EL1 scheduler exits indexed by [`El1ExitReason`].
    pub exit_reasons: [AtomicU64; El1ExitReason::COUNT],
    /// Pipe/eventfd calls the EL1 adapter left for the host, by [`IpcLeave`].
    pub ipc_leaves: [AtomicU64; IpcLeave::COUNT],
    /// Exact lifecycle declines; separate from the eventual host exit class.
    pub lifecycle_declines: [AtomicU64; LifecycleDecline::COUNT],
    /// Delegated-MM anonymous calls EL1 left for the host, by
    /// [`AnonymousLeave`].
    pub anonymous_leaves: [AtomicU64; AnonymousLeave::COUNT],
    /// Syscall refusals answering -ENOSYS directly from kernel entry, indexed
    /// by native ordinal 0..512 plus one overflow bucket for values >= 512
    /// and unmapped/undecodable natives.
    pub refused: [AtomicU64; 513],
    /// ARM process-entry refusals: missing slot, root admission, service,
    /// registered entry, root-exit crossing, or personality forwarding.
    pub process_refusals: [AtomicU64; ProcessRefusal::COUNT],
    /// First typed ARM fork service failure, retained across a carrier run.
    pub first_native_fork_failure: AtomicU64,
    /// First owner process call without an authenticated slot entry: bit 0
    /// marks presence, bits 1-4 mark slot/task/current/host presence, bits
    /// 16-31 hold the raw slot, and bits 32-47 the native syscall ordinal.
    pub first_process_missing_entry: AtomicU64,
    /// First live TTBR0 root rejected by owner process admission. Bit zero
    /// marks a recorded refusal, including a zero root.
    pub first_process_admission_root: AtomicU64,
    /// First ARM admission stage that actually failed (see `admit_entry`).
    pub first_process_admission_stage: AtomicU64,
    /// First root-registry refusal: publication tag, then observed and registered
    /// task, execution generation, MM, thread generation, address generation,
    /// record id and record incarnation (seven words per identity).
    pub first_process_registry_refusal: [AtomicU64; 15],
    /// Completed milestones of owner-served ARM forks.
    pub native_fork_progress: [AtomicU64; NativeForkProgress::COUNT],
}

impl Counters {
    pub const fn new() -> Self {
        Self {
            served: [const { AtomicU64::new(0) }; 512],
            forwarded: [const { AtomicU64::new(0) }; 512],
            irq_taken: [const { AtomicU64::new(0) }; 32],
            fault_taken: AtomicU64::new(0),
            exit_reasons: [const { AtomicU64::new(0) }; El1ExitReason::COUNT],
            ipc_leaves: [const { AtomicU64::new(0) }; IpcLeave::COUNT],
            lifecycle_declines: [const { AtomicU64::new(0) }; LifecycleDecline::COUNT],
            anonymous_leaves: [const { AtomicU64::new(0) }; AnonymousLeave::COUNT],
            refused: [const { AtomicU64::new(0) }; 513],
            process_refusals: [const { AtomicU64::new(0) }; ProcessRefusal::COUNT],
            first_native_fork_failure: AtomicU64::new(0),
            first_process_missing_entry: AtomicU64::new(0),
            first_process_admission_root: AtomicU64::new(0),
            first_process_admission_stage: AtomicU64::new(0),
            first_process_registry_refusal: [const { AtomicU64::new(0) }; 15],
            native_fork_progress: [const { AtomicU64::new(0) }; NativeForkProgress::COUNT],
        }
    }

    pub fn copy_snapshot(&self) -> Self {
        let snapshot = Self::new();
        for i in 0..512 {
            snapshot.served[i].store(self.served[i].load(Ordering::Relaxed), Ordering::Relaxed);
            snapshot.forwarded[i]
                .store(self.forwarded[i].load(Ordering::Relaxed), Ordering::Relaxed);
        }
        for i in 0..32 {
            snapshot.irq_taken[i]
                .store(self.irq_taken[i].load(Ordering::Relaxed), Ordering::Relaxed);
        }
        snapshot
            .fault_taken
            .store(self.fault_taken.load(Ordering::Relaxed), Ordering::Relaxed);
        for i in 0..El1ExitReason::COUNT {
            snapshot.exit_reasons[i].store(
                self.exit_reasons[i].load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
        }
        for i in 0..IpcLeave::COUNT {
            snapshot.ipc_leaves[i].store(
                self.ipc_leaves[i].load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
        }
        for (target, source) in snapshot
            .lifecycle_declines
            .iter()
            .zip(&self.lifecycle_declines)
        {
            target.store(source.load(Ordering::Relaxed), Ordering::Relaxed);
        }
        for i in 0..AnonymousLeave::COUNT {
            snapshot.anonymous_leaves[i].store(
                self.anonymous_leaves[i].load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
        }
        for i in 0..513 {
            snapshot.refused[i].store(self.refused[i].load(Ordering::Relaxed), Ordering::Relaxed);
        }
        for i in 0..ProcessRefusal::COUNT {
            snapshot.process_refusals[i].store(
                self.process_refusals[i].load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
        }
        snapshot.first_native_fork_failure.store(
            self.first_native_fork_failure.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        snapshot.first_process_missing_entry.store(
            self.first_process_missing_entry.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        snapshot.first_process_admission_root.store(
            self.first_process_admission_root.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        snapshot.first_process_admission_stage.store(
            self.first_process_admission_stage.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        for (target, source) in snapshot
            .first_process_registry_refusal
            .iter()
            .zip(&self.first_process_registry_refusal)
        {
            target.store(source.load(Ordering::Acquire), Ordering::Relaxed);
        }
        for (target, source) in snapshot
            .native_fork_progress
            .iter()
            .zip(&self.native_fork_progress)
        {
            target.store(source.load(Ordering::Relaxed), Ordering::Relaxed);
        }
        snapshot
    }

    pub fn record_lifecycle_decline(&self, reason: LifecycleDecline) {
        self.lifecycle_declines[reason as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_first_native_fork_failure(&self, stage: NativeForkFailureStage) {
        let _ = self.first_native_fork_failure.compare_exchange(
            0,
            stage as u64,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    pub fn record_first_process_missing_entry(
        &self,
        slot: u64,
        ordinal: u64,
        slot_valid: bool,
        task_present: bool,
        current_record: bool,
        host_record: bool,
    ) {
        let packed = 1
            | (u64::from(slot_valid) << 1)
            | (u64::from(task_present) << 2)
            | (u64::from(current_record) << 3)
            | (u64::from(host_record) << 4)
            | ((slot & 0xffff) << 16)
            | ((ordinal & 0xffff) << 32);
        let _ = self.first_process_missing_entry.compare_exchange(
            0,
            packed,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    pub fn record_first_process_admission_failure(&self, ttbr0: u64) {
        let _ = self.first_process_admission_root.compare_exchange(
            0,
            ttbr0 | 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    pub fn record_first_process_admission_stage(&self, stage: u64) {
        let _ = self.first_process_admission_stage.compare_exchange(
            0,
            stage,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    pub fn record_first_process_registry_refusal(&self, observed: [u64; 7], registered: [u64; 7]) {
        if self.first_process_registry_refusal[0]
            .compare_exchange(0, u64::MAX, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            for (target, value) in self.first_process_registry_refusal[1..]
                .iter()
                .zip(observed.into_iter().chain(registered))
            {
                target.store(value, Ordering::Relaxed);
            }
            self.first_process_registry_refusal[0].store(1, Ordering::Release);
        }
    }

    pub fn record_native_fork_progress(&self, stage: NativeForkProgress) {
        self.native_fork_progress[stage as usize].fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(target_os = "none")]
fn native_fork_counters() -> &'static Counters {
    // SAFETY: EL1 maps the shared counters aperture for every carrier vCPU.
    unsafe { &*(EL1_COUNTERS_BASE as *const Counters) }
}

#[cfg(target_os = "none")]
pub fn record_native_fork_failure(stage: NativeForkFailureStage) {
    native_fork_counters().record_first_native_fork_failure(stage);
}

#[cfg(target_os = "none")]
pub fn record_native_fork_progress(stage: NativeForkProgress) {
    native_fork_counters().record_native_fork_progress(stage);
}

const _: () = assert!(core::mem::size_of::<Counters>() as u64 <= EL1_COUNTERS_SIZE);

impl Default for Counters {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Counters {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Counters")
            .field("forwarded_64", &self.forwarded[64].load(Ordering::Relaxed))
            .finish()
    }
}

/// Byte offset of the inotify table within the region.
pub const EL1_INOTIFY_TABLE_OFFSET: u64 = 0x310_0000;

/// Base guest virtual address of the inotify table.
pub const EL1_INOTIFY_TABLE_BASE: u64 = EL1_REGION_BASE + EL1_INOTIFY_TABLE_OFFSET;

/// Size of the inotify table (3 MiB).
pub const EL1_INOTIFY_TABLE_SIZE: u64 = 0x30_0000;

/// Byte offset of the name cache within the region.
pub const EL1_NAME_CACHE_OFFSET: u64 = 0x340_0000;

/// Base guest virtual address of the name cache.
pub const EL1_NAME_CACHE_BASE: u64 = EL1_REGION_BASE + EL1_NAME_CACHE_OFFSET;

/// Size of the name cache (64 KiB).
pub const EL1_NAME_CACHE_SIZE: u64 = 0x1_0000;

pub use carrick_sched_core::{
    Aarch64ParkedContext, AddressSpaces, BoundedSpin, Claim, CurrentHandback, CurrentRelease,
    ExcludedEditor, Exhausted, Handback, HostClaim, HostPlacement, HostTransfer, LockWait,
    ParkedContextRead, RecordId, RecordRef, SlotDrain, SlotId, SlotState, SwitchedIn, ThreadCtx,
    ThreadIdentity, WakeEffects, WakeRecord, WakeRefusal, Waker, ZONE_SLOTS,
};

/// The ARM guest and its carrier share one record context type. Every zone
/// reference uses these aliases, including scheduler and process ownership.
#[cfg(target_arch = "aarch64")]
pub type ZoneTables = carrick_sched_core::ZoneTables<Aarch64ParkedContext>;
#[cfg(target_arch = "aarch64")]
pub type ZoneContext = Aarch64ParkedContext;
#[cfg(target_arch = "aarch64")]
pub type ZoneRecord = carrick_sched_core::ZoneRecord<Aarch64ParkedContext>;
#[cfg(not(target_arch = "aarch64"))]
pub type ZoneTables = carrick_sched_core::ZoneTables<ThreadCtx>;
#[cfg(not(target_arch = "aarch64"))]
pub type ZoneContext = ThreadCtx;
#[cfg(not(target_arch = "aarch64"))]
pub type ZoneRecord = carrick_sched_core::ZoneRecord<ThreadCtx>;

/// Byte offset of the in-guest scheduler's tables ([`ZoneTables`]: futex
/// wait queues, parked-thread records, per-vCPU run queues).
pub const EL1_ZONE_OFFSET: u64 = 0x350_0000;

/// Base guest virtual address of the zone tables.
pub const EL1_ZONE_BASE: u64 = EL1_REGION_BASE + EL1_ZONE_OFFSET;

/// Space reserved for the zone tables (11 MiB, to the end of the region).
pub const EL1_ZONE_SIZE: u64 = 0xB0_0000;

const _: () = assert!(core::mem::size_of::<ZoneTables>() as u64 <= EL1_ZONE_SIZE);
const _: () = assert!(EL1_ZONE_OFFSET.is_multiple_of(core::mem::align_of::<ZoneTables>() as u64));
const _: () = assert!(carrick_sched_core::ZONE_SLOTS as u64 >= EL1_STACK_SLOTS);

const _: () = assert!(EL1_REGION_BASE.is_multiple_of(0x0400_0000));
const _: () = assert!(EL1_REGION_SIZE == 64 * 1024 * 1024);
const _: () = assert!(EL1_IMAGE_OFFSET + EL1_IMAGE_SIZE <= EL1_COUNTERS_OFFSET);
const _: () = assert!(EL1_COUNTERS_OFFSET + EL1_COUNTERS_SIZE <= EL1_STACKS_OFFSET);
const _: () = assert!(
    EL1_STACKS_OFFSET + EL1_STACK_SLOTS * EL1_STACK_SIZE <= EL1_STACKS_OFFSET + EL1_STACKS_SIZE
);
const _: () = assert!(EL1_STACKS_OFFSET + EL1_STACKS_SIZE <= EL1_CURRENT_TASKS_OFFSET);
const _: () = assert!(
    EL1_CURRENT_TASKS_OFFSET + EL1_STACK_SLOTS * core::mem::size_of::<CurrentTask>() as u64
        <= EL1_METADATA_MAILBOX_OFFSET
);
const _: () = assert!(
    EL1_METADATA_MAILBOX_OFFSET
        .is_multiple_of(core::mem::align_of::<MetadataGrantMailbox>() as u64)
);
const _: () = assert!(
    EL1_METADATA_MAILBOX_OFFSET + core::mem::size_of::<MetadataGrantMailbox>() as u64
        <= EL1_FRAME_GRANT_MAILBOX_OFFSET
);
const _: () = assert!(
    EL1_FRAME_GRANT_MAILBOX_OFFSET
        .is_multiple_of(core::mem::align_of::<FrameGrantMailboxes>() as u64)
);
const _: () = assert!(
    EL1_FRAME_GRANT_MAILBOX_OFFSET + core::mem::size_of::<FrameGrantMailboxes>() as u64
        <= EL1_FRAME_GRANT_RESIDENCY_OFFSET
);
const _: () = assert!(
    EL1_FRAME_GRANT_RESIDENCY_OFFSET
        .is_multiple_of(core::mem::align_of::<FrameGrantResidencyTable>() as u64)
);
const _: () = assert!(
    EL1_FRAME_GRANT_RESIDENCY_OFFSET + core::mem::size_of::<FrameGrantResidencyTable>() as u64
        <= EL1_CURRENT_TASKS_OFFSET + EL1_CURRENT_TASKS_SIZE
);
const _: () =
    assert!(EL1_CURRENT_TASKS_OFFSET + EL1_CURRENT_TASKS_SIZE <= EL1_BOOTSTRAP_METADATA_OFFSET);
const _: () =
    assert!(EL1_BOOTSTRAP_METADATA_OFFSET + EL1_BOOTSTRAP_METADATA_SIZE <= EL1_HEAP_OFFSET);
const _: () = assert!(EL1_OBJECT_TABLE_OFFSET + EL1_OBJECT_TABLE_SIZE <= EL1_FD_MAP_OFFSET);
const _: () = assert!(EL1_FD_MAP_OFFSET + EL1_FD_MAP_SIZE <= EL1_CACHE_OFFSET);
const _: () = assert!(EL1_CACHE_OFFSET + EL1_CACHE_SIZE <= EL1_INOTIFY_TABLE_OFFSET);
const _: () = assert!(EL1_INOTIFY_TABLE_OFFSET + EL1_INOTIFY_TABLE_SIZE <= EL1_NAME_CACHE_OFFSET);
const _: () = assert!(EL1_NAME_CACHE_OFFSET + EL1_NAME_CACHE_SIZE <= EL1_ZONE_OFFSET);
const _: () = assert!(EL1_ZONE_OFFSET + EL1_ZONE_SIZE <= EL1_REGION_SIZE);

use core::sync::atomic::AtomicUsize;

static EL1_REGION_HOST_PTR: AtomicUsize = AtomicUsize::new(0);

/// Record the host virtual address of the mapped EL1 region.
pub fn record_el1_region_host_ptr(ptr: usize) {
    EL1_REGION_HOST_PTR.store(ptr, Ordering::Release);
}

/// Read the host virtual address of the mapped EL1 region.
pub fn get_el1_region_host_ptr() -> usize {
    EL1_REGION_HOST_PTR.load(Ordering::Acquire)
}

/// Shared aperture control word.
#[repr(C, align(64))]
pub struct ApertureControl {
    pub control: core::sync::atomic::AtomicU64,
}

impl ApertureControl {
    pub const fn new() -> Self {
        Self {
            control: core::sync::atomic::AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn is_strict(&self) -> bool {
        (self.control.load(Ordering::Acquire) & APERTURE_CONTROL_ARM_RING_FIRST_OPT_OUT) == 0
    }

    #[inline]
    pub fn set_strict(&self, strict: bool) {
        if strict {
            self.control
                .fetch_and(!APERTURE_CONTROL_ARM_RING_FIRST_OPT_OUT, Ordering::Release);
        } else {
            self.control
                .fetch_or(APERTURE_CONTROL_ARM_RING_FIRST_OPT_OUT, Ordering::Release);
        }
    }
}

impl Default for ApertureControl {
    fn default() -> Self {
        Self::new()
    }
}

/// Read the ARM guest aperture control word.
///
/// # Safety
/// The caller must have mapped and initialized the ABI aperture at the ARM
/// kernel VA and retain that mapping for the returned reference's lifetime.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
#[inline]
pub unsafe fn aperture_control() -> &'static ApertureControl {
    unsafe { &*(EL1_APERTURE_CONTROL_BASE as *const ApertureControl) }
}

fn checked_aperture_host_address(base: usize, region_len: usize) -> Option<usize> {
    let offset = usize::try_from(EL1_APERTURE_CONTROL_OFFSET).ok()?;
    let end = offset.checked_add(core::mem::size_of::<ApertureControl>())?;
    if base == 0 || end > region_len {
        return None;
    }
    let address = base.checked_add(offset)?;
    base.checked_add(end)?;
    address
        .is_multiple_of(core::mem::align_of::<ApertureControl>())
        .then_some(address)
}

/// Read the host view of the guest aperture control word, if mapped.
///
/// # Safety
/// The caller must retain the registered, initialized EL1 region mapping
/// (EL1_REGION_SIZE bytes) throughout use of the returned reference. The
/// registration must not be replaced or unmapped while the reference is live.
pub unsafe fn host_aperture_control() -> Option<&'static ApertureControl> {
    let address =
        checked_aperture_host_address(get_el1_region_host_ptr(), EL1_REGION_SIZE as usize)?;
    // SAFETY: checked geometry keeps this aligned object within the registered
    // region; the caller retains the mapping and its initialized atomic word.
    unsafe { Some(&*(address as *const ApertureControl)) }
}

/// The shared IPC memory as one venue addresses it: the directory and the
/// pool at this venue's addresses (the host authority's allocations, or the
/// fixed EL1 VAs). Nothing here is persisted in shared memory.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct IpcWindow {
    directory: usize,
    directory_len: usize,
    pool: usize,
    pool_len: usize,
}

impl IpcWindow {
    /// Describe a venue's mapping. Fails closed on a directory that does not
    /// fit its span or a pool whose length is not the ABI's.
    ///
    /// # Safety
    /// Both ranges are mapped, shared with the other venue, for `'static`.
    pub unsafe fn new(
        directory: usize,
        directory_len: usize,
        pool: usize,
        pool_len: usize,
    ) -> Option<Self> {
        (directory != 0
            && pool != 0
            && directory_len >= ipc::IPC_DIRECTORY_BYTES
            && directory_len as u64 <= EL1_IPC_DIRECTORY_SPAN
            && pool_len as u64 == EL1_IPC_POOL_SPAN)
            .then_some(Self {
                directory,
                directory_len,
                pool,
                pool_len,
            })
    }
    pub const fn directory_ptr(self) -> usize {
        self.directory
    }
    pub const fn directory_len(self) -> usize {
        self.directory_len
    }
    pub const fn pool_ptr(self) -> usize {
        self.pool
    }
    pub const fn pool_len(self) -> usize {
        self.pool_len
    }
    /// Attach to the published directory; fails closed (`BadRegion`) until
    /// the host authority has published it.
    pub fn attach(self) -> Result<ipc::IpcRegion<'static>, ipc::IpcError> {
        // SAFETY: `new`'s contract; `attach` authenticates the header.
        unsafe {
            ipc::IpcRegion::attach(
                self.directory as *mut ipc::IpcDirectory,
                self.directory_len,
                self.pool as *mut u8,
                self.pool_len,
            )
        }
    }
}

/// The host IPC authority's memory, in the shape of the kernel authority's
/// accessors: what the carrier maps into the IPC window (the directory at
/// [`EL1_IPC_BASE`], the pool at [`EL1_IPC_POOL_BASE`]).
pub trait IpcWindowBacking: Send + Sync {
    fn directory_ptr(&self) -> *mut u8;
    fn directory_len(&self) -> usize;
    fn pool_ptr(&self) -> *mut u8;
    fn pool_len(&self) -> usize;
}

static IPC_WINDOW_HOST: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
static IPC_WINDOW_HOST_LIVE: AtomicU32 = AtomicU32::new(0);

/// Record the host's view of the window the carrier mapped (`None`: the
/// carrier retired it). Recorded by the mapping owner only.
pub fn record_ipc_window_host(window: Option<IpcWindow>) {
    IPC_WINDOW_HOST_LIVE.store(0, Ordering::Release);
    if let Some(w) = window {
        IPC_WINDOW_HOST[0].store(w.directory, Ordering::Relaxed);
        IPC_WINDOW_HOST[1].store(w.directory_len, Ordering::Relaxed);
        IPC_WINDOW_HOST[2].store(w.pool, Ordering::Relaxed);
        IPC_WINDOW_HOST[3].store(w.pool_len, Ordering::Relaxed);
        IPC_WINDOW_HOST_LIVE.store(1, Ordering::Release);
    }
}

/// The host's view of the mapped IPC window, if the carrier mapped one.
pub fn ipc_window_host() -> Option<IpcWindow> {
    if IPC_WINDOW_HOST_LIVE.load(Ordering::Acquire) == 0 {
        return None;
    }
    // SAFETY: recorded by the mapping owner, which retains the memory while
    // the record is live.
    unsafe {
        IpcWindow::new(
            IPC_WINDOW_HOST[0].load(Ordering::Relaxed),
            IPC_WINDOW_HOST[1].load(Ordering::Relaxed),
            IPC_WINDOW_HOST[2].load(Ordering::Relaxed),
            IPC_WINDOW_HOST[3].load(Ordering::Relaxed),
        )
    }
}

/// EL1's view of the IPC window (identity mapped kernel-only).
#[cfg(target_os = "none")]
pub fn ipc_window_guest() -> Option<IpcWindow> {
    // SAFETY: the window is mapped in every EL1 translation regime; an
    // unmapped window never has a published header, so attach fails.
    unsafe {
        IpcWindow::new(
            EL1_IPC_BASE as usize,
            EL1_IPC_DIRECTORY_SPAN as usize,
            EL1_IPC_POOL_BASE as usize,
            EL1_IPC_POOL_SPAN as usize,
        )
    }
}

/// The IPC table map in the EL1 region, as the host maps it.
pub fn ipc_table_map_host() -> Option<&'static ipc_tables::IpcTableMap> {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 {
        return None;
    }
    // SAFETY: the EL1 region mapping outlives the carrier; the map is at an
    // aligned offset inside it and all-zero is an empty map.
    Some(unsafe { &*((ptr + EL1_IPC_TABLE_MAP_OFFSET as usize) as *const ipc_tables::IpcTableMap) })
}

/// The IPC table map in the EL1 region, as EL1 maps it.
#[cfg(target_os = "none")]
pub fn ipc_table_map_guest() -> &'static ipc_tables::IpcTableMap {
    // SAFETY: the EL1 region is mapped for EL1's lifetime.
    unsafe { &*((EL1_REGION_BASE + EL1_IPC_TABLE_MAP_OFFSET) as *const ipc_tables::IpcTableMap) }
}

/// Host view of the shared metadata mailbox, if an EL1 region is installed.
pub fn metadata_mailbox_host() -> Option<&'static MetadataGrantMailbox> {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 {
        return None;
    }
    // SAFETY: the EL1 region owner keeps this shared mapping alive until it
    // first clears EL1_REGION_HOST_PTR; the mailbox contains only atomics.
    Some(unsafe { &*((ptr + EL1_METADATA_MAILBOX_OFFSET as usize) as *const MetadataGrantMailbox) })
}

/// Host view of one slot's anonymous-frame mailbox, if an EL1 region is
/// installed and `slot` names a persistent vCPU slot.
pub fn frame_grant_mailbox_host_for_slot(slot: usize) -> Option<&'static FrameGrantMailbox> {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 {
        return None;
    }
    // SAFETY: the EL1 region owner keeps this shared mapping alive until it
    // first clears EL1_REGION_HOST_PTR; the arena and its mailboxes contain
    // only atomics and the ABI offset preserves the declared alignment.
    let mailboxes = unsafe {
        &*((ptr + EL1_FRAME_GRANT_MAILBOX_OFFSET as usize) as *const FrameGrantMailboxes)
    };
    mailboxes.slot(slot)
}

pub fn frame_grant_residency_host() -> Option<&'static FrameGrantResidencyTable> {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 {
        return None;
    }
    // SAFETY: the EL1 region owner retains this mapping; the table contains
    // only atomics and its layout is checked against the image hash.
    Some(unsafe {
        &*((ptr + EL1_FRAME_GRANT_RESIDENCY_OFFSET as usize) as *const FrameGrantResidencyTable)
    })
}

/// Guest view of the shared metadata mailbox. Call only while executing in
/// the installed Carrick EL1 image.
#[cfg(target_os = "none")]
pub fn metadata_mailbox_guest() -> &'static MetadataGrantMailbox {
    // SAFETY: EL1_METADATA_MAILBOX_BASE is part of the mapped kernel-only EL1
    // ABI region and the object layout is included in EL1_ABI_LAYOUT_HASH.
    unsafe { &*(EL1_METADATA_MAILBOX_BASE as *const MetadataGrantMailbox) }
}

/// Guest view of every slot's anonymous-frame mailbox. Call only while
/// executing in the installed Carrick EL1 image.
#[cfg(target_os = "none")]
pub fn frame_grant_mailboxes_guest() -> &'static FrameGrantMailboxes {
    // SAFETY: identical to `frame_grant_mailbox_guest_for_slot`.
    unsafe { &*(EL1_FRAME_GRANT_MAILBOX_BASE as *const FrameGrantMailboxes) }
}

/// Guest view of one slot's anonymous-frame mailbox. Call only while executing
/// in the installed Carrick EL1 image.
#[cfg(target_os = "none")]
pub fn frame_grant_mailbox_guest_for_slot(slot: usize) -> Option<&'static FrameGrantMailbox> {
    // SAFETY: EL1_FRAME_GRANT_MAILBOX_BASE is part of the mapped kernel-only
    // EL1 ABI region and the arena layout is included in EL1_ABI_LAYOUT_HASH.
    let mailboxes = unsafe { &*(EL1_FRAME_GRANT_MAILBOX_BASE as *const FrameGrantMailboxes) };
    mailboxes.slot(slot)
}

/// Guest view of one current-task record.
#[cfg(target_os = "none")]
pub fn current_task_guest(slot: usize) -> Option<&'static CurrentTask> {
    if slot >= EL1_STACK_SLOTS as usize {
        return None;
    }
    // SAFETY: the array is part of the mapped kernel-only EL1 ABI region and
    // CurrentTask's layout is included in EL1_ABI_LAYOUT_HASH.
    Some(unsafe {
        &*((EL1_CURRENT_TASKS_BASE as usize + slot * core::mem::size_of::<CurrentTask>())
            as *const CurrentTask)
    })
}

/// End the current-task record of mailbox `slot`: it names no thread, so EL1
/// forwards every syscall trapped through that slot until a host boundary
/// publishes the thread that holds it. The mailbox slot allocator calls this
/// when a slot's lease begins and ends, so a record never outlives, or
/// predates, the lease of the vCPU that reads it.
pub fn clear_current_task_record(slot: usize) {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 || slot >= EL1_STACK_SLOTS as usize {
        return;
    }
    let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
    // SAFETY: the record lives in the EL1 region; only atomics are touched.
    let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
    current_task.clear();
}

/// The guest virtual address of `slot`'s [`TrapFrame`] on its EL1 stack: the
/// frame the EL1 hooks save and the idle entry starts from (stack top minus
/// 0x120, the frame rounded up to 16 bytes).
pub const fn el1_slot_frame_va(slot: usize) -> u64 {
    EL1_STACKS_BASE + EL1_STACK_SIZE * (slot as u64 + 1) - 0x120
}

/// Prepare `slot` for the idle entry (EL1 plan 1d): its task record names no
/// thread and no address space (pending host work is kept: a kick owed now
/// makes the idle vCPU leave at once), and its frame is the idle-entry frame
/// (the slot index, syndrome and ELR 0). Returns the frame's address, for
/// `x16` at the entry; `None` if the region is not mapped.
pub fn prepare_idle_entry(slot: usize) -> Option<u64> {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 || slot >= EL1_STACK_SLOTS as usize {
        return None;
    }
    let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
    // SAFETY: the record lives in the EL1 region; only atomics are touched.
    let task = unsafe { &*((ptr + offset) as *const CurrentTask) };
    task.execution.task.store(0, Ordering::Relaxed);
    task.execution.generation.store(0, Ordering::Relaxed);
    task.linux.file_table.store(0, Ordering::Relaxed);
    task.mm.thread_generation.store(0, Ordering::Relaxed);
    task.publish_lifecycle(0, 0);
    task.linux.served_with_work.store(0, Ordering::Relaxed);
    task.mm.key.store(0, Ordering::Release);
    let frame = el1_slot_frame_va(slot);
    let frame_offset = (frame - EL1_REGION_BASE) as usize;
    // SAFETY: the frame lies on the slot's EL1 stack in the mapped region,
    // and the slot's vCPU is stopped (its executor calls this): nothing else
    // reads or writes that stack now.
    unsafe {
        ::core::ptr::write(
            (ptr + frame_offset) as *mut TrapFrame,
            TrapFrame {
                slot: slot as u64,
                ..TrapFrame::default()
            },
        );
    }
    Some(frame)
}

/// Host publication path for a vCPU's pending-work bit.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
#[repr(usize)]
pub enum HostWorkPublishReason {
    DirectSlot,
    AllSlots,
    ExactTask,
    FileTable,
}

impl HostWorkPublishReason {
    pub const COUNT: usize = 4;
}

static HOST_WORK_PUBLICATIONS: [AtomicU64; HostWorkPublishReason::COUNT] =
    [const { AtomicU64::new(0) }; HostWorkPublishReason::COUNT];

/// Process-lifetime count of pending-host-work publications by source.
pub fn host_work_publication_counts() -> [u64; HostWorkPublishReason::COUNT] {
    core::array::from_fn(|i| HOST_WORK_PUBLICATIONS[i].load(Ordering::Relaxed))
}

/// Per-vCPU-slot run sequence, host-process state: odd while the slot's vCPU
/// is inside the host run loop (`carrick_vmm_hvf` `run_to_exit`), which
/// resumes an interrupted EL1 critical section to completion before it
/// returns; even otherwise. Bumped at every entry and every return, so a
/// host thread that reads the same even value twice knows that slot's vCPU
/// executed nothing in between: EL1 there can neither take nor release a
/// lock.
static SLOT_RUN_SEQUENCE: [AtomicU64; EL1_STACK_SLOTS as usize] =
    [const { AtomicU64::new(0) }; EL1_STACK_SLOTS as usize];

/// The slot's run sequence (see [`SlotRun`]); 0 for a slot out of range.
pub fn slot_run_sequence(slot: usize) -> u64 {
    SLOT_RUN_SEQUENCE
        .get(slot)
        .map_or(0, |sequence| sequence.load(Ordering::SeqCst))
}

/// The host run loop's residence on one vCPU slot: entered when the loop
/// starts running the slot's vCPU, left when it returns to its caller.
pub struct SlotRun(Option<usize>);

impl SlotRun {
    pub fn enter(slot: Option<usize>) -> Self {
        let slot = slot.filter(|slot| *slot < EL1_STACK_SLOTS as usize);
        if let Some(slot) = slot {
            SLOT_RUN_SEQUENCE[slot].fetch_add(1, Ordering::SeqCst);
        }
        Self(slot)
    }
}

impl Drop for SlotRun {
    fn drop(&mut self) {
        if let Some(slot) = self.0 {
            SLOT_RUN_SEQUENCE[slot].fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// Mark return-to-user work pending for the vCPU at `slot`.
pub fn mark_pending_host_work(slot: usize) {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 || slot >= EL1_STACK_SLOTS as usize {
        return;
    }
    let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
    let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
    current_task
        .linux
        .pending_host_work
        .store(1, Ordering::Release);
    HOST_WORK_PUBLICATIONS[HostWorkPublishReason::DirectSlot as usize]
        .fetch_add(1, Ordering::Relaxed);
}

/// Clear return-to-user work for the vCPU at `slot`.
pub fn clear_pending_host_work(slot: usize) {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 || slot >= EL1_STACK_SLOTS as usize {
        return;
    }
    let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
    let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
    current_task
        .linux
        .pending_host_work
        .store(0, Ordering::Release);
}

/// Check and atomically clear return-to-user work for the vCPU at `slot`.
pub fn take_pending_host_work(slot: usize) -> bool {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 || slot >= EL1_STACK_SLOTS as usize {
        return false;
    }
    let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
    let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
    current_task
        .linux
        .pending_host_work
        .swap(0, Ordering::AcqRel)
        != 0
}

/// Mark return-to-user work pending for all vCPU slots.
pub fn mark_pending_host_work_all() {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 {
        return;
    }
    HOST_WORK_PUBLICATIONS[HostWorkPublishReason::AllSlots as usize]
        .fetch_add(1, Ordering::Relaxed);
    for slot in 0..EL1_STACK_SLOTS as usize {
        let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
        let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
        current_task
            .linux
            .pending_host_work
            .store(1, Ordering::Release);
    }
}

/// Mark return-to-user work pending for any vCPU slot running the given task identity (tid).
pub fn mark_pending_host_work_for_task(tid: El1TaskId) {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 {
        return;
    }
    for slot in 0..EL1_STACK_SLOTS as usize {
        let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
        let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
        if current_task.execution.task.load(Ordering::Relaxed) == tid.raw() {
            current_task
                .linux
                .pending_host_work
                .store(1, Ordering::Release);
            HOST_WORK_PUBLICATIONS[HostWorkPublishReason::ExactTask as usize]
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Mark return-to-user work pending for any vCPU slot running a task whose `file_table`
/// matches one of the given tables. Slots with no task (`task_id == 0`) are never marked.
pub fn mark_pending_host_work_for_file_tables(tables: &[u64]) {
    if tables.is_empty() {
        return;
    }
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 {
        return;
    }
    for slot in 0..EL1_STACK_SLOTS as usize {
        let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
        let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
        if current_task.execution.task.load(Ordering::Relaxed) == 0 {
            continue;
        }
        let ft = current_task.linux.file_table.load(Ordering::Relaxed);
        if tables.contains(&ft) {
            current_task
                .linux
                .pending_host_work
                .store(1, Ordering::Release);
            HOST_WORK_PUBLICATIONS[HostWorkPublishReason::FileTable as usize]
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Update the file table for any vCPU slot running the given task identity (tid).
pub fn update_current_task_file_table_for_task(tid: El1TaskId, file_table: u64) {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 {
        return;
    }
    for slot in 0..EL1_STACK_SLOTS as usize {
        let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
        let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
        if current_task.execution.task.load(Ordering::Relaxed) == tid.raw() {
            current_task
                .linux
                .file_table
                .store(file_table, Ordering::Release);
        }
    }
}

/// The zone tables through the host's mapping of the EL1 region, when it is
/// mapped. The tables are shared with guest EL1; every access follows the
/// ownership protocol of `carrick_sched_core`.
pub fn zone_tables() -> Option<&'static ZoneTables> {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 {
        return None;
    }
    // SAFETY: the region is mapped for the carrier's life while the pointer
    // is recorded, zero-initialised (a valid empty zone), suitably aligned
    // (the region base is 64 MiB aligned and the offset is checked above),
    // and ZoneTables is atomics plus claim-protected context.
    Some(unsafe { &*((ptr + EL1_ZONE_OFFSET as usize) as *const ZoneTables) })
}

/// Publish the zone identity of the task loaded on `slot` (0 disables
/// in-guest futex service for it).
pub fn publish_zone_identity(slot: usize, zone_mm: u64, thread_serial: u64) {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 || slot >= EL1_STACK_SLOTS as usize {
        return;
    }
    let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
    // SAFETY: the record lives in the EL1 region; only atomics are touched.
    let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
    current_task
        .mm
        .thread_generation
        .store(thread_serial, Ordering::Relaxed);
    current_task.mm.key.store(zone_mm, Ordering::Release);
}

/// For a wedge post-mortem: every slot's task record with its boundary
/// flags. `pending_host_work` or `served_with_work` still set on a slot that
/// waits in the guest is host work EL1 announced and no host boundary took:
/// EL1 announces an owed host IPC wake solely through these flags.
pub fn write_current_task_census(out: &mut impl core::fmt::Write) -> core::fmt::Result {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 {
        return Ok(());
    }
    for slot in 0..EL1_STACK_SLOTS as usize {
        let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
        // SAFETY: the record lives in the EL1 region; only atomics are touched.
        let task = unsafe { &*((ptr + offset) as *const CurrentTask) };
        let tid = task.execution.task.load(Ordering::Acquire);
        let pending = task.linux.pending_host_work.load(Ordering::Acquire);
        let served = task.linux.served_with_work.load(Ordering::Acquire);
        if tid == 0 && pending == 0 && served == 0 {
            continue;
        }
        writeln!(
            out,
            "el1 task slot {slot}: tid={tid} serial={} mm={} pending_host_work={pending} served_with_work={served}",
            task.mm.thread_generation.load(Ordering::Acquire),
            task.mm.key.load(Ordering::Acquire),
        )?;
    }
    Ok(())
}

/// Read the task record of `slot` (what EL1 last published as running): the
/// task id and thread serial.
pub fn current_task_snapshot(slot: usize) -> Option<(El1TaskId, u64)> {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 || slot >= EL1_STACK_SLOTS as usize {
        return None;
    }
    let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
    // SAFETY: the record lives in the EL1 region; only atomics are touched.
    let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
    Some((
        El1TaskId(current_task.execution.task.load(Ordering::Acquire)),
        current_task.mm.thread_generation.load(Ordering::Acquire),
    ))
}

/// Check and atomically clear the `served_with_work` flag for an executor slot.
pub fn take_served_with_work(slot: usize) -> bool {
    take_served_boundary(slot).is_some()
}

/// Whether the syscall the vCPU at `slot` last left EL1 with was served at
/// EL1 and forwarded only for pending host work, without consuming the flag.
pub fn peek_served_with_work(slot: usize) -> bool {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 || slot >= EL1_STACK_SLOTS as usize {
        return false;
    }
    let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
    let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
    current_task.linux.served_with_work.load(Ordering::Acquire) != 0
}

/// Atomically take the served-with-work boundary of an executor slot: `None`
/// when the slot's last call left no work, else what it owes.
pub fn take_served_boundary(slot: usize) -> Option<ServedBoundary> {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 || slot >= EL1_STACK_SLOTS as usize {
        return None;
    }
    let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
    let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
    current_task.linux.take_served_boundary()
}

/// Read the preserved original argument 0 for an executor slot.
pub fn get_orig_arg0(slot: usize) -> u64 {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 || slot >= EL1_STACK_SLOTS as usize {
        return 0;
    }
    let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
    let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
    current_task.linux.orig_arg0.load(Ordering::Relaxed)
}

pub use carrick_inotify_core::QueuePush;
use carrick_inotify_core::{
    INOTIFY_EVENT_HEADER_SIZE, INOTIFY_MAX_QUEUED_EVENTS, InotifyEventQueue, LinuxErrno, alloc_wd,
};
use core::sync::atomic::AtomicI32;

/// Lock word values for delegated objects: which side holds the lock.
pub const LOCK_GUEST: u32 = 1;
pub const LOCK_HOST: u32 = 2;
/// How long EL1 waits for another vCPU's in-guest critical section before
/// forwarding (a few hundred nanoseconds; those sections copy a page at most).
pub const EL1_GUEST_LOCK_SPINS: u32 = 1024;

/// Maximum number of simultaneously delegated inotify instances.
pub const MAX_DELEGATED_INOTIFY: usize = 8;

/// Maximum number of live watches per delegated inotify instance.
pub const MAX_DELEGATED_WATCHES: usize = 64;

/// In-guest record of a live watch descriptor registered on an inotify instance.
#[repr(C)]
#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
    ::core::default::Default,
)]
pub struct DelegatedWatch {
    pub wd: i32,
    pub file_handle: u32,
    pub mask: u32,
    pub alive: u32,
}

/// EL1 inotify instance object table entry.
#[repr(C)]
#[repr(align(64))]
pub struct DelegatedInotify {
    pub state: AtomicU32,
    pub lock: AtomicU32,
    pub generation: AtomicU64,
    pub flags: AtomicU32,
    pub next_wd: AtomicI32,
    /// Mirror of the queue's byte count, published under the lock so
    /// readiness and FIONREAD can read it without the lock.
    pub queued_bytes: AtomicUsize,
    /// Nonzero while the host holds an ordered spill of records that did not
    /// fit the queue: EL1 then forwards reads and marked writes, so FIFO order
    /// is kept by the host until the spill drains.
    pub spilled: AtomicU32,
    pub num_watches: AtomicU32,
    /// Nonzero once a host thread has waited on (polled, epolled or blocked
    /// reading) this instance: from then on an EL1 enqueue onto an empty
    /// queue owes that waiter a wake.
    pub host_observed: AtomicU32,
    /// Set by an enqueue that owes a host waiter a wake; the host delivers
    /// it at its next boundary and clears it.
    pub wake_owed: AtomicU32,
    pub _reserved: [u32; 2],
    pub watches: UnsafeCell<[DelegatedWatch; MAX_DELEGATED_WATCHES]>,
    /// The instance's one event queue (shared implementation with the host).
    pub queue: UnsafeCell<InotifyEventQueue<INOTIFY_QUEUE_BYTES>>,
}

/// Byte capacity of an in-zone instance's queue: every header-only event up
/// to the event limit plus the overflow marker; named events beyond that
/// spill to the host in order.
pub const INOTIFY_QUEUE_BYTES: usize = (INOTIFY_MAX_QUEUED_EVENTS + 1) * INOTIFY_EVENT_HEADER_SIZE;

unsafe impl Sync for DelegatedInotify {}

impl DelegatedInotify {
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(DELEGATED_STATE_DEAD),
            lock: AtomicU32::new(0),
            generation: AtomicU64::new(0),
            flags: AtomicU32::new(0),
            next_wd: AtomicI32::new(1),
            queued_bytes: AtomicUsize::new(0),
            spilled: AtomicU32::new(0),
            num_watches: AtomicU32::new(0),
            host_observed: AtomicU32::new(0),
            wake_owed: AtomicU32::new(0),
            _reserved: [0; 2],
            watches: UnsafeCell::new(
                [const {
                    DelegatedWatch {
                        wd: 0,
                        file_handle: 0,
                        mask: 0,
                        alive: 0,
                    }
                }; MAX_DELEGATED_WATCHES],
            ),
            queue: UnsafeCell::new(InotifyEventQueue::new()),
        }
    }

    #[inline]
    pub fn try_lock(&self) -> bool {
        // Strong: a spurious LL/SC failure must not look like contention.
        self.lock
            .compare_exchange(0, LOCK_GUEST, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// EL1 acquire: wait a bounded while only for another vCPU's in-guest
    /// critical section (short, and completed even across kicks); a host
    /// holder may be a long recall, so forward at once. Bounded, so a lock
    /// order inversion between vCPUs costs a forward, never a deadlock.
    #[inline]
    pub fn lock_guest_bounded(&self, max_spins: u32) -> bool {
        for _ in 0..max_spins {
            match self
                .lock
                .compare_exchange(0, LOCK_GUEST, Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(LOCK_HOST) => return false,
                Err(_) => core::hint::spin_loop(),
            }
        }
        false
    }

    #[inline]
    pub fn unlock(&self) {
        self.lock.store(0, Ordering::Release);
    }

    #[inline]
    pub fn is_locked(&self) -> bool {
        self.lock.load(Ordering::Relaxed) != 0
    }

    pub fn host_lock_bounded(&self, max_spins: u64) -> bool {
        for _ in 0..max_spins {
            if self
                .lock
                .compare_exchange(0, LOCK_HOST, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    pub fn alloc_wd(&self) -> Result<i32, LinuxErrno> {
        let mut next = self.next_wd.load(Ordering::Relaxed);
        let live_count = self.num_watches.load(Ordering::Relaxed) as usize;
        let wd = alloc_wd(&mut next, live_count, |w| self.find_watch(w).is_some())?;
        self.next_wd.store(next, Ordering::Relaxed);
        Ok(wd)
    }

    pub fn find_watch(&self, wd: i32) -> Option<(usize, DelegatedWatch)> {
        if wd <= 0 {
            return None;
        }
        let watches = unsafe { &*self.watches.get() };
        for (i, w) in watches.iter().enumerate() {
            if w.alive != 0 && w.wd == wd {
                return Some((i, *w));
            }
        }
        None
    }

    pub fn add_watch(&self, wd: i32, file_handle: u32, mask: u32) -> bool {
        let watches = unsafe { &mut *self.watches.get() };
        for w in watches.iter_mut() {
            if w.alive == 0 {
                *w = DelegatedWatch {
                    wd,
                    file_handle,
                    mask,
                    alive: 1,
                };
                self.num_watches.fetch_add(1, Ordering::Release);
                return true;
            }
        }
        false
    }

    /// Point live watch `wd` at delegated file `file_handle` with `mask`,
    /// adding the entry if the watch is not in the table yet. The caller holds
    /// the instance lock.
    pub fn attach_watch_file(&self, wd: i32, file_handle: u32, mask: u32) -> bool {
        let watches = unsafe { &mut *self.watches.get() };
        if let Some(w) = watches.iter_mut().find(|w| w.alive != 0 && w.wd == wd) {
            w.file_handle = file_handle;
            w.mask = mask;
            return true;
        }
        self.add_watch(wd, file_handle, mask)
    }

    pub fn remove_watch(&self, wd: i32) -> Option<u32> {
        let watches = unsafe { &mut *self.watches.get() };
        for w in watches.iter_mut() {
            if w.alive != 0 && w.wd == wd {
                let file_handle = w.file_handle;
                *w = DelegatedWatch::default();
                self.num_watches.fetch_sub(1, Ordering::Release);
                return Some(file_handle);
            }
        }
        None
    }

    /// Queue one event. The caller holds the instance lock.
    pub fn push_record(&self, wd: i32, mask: u32, cookie: u32, name: Option<&[u8]>) -> QueuePush {
        // SAFETY: the queue is only touched under the instance lock.
        let queue = unsafe { &mut *self.queue.get() };
        let was_empty = queue.is_empty();
        let result = queue.push(wd, mask, cookie, name);
        // SeqCst store and load: pairs with the host's `host_observed` store
        // and its readiness probe, so a waiter either sees the record or is
        // owed the wake.
        self.queued_bytes
            .store(queue.queued_bytes(), Ordering::SeqCst);
        // Readable edge: a host thread that waited on the empty instance
        // sleeps on a host object EL1 cannot signal, so the wake is owed.
        if was_empty && !queue.is_empty() && self.host_observed.load(Ordering::SeqCst) != 0 {
            self.wake_owed.store(1, Ordering::Release);
        }
        result
    }

    /// Whether an enqueue owes a host waiter a wake (without clearing it).
    #[inline]
    pub fn wake_is_owed(&self) -> bool {
        self.wake_owed.load(Ordering::Acquire) != 0
    }

    /// Take the owed wake, if any.
    #[inline]
    pub fn take_wake_owed(&self) -> bool {
        self.wake_owed.swap(0, Ordering::AcqRel) != 0
    }

    /// Move whole records into `dest` (read(2) semantics). The caller holds
    /// the instance lock.
    pub fn drain_into(&self, dest: &mut [u8]) -> Result<usize, LinuxErrno> {
        // SAFETY: the queue is only touched under the instance lock.
        let queue = unsafe { &mut *self.queue.get() };
        let result = queue.drain_into(dest);
        self.queued_bytes
            .store(queue.queued_bytes(), Ordering::Release);
        result
    }

    /// Whether any record is queued. The caller holds the instance lock.
    pub fn has_records(&self) -> bool {
        // SAFETY: the queue is only touched under the instance lock.
        !unsafe { &*self.queue.get() }.is_empty()
    }

    /// Reset the queue for a new incarnation. The caller holds the lock.
    pub fn reset_queue(&self) {
        // SAFETY: the queue is only touched under the instance lock.
        unsafe { *self.queue.get() = InotifyEventQueue::new() };
        self.queued_bytes.store(0, Ordering::Release);
        self.spilled.store(0, Ordering::Release);
        self.host_observed.store(0, Ordering::Release);
        self.wake_owed.store(0, Ordering::Release);
    }
}

impl Default for DelegatedInotify {
    fn default() -> Self {
        Self::new()
    }
}

/// Number of entries in the in-guest inotify name cache.
pub const NAME_CACHE_ENTRIES: usize = 32;

/// Maximum pathname length cached in an inotify name cache entry.
pub const MAX_NAME_CACHE_PATH_LEN: usize = 256;

/// Fast, non-cryptographic FNV-1a hash for path byte slices.
#[inline]
pub fn hash_path(path: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in path {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// A single cache entry mapping `(cwd_gen, path_bytes)` -> `delegated_file_handle`.
#[repr(C)]
pub struct InotifyNameCacheEntry {
    pub lock: AtomicU32,
    pub valid: AtomicU32,
    pub file_table: AtomicU64,
    pub cwd_generation: AtomicU64,
    pub path_len: AtomicU32,
    pub delegated_file_handle: AtomicU32,
    pub path_hash: AtomicU64,
    pub path_bytes: UnsafeCell<[u8; MAX_NAME_CACHE_PATH_LEN]>,
}

unsafe impl Sync for InotifyNameCacheEntry {}

impl InotifyNameCacheEntry {
    pub const fn new() -> Self {
        Self {
            lock: AtomicU32::new(0),
            valid: AtomicU32::new(0),
            file_table: AtomicU64::new(0),
            cwd_generation: AtomicU64::new(0),
            path_len: AtomicU32::new(0),
            delegated_file_handle: AtomicU32::new(0),
            path_hash: AtomicU64::new(0),
            path_bytes: UnsafeCell::new([0; MAX_NAME_CACHE_PATH_LEN]),
        }
    }

    #[inline]
    pub fn try_lock(&self) -> bool {
        // Strong: a spurious LL/SC failure must not look like contention.
        self.lock
            .compare_exchange(0, LOCK_GUEST, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// EL1 acquire: wait a bounded while only for another vCPU's in-guest
    /// critical section (short, and completed even across kicks); a host
    /// holder may be a long recall, so forward at once. Bounded, so a lock
    /// order inversion between vCPUs costs a forward, never a deadlock.
    #[inline]
    pub fn lock_guest_bounded(&self, max_spins: u32) -> bool {
        for _ in 0..max_spins {
            match self
                .lock
                .compare_exchange(0, LOCK_GUEST, Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(LOCK_HOST) => return false,
                Err(_) => core::hint::spin_loop(),
            }
        }
        false
    }

    #[inline]
    pub fn unlock(&self) {
        self.lock.store(0, Ordering::Release);
    }
}

impl Default for InotifyNameCacheEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-process inotify path name cache at EL1 for exit-free `inotify_add_watch`.
#[repr(C)]
#[repr(align(64))]
pub struct InotifyNameCache {
    pub global_cwd_generation: AtomicU64,
    pub entries: [InotifyNameCacheEntry; NAME_CACHE_ENTRIES],
}

unsafe impl Sync for InotifyNameCache {}

impl InotifyNameCache {
    pub const fn new() -> Self {
        Self {
            global_cwd_generation: AtomicU64::new(1),
            entries: [const { InotifyNameCacheEntry::new() }; NAME_CACHE_ENTRIES],
        }
    }

    #[inline]
    pub fn bump_cwd_generation(&self) -> u64 {
        self.global_cwd_generation.fetch_add(1, Ordering::AcqRel) + 1
    }

    #[inline]
    pub fn cwd_generation(&self) -> u64 {
        self.global_cwd_generation.load(Ordering::Acquire)
    }

    pub fn lookup(&self, file_table: u64, path: &[u8], path_hash: u64) -> Option<u32> {
        let cur_cwd_gen = self.cwd_generation();
        let path_len = path.len();
        if path_len == 0 || path_len > MAX_NAME_CACHE_PATH_LEN {
            return None;
        }

        for entry in self.entries.iter() {
            if entry.valid.load(Ordering::Acquire) != 0
                && entry.file_table.load(Ordering::Relaxed) == file_table
                && entry.cwd_generation.load(Ordering::Relaxed) == cur_cwd_gen
                && entry.path_hash.load(Ordering::Relaxed) == path_hash
                && entry.path_len.load(Ordering::Relaxed) as usize == path_len
            {
                let path_bytes = unsafe { &*entry.path_bytes.get() };
                if &path_bytes[..path_len] == path {
                    let handle = entry.delegated_file_handle.load(Ordering::Relaxed);
                    if handle != 0 && entry.valid.load(Ordering::Acquire) != 0 {
                        return Some(handle);
                    }
                }
            }
        }
        None
    }

    pub fn insert(
        &self,
        file_table: u64,
        cwd_gen: u64,
        path: &[u8],
        path_hash: u64,
        delegated_file_handle: u32,
    ) {
        let path_len = path.len();
        if path_len == 0 || path_len > MAX_NAME_CACHE_PATH_LEN {
            return;
        }

        for entry in self.entries.iter() {
            if !entry.try_lock() {
                continue;
            }
            let is_match = {
                let cur_path = unsafe { &*entry.path_bytes.get() };
                entry.valid.load(Ordering::Relaxed) != 0
                    && entry.file_table.load(Ordering::Relaxed) == file_table
                    && entry.path_hash.load(Ordering::Relaxed) == path_hash
                    && entry.path_len.load(Ordering::Relaxed) as usize == path_len
                    && &cur_path[..path_len] == path
            };

            let is_empty = entry.valid.load(Ordering::Relaxed) == 0;

            if is_match || is_empty {
                entry.valid.store(0, Ordering::Release);
                entry.file_table.store(file_table, Ordering::Relaxed);
                entry.cwd_generation.store(cwd_gen, Ordering::Relaxed);
                entry.path_len.store(path_len as u32, Ordering::Relaxed);
                entry.path_hash.store(path_hash, Ordering::Relaxed);
                let path_bytes = unsafe { &mut *entry.path_bytes.get() };
                path_bytes[..path_len].copy_from_slice(path);
                entry
                    .delegated_file_handle
                    .store(delegated_file_handle, Ordering::Relaxed);
                entry.valid.store(1, Ordering::Release);
                entry.unlock();
                return;
            }
            entry.unlock();
        }

        let Some(entry) = self.entries.first() else {
            return;
        };
        if entry.try_lock() {
            entry.valid.store(0, Ordering::Release);
            entry.file_table.store(file_table, Ordering::Relaxed);
            entry.cwd_generation.store(cwd_gen, Ordering::Relaxed);
            entry.path_len.store(path_len as u32, Ordering::Relaxed);
            entry.path_hash.store(path_hash, Ordering::Relaxed);
            let path_bytes = unsafe { &mut *entry.path_bytes.get() };
            path_bytes[..path_len].copy_from_slice(path);
            entry
                .delegated_file_handle
                .store(delegated_file_handle, Ordering::Relaxed);
            entry.valid.store(1, Ordering::Release);
            entry.unlock();
        }
    }

    pub fn invalidate_all(&self) {
        for entry in self.entries.iter() {
            entry.valid.store(0, Ordering::Release);
        }
    }

    pub fn invalidate_file(&self, file_handle: u32) {
        for entry in self.entries.iter() {
            if entry.delegated_file_handle.load(Ordering::Relaxed) == file_handle {
                entry.valid.store(0, Ordering::Release);
            }
        }
    }
}

impl Default for InotifyNameCache {
    fn default() -> Self {
        Self::new()
    }
}

const _: () = {
    assert!(core::mem::size_of::<ApertureControl>() == 64);
    assert!(core::mem::align_of::<ApertureControl>() == 64);
    assert!(
        EL1_APERTURE_CONTROL_OFFSET.is_multiple_of(core::mem::align_of::<ApertureControl>() as u64)
    );
    assert!(
        EL1_APERTURE_CONTROL_OFFSET + core::mem::size_of::<ApertureControl>() as u64
            <= EL1_MM_PORTAL_OFFSET
    );
};
#[cfg(target_arch = "aarch64")]
const _: () = assert!(EL1_ABI_LAYOUT_HASH == 0x9cdc6e5153bc05c7);
#[cfg(not(target_arch = "aarch64"))]
const _: () = assert!(EL1_ABI_LAYOUT_HASH == 0x872a389c195ace73);

#[cfg(test)]
mod tests {
    #[test]
    fn first_process_admission_failure_keeps_live_root() {
        let counters = Counters::new();
        counters.record_first_process_admission_failure(0);
        counters.record_first_process_admission_failure(0x2000);
        assert_eq!(
            counters
                .copy_snapshot()
                .first_process_admission_root
                .load(Ordering::Acquire),
            1
        );
    }

    #[test]
    fn first_registry_refusal_keeps_both_identity_domains() {
        let counters = Counters::new();
        counters.record_first_process_registry_refusal(
            [11, 12, 13, 14, 15, 16, 17],
            [21, 22, 23, 24, 25, 26, 27],
        );
        counters.record_first_process_registry_refusal([0; 7], [0; 7]);
        let snapshot = counters.copy_snapshot();
        assert_eq!(
            snapshot
                .first_process_registry_refusal
                .map(|word| word.load(Ordering::Acquire)),
            [1, 11, 12, 13, 14, 15, 16, 17, 21, 22, 23, 24, 25, 26, 27]
        );
    }

    #[test]
    fn first_process_admission_stage_keeps_first_failure() {
        let counters = Counters::new();
        counters.record_first_process_admission_stage(5);
        counters.record_first_process_admission_stage(6);
        let snapshot = counters.copy_snapshot();
        assert_eq!(
            snapshot
                .first_process_admission_stage
                .load(Ordering::Relaxed),
            5
        );
    }

    #[test]
    fn first_process_missing_entry_keeps_exact_call_and_slot() {
        let counters = Counters::new();
        counters.record_first_process_missing_entry(7, 260, true, true, false, false);
        counters.record_first_process_missing_entry(8, 94, true, true, true, false);
        assert_eq!(
            counters
                .copy_snapshot()
                .first_process_missing_entry
                .load(Ordering::Acquire),
            1 | (1 << 1) | (1 << 2) | (7 << 16) | (260 << 32)
        );
    }

    #[test]
    fn first_process_missing_entry_keeps_first_failure() {
        let counters = Counters::new();
        counters.record_first_process_missing_entry(1, 220, true, true, false, true);
        counters.record_first_process_missing_entry(2, 260, true, false, false, false);
        assert_eq!(
            counters
                .copy_snapshot()
                .first_process_missing_entry
                .load(Ordering::Acquire),
            1 | (1 << 1) | (1 << 2) | (1 << 4) | (1 << 16) | (220 << 32)
        );
    }

    #[test]
    fn aperture_control_is_disjoint_from_service_copy_descriptors() {
        let aperture_end =
            EL1_APERTURE_CONTROL_OFFSET + core::mem::size_of::<ApertureControl>() as u64;
        let service_end =
            EL1_SERVICE_COPY_TABLE_OFFSET + core::mem::size_of::<ServiceCopyTable>() as u64;
        assert!(
            aperture_end <= EL1_SERVICE_COPY_TABLE_OFFSET
                || service_end <= EL1_APERTURE_CONTROL_OFFSET,
            "strict control aliases the service-copy L3 descriptors"
        );
    }

    #[test]
    fn fork_stock_window_is_one_backed_extent() {
        let first =
            super::EL1_DYNAMIC_METADATA_BASE + super::EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64;
        let window = super::fork_stock_table_window(first + 4096).unwrap();
        assert_eq!(window.physical_base, first);
        assert_eq!(window.byte_len, super::EL1_DYNAMIC_METADATA_EXTENT_SIZE);
        assert!(super::fork_stock_table_window(super::EL1_DYNAMIC_METADATA_BASE - 4096).is_none());
        assert!(
            super::fork_stock_table_window(
                super::EL1_DYNAMIC_METADATA_BASE + super::EL1_DYNAMIC_METADATA_SIZE
            )
            .is_none()
        );
    }

    #[test]
    fn native_fork_failure_preserves_the_first_stage() {
        let counters = Counters::new();
        counters.record_first_native_fork_failure(NativeForkFailureStage::Census);
        counters.record_first_native_fork_failure(NativeForkFailureStage::Publish);
        let snapshot = counters.copy_snapshot();
        assert_eq!(
            NativeForkFailureStage::from_raw(
                snapshot.first_native_fork_failure.load(Ordering::Acquire)
            ),
            Some(NativeForkFailureStage::Census)
        );
    }

    #[test]
    fn host_aperture_address_checks_region_bounds_alignment_and_overflow() {
        let offset = EL1_APERTURE_CONTROL_OFFSET as usize;
        let size = core::mem::size_of::<ApertureControl>();
        assert_eq!(
            checked_aperture_host_address(0x1000, offset + size),
            Some(0x1000 + offset)
        );
        assert_eq!(
            checked_aperture_host_address(0x1000, offset + size - 1),
            None
        );
        assert_eq!(checked_aperture_host_address(0x1001, offset + size), None);
        assert_eq!(
            checked_aperture_host_address(usize::MAX - 63, EL1_REGION_SIZE as usize),
            None
        );
        assert_eq!(
            checked_aperture_host_address(0, EL1_REGION_SIZE as usize),
            None
        );
    }

    #[test]
    fn test_aperture_control_strict_flag() {
        let aperture = ApertureControl::new();
        assert!(
            aperture.is_strict(),
            "zero control must enforce strict admission"
        );
        aperture.set_strict(true);
        assert!(aperture.is_strict());
        assert_eq!(
            aperture.control.load(Ordering::Relaxed) & APERTURE_CONTROL_ARM_RING_FIRST_OPT_OUT,
            0
        );
        aperture.set_strict(false);
        assert!(!aperture.is_strict());
    }

    #[test]
    fn readiness_timeout_rejects_noncanonical_wire_words() {
        use super::HostReadinessTimeout;
        assert_eq!(
            HostReadinessTimeout::from_wire(u64::MAX).unwrap().millis(),
            -1
        );
        assert_eq!(HostReadinessTimeout::from_wire(7).unwrap().millis(), 7);
        assert_eq!(HostReadinessTimeout::from_wire(0x1_0000_0000), None);
    }

    #[test]
    fn host_binding_does_not_survive_description_reuse() {
        let description = super::DelegatedOpenFile::new();
        description.bind_host_fd(super::HostBoundFd::new(0).unwrap());
        assert_eq!(description.host_fd().map(super::HostBoundFd::raw), Some(0));
        description.clear_host_fd();
        assert_eq!(description.host_fd(), None);
    }
    #[test]
    fn lifecycle_mapping_binding_is_revoked_on_task_clear() {
        let task = CurrentTask::new();
        task.publish_lifecycle(0x10000, 0x20000);
        assert_eq!(
            task.metadata.lifecycle_page.load(Ordering::Acquire),
            0x10000
        );
        assert_eq!(task.metadata.control_slot.load(Ordering::Acquire), 0x20000);
        task.clear();
        assert_eq!(task.metadata.lifecycle_page.load(Ordering::Acquire), 0);
        assert_eq!(task.metadata.control_slot.load(Ordering::Acquire), 0);
    }
    #[test]
    fn only_a_commit_owed_call_replays_and_a_drain_never_downgrades_it() {
        let task = CurrentTask::new();
        // A plain served call that left because a drain blocked: complete,
        // whatever its stale `orig_arg0` and syscall number.
        task.linux.orig_arg0.store(0, Ordering::Relaxed);
        task.linux.record_completed_with_work();
        assert_eq!(
            task.linux.served_with_work.load(Ordering::Relaxed),
            SERVED_WAKES_OWED
        );
        // A call owing its commit replays with the preserved argument ...
        task.linux.record_commit_owed(0x6000);
        assert_eq!(
            task.linux.served_with_work.load(Ordering::Relaxed),
            SERVED_COMMIT_OWED
        );
        assert_eq!(task.linux.orig_arg0.load(Ordering::Relaxed), 0x6000);
        // ... and a later blocked drain (`record_completed_with_work`) keeps it.
        task.linux.record_completed_with_work();
        assert_eq!(
            task.linux.served_with_work.load(Ordering::Relaxed),
            SERVED_COMMIT_OWED
        );
    }

    use super::*;

    #[test]
    fn test_region_layout() {
        assert_eq!(EL1_REGION_BASE, 0x2D_0400_0000);
        assert_eq!(EL1_REGION_SIZE, 0x0400_0000);
        assert_eq!(EL1_IPC_BASE, 0x2D_0C00_0000);
    }

    #[test]
    fn test_trap_frame_layout() {
        assert_eq!(core::mem::size_of::<TrapFrame>(), 288);
        assert_eq!(core::mem::align_of::<TrapFrame>(), 8);
        assert_eq!(core::mem::offset_of!(TrapFrame, x), 0);
        assert_eq!(core::mem::offset_of!(TrapFrame, elr), 31 * 8);
        assert_eq!(core::mem::offset_of!(TrapFrame, spsr), 32 * 8);
        assert_eq!(core::mem::offset_of!(TrapFrame, esr), 33 * 8);
        assert_eq!(core::mem::offset_of!(TrapFrame, slot), 34 * 8);
        assert_eq!(core::mem::offset_of!(TrapFrame, far), 35 * 8);
    }

    #[test]
    fn test_action_discriminants() {
        assert_eq!(Action::Served as u64, 0);
        assert_eq!(Action::Forward as u64, 1);
        assert_eq!(Action::ServedWithWork as u64, 2);
    }

    #[test]
    fn test_counters_layout() {
        assert_eq!(
            core::mem::size_of::<Counters>(),
            (1024
                + 32
                + 1
                + El1ExitReason::COUNT
                + IpcLeave::COUNT
                + LifecycleDecline::COUNT
                + AnonymousLeave::COUNT
                + 513
                + ProcessRefusal::COUNT
                + 4
                + 15
                + NativeForkProgress::COUNT)
                * 8
        );
        assert_eq!(
            core::mem::offset_of!(Counters, first_native_fork_failure),
            core::mem::size_of::<Counters>() - (NativeForkProgress::COUNT + 4 + 15) * 8
        );
        assert_eq!(core::mem::offset_of!(Counters, served), 0);
        assert_eq!(core::mem::offset_of!(Counters, forwarded), 512 * 8);
        // The vector page's IRQ hook addresses this array directly.
        assert_eq!(core::mem::offset_of!(Counters, irq_taken), 1024 * 8);
        assert_eq!(
            core::mem::offset_of!(Counters, fault_taken),
            (1024 + 32) * 8
        );
        assert_eq!(
            core::mem::offset_of!(Counters, exit_reasons),
            (1024 + 32 + 1) * 8
        );
        assert_eq!(
            core::mem::offset_of!(Counters, refused),
            (1024
                + 32
                + 1
                + El1ExitReason::COUNT
                + IpcLeave::COUNT
                + LifecycleDecline::COUNT
                + AnonymousLeave::COUNT)
                * 8
        );
    }

    #[test]
    fn test_counters_snapshot_and_initialization() {
        let counters = Counters::new();
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 0);
        assert_eq!(counters.served[0].load(Ordering::Relaxed), 0);
        assert_eq!(counters.forwarded[0].load(Ordering::Relaxed), 0);
        assert_eq!(counters.irq_taken[0].load(Ordering::Relaxed), 0);

        counters.fault_taken.store(5, Ordering::Relaxed);
        counters.served[10].store(20, Ordering::Relaxed);
        counters.forwarded[30].store(40, Ordering::Relaxed);
        counters.irq_taken[2].store(8, Ordering::Relaxed);
        counters.exit_reasons[El1ExitReason::Service as usize].store(3, Ordering::Relaxed);
        counters.record_lifecycle_decline(LifecycleDecline::ExitHome);

        let snap = counters.copy_snapshot();
        assert_eq!(
            snap.lifecycle_declines[LifecycleDecline::ExitHome as usize].load(Ordering::Relaxed),
            1
        );
        assert_eq!(snap.fault_taken.load(Ordering::Relaxed), 5);
        assert_eq!(snap.served[10].load(Ordering::Relaxed), 20);
        assert_eq!(snap.forwarded[30].load(Ordering::Relaxed), 40);
        assert_eq!(snap.irq_taken[2].load(Ordering::Relaxed), 8);
        assert_eq!(
            snap.exit_reasons[El1ExitReason::Service as usize].load(Ordering::Relaxed),
            3
        );

        // Modifying original doesn't affect snapshot
        counters.fault_taken.store(100, Ordering::Relaxed);
        assert_eq!(snap.fault_taken.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn host_exit_classes_keep_hvf_and_el1_reasons_distinct() {
        use HostExitClass::*;
        let hvc = |imm| (0x16_u64 << 26) | imm;
        assert_eq!(HostExitClass::from_hvf(true, false, 0), Canceled);
        assert_eq!(HostExitClass::from_hvf(false, true, hvc(5)), Idle);
        assert_eq!(HostExitClass::from_hvf(false, true, hvc(4)), Kick);
        assert_eq!(HostExitClass::from_hvf(false, true, hvc(2)), Syscall);
        assert_eq!(HostExitClass::from_hvf(false, true, hvc(6)), Metadata);
        assert_eq!(HostExitClass::from_hvf(false, true, hvc(1)), Maintenance);
        assert_eq!(HostExitClass::from_hvf(false, true, 0x24_u64 << 26), Fault);
        assert_eq!(HostExitClass::from_hvf(false, false, 0), Other);
    }

    #[test]
    fn host_exit_class_ordinals_round_trip_and_index_the_counters() {
        for (index, class) in HostExitClass::ALL.into_iter().enumerate() {
            assert_eq!(class as usize, index);
            assert_eq!(class.ordinal() as usize, index);
            assert_eq!(HostExitClass::from_ordinal(class.ordinal()), Some(class));
        }
        assert_eq!(
            HostExitClass::from_ordinal(HostExitClass::COUNT as u32),
            None
        );
        assert_eq!(HostExitClass::from_ordinal(u32::MAX), None);
    }

    #[test]
    fn hvc_not_svc_reason_keeps_el0_syndrome_and_fault_status() {
        let data_abort = HvcNotSvcReason::from_esr((0x24_u64 << 26) | 0x45);
        assert_eq!(data_abort.ec, 0x24);
        assert_eq!(data_abort.fault_status, Some(0x05));
        let sys64 = HvcNotSvcReason::from_esr(0x18_u64 << 26);
        assert_eq!(sys64.ec, 0x18);
        assert_eq!(sys64.fault_status, None);
        assert_eq!(
            sys64_sysreg_kind(
                (0x18_u64 << 26) | (3 << 20) | (2 << 17) | (3 << 14) | (14 << 10) | 1
            ),
            HvcSysregKind::Cntvct
        );
        assert_eq!(sys64_sysreg_kind(0x6232c021), HvcSysregKind::Ctr);
    }

    #[test]
    fn test_image_header_layout() {
        assert_eq!(core::mem::size_of::<ImageHeader>(), 32);
        assert_eq!(core::mem::offset_of!(ImageHeader, abi_hash_offset), 24);
        assert_eq!(core::mem::offset_of!(ImageHeader, magic), 0);
        assert_eq!(core::mem::offset_of!(ImageHeader, version), 4);
        assert_eq!(core::mem::offset_of!(ImageHeader, entry_offset), 8);
        assert_eq!(core::mem::offset_of!(ImageHeader, image_size), 16);
    }

    #[test]
    fn test_current_task_layout() {
        assert_eq!(core::mem::size_of::<CurrentTask>(), 128);
        assert_eq!(core::mem::align_of::<CurrentTask>(), 8);
        assert_eq!(core::mem::offset_of!(CurrentTask, execution.generation), 0);
        assert_eq!(core::mem::offset_of!(CurrentTask, execution.task), 8);
        assert_eq!(core::mem::offset_of!(CurrentTask, linux.file_table), 16);
        assert_eq!(core::mem::offset_of!(CurrentTask, linux.fixup_pc), 24);
        assert_eq!(core::mem::offset_of!(CurrentTask, linux.orig_arg0), 32);
        assert_eq!(
            core::mem::offset_of!(CurrentTask, linux.pending_host_work),
            40
        );
        assert_eq!(
            core::mem::offset_of!(CurrentTask, linux.served_with_work),
            44
        );
    }

    #[test]
    fn test_delegated_file_layout() {
        assert_eq!(core::mem::size_of::<DelegatedFile>(), 256);
        assert_eq!(core::mem::align_of::<DelegatedFile>(), 64);
    }

    #[test]
    fn test_delegated_inotify_layout() {
        assert!(core::mem::size_of::<DelegatedInotify>() <= 300 * 1024);
        assert_eq!(core::mem::align_of::<DelegatedInotify>(), 64);
        assert!(
            MAX_DELEGATED_INOTIFY * core::mem::size_of::<DelegatedInotify>()
                <= EL1_INOTIFY_TABLE_SIZE as usize
        );
        assert!(core::mem::size_of::<InotifyNameCache>() <= EL1_NAME_CACHE_SIZE as usize);
    }

    #[test]
    fn test_fd_map_slot_layout() {
        assert_eq!(core::mem::size_of::<FdMapSlot>(), 32);
        assert_eq!(core::mem::align_of::<FdMapSlot>(), 8);
        assert_eq!(core::mem::offset_of!(FdMapSlot, file_table), 0);
        assert_eq!(core::mem::offset_of!(FdMapSlot, fd), 8);
        assert_eq!(core::mem::offset_of!(FdMapSlot, handle), 12);
        assert_eq!(core::mem::offset_of!(FdMapSlot, incarnation), 16);
    }

    #[test]
    fn el1_task_id_zero_extends_and_never_matches_none() {
        assert_eq!(El1TaskId::NONE.raw(), 0);
        assert_eq!(El1TaskId::from_linux_tid(7).raw(), 7);
        // A bare `tid as u64` would sign-extend a negative i32; the typed
        // constructor zero-extends so the word is always a 32-bit value.
        assert_eq!(El1TaskId::from_linux_tid(-1).raw(), 0xffff_ffff);
        assert_ne!(El1TaskId::from_linux_tid(-1).raw(), (-1i32) as u64);
    }

    #[test]
    fn test_current_task_operations() {
        let task = CurrentTask::new();
        assert_eq!(task.execution.task.load(Ordering::Relaxed), 0);
        assert_eq!(task.execution.generation.load(Ordering::Relaxed), 0);
        assert_eq!(task.linux.file_table.load(Ordering::Relaxed), 0);

        task.set(El1TaskId::from_linux_tid(7), 42, 100);
        assert_eq!(task.execution.task.load(Ordering::Relaxed), 7);
        assert_eq!(task.execution.generation.load(Ordering::Relaxed), 42);
        assert_eq!(task.linux.file_table.load(Ordering::Relaxed), 100);

        task.clear();
        assert_eq!(task.execution.task.load(Ordering::Relaxed), 0);
        assert_eq!(task.execution.generation.load(Ordering::Relaxed), 0);
        assert_eq!(task.linux.file_table.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_delegated_file_locking() {
        let file = DelegatedFile::new();
        assert!(!file.is_locked());
        assert!(file.try_lock());
        assert!(file.is_locked());
        assert!(!file.try_lock());
        file.unlock();
        assert!(!file.is_locked());
        assert!(file.try_lock());
        file.unlock();
    }

    #[test]
    fn test_fd_map_operations() {
        let slots = [const { FdMapSlot::new() }; FD_MAP_CAPACITY];
        assert_eq!(fd_map_lookup(&slots, 10, 3), None);

        slots[0].set(10, 3, 1, 101);
        slots[1].set(10, 4, 2, 102);
        slots[2].set(20, 3, 3, 103);

        assert_eq!(fd_map_lookup(&slots, 10, 3), Some((1, 0)));
        assert_eq!(fd_map_lookup(&slots, 10, 4), Some((2, 1)));
        assert_eq!(fd_map_lookup(&slots, 20, 3), Some((3, 2)));
        assert_eq!(fd_map_lookup(&slots, 10, 5), None);
        assert_eq!(fd_map_lookup(&slots, 30, 3), None);

        slots[0].clear();
        assert_eq!(fd_map_lookup(&slots, 10, 3), None);
    }

    #[test]
    fn test_delegated_file_cache_va() {
        let va1 = delegated_file_cache_va(1);
        let va2 = delegated_file_cache_va(2);
        assert_eq!(va1, EL1_CACHE_BASE);
        assert_eq!(va2, EL1_CACHE_BASE + DELEGATED_FILE_MAX_SIZE);
    }

    #[test]
    fn test_pending_host_work_helpers() {
        extern crate std;
        let mut arena = std::vec![0u8; EL1_CURRENT_TASKS_OFFSET as usize + 256 * core::mem::size_of::<CurrentTask>()];
        let ptr = arena.as_mut_ptr() as usize;
        record_el1_region_host_ptr(ptr);
        assert_eq!(get_el1_region_host_ptr(), ptr);

        let publications_before = host_work_publication_counts();
        mark_pending_host_work(5);
        let publications_after = host_work_publication_counts();
        assert_eq!(
            publications_after[HostWorkPublishReason::DirectSlot as usize],
            publications_before[HostWorkPublishReason::DirectSlot as usize] + 1
        );
        let task_5 = unsafe {
            &*((ptr + EL1_CURRENT_TASKS_OFFSET as usize + 5 * core::mem::size_of::<CurrentTask>())
                as *const CurrentTask)
        };
        assert!(task_5.linux.has_pending_host_work());

        clear_pending_host_work(5);
        assert!(!task_5.linux.has_pending_host_work());

        let task_6 = unsafe {
            &*((ptr + EL1_CURRENT_TASKS_OFFSET as usize + 6 * core::mem::size_of::<CurrentTask>())
                as *const CurrentTask)
        };
        task_6.execution.task.store(43, Ordering::Relaxed);

        task_5.execution.task.store(42, Ordering::Relaxed);
        mark_pending_host_work_for_task(El1TaskId::from_linux_tid(42));
        assert!(task_5.linux.has_pending_host_work());
        assert!(!task_6.linux.has_pending_host_work()); // sibling task remains untouched

        task_5.linux.file_table.store(100, Ordering::Relaxed);
        update_current_task_file_table_for_task(El1TaskId::from_linux_tid(42), 200);
        assert_eq!(task_5.linux.file_table.load(Ordering::Acquire), 200);
        assert_eq!(task_6.linux.file_table.load(Ordering::Acquire), 0);

        task_5.linux.served_with_work.store(1, Ordering::Relaxed);
        assert!(take_served_with_work(5));
        assert!(!take_served_with_work(5));

        task_5.linux.clear_pending_host_work();
        task_6.linux.clear_pending_host_work();
        let task_7 = unsafe {
            &*((ptr + EL1_CURRENT_TASKS_OFFSET as usize + 7 * core::mem::size_of::<CurrentTask>())
                as *const CurrentTask)
        };
        task_7.linux.file_table.store(200, Ordering::Relaxed);
        // task_7 has task_id = 0 (no task running)
        assert_eq!(task_7.execution.task.load(Ordering::Relaxed), 0);

        mark_pending_host_work_for_file_tables(&[200]);
        // task_5 has task_id = 42 and file_table = 200, so it must be marked
        assert!(task_5.linux.has_pending_host_work());
        // task_6 has task_id = 43 and file_table = 0, so it must NOT be marked
        assert!(!task_6.linux.has_pending_host_work());
        // task_7 has no task (task_id = 0), so it must NEVER be marked
        assert!(!task_7.linux.has_pending_host_work()); // cleared after take

        record_el1_region_host_ptr(0);
        assert_eq!(get_el1_region_host_ptr(), 0);
    }

    #[test]
    fn test_delegated_inotify_operations() {
        let inotify = DelegatedInotify::new();
        assert!(!inotify.is_locked());
        assert!(inotify.try_lock());
        assert!(inotify.is_locked());
        inotify.unlock();

        let wd1 = inotify.alloc_wd().unwrap();
        assert_eq!(wd1, 1);
        let wd2 = inotify.alloc_wd().unwrap();
        assert_eq!(wd2, 2);

        assert!(inotify.add_watch(wd1, 10, 0x2)); // IN_MODIFY
        assert!(inotify.add_watch(wd2, 11, 0x2));
        assert_eq!(inotify.find_watch(wd1).unwrap().1.file_handle, 10);
        assert_eq!(inotify.find_watch(wd2).unwrap().1.file_handle, 11);

        // Test push & coalesce
        assert_eq!(
            inotify.push_record(wd1, 0x2, 0, None),
            QueuePush::Appended { was_empty: true }
        );
        assert_eq!(inotify.push_record(wd1, 0x2, 0, None), QueuePush::Coalesced);
        assert_eq!(
            inotify.push_record(wd2, 0x2, 0, None),
            QueuePush::Appended { was_empty: false }
        );
        // IN_IGNORED (0x8000) does not coalesce
        assert_eq!(
            inotify.push_record(wd1, 0x8000, 0, None),
            QueuePush::Appended { was_empty: false }
        );

        let mut buf = [0u8; 64];
        let n = inotify.drain_into(&mut buf).unwrap();
        assert_eq!(n, 48); // 3 events * 16 bytes

        // Check removed watch
        assert_eq!(inotify.remove_watch(wd1), Some(10));
        assert_eq!(inotify.find_watch(wd1), None);
    }

    #[test]
    fn test_inotify_name_cache() {
        let cache = InotifyNameCache::new();
        let path = b"test_file.txt";
        let hash = hash_path(path);
        let file_table = 42;

        assert_eq!(cache.lookup(file_table, path, hash), None);

        let cwd_gen = cache.cwd_generation();
        cache.insert(file_table, cwd_gen, path, hash, 7);
        assert_eq!(cache.lookup(file_table, path, hash), Some(7));
        assert_eq!(cache.lookup(99, path, hash), None);
        assert_eq!(
            cache.lookup(file_table, b"other.txt", hash_path(b"other.txt")),
            None
        );

        // Bump cwd_gen invalidates entries from old cwd_gen
        cache.bump_cwd_generation();
        assert_eq!(cache.lookup(file_table, path, hash), None);

        // Re-insert under new cwd_gen
        let new_gen = cache.cwd_generation();
        cache.insert(file_table, new_gen, path, hash, 8);
        assert_eq!(cache.lookup(file_table, path, hash), Some(8));

        // Invalidate file
        cache.invalidate_file(8);
        assert_eq!(cache.lookup(file_table, path, hash), None);

        // Invalidate all
        cache.insert(file_table, new_gen, path, hash, 9);
        assert_eq!(cache.lookup(file_table, path, hash), Some(9));
        cache.invalidate_all();
        assert_eq!(cache.lookup(file_table, path, hash), None);
    }

    #[test]
    fn an_enqueue_owes_a_wake_only_on_the_readable_edge_of_an_observed_instance() {
        extern crate std;
        let instance = std::boxed::Box::new(DelegatedInotify::new());
        // Unobserved: nobody waits on a host object, nothing is owed.
        let _ = instance.push_record(1, 0x2, 0, None);
        assert!(!instance.wake_is_owed());
        let mut out = [0u8; 64];
        assert!(instance.drain_into(&mut out).is_ok());
        // Observed and empty: the first record owes the waiter a wake.
        instance.host_observed.store(1, Ordering::SeqCst);
        let _ = instance.push_record(1, 0x2, 0, None);
        assert!(instance.take_wake_owed());
        // Already readable: a second record owes nothing new.
        let _ = instance.push_record(2, 0x2, 0, None);
        assert!(!instance.wake_is_owed());
        // A new incarnation forgets its waiters.
        instance.reset_queue();
        assert_eq!(instance.host_observed.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn an_image_built_against_another_layout_is_refused() {
        extern crate std;
        let mut image = std::vec![0u8; 64];
        image[0..4].copy_from_slice(&IMAGE_MAGIC);
        image[4..8].copy_from_slice(&IMAGE_VERSION.to_le_bytes());
        image[24..32].copy_from_slice(&40u64.to_le_bytes());
        image[40..48].copy_from_slice(&EL1_ABI_LAYOUT_HASH.to_le_bytes());
        assert!(check_image_abi(&image).is_ok());
        image[40] ^= 1;
        assert!(matches!(
            check_image_abi(&image),
            Err(ImageAbiError::LayoutMismatch { .. })
        ));
        image[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            check_image_abi(&image),
            Err(ImageAbiError::Version { found: 1 })
        );
        image[24..32].copy_from_slice(&60u64.to_le_bytes());
        image[4..8].copy_from_slice(&IMAGE_VERSION.to_le_bytes());
        assert_eq!(check_image_abi(&image), Err(ImageAbiError::HashOutOfBounds));
    }

    #[test]
    fn metadata_mailbox_admits_wait_identity_before_host_claim() {
        let mailbox = MetadataGrantMailbox::new();
        let request = MetadataGrantRequest {
            op: METADATA_GRANT_OP_ALLOC,
            arg1: 4096,
            arg2: 0,
            arg3: 0,
            cookie: 0,
        };
        assert!(!mailbox.try_publish_request_prepared(request, |_| false));
        assert_eq!(mailbox.request_generation(), 0);
        assert!(mailbox.claim_request().is_none());
        for expected in [1, 2] {
            assert!(mailbox.try_publish_request_prepared(request, |generation| {
                assert_eq!(generation, expected);
                assert!(
                    mailbox.claim_request().is_none(),
                    "host claim before queue admission"
                );
                true
            }));
            assert_eq!(mailbox.request_generation(), expected);
            assert_eq!(mailbox.claim_request(), Some(request));
            assert!(!mailbox.try_publish_request_prepared(request, |_| panic!(
                "occupied request was prepared twice"
            )));
            mailbox.publish_response(METADATA_GRANT_SUCCESS, 1, 4096, expected);
            assert!(mailbox.claim_response().is_some());
            mailbox.finish_response();
        }
        mailbox
            .request_generation
            .store(u64::MAX, Ordering::Relaxed);
        assert!(!mailbox.try_publish_request(request));
        assert_eq!(mailbox.request_generation(), u64::MAX);
        assert!(
            mailbox.claim_request().is_none(),
            "request incarnation must never wrap"
        );
    }

    #[test]
    fn metadata_mailbox_transfers_one_request_and_response_without_overwrite() {
        let mailbox = MetadataGrantMailbox::new();
        let request = MetadataGrantRequest {
            op: METADATA_GRANT_OP_ALLOC,
            arg1: 0x20_0000,
            arg2: 0,
            arg3: 0,
            cookie: 17,
        };
        assert!(mailbox.try_publish_request(request));
        assert!(!mailbox.try_publish_request(request));
        assert_eq!(mailbox.claim_request(), Some(request));
        assert_eq!(mailbox.claim_request(), None);
        mailbox.publish_response(METADATA_GRANT_SUCCESS, 0x002d_0800_0000, 0x20_0000, 9);
        assert_eq!(
            mailbox.claim_response(),
            Some(MetadataGrantResponse {
                op: METADATA_GRANT_OP_ALLOC,
                status: METADATA_GRANT_SUCCESS,
                arg1: 0x002d_0800_0000,
                arg2: 0x20_0000,
                arg3: 9,
                cookie: 17,
            })
        );
        assert!(!mailbox.try_publish_request(request));
        mailbox.finish_response();
        assert!(mailbox.try_publish_request(request));
    }

    #[test]
    fn frame_grant_commit_interleaving_never_exposes_unpublished_residency() {
        use core::cell::Cell;
        let mailbox = FrameGrantMailbox::new();
        let request = FrameGrantRequest {
            mm_key: 41,
            request_generation: 7,
            fault_va: 0x4000_3000,
            requested_len: EL1_FRAME_GRANT_TARGET_SIZE,
            access: 2,
        };
        let ready = FrameGrantReady {
            mm_key: 41,
            request_generation: 7,
            semantic_base: 0x4000_0000,
            physical_ipa: 0x9000_0000,
            len: EL1_FRAME_GRANT_TARGET_SIZE,
            permissions: 3,
            frame_id: 1,
            mapping_id: 2,
            owner_generation: 3,
            inventory_revision: 4,
        };
        assert!(mailbox.try_publish_request(request));
        assert_eq!(mailbox.claim_request(), Some(request));
        let published = Cell::new(false);
        let committed = Cell::new(false);
        let result = mailbox.complete_grant(
            ready,
            |_| {
                published.set(true);
                Ok::<_, ()>(true)
            },
            || {
                committed.set(true);
                // Pause slot A after claiming the old Ready, before publishing
                // leaves. Slot B's covering fault now has no claimable response.
                let _slot_a = mailbox.claim_response(41, 7);
                assert!(
                    mailbox
                        .response_covering_fault(41, 0x4000_5000, 2)
                        .is_none()
                );
                assert!(
                    published.get(),
                    "slot B would signal: plan committed, no response, no live leaf"
                );
            },
        );
        assert_eq!(result, Ok(true));
        assert!(committed.get());
    }

    #[test]
    fn transfer_pin_blocks_retirement_and_generation_reuse() {
        let table = FrameGrantResidencyTable::new();
        let identity = FrameGrantResidencyIdentity {
            mm_key: 41,
            semantic_base: 0x4000_0000,
            physical_ipa: 0x9000_0000,
            len: 4096,
            mapping_id: 17,
            frame_id: 19,
            owner_generation: 23,
            inventory_revision: 29,
        };
        let slot = table.publish(identity).unwrap();
        let page = table.lookup(41, identity.semantic_base).unwrap();
        let pin = table.pin_transfer(page).unwrap();
        assert!(!table.retire(slot, identity));
        assert_eq!(table.lookup(41, identity.semantic_base), Some(page));
        assert!(table.publish(identity).is_none());
        let second_pin = table.pin_transfer(page).unwrap();
        drop(pin);
        assert!(!table.retire(slot, identity));
        drop(second_pin);
        assert!(table.retire(slot, identity));
        assert!(table.pin_transfer(page).is_none());
        let successor = FrameGrantResidencyIdentity {
            owner_generation: 31,
            ..identity
        };
        let successor_slot = table.publish(successor).unwrap();
        assert!(table.pin_transfer(page).is_none());
        assert!(table.retire(successor_slot, successor));
    }

    #[test]
    fn grant_residency_rejects_retired_and_reused_identity() {
        let table = FrameGrantResidencyTable::new();
        let first = FrameGrantResidencyIdentity {
            mm_key: 41,
            semantic_base: 0x4000_0000,
            physical_ipa: 0x9000_0000,
            len: 3 * 4096,
            mapping_id: 17,
            frame_id: 19,
            owner_generation: 23,
            inventory_revision: 29,
        };
        let slot = table.publish(first).expect("first grant");
        let page = table
            .lookup(41, first.semantic_base + 4096)
            .expect("prepared page");
        assert_eq!(page.expected_ipa, first.physical_ipa + 4096);
        assert!(table.record_commit(page));
        assert_eq!(table.committed_words(slot, first).unwrap()[0], 0b10);
        let mut dirty = 0;
        table.for_each_dirty_mm(41, |seen, identity, bits| {
            assert_eq!((seen, identity, bits[0]), (slot, first, 0b10));
            dirty += 1;
            assert!(table.ack_dirty(seen, identity));
        });
        assert_eq!(dirty, 1);
        table.for_each_dirty_mm(41, |_, _, _| panic!("dirty bit was acknowledged"));
        assert!(table.retire(slot, first));
        assert!(table.lookup(41, first.semantic_base + 4096).is_none());
        assert!(!table.record_commit(page));
        let second = FrameGrantResidencyIdentity {
            owner_generation: 31,
            ..first
        };
        let reused = table.publish(second).expect("reused grant");
        assert!(table.committed_words(reused, first).is_none());
        assert_eq!(table.committed_words(reused, second).unwrap()[0], 0);
        assert!(!table.record_commit(page));
        assert!(table.record_commit(table.lookup(41, first.semantic_base).unwrap()));
        assert_eq!(table.committed_words(reused, second).unwrap()[0], 1);
        table.retire_overlapping(41, second.semantic_base, 4096);
        assert!(table.lookup(41, first.semantic_base).is_none());
        assert!(table.lookup(41, first.semantic_base + 4096).is_some());
        // Even a byte-for-byte recycled identity cannot reuse a captured
        // page token from a retired publication.
        let stale = table.lookup(41, second.semantic_base);
        assert!(stale.is_none());
        table.retire_overlapping(41, second.semantic_base, second.len);
        let fresh_slot = table.publish(second).unwrap();
        let stale_page = table.lookup(41, second.semantic_base).unwrap();
        assert!(table.retire(fresh_slot, second));
        table.publish(second).unwrap();
        assert!(!table.record_commit(stale_page));
    }

    #[test]
    fn one_page_file_grants_do_not_fill_one_bulk_window_probe_chain() {
        let base = 0x4000_0000;
        let pages = EL1_FRAME_GRANT_TARGET_SIZE / GRANT_PAGE_SIZE;
        for scattered in [false, true] {
            let table = FrameGrantResidencyTable::new();
            for ordinal in 0..pages {
                // 73 is coprime to 512: every page is reached once, with
                // non-contiguous insertion across the entire window.
                let index = if scattered {
                    (ordinal * 73) % pages
                } else {
                    ordinal
                };
                let identity = FrameGrantResidencyIdentity {
                    mm_key: 41,
                    semantic_base: base + index * GRANT_PAGE_SIZE,
                    physical_ipa: 0x9000_0000 + index * GRANT_PAGE_SIZE,
                    len: GRANT_PAGE_SIZE,
                    mapping_id: index + 1,
                    frame_id: index + 1,
                    owner_generation: 23,
                    inventory_revision: 29,
                };
                assert!(
                    table.publish(identity).is_some(),
                    "file page {index} rejected inside one 2 MiB window, scattered={scattered}"
                );
                assert_eq!(
                    table.lookup(41, identity.semantic_base).unwrap().identity,
                    identity
                );
            }
        }
    }

    #[test]
    fn disjoint_bulk_grants_share_a_window_without_losing_residency() {
        let table = FrameGrantResidencyTable::new();
        assert!(table.lookup(41, 0).is_none());
        let base = 0x4000_0000;
        for ordinal in 0..160_u64 {
            let identity = FrameGrantResidencyIdentity {
                mm_key: 41,
                semantic_base: base + ordinal * 3 * GRANT_PAGE_SIZE,
                physical_ipa: 0x9000_0000 + ordinal * 3 * GRANT_PAGE_SIZE,
                len: 2 * GRANT_PAGE_SIZE,
                mapping_id: ordinal + 1,
                frame_id: ordinal + 1,
                owner_generation: 23,
                inventory_revision: 29,
            };
            assert!(
                table.publish(identity).is_some(),
                "bulk grant {ordinal} lost residency with free table slots"
            );
            assert_eq!(
                table
                    .lookup(41, identity.semantic_base + GRANT_PAGE_SIZE)
                    .unwrap()
                    .identity,
                identity
            );
        }
        for ordinal in 0..160_u64 {
            let start = base + ordinal * 3 * GRANT_PAGE_SIZE;
            assert_eq!(
                table
                    .lookup(41, start + GRANT_PAGE_SIZE)
                    .expect("earlier grant remains indexed")
                    .identity
                    .semantic_base,
                start
            );
        }
        let crossing = FrameGrantResidencyIdentity {
            mm_key: 41,
            semantic_base: base + 483 * GRANT_PAGE_SIZE,
            physical_ipa: 0xa000_0000,
            len: 3 * GRANT_PAGE_SIZE,
            mapping_id: 500,
            frame_id: 500,
            owner_generation: 23,
            inventory_revision: 29,
        };
        table.publish(crossing).expect("cross-bucket grant");
        assert_eq!(
            table
                .lookup(41, crossing.semantic_base + 2 * GRANT_PAGE_SIZE)
                .expect("next bucket finds grant")
                .identity,
            crossing
        );
    }

    #[test]
    fn page_and_bulk_grants_reject_overlaps_across_hash_classes() {
        let table = FrameGrantResidencyTable::new();
        let bulk = FrameGrantResidencyIdentity {
            mm_key: 41,
            semantic_base: 0x4000_0000,
            physical_ipa: 0x9000_0000,
            len: 4 * 4096,
            mapping_id: 17,
            frame_id: 19,
            owner_generation: 23,
            inventory_revision: 29,
        };
        let page = FrameGrantResidencyIdentity {
            semantic_base: bulk.semantic_base + 2 * 4096,
            physical_ipa: bulk.physical_ipa + 2 * 4096,
            len: 4096,
            ..bulk
        };
        let bulk_slot = table.publish(bulk).unwrap();
        assert_eq!(
            table
                .lookup(bulk.mm_key, page.semantic_base)
                .unwrap()
                .identity,
            bulk
        );
        assert!(table.publish(page).is_none());
        assert!(table.retire(bulk_slot, bulk));
        let page_slot = table.publish(page).unwrap();
        assert!(table.publish(bulk).is_none());
        assert!(table.retire(page_slot, page));
    }

    #[test]
    fn grant_residency_partial_replacement_preserves_outside_commits() {
        let table = FrameGrantResidencyTable::new();
        let identity = FrameGrantResidencyIdentity {
            mm_key: 41,
            semantic_base: 0x4000_0000,
            physical_ipa: 0x9000_0000,
            len: 5 * 4096,
            mapping_id: 17,
            frame_id: 19,
            owner_generation: 23,
            inventory_revision: 29,
        };
        table.publish(identity).unwrap();
        let base = identity.semantic_base;
        let old_middle = table.lookup(41, base + 2 * 4096).unwrap();
        let old_last = table.lookup(41, base + 4 * 4096).unwrap();
        assert!(table.record_commit(table.lookup(41, base).unwrap()));
        assert!(table.record_commit(old_middle));
        assert!(table.record_commit(old_last));
        table.retire_overlapping(41, base + 2 * 4096, 4096);
        assert!(table.lookup(41, base + 2 * 4096).is_none());
        assert!(!table.record_commit(old_middle));
        assert!(!table.record_commit(old_last));
        assert!(table.is_guest_committed(41, base));
        assert!(table.is_guest_committed(41, base + 4 * 4096));
        let surviving = table.lookup(41, base + 3 * 4096).unwrap();
        assert_eq!(surviving.expected_ipa, identity.physical_ipa + 3 * 4096);
        assert!(table.record_commit(surviving));
        assert!(table.lookup(42, base).is_none());
        let replacement = FrameGrantResidencyIdentity {
            semantic_base: base + 2 * 4096,
            physical_ipa: 0xa000_0000,
            len: 4096,
            owner_generation: 31,
            ..identity
        };
        table.publish(replacement).unwrap();
        assert!(!table.is_guest_committed(41, replacement.semantic_base));
        assert!(!table.record_commit(old_middle));
        let mut spans = 0;
        table.live_spans_overlapping(41, base, identity.len, |_, _| spans += 1);
        assert_eq!(spans, 3);
    }

    #[test]
    fn grant_residency_reports_only_live_spans_of_the_exact_mm() {
        extern crate std;
        use std::{boxed::Box, vec, vec::Vec};
        let table = Box::new(FrameGrantResidencyTable::new());
        let grant = |mm_key, semantic_base, owner_generation| FrameGrantResidencyIdentity {
            mm_key,
            semantic_base,
            physical_ipa: 0x9000_0000 + semantic_base,
            len: 4 * 4096,
            mapping_id: 17,
            frame_id: 19,
            owner_generation,
            inventory_revision: 29,
        };
        let spans = |table: &FrameGrantResidencyTable, mm_key, start, len| {
            let mut seen = Vec::new();
            table.live_spans_overlapping(mm_key, start, len, |base, end| seen.push((base, end)));
            seen.sort_unstable();
            seen
        };
        let near = grant(41, 0x4000_0000, 23);
        let far = grant(41, 0x4020_0000, 24);
        let other_mm = grant(42, 0x4000_0000, 25);
        let near_slot = table.publish(near).unwrap();
        table.publish(far).unwrap();
        table.publish(other_mm).unwrap();
        assert_eq!(
            spans(&table, 41, 0x4000_2000, 0x20_0000),
            vec![(0x4000_0000, 0x4000_4000), (0x4020_0000, 0x4020_4000)]
        );
        assert_eq!(spans(&table, 41, 0x4000_4000, 0x1000), vec![]);
        assert!(table.retire(near_slot, near));
        assert_eq!(spans(&table, 41, 0x4000_0000, 0x1000), vec![]);
        assert_eq!(
            spans(&table, 42, 0x4000_0000, 0x1000),
            vec![(0x4000_0000, 0x4000_4000)]
        );
    }

    #[test]
    fn frame_grant_publication_failure_keeps_arming_and_refuses_without_commit() {
        use core::cell::Cell;
        for publication in [Ok(false), Err(())] {
            let mailbox = FrameGrantMailbox::new();
            let request = FrameGrantRequest {
                mm_key: 41,
                request_generation: 7,
                fault_va: 0x4000_3000,
                requested_len: EL1_FRAME_GRANT_TARGET_SIZE,
                access: 2,
            };
            assert!(mailbox.try_publish_request(request));
            assert_eq!(mailbox.claim_request(), Some(request));
            let committed = Cell::new(false);
            assert_eq!(
                mailbox.complete_grant(
                    FrameGrantReady {
                        mm_key: 41,
                        request_generation: 7,
                        semantic_base: 0x4000_0000,
                        physical_ipa: 0x9000_0000,
                        len: EL1_FRAME_GRANT_TARGET_SIZE,
                        permissions: 3,
                        frame_id: 1,
                        mapping_id: 2,
                        owner_generation: 3,
                        inventory_revision: 4,
                    },
                    |_| publication,
                    || committed.set(true)
                ),
                publication
            );
            assert!(!committed.get());
            assert_eq!(
                mailbox.state.load(Ordering::Acquire),
                FRAME_GRANT_MAILBOX_HOST_WORKING
            );
            assert!(!mailbox.try_publish_request(request));
            assert!(mailbox.publish_refusal(FRAME_GRANT_ERR_DENIED));
            let response = mailbox.claim_response(41, 7).unwrap();
            assert_eq!(response.status, FRAME_GRANT_ERR_DENIED);
            assert!(mailbox.finish_response(41, 7));
            assert!(!mailbox.has_guest_work());
        }
    }

    #[test]
    fn frame_grant_mailbox_binds_ready_data_to_exact_request_and_mm() {
        let mailbox = FrameGrantMailbox::new();
        let request = FrameGrantRequest {
            mm_key: 41,
            request_generation: 7,
            fault_va: 0x4000_3000,
            requested_len: EL1_FRAME_GRANT_TARGET_SIZE,
            access: 2,
        };
        assert!(mailbox.try_publish_request(request));
        assert!(!mailbox.try_publish_request(request));
        assert_eq!(mailbox.claim_request(), Some(request));

        let ready = FrameGrantReady {
            mm_key: request.mm_key,
            request_generation: request.request_generation,
            semantic_base: 0x4000_0000,
            physical_ipa: 0x9000_0000,
            len: EL1_FRAME_GRANT_TARGET_SIZE,
            permissions: 3,
            frame_id: 101,
            mapping_id: 102,
            owner_generation: 103,
            inventory_revision: 104,
        };
        assert_eq!(
            mailbox.complete_grant(ready, |_| Ok::<_, ()>(true), || {}),
            Ok(true)
        );
        assert_eq!(mailbox.claim_response(41, 7), None);
        assert!(!mailbox.has_guest_work());
        assert!(mailbox.try_publish_request(request));
    }

    #[test]
    fn resolved_owner_file_page_releases_mailbox_for_the_next_page() {
        let mailbox = FrameGrantMailbox::new();
        let first = FrameGrantRequest {
            mm_key: 41,
            request_generation: 7,
            fault_va: 0x4000_3000,
            requested_len: 4096,
            access: 1,
        };
        let second = FrameGrantRequest {
            request_generation: 8,
            fault_va: first.fault_va + 4096,
            ..first
        };
        assert!(mailbox.try_publish_request(first));
        assert_eq!(
            mailbox.claim_request_for_fault(41, first.fault_va, 1),
            Some(first)
        );
        assert!(!mailbox.complete_resolved_owner_fault(second));
        assert!(mailbox.complete_resolved_owner_fault(first));
        assert!(
            mailbox.try_publish_request(second),
            "a resolved file page must release its slot before the next page faults"
        );
    }

    #[test]
    fn frame_grant_mailboxes_are_single_flight_per_vcpu_slot() {
        let mailboxes = FrameGrantMailboxes::new();
        let first = FrameGrantRequest {
            mm_key: 61,
            request_generation: 17,
            fault_va: 0x6100_1000,
            requested_len: EL1_FRAME_GRANT_TARGET_SIZE,
            access: 2,
        };
        let second = FrameGrantRequest {
            mm_key: 62,
            request_generation: 18,
            fault_va: 0x6200_1000,
            requested_len: EL1_FRAME_GRANT_TARGET_SIZE,
            access: 2,
        };

        assert!(mailboxes.slot(3).unwrap().try_publish_request(first));
        assert!(
            mailboxes.slot(7).unwrap().try_publish_request(second),
            "an unrelated vCPU slot must not fall back while another slot has an in-flight grant",
        );
        assert!(!mailboxes.slot(3).unwrap().try_publish_request(second));
        assert_eq!(mailboxes.slot(3).unwrap().claim_request(), Some(first));
        assert_eq!(mailboxes.slot(7).unwrap().claim_request(), Some(second));
        assert!(mailboxes.slot(EL1_STACK_SLOTS as usize).is_none());
    }

    /// A retiring MM leaves no request or refusal behind: its threads will
    /// never fault again to claim them, and a mailbox left busy refuses every
    /// later request on that vCPU slot, whichever MM it next runs.
    #[test]
    fn a_retiring_mm_withdraws_exactly_its_own_mailbox_work() {
        let request = |mm_key, request_generation| FrameGrantRequest {
            mm_key,
            request_generation,
            fault_va: 0x4000_3000,
            requested_len: EL1_FRAME_GRANT_TARGET_SIZE,
            access: 2,
        };
        let refused = FrameGrantMailbox::new();
        assert!(refused.try_publish_request(request(71, 1)));
        assert!(refused.claim_request().is_some());
        assert!(refused.publish_refusal(FRAME_GRANT_ERR_DENIED));
        let requested = FrameGrantMailbox::new();
        assert!(requested.try_publish_request(request(71, 2)));
        let other = FrameGrantMailbox::new();
        assert!(other.try_publish_request(request(72, 3)));
        assert!(other.claim_request().is_some());
        assert!(other.publish_refusal(FRAME_GRANT_ERR_DENIED));
        let working = FrameGrantMailbox::new();
        assert!(working.try_publish_request(request(71, 4)));
        assert!(working.claim_request().is_some());

        for mailbox in [&refused, &requested, &other, &working] {
            let _ = mailbox.withdraw_mm(71);
        }
        assert!(!refused.has_guest_work(), "a retired MM's refusal stayed");
        assert!(!requested.has_guest_work(), "a retired MM's request stayed");
        assert!(other.has_guest_work(), "another MM's refusal was withdrawn");
        assert!(other.claim_response(72, 3).is_some());
        assert!(
            working.has_guest_work(),
            "a request the host is serving belongs to that boundary"
        );
        assert!(refused.try_publish_request(request(73, 5)));
        assert!(requested.try_publish_request(request(73, 6)));
    }

    #[test]
    fn frame_grant_host_claim_leaves_another_faults_request_pending() {
        let mailbox = FrameGrantMailbox::new();
        let request = FrameGrantRequest {
            mm_key: 41,
            request_generation: 8,
            fault_va: 0x4000_3000,
            requested_len: EL1_FRAME_GRANT_TARGET_SIZE,
            access: 2,
        };
        assert!(mailbox.try_publish_request(request));

        assert_eq!(
            mailbox.claim_request_for_fault(
                request.mm_key,
                request.fault_va + 4096,
                request.access,
            ),
            None,
            "an unrelated carrier fault must not consume the single-flight request",
        );
        assert_eq!(
            mailbox.claim_request_for_fault(request.mm_key, request.fault_va, request.access),
            Some(request),
            "the host boundary for the requesting fault must still be able to claim it",
        );

        let mailbox = FrameGrantMailbox::new();
        assert!(mailbox.try_publish_request(request));
        assert!(!mailbox.cancel_request_for_fault(
            request.mm_key,
            request.fault_va + 4096,
            request.access,
        ));
        assert!(
            mailbox.cancel_request_for_fault(request.mm_key, request.fault_va, request.access,)
        );
        assert!(
            mailbox.try_publish_request(request),
            "a host-resolved fault must release its exact unused request",
        );
    }

    #[test]
    fn frame_grant_mailbox_rejects_mismatched_or_unauthenticated_ready_data() {
        let mailbox = FrameGrantMailbox::new();
        let request = FrameGrantRequest {
            mm_key: 51,
            request_generation: 11,
            fault_va: 0x5000_1000,
            requested_len: EL1_FRAME_GRANT_TARGET_SIZE,
            access: 1,
        };
        assert!(mailbox.try_publish_request(request));
        assert_eq!(mailbox.claim_request(), Some(request));

        let mut ready = FrameGrantReady {
            mm_key: request.mm_key,
            request_generation: request.request_generation,
            semantic_base: 0x5000_0000,
            physical_ipa: 0xa000_0000,
            len: EL1_FRAME_GRANT_TARGET_SIZE,
            permissions: 1,
            frame_id: 201,
            mapping_id: 202,
            owner_generation: 203,
            inventory_revision: 204,
        };
        ready.mm_key += 1;
        assert_eq!(
            mailbox.complete_grant(ready, |_| Ok::<_, ()>(true), || {}),
            Ok(false)
        );
        ready.mm_key = request.mm_key;
        ready.owner_generation = 0;
        assert_eq!(
            mailbox.complete_grant(ready, |_| Ok::<_, ()>(true), || {}),
            Ok(false)
        );
        ready.owner_generation = 203;
        ready.semantic_base = request.fault_va + 0x1000;
        assert_eq!(
            mailbox.complete_grant(ready, |_| Ok::<_, ()>(true), || {}),
            Ok(false)
        );

        assert!(mailbox.publish_refusal(FRAME_GRANT_ERR_DENIED));
        assert_eq!(
            mailbox.claim_response(request.mm_key, request.request_generation),
            Some(FrameGrantResponse {
                status: FRAME_GRANT_ERR_DENIED,
                request,
            })
        );
        assert!(mailbox.finish_response(request.mm_key, request.request_generation));
    }

    #[test]
    fn frame_grant_read_accepts_every_accessible_linux_vma_permission() {
        for permissions in [1, 2, 4] {
            let mailbox = FrameGrantMailbox::new();
            let request = FrameGrantRequest {
                mm_key: 301,
                request_generation: permissions,
                fault_va: 0x6000_1000,
                requested_len: 4096,
                access: 1,
            };
            assert!(mailbox.try_publish_request(request));
            assert_eq!(mailbox.claim_request(), Some(request));
            assert_eq!(
                mailbox.complete_grant(
                    FrameGrantReady {
                        mm_key: request.mm_key,
                        request_generation: request.request_generation,
                        semantic_base: 0x6000_1000,
                        physical_ipa: 0xb000_1000,
                        len: 4096,
                        permissions,
                        frame_id: 401,
                        mapping_id: 402,
                        owner_generation: 403,
                        inventory_revision: 404,
                    },
                    |_| Ok::<_, ()>(true),
                    || {}
                ),
                Ok(true)
            );
        }
    }

    #[test]
    fn frame_grant_guest_claims_only_the_exact_fault_response() {
        let mailbox = FrameGrantMailbox::new();
        let request = FrameGrantRequest {
            mm_key: 501,
            request_generation: 502,
            fault_va: 0x7000_2123,
            requested_len: 4096,
            access: 2,
        };
        assert!(mailbox.try_publish_request(request));
        assert_eq!(mailbox.claim_request(), Some(request));
        assert!(mailbox.publish_refusal(FRAME_GRANT_ERR_DENIED));

        assert_eq!(
            mailbox.claim_response_for_fault(request.mm_key + 1, request.fault_va, request.access),
            None
        );
        assert_eq!(
            mailbox.claim_response_for_fault(
                request.mm_key,
                request.fault_va + 4096,
                request.access
            ),
            None
        );
        assert_eq!(
            mailbox.claim_response_for_fault(request.mm_key, request.fault_va, 1),
            None
        );
        assert_eq!(
            mailbox.claim_response_for_fault(request.mm_key, request.fault_va, request.access),
            Some(FrameGrantResponse {
                status: FRAME_GRANT_ERR_DENIED,
                request,
            })
        );
    }
    #[test]
    fn metadata_free_response_retains_the_exact_return_request() {
        let mailbox = MetadataGrantMailbox::new();
        let request = MetadataGrantRequest {
            op: METADATA_GRANT_OP_FREE,
            arg1: 0x100000,
            arg2: 0x80000,
            arg3: 41,
            cookie: 7,
        };
        assert!(mailbox.try_publish_request(request));
        assert_eq!(mailbox.claim_request(), Some(request));
        mailbox.publish_response(METADATA_GRANT_SUCCESS, 0, 0, 0);
        let response = mailbox.claim_response().unwrap();
        assert_eq!(
            (response.arg1, response.arg2, response.arg3, response.cookie),
            (request.arg1, request.arg2, request.arg3, request.cookie)
        );
    }
}

// Literal wire layout captured from 3fd7862be on a 64-bit host.
// Keep these values fixed when moving the shared kernel implementation.
#[cfg(test)]
mod layout_manifest {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    macro_rules! field {
        ($record:ty, $field:ident, $ty:ty, $offset:literal, $size:literal, $align:literal) => {
            // Type-check the manifest's field type without constructing a record.
            let _ = |record: &$record| {
                let _: &$ty = &record.$field;
            };
            assert_eq!(
                (
                    offset_of!($record, $field),
                    size_of::<$ty>(),
                    align_of::<$ty>()
                ),
                ($offset, $size, $align),
                concat!(stringify!($record), "::", stringify!($field))
            );
        };
    }

    #[test]
    fn trap_frame() {
        assert_eq!((size_of::<TrapFrame>(), align_of::<TrapFrame>()), (288, 8));
        // Exhaustive pattern makes newly added fields require a manifest entry.
        let _ = |TrapFrame {
                     x: _,
                     elr: _,
                     spsr: _,
                     esr: _,
                     slot: _,
                     far: _,
                 }: TrapFrame| {};
        field!(TrapFrame, x, [u64; 31], 0, 248, 8);
        field!(TrapFrame, elr, u64, 248, 8, 8);
        field!(TrapFrame, spsr, u64, 256, 8, 8);
        field!(TrapFrame, esr, u64, 264, 8, 8);
        field!(TrapFrame, slot, u64, 272, 8, 8);
        field!(TrapFrame, far, u64, 280, 8, 8);
    }

    #[test]
    fn current_task() {
        assert_eq!(
            (size_of::<CurrentTask>(), align_of::<CurrentTask>()),
            (128, 8)
        );
        // Exhaustive pattern makes newly added fields require a manifest entry.
        let _ = |CurrentTask {
                     execution: _,
                     linux: _,
                     mm: _,
                     metadata: _,
                     _stride_padding: _,
                 }: CurrentTask| {};
        field!(CurrentTask, execution, ExecutionIdentity, 0, 16, 8);
        field!(CurrentTask, linux, LinuxTaskState, 16, 32, 8);
        field!(CurrentTask, mm, ExecutionMm, 48, 16, 8);
        field!(CurrentTask, metadata, LinuxTaskMetadata, 64, 24, 8);
        field!(CurrentTask, _stride_padding, [u64; 5], 88, 40, 8);
    }

    #[test]
    fn metadata_grant_mailbox() {
        assert_eq!(
            (
                size_of::<MetadataGrantMailbox>(),
                align_of::<MetadataGrantMailbox>()
            ),
            (64, 64)
        );
        // Exhaustive pattern makes newly added fields require a manifest entry.
        let _ = |MetadataGrantMailbox {
                     state: _,
                     op: _,
                     status: _,
                     arg1: _,
                     arg2: _,
                     arg3: _,
                     cookie: _,
                     request_generation: _,
                 }: MetadataGrantMailbox| {};
        field!(MetadataGrantMailbox, state, AtomicU32, 0, 4, 4);
        field!(MetadataGrantMailbox, op, AtomicU32, 4, 4, 4);
        field!(MetadataGrantMailbox, status, AtomicU64, 8, 8, 8);
        field!(MetadataGrantMailbox, arg1, AtomicU64, 16, 8, 8);
        field!(MetadataGrantMailbox, arg2, AtomicU64, 24, 8, 8);
        field!(MetadataGrantMailbox, arg3, AtomicU64, 32, 8, 8);
        field!(MetadataGrantMailbox, cookie, AtomicU64, 40, 8, 8);
        field!(
            MetadataGrantMailbox,
            request_generation,
            AtomicU64,
            48,
            8,
            8
        );
    }
}
