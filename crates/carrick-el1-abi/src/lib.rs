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

#![no_std]

use core::cell::UnsafeCell;

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

/// Byte offset of the per-vCPU stack arena within the region.
pub const EL1_STACKS_OFFSET: u64 = 0x20_0000;

/// Base guest virtual address of the per-vCPU stack arena.
pub const EL1_STACKS_BASE: u64 = EL1_REGION_BASE + EL1_STACKS_OFFSET;

/// Size of each vCPU's EL1 kernel stack: 16 KiB.
pub const EL1_STACK_SIZE: u64 = 0x4000;

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

/// Requested bulk extent. One successful host boundary can cover 512 Linux
/// 4 KiB pages; the host may clamp the response at a VMA or alignment edge.
pub const EL1_FRAME_GRANT_TARGET_SIZE: u64 = 2 * 1024 * 1024;

/// EL1-only virtual alias of the current MM's primary AArch64 stage-1 table
/// arena. Every published address space maps its own arena at this fixed VA.
pub const AARCH64_STAGE1_TABLES_ALIAS_BASE: u64 = 0x2D_0002_0000;

/// Bytes available through [`AARCH64_STAGE1_TABLES_ALIAS_BASE`]. Guest leaf
/// publication must reject every descriptor outside this primary arena.
pub const AARCH64_STAGE1_TABLES_PRIMARY_SIZE: u64 = 0x1C_0000;

/// Canonical accessible user address used when adopting a live AArch64 table
/// image and detecting its ASID-scoped construction mode.
pub const AARCH64_USER_LEAF_CHECK_VA: u64 = 0x1_0000;

/// Guest-physical window reserved for the in-kernel GIC implementation.
/// A stage-1 publication must never expose this range as ordinary memory.
pub const AARCH64_GIC_WINDOW_BASE: u64 = 0x2F_0000_0000;
pub const AARCH64_GIC_WINDOW_SIZE: u64 = 0x1000_0000;

pub const FRAME_GRANT_MAILBOX_IDLE: u32 = 0;
pub const FRAME_GRANT_MAILBOX_GUEST_WRITING: u32 = 1;
pub const FRAME_GRANT_MAILBOX_REQUESTED: u32 = 2;
pub const FRAME_GRANT_MAILBOX_HOST_WORKING: u32 = 3;
pub const FRAME_GRANT_MAILBOX_RESPONSE: u32 = 4;
pub const FRAME_GRANT_MAILBOX_GUEST_CONSUMING: u32 = 5;
/// Guest EL1 claimed a successful response but could not publish its leaves
/// (a table page is missing and only the host allocates tables). The Ready
/// grant stays here for the host to publish on the forwarded fault.
pub const FRAME_GRANT_MAILBOX_GUEST_FAILED: u32 = 6;

pub const FRAME_GRANT_SUCCESS: u64 = 0;
pub const FRAME_GRANT_ERR_DENIED: u64 = 1;
pub const FRAME_GRANT_ERR_INVALID: u64 = 2;
pub const FRAME_GRANT_ERR_STALE: u64 = 3;

/// Byte offset of the EL1 bootstrap metadata allocator arena within the region.
pub const EL1_BOOTSTRAP_METADATA_OFFSET: u64 = 0x70_0000;

/// Base guest virtual address of the EL1 bootstrap metadata allocator arena.
pub const EL1_BOOTSTRAP_METADATA_BASE: u64 = EL1_REGION_BASE + EL1_BOOTSTRAP_METADATA_OFFSET;

/// Size of the EL1 bootstrap metadata allocator arena (9 MiB).
pub const EL1_BOOTSTRAP_METADATA_SIZE: u64 = 0x90_0000;

/// Base guest virtual address of the dynamic metadata grant aperture (64 MiB window).
pub const EL1_DYNAMIC_METADATA_BASE: u64 = 0x2D_0800_0000;

/// Total size of the dynamic metadata grant aperture (64 MiB).
pub const EL1_DYNAMIC_METADATA_SIZE: u64 = 0x0400_0000;

/// Standard quantum size of a dynamic metadata extent granted by the host (512 KiB).
pub const EL1_DYNAMIC_METADATA_EXTENT_SIZE: usize = 512 * 1024;

/// Operation code for requesting an extent grant from the host (HVC #6).
pub const METADATA_GRANT_OP_ALLOC: u64 = 1;

/// Operation code for returning an unused extent to the host (HVC #6).
pub const METADATA_GRANT_OP_FREE: u64 = 2;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        EL1_STACKS_OFFSET,
        EL1_STACK_SIZE,
        EL1_CURRENT_TASKS_OFFSET,
        EL1_METADATA_MAILBOX_OFFSET,
        EL1_FRAME_GRANT_MAILBOX_OFFSET,
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
        core::mem::size_of::<CurrentTask>() as u64,
        core::mem::offset_of!(CurrentTask, file_table) as u64,
        core::mem::offset_of!(CurrentTask, pending_host_work) as u64,
        core::mem::offset_of!(CurrentTask, served_with_work) as u64,
        core::mem::offset_of!(CurrentTask, zone_mm) as u64,
        core::mem::offset_of!(CurrentTask, thread_serial) as u64,
        core::mem::size_of::<MetadataGrantMailbox>() as u64,
        core::mem::align_of::<MetadataGrantMailbox>() as u64,
        core::mem::size_of::<FrameGrantMailbox>() as u64,
        core::mem::align_of::<FrameGrantMailbox>() as u64,
        core::mem::size_of::<FrameGrantMailboxes>() as u64,
        core::mem::align_of::<FrameGrantMailboxes>() as u64,
        core::mem::offset_of!(FrameGrantMailbox, state) as u64,
        core::mem::offset_of!(FrameGrantMailbox, status) as u64,
        core::mem::offset_of!(FrameGrantMailbox, mm_key) as u64,
        core::mem::offset_of!(FrameGrantMailbox, request_generation) as u64,
        core::mem::offset_of!(FrameGrantMailbox, fault_va) as u64,
        core::mem::offset_of!(FrameGrantMailbox, requested_len) as u64,
        core::mem::offset_of!(FrameGrantMailbox, access) as u64,
        core::mem::offset_of!(FrameGrantMailbox, semantic_base) as u64,
        core::mem::offset_of!(FrameGrantMailbox, physical_ipa) as u64,
        core::mem::offset_of!(FrameGrantMailbox, granted_len) as u64,
        core::mem::offset_of!(FrameGrantMailbox, permissions) as u64,
        core::mem::offset_of!(FrameGrantMailbox, frame_id) as u64,
        core::mem::offset_of!(FrameGrantMailbox, mapping_id) as u64,
        core::mem::offset_of!(FrameGrantMailbox, owner_generation) as u64,
        core::mem::offset_of!(FrameGrantMailbox, inventory_revision) as u64,
        EL1_ZONE_OFFSET,
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
        core::mem::offset_of!(DelegatedFile, marks) as u64,
        core::mem::size_of::<DelegatedOpenFile>() as u64,
        core::mem::offset_of!(DelegatedOpenFile, inode_handle) as u64,
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
    while i < facts.len() {
        let mut word = facts[i];
        let mut b = 0;
        while b < 8 {
            hash ^= word & 0xff;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            word >>= 8;
            b += 1;
        }
        i += 1;
    }
    hash
};

/// Fixed header placed at the beginning of the `carrick-el1` binary image.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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

pub use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Linux thread identity as published into a [`CurrentTask`] record.
///
/// The record stores a `u64` word; this newtype is the only way to produce or
/// compare that word, so a bare `tid as u64` (which sign-extends) can never
/// cross the host/EL1 boundary. `NONE` (0) means no task is bound.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(transparent)]
pub struct El1TaskId(u64);

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
#[derive(Debug)]
pub struct CurrentTask {
    /// Host-managed generation of the currently loaded task.
    pub generation: AtomicU64,
    /// [`El1TaskId`] word of the currently loaded task (0 = none).
    pub task_id: AtomicU64,
    /// Raw FileTableId of the currently loaded task (0 = none/unbound).
    pub file_table: AtomicU64,
    /// Per-vCPU fixup PC for EL1 user copies (0 = unarmed).
    pub fixup_pc: AtomicU64,
    /// Original x0 / arg0 before EL1 served the syscall (for reconstruction on served_with_work).
    pub orig_arg0: AtomicU64,
    /// Return-to-user work pending flag set by the host before kicks/signals/teardown.
    pub pending_host_work: AtomicU32,
    /// Flag indicating this syscall completed at EL1 with return value in `x0`/`args[0]`.
    pub served_with_work: AtomicU32,
    /// The zone key of the loaded task's process (its address-space id), or 0
    /// when the process's futexes are not served in-guest. EL1 serves a
    /// futex operation only for a non-zero key and switches only among
    /// threads with the same key.
    pub zone_mm: AtomicU64,
    /// The host's serial of the loaded thread (with `task_id`, the exact
    /// kernel thread a parked record names).
    pub thread_serial: AtomicU64,
}

impl CurrentTask {
    pub const fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            task_id: AtomicU64::new(0),
            file_table: AtomicU64::new(0),
            fixup_pc: AtomicU64::new(0),
            orig_arg0: AtomicU64::new(0),
            pending_host_work: AtomicU32::new(0),
            served_with_work: AtomicU32::new(0),
            zone_mm: AtomicU64::new(0),
            thread_serial: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn clear(&self) {
        self.file_table.store(0, Ordering::Release);
        self.generation.store(0, Ordering::Release);
        self.task_id.store(0, Ordering::Release);
        self.fixup_pc.store(0, Ordering::Relaxed);
        self.orig_arg0.store(0, Ordering::Relaxed);
        self.pending_host_work.store(0, Ordering::Release);
        self.served_with_work.store(0, Ordering::Release);
        self.zone_mm.store(0, Ordering::Release);
        self.thread_serial.store(0, Ordering::Release);
    }

    #[inline]
    pub fn set(&self, task_id: El1TaskId, generation: u64, file_table: u64) {
        self.task_id.store(task_id.raw(), Ordering::Relaxed);
        self.generation.store(generation, Ordering::Release);
        self.file_table.store(file_table, Ordering::Release);
    }

    #[inline]
    pub fn has_pending_host_work(&self) -> bool {
        self.pending_host_work.load(Ordering::Acquire) != 0
    }

    #[inline]
    pub fn mark_pending_host_work(&self) {
        self.pending_host_work.store(1, Ordering::Release);
    }

    #[inline]
    pub fn clear_pending_host_work(&self) {
        self.pending_host_work.store(0, Ordering::Release);
    }
}

impl Default for CurrentTask {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetadataGrantRequest {
    pub op: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub cookie: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Debug)]
pub struct MetadataGrantMailbox {
    pub state: AtomicU32,
    op: AtomicU32,
    status: AtomicU64,
    arg1: AtomicU64,
    arg2: AtomicU64,
    arg3: AtomicU64,
    cookie: AtomicU64,
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
        }
    }

    pub fn try_publish_request(&self, request: MetadataGrantRequest) -> bool {
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
        self.arg1.store(arg1, Ordering::Relaxed);
        self.arg2.store(arg2, Ordering::Relaxed);
        self.arg3.store(arg3, Ordering::Relaxed);
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

impl Default for MetadataGrantMailbox {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameGrantRequest {
    /// Exact zone/MM key from the loaded [`CurrentTask`].
    pub mm_key: u64,
    /// Nonzero carrier-wide request incarnation chosen by EL1.
    pub request_generation: u64,
    /// The semantic address whose recoverable data abort created the request.
    pub fault_va: u64,
    /// Maximum semantic span the host may return.
    pub requested_len: u64,
    /// Exact access that faulted: one Linux read, write or execute bit. The
    /// host returns authoritative VMA permissions separately.
    pub access: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameGrantReady {
    pub mm_key: u64,
    pub request_generation: u64,
    pub semantic_base: u64,
    pub physical_ipa: u64,
    pub len: u64,
    pub permissions: u64,
    /// Raw kernel frame identity, exported only at this shared ABI boundary.
    pub frame_id: u64,
    /// Raw kernel mapping identity, exported only at this shared ABI boundary.
    pub mapping_id: u64,
    /// Exact global stage-2 owner incarnation authenticated by the host.
    pub owner_generation: u64,
    /// Exact committed inventory revision that contains `mapping_id`.
    pub inventory_revision: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameGrantResponse {
    pub status: u64,
    pub request: FrameGrantRequest,
    pub ready: Option<FrameGrantReady>,
}

/// One slot-local anonymous-frame request. The request generation and MM key
/// prevent a response from crossing address-space or request incarnations. A
/// successful response carries identities rather than authority: EL1 may use
/// them only to authenticate the exact host-published grant before installing
/// a leaf.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct FrameGrantMailbox {
    pub state: AtomicU32,
    status: AtomicU64,
    mm_key: AtomicU64,
    request_generation: AtomicU64,
    fault_va: AtomicU64,
    requested_len: AtomicU64,
    access: AtomicU64,
    semantic_base: AtomicU64,
    physical_ipa: AtomicU64,
    granted_len: AtomicU64,
    permissions: AtomicU64,
    frame_id: AtomicU64,
    mapping_id: AtomicU64,
    owner_generation: AtomicU64,
    inventory_revision: AtomicU64,
}

impl FrameGrantMailbox {
    const PAGE_SIZE: u64 = 4096;
    const PERMISSION_MASK: u64 = 0x7;

    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(FRAME_GRANT_MAILBOX_IDLE),
            status: AtomicU64::new(FRAME_GRANT_ERR_INVALID),
            mm_key: AtomicU64::new(0),
            request_generation: AtomicU64::new(0),
            fault_va: AtomicU64::new(0),
            requested_len: AtomicU64::new(0),
            access: AtomicU64::new(0),
            semantic_base: AtomicU64::new(0),
            physical_ipa: AtomicU64::new(0),
            granted_len: AtomicU64::new(0),
            permissions: AtomicU64::new(0),
            frame_id: AtomicU64::new(0),
            mapping_id: AtomicU64::new(0),
            owner_generation: AtomicU64::new(0),
            inventory_revision: AtomicU64::new(0),
        }
    }

    fn request_is_valid(request: FrameGrantRequest) -> bool {
        request.mm_key != 0
            && request.request_generation != 0
            && request.requested_len != 0
            && request.requested_len <= EL1_FRAME_GRANT_TARGET_SIZE
            && request.requested_len.is_multiple_of(Self::PAGE_SIZE)
            && request.access.is_power_of_two()
            && request.access & !Self::PERMISSION_MASK == 0
    }

    fn load_request(&self) -> FrameGrantRequest {
        FrameGrantRequest {
            mm_key: self.mm_key.load(Ordering::Relaxed),
            request_generation: self.request_generation.load(Ordering::Relaxed),
            fault_va: self.fault_va.load(Ordering::Relaxed),
            requested_len: self.requested_len.load(Ordering::Relaxed),
            access: self.access.load(Ordering::Relaxed),
        }
    }

    fn permissions_allow_access(permissions: u64, access: u64) -> bool {
        match access {
            // Carrick's current AArch64 stage-1 lowering makes every
            // accessible Linux VMA readable, including PROT_WRITE-only and
            // PROT_EXEC-only mappings. Keep the grant check identical to the
            // established first-touch protection rule.
            1 => permissions != 0,
            2 => permissions & 2 != 0,
            4 => permissions & 4 != 0,
            _ => false,
        }
    }

    fn ready_is_valid(request: FrameGrantRequest, ready: FrameGrantReady) -> bool {
        let Some(end) = ready.semantic_base.checked_add(ready.len) else {
            return false;
        };
        ready.mm_key == request.mm_key
            && ready.request_generation == request.request_generation
            && ready.semantic_base.is_multiple_of(Self::PAGE_SIZE)
            && ready.physical_ipa.is_multiple_of(Self::PAGE_SIZE)
            && ready.len != 0
            && ready.len <= request.requested_len
            && ready.len.is_multiple_of(Self::PAGE_SIZE)
            && ready.semantic_base <= request.fault_va
            && request.fault_va < end
            && ready.permissions != 0
            && ready.permissions & !Self::PERMISSION_MASK == 0
            && Self::permissions_allow_access(ready.permissions, request.access)
            && ready.frame_id != 0
            && ready.mapping_id != 0
            && ready.owner_generation != 0
            && ready.inventory_revision != 0
    }

    pub fn try_publish_request(&self, request: FrameGrantRequest) -> bool {
        if !Self::request_is_valid(request)
            || self
                .state
                .compare_exchange(
                    FRAME_GRANT_MAILBOX_IDLE,
                    FRAME_GRANT_MAILBOX_GUEST_WRITING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            return false;
        }
        self.status
            .store(FRAME_GRANT_ERR_INVALID, Ordering::Relaxed);
        self.mm_key.store(request.mm_key, Ordering::Relaxed);
        self.request_generation
            .store(request.request_generation, Ordering::Relaxed);
        self.fault_va.store(request.fault_va, Ordering::Relaxed);
        self.requested_len
            .store(request.requested_len, Ordering::Relaxed);
        self.access.store(request.access, Ordering::Relaxed);
        self.semantic_base.store(0, Ordering::Relaxed);
        self.physical_ipa.store(0, Ordering::Relaxed);
        self.granted_len.store(0, Ordering::Relaxed);
        self.permissions.store(0, Ordering::Relaxed);
        self.frame_id.store(0, Ordering::Relaxed);
        self.mapping_id.store(0, Ordering::Relaxed);
        self.owner_generation.store(0, Ordering::Relaxed);
        self.inventory_revision.store(0, Ordering::Relaxed);
        self.state
            .store(FRAME_GRANT_MAILBOX_REQUESTED, Ordering::Release);
        true
    }

    pub fn claim_request(&self) -> Option<FrameGrantRequest> {
        self.state
            .compare_exchange(
                FRAME_GRANT_MAILBOX_REQUESTED,
                FRAME_GRANT_MAILBOX_HOST_WORKING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;
        Some(self.load_request())
    }

    /// Claim only the request produced by this exact forwarded fault.
    ///
    /// The mailbox is carrier-wide, so another vCPU may reach a host boundary
    /// while this request is pending. That boundary must leave the request for
    /// its owner instead of converting ordinary concurrency into a refusal.
    pub fn claim_request_for_fault(
        &self,
        mm_key: u64,
        fault_va: u64,
        access: u64,
    ) -> Option<FrameGrantRequest> {
        let matches = |request: FrameGrantRequest| {
            request.mm_key == mm_key && request.fault_va == fault_va && request.access == access
        };
        if self.state.load(Ordering::Acquire) != FRAME_GRANT_MAILBOX_REQUESTED {
            return None;
        }
        let preview = self.load_request();
        if !matches(preview) {
            return None;
        }
        self.state
            .compare_exchange(
                FRAME_GRANT_MAILBOX_REQUESTED,
                FRAME_GRANT_MAILBOX_HOST_WORKING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;
        let claimed = self.load_request();
        if matches(claimed) {
            return Some(claimed);
        }

        // The mailbox completed one request and accepted another between the
        // preview and CAS. We own HOST_WORKING now, so return the new request
        // unchanged to REQUESTED for its exact host boundary.
        self.state
            .store(FRAME_GRANT_MAILBOX_REQUESTED, Ordering::Release);
        None
    }

    /// Release the exact request when the host resolved the fault through an
    /// existing path and therefore has no frame-grant response for EL1.
    pub fn cancel_request_for_fault(&self, mm_key: u64, fault_va: u64, access: u64) -> bool {
        if self
            .claim_request_for_fault(mm_key, fault_va, access)
            .is_none()
        {
            return false;
        }
        self.state
            .store(FRAME_GRANT_MAILBOX_IDLE, Ordering::Release);
        true
    }

    pub fn publish_ready(&self, ready: FrameGrantReady) -> bool {
        if self.state.load(Ordering::Acquire) != FRAME_GRANT_MAILBOX_HOST_WORKING {
            return false;
        }
        let request = self.load_request();
        if !Self::ready_is_valid(request, ready) {
            return false;
        }
        self.semantic_base
            .store(ready.semantic_base, Ordering::Relaxed);
        self.physical_ipa
            .store(ready.physical_ipa, Ordering::Relaxed);
        self.granted_len.store(ready.len, Ordering::Relaxed);
        self.permissions.store(ready.permissions, Ordering::Relaxed);
        self.frame_id.store(ready.frame_id, Ordering::Relaxed);
        self.mapping_id.store(ready.mapping_id, Ordering::Relaxed);
        self.owner_generation
            .store(ready.owner_generation, Ordering::Relaxed);
        self.inventory_revision
            .store(ready.inventory_revision, Ordering::Relaxed);
        self.status.store(FRAME_GRANT_SUCCESS, Ordering::Relaxed);
        self.state
            .store(FRAME_GRANT_MAILBOX_RESPONSE, Ordering::Release);
        true
    }

    pub fn publish_refusal(&self, status: u64) -> bool {
        if status == FRAME_GRANT_SUCCESS
            || !matches!(
                status,
                FRAME_GRANT_ERR_DENIED | FRAME_GRANT_ERR_INVALID | FRAME_GRANT_ERR_STALE
            )
            || self.state.load(Ordering::Acquire) != FRAME_GRANT_MAILBOX_HOST_WORKING
        {
            return false;
        }
        self.status.store(status, Ordering::Relaxed);
        self.state
            .store(FRAME_GRANT_MAILBOX_RESPONSE, Ordering::Release);
        true
    }

    fn load_response(&self, request: FrameGrantRequest) -> FrameGrantResponse {
        let status = self.status.load(Ordering::Relaxed);
        let ready = (status == FRAME_GRANT_SUCCESS).then(|| FrameGrantReady {
            mm_key: request.mm_key,
            request_generation: request.request_generation,
            semantic_base: self.semantic_base.load(Ordering::Relaxed),
            physical_ipa: self.physical_ipa.load(Ordering::Relaxed),
            len: self.granted_len.load(Ordering::Relaxed),
            permissions: self.permissions.load(Ordering::Relaxed),
            frame_id: self.frame_id.load(Ordering::Relaxed),
            mapping_id: self.mapping_id.load(Ordering::Relaxed),
            owner_generation: self.owner_generation.load(Ordering::Relaxed),
            inventory_revision: self.inventory_revision.load(Ordering::Relaxed),
        });
        FrameGrantResponse {
            status,
            request,
            ready,
        }
    }

    /// Observe, without consuming, a response bound to this exact fault. EL1
    /// uses this before acquiring the MM editor; the host uses it to retry a
    /// fault whose Ready response is waiting behind a closed MM gate.
    pub fn response_for_fault(
        &self,
        mm_key: u64,
        fault_va: u64,
        access: u64,
    ) -> Option<FrameGrantResponse> {
        if self.state.load(Ordering::Acquire) != FRAME_GRANT_MAILBOX_RESPONSE {
            return None;
        }
        let request = self.load_request();
        if request.mm_key != mm_key || request.fault_va != fault_va || request.access != access {
            return None;
        }
        Some(self.load_response(request))
    }

    /// Observe, without consuming, a response for this MM whose granted
    /// range covers `fault_va`, or a refusal for the same page. The EL1
    /// scheduler migrates threads between vCPUs, so a retried fault can land
    /// on a vCPU other than the one whose mailbox holds its response; left
    /// unclaimed, that response would also wedge the original mailbox.
    pub fn response_covering_fault(
        &self,
        mm_key: u64,
        fault_va: u64,
        access: u64,
    ) -> Option<FrameGrantResponse> {
        if self.state.load(Ordering::Acquire) != FRAME_GRANT_MAILBOX_RESPONSE {
            return None;
        }
        let request = self.load_request();
        if request.mm_key != mm_key {
            return None;
        }
        let response = self.load_response(request);
        let covers = match response.ready {
            Some(ready) => {
                ready.semantic_base <= fault_va
                    && ready
                        .semantic_base
                        .checked_add(ready.len)
                        .is_some_and(|end| fault_va < end)
                    && Self::permissions_allow_access(ready.permissions, access)
            }
            None => request.fault_va / Self::PAGE_SIZE == fault_va / Self::PAGE_SIZE,
        };
        covers.then_some(response)
    }

    pub fn claim_response(
        &self,
        mm_key: u64,
        request_generation: u64,
    ) -> Option<FrameGrantResponse> {
        if self.state.load(Ordering::Acquire) != FRAME_GRANT_MAILBOX_RESPONSE
            || self.mm_key.load(Ordering::Relaxed) != mm_key
            || self.request_generation.load(Ordering::Relaxed) != request_generation
        {
            return None;
        }
        self.state
            .compare_exchange(
                FRAME_GRANT_MAILBOX_RESPONSE,
                FRAME_GRANT_MAILBOX_GUEST_CONSUMING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;
        let request = self.load_request();
        Some(self.load_response(request))
    }

    /// Guest: claim the response only when it belongs to this exact fault.
    /// The generation is read from the immutable published request, then
    /// rechecked by [`Self::claim_response`] during the state transition. This
    /// lets a retried fault find its own response without storing a second
    /// generation shadow in a per-vCPU record.
    pub fn claim_response_for_fault(
        &self,
        mm_key: u64,
        fault_va: u64,
        access: u64,
    ) -> Option<FrameGrantResponse> {
        let response = self.response_for_fault(mm_key, fault_va, access)?;
        self.claim_response(mm_key, response.request.request_generation)
    }

    /// Guest: hand a claimed successful response back unpublished.
    pub fn fail_response(&self, mm_key: u64, request_generation: u64) -> bool {
        if self.mm_key.load(Ordering::Relaxed) != mm_key
            || self.request_generation.load(Ordering::Relaxed) != request_generation
            || self.status.load(Ordering::Relaxed) != FRAME_GRANT_SUCCESS
        {
            return false;
        }
        self.state
            .compare_exchange(
                FRAME_GRANT_MAILBOX_GUEST_CONSUMING,
                FRAME_GRANT_MAILBOX_GUEST_FAILED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Host: whether this mailbox holds a grant guest EL1 handed back.
    pub fn has_failed_publication(&self) -> bool {
        self.state.load(Ordering::Acquire) == FRAME_GRANT_MAILBOX_GUEST_FAILED
    }

    /// Host: take a grant guest EL1 handed back for this MM whose range
    /// covers `fault_va`, releasing the mailbox. The caller publishes it.
    pub fn take_failed_publication(&self, mm_key: u64, fault_va: u64) -> Option<FrameGrantReady> {
        if self.state.load(Ordering::Acquire) != FRAME_GRANT_MAILBOX_GUEST_FAILED {
            return None;
        }
        let request = self.load_request();
        if request.mm_key != mm_key {
            return None;
        }
        let ready = self.load_response(request).ready?;
        let covers = ready.semantic_base <= fault_va
            && ready
                .semantic_base
                .checked_add(ready.len)
                .is_some_and(|end| fault_va < end);
        if !covers {
            return None;
        }
        self.state
            .compare_exchange(
                FRAME_GRANT_MAILBOX_GUEST_FAILED,
                FRAME_GRANT_MAILBOX_IDLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;
        Some(ready)
    }

    pub fn finish_response(&self, mm_key: u64, request_generation: u64) -> bool {
        if self.mm_key.load(Ordering::Relaxed) != mm_key
            || self.request_generation.load(Ordering::Relaxed) != request_generation
        {
            return false;
        }
        self.state
            .compare_exchange(
                FRAME_GRANT_MAILBOX_GUEST_CONSUMING,
                FRAME_GRANT_MAILBOX_IDLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    pub fn has_guest_work(&self) -> bool {
        self.state.load(Ordering::Acquire) != FRAME_GRANT_MAILBOX_IDLE
    }
}

impl Default for FrameGrantMailbox {
    fn default() -> Self {
        Self::new()
    }
}

/// One independent frame-grant transaction for every persistent vCPU slot.
///
/// A carrier-wide single-flight mailbox makes an unrelated runnable slot fall
/// back to page-granular host service while the owner of the outstanding
/// response is waiting to run. Slot-local mailboxes preserve the exact request
/// authentication while allowing independent address spaces to make progress.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct FrameGrantMailboxes {
    slots: [FrameGrantMailbox; EL1_STACK_SLOTS as usize],
}

impl FrameGrantMailboxes {
    pub const fn new() -> Self {
        Self {
            slots: [const { FrameGrantMailbox::new() }; EL1_STACK_SLOTS as usize],
        }
    }

    pub fn slot(&self, slot: usize) -> Option<&FrameGrantMailbox> {
        self.slots.get(slot)
    }

    pub fn iter(&self) -> impl Iterator<Item = &FrameGrantMailbox> {
        self.slots.iter()
    }
}

impl Default for FrameGrantMailboxes {
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
pub const MAX_DELEGATED_FILES: usize = 128;

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
#[derive(Debug, Default)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
    /// Formerly the served-operation count that fed the delegation backoff;
    /// a file now enters the zone only at open, so nothing reads it.
    pub _reserved_served_ops: u64,
    /// Exact host inode identity for inotify correspondence.
    pub inode: DelegatedInodeIdentity,
    /// Count of active marks currently attached.
    pub num_marks: AtomicU32,
    pub _reserved1: u32,
    /// Fixed table of active marks attached to this file.
    pub marks: UnsafeCell<[DelegatedMark; MAX_DELEGATED_MARKS_PER_FILE]>,
    pub _pad: [u8; 40],
}

unsafe impl Sync for DelegatedFile {}

/// One open description of an in-zone inode (open(2): an open file
/// description has its own offset and status flags; every description of an
/// inode shares its bytes). Guarded by its inode's lock.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct DelegatedOpenFile {
    /// Dead (0) or Guest (1).
    pub state: AtomicU32,
    /// Access flags (`DELEGATED_FLAG_*`).
    pub flags: AtomicU32,
    /// This record's incarnation; the fd map publishes it.
    pub generation: AtomicU64,
    /// 1-based handle of the inode record ([`DelegatedFile`]).
    pub inode_handle: AtomicU32,
    pub _reserved0: u32,
    /// The inode's generation when this record joined it: an inode handle
    /// reused by another inode never matches.
    pub inode_generation: AtomicU64,
    /// Current file offset of this description.
    pub offset: AtomicU64,
    pub _pad: [u64; 3],
}

impl DelegatedOpenFile {
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(DELEGATED_STATE_DEAD),
            flags: AtomicU32::new(0),
            generation: AtomicU64::new(0),
            inode_handle: AtomicU32::new(0),
            _reserved0: 0,
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
            _reserved_served_ops: 0,
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
            _pad: [0; 40],
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
#[derive(Debug)]
pub struct FdMapSlot {
    /// Owning FileTableId (0 = empty).
    pub file_table: AtomicU64,
    /// Guest file descriptor number.
    pub fd: AtomicU32,
    /// 1-based delegated file handle (0 = empty).
    pub handle: AtomicU32,
    /// Host-assigned incarnation of the delegated file.
    pub incarnation: AtomicU64,
}

impl FdMapSlot {
    pub const fn new() -> Self {
        Self {
            file_table: AtomicU64::new(0),
            fd: AtomicU32::new(0),
            handle: AtomicU32::new(0),
            incarnation: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn clear(&self) {
        self.incarnation.store(0, Ordering::Release);
        self.handle.store(0, Ordering::Relaxed);
        self.fd.store(0, Ordering::Relaxed);
        self.file_table.store(0, Ordering::Relaxed);
    }

    #[inline]
    pub fn set(&self, file_table: u64, fd: u32, handle: u32, incarnation: u64) {
        self.file_table.store(file_table, Ordering::Relaxed);
        self.fd.store(fd, Ordering::Relaxed);
        self.handle.store(handle, Ordering::Relaxed);
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

impl Counters {
    pub const fn new() -> Self {
        Self {
            served: [const { AtomicU64::new(0) }; 512],
            forwarded: [const { AtomicU64::new(0) }; 512],
            irq_taken: [const { AtomicU64::new(0) }; 32],
            fault_taken: AtomicU64::new(0),
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
        snapshot
    }
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
    BoundedSpin, Claim, CurrentHandback, Exhausted, Handback, HostClaim, HostPlacement, LockWait,
    RecordId, RecordRef, SlotDrain, SlotId, SlotState, SwitchedIn, ThreadCtx, ThreadIdentity,
    WakeEffects, WakeRefusal, Waker, ZONE_SLOTS, ZoneRecord, ZoneTables,
};

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
    task.task_id.store(0, Ordering::Relaxed);
    task.generation.store(0, Ordering::Relaxed);
    task.file_table.store(0, Ordering::Relaxed);
    task.thread_serial.store(0, Ordering::Relaxed);
    task.served_with_work.store(0, Ordering::Relaxed);
    task.zone_mm.store(0, Ordering::Release);
    let frame = el1_slot_frame_va(slot);
    let frame_offset = (frame - EL1_REGION_BASE) as usize;
    // SAFETY: the frame lies on the slot's EL1 stack in the mapped region,
    // and the slot's vCPU is stopped (its executor calls this): nothing else
    // reads or writes that stack now.
    unsafe {
        core::ptr::write(
            (ptr + frame_offset) as *mut TrapFrame,
            TrapFrame {
                slot: slot as u64,
                ..TrapFrame::default()
            },
        );
    }
    Some(frame)
}

/// Mark return-to-user work pending for the vCPU at `slot`.
pub fn mark_pending_host_work(slot: usize) {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 || slot >= EL1_STACK_SLOTS as usize {
        return;
    }
    let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
    let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
    current_task.pending_host_work.store(1, Ordering::Release);
}

/// Clear return-to-user work for the vCPU at `slot`.
pub fn clear_pending_host_work(slot: usize) {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 || slot >= EL1_STACK_SLOTS as usize {
        return;
    }
    let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
    let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
    current_task.pending_host_work.store(0, Ordering::Release);
}

/// Mark return-to-user work pending for all vCPU slots.
pub fn mark_pending_host_work_all() {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 {
        return;
    }
    for slot in 0..EL1_STACK_SLOTS as usize {
        let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
        let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
        current_task.pending_host_work.store(1, Ordering::Release);
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
        if current_task.task_id.load(Ordering::Relaxed) == tid.raw() {
            current_task.pending_host_work.store(1, Ordering::Release);
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
        if current_task.task_id.load(Ordering::Relaxed) == 0 {
            continue;
        }
        let ft = current_task.file_table.load(Ordering::Relaxed);
        if tables.contains(&ft) {
            current_task.pending_host_work.store(1, Ordering::Release);
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
        if current_task.task_id.load(Ordering::Relaxed) == tid.raw() {
            current_task.file_table.store(file_table, Ordering::Release);
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
        .thread_serial
        .store(thread_serial, Ordering::Relaxed);
    current_task.zone_mm.store(zone_mm, Ordering::Release);
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
        El1TaskId(current_task.task_id.load(Ordering::Acquire)),
        current_task.thread_serial.load(Ordering::Acquire),
    ))
}

/// Check and atomically clear the `served_with_work` flag for an executor slot.
pub fn take_served_with_work(slot: usize) -> bool {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 || slot >= EL1_STACK_SLOTS as usize {
        return false;
    }
    let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
    let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
    current_task.served_with_work.swap(0, Ordering::AcqRel) != 0
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
    current_task.served_with_work.load(Ordering::Acquire) != 0
}

/// Read the preserved original argument 0 for an executor slot.
pub fn get_orig_arg0(slot: usize) -> u64 {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 || slot >= EL1_STACK_SLOTS as usize {
        return 0;
    }
    let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
    let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
    current_task.orig_arg0.load(Ordering::Relaxed)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_region_layout() {
        assert_eq!(EL1_REGION_BASE, 0x2D_0400_0000);
        assert_eq!(EL1_REGION_SIZE, 0x0400_0000);
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
        assert_eq!(core::mem::size_of::<Counters>(), (1024 + 32 + 1) * 8);
        assert_eq!(core::mem::offset_of!(Counters, served), 0);
        assert_eq!(core::mem::offset_of!(Counters, forwarded), 512 * 8);
        // The vector page's IRQ hook addresses this array directly.
        assert_eq!(core::mem::offset_of!(Counters, irq_taken), 1024 * 8);
        assert_eq!(
            core::mem::offset_of!(Counters, fault_taken),
            (1024 + 32) * 8
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

        let snap = counters.copy_snapshot();
        assert_eq!(snap.fault_taken.load(Ordering::Relaxed), 5);
        assert_eq!(snap.served[10].load(Ordering::Relaxed), 20);
        assert_eq!(snap.forwarded[30].load(Ordering::Relaxed), 40);
        assert_eq!(snap.irq_taken[2].load(Ordering::Relaxed), 8);

        // Modifying original doesn't affect snapshot
        counters.fault_taken.store(100, Ordering::Relaxed);
        assert_eq!(snap.fault_taken.load(Ordering::Relaxed), 5);
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
        assert_eq!(core::mem::size_of::<CurrentTask>(), 64);
        assert_eq!(core::mem::align_of::<CurrentTask>(), 8);
        assert_eq!(core::mem::offset_of!(CurrentTask, generation), 0);
        assert_eq!(core::mem::offset_of!(CurrentTask, task_id), 8);
        assert_eq!(core::mem::offset_of!(CurrentTask, file_table), 16);
        assert_eq!(core::mem::offset_of!(CurrentTask, fixup_pc), 24);
        assert_eq!(core::mem::offset_of!(CurrentTask, orig_arg0), 32);
        assert_eq!(core::mem::offset_of!(CurrentTask, pending_host_work), 40);
        assert_eq!(core::mem::offset_of!(CurrentTask, served_with_work), 44);
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
        assert_eq!(core::mem::size_of::<FdMapSlot>(), 24);
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
        assert_eq!(task.task_id.load(Ordering::Relaxed), 0);
        assert_eq!(task.generation.load(Ordering::Relaxed), 0);
        assert_eq!(task.file_table.load(Ordering::Relaxed), 0);

        task.set(El1TaskId::from_linux_tid(7), 42, 100);
        assert_eq!(task.task_id.load(Ordering::Relaxed), 7);
        assert_eq!(task.generation.load(Ordering::Relaxed), 42);
        assert_eq!(task.file_table.load(Ordering::Relaxed), 100);

        task.clear();
        assert_eq!(task.task_id.load(Ordering::Relaxed), 0);
        assert_eq!(task.generation.load(Ordering::Relaxed), 0);
        assert_eq!(task.file_table.load(Ordering::Relaxed), 0);
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
        let mut arena = std::vec![0u8; EL1_CURRENT_TASKS_OFFSET as usize + 256 * 64];
        let ptr = arena.as_mut_ptr() as usize;
        record_el1_region_host_ptr(ptr);
        assert_eq!(get_el1_region_host_ptr(), ptr);

        mark_pending_host_work(5);
        let task_5 =
            unsafe { &*((ptr + EL1_CURRENT_TASKS_OFFSET as usize + 5 * 64) as *const CurrentTask) };
        assert!(task_5.has_pending_host_work());

        clear_pending_host_work(5);
        assert!(!task_5.has_pending_host_work());

        let task_6 =
            unsafe { &*((ptr + EL1_CURRENT_TASKS_OFFSET as usize + 6 * 64) as *const CurrentTask) };
        task_6.task_id.store(43, Ordering::Relaxed);

        task_5.task_id.store(42, Ordering::Relaxed);
        mark_pending_host_work_for_task(El1TaskId::from_linux_tid(42));
        assert!(task_5.has_pending_host_work());
        assert!(!task_6.has_pending_host_work()); // sibling task remains untouched

        task_5.file_table.store(100, Ordering::Relaxed);
        update_current_task_file_table_for_task(El1TaskId::from_linux_tid(42), 200);
        assert_eq!(task_5.file_table.load(Ordering::Acquire), 200);
        assert_eq!(task_6.file_table.load(Ordering::Acquire), 0);

        task_5.served_with_work.store(1, Ordering::Relaxed);
        assert!(take_served_with_work(5));
        assert!(!take_served_with_work(5));

        task_5.clear_pending_host_work();
        task_6.clear_pending_host_work();
        let task_7 =
            unsafe { &*((ptr + EL1_CURRENT_TASKS_OFFSET as usize + 7 * 64) as *const CurrentTask) };
        task_7.file_table.store(200, Ordering::Relaxed);
        // task_7 has task_id = 0 (no task running)
        assert_eq!(task_7.task_id.load(Ordering::Relaxed), 0);

        mark_pending_host_work_for_file_tables(&[200]);
        // task_5 has task_id = 42 and file_table = 200, so it must be marked
        assert!(task_5.has_pending_host_work());
        // task_6 has task_id = 43 and file_table = 0, so it must NOT be marked
        assert!(!task_6.has_pending_host_work());
        // task_7 has no task (task_id = 0), so it must NEVER be marked
        assert!(!task_7.has_pending_host_work()); // cleared after take

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
        assert!(mailbox.publish_ready(ready));
        assert_eq!(mailbox.claim_response(42, 7), None);
        assert_eq!(mailbox.claim_response(41, 8), None);
        assert_eq!(
            mailbox.claim_response(41, 7),
            Some(FrameGrantResponse {
                status: FRAME_GRANT_SUCCESS,
                request,
                ready: Some(ready),
            })
        );
        assert!(!mailbox.finish_response(42, 7));
        assert!(!mailbox.finish_response(41, 8));
        assert!(mailbox.finish_response(41, 7));
        assert!(mailbox.try_publish_request(request));
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
        assert!(!mailbox.publish_ready(ready));
        ready.mm_key = request.mm_key;
        ready.owner_generation = 0;
        assert!(!mailbox.publish_ready(ready));
        ready.owner_generation = 203;
        ready.semantic_base = request.fault_va + 0x1000;
        assert!(!mailbox.publish_ready(ready));

        assert!(mailbox.publish_refusal(FRAME_GRANT_ERR_DENIED));
        assert_eq!(
            mailbox.claim_response(request.mm_key, request.request_generation),
            Some(FrameGrantResponse {
                status: FRAME_GRANT_ERR_DENIED,
                request,
                ready: None,
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
            assert!(mailbox.publish_ready(FrameGrantReady {
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
            }));
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
                ready: None,
            })
        );
    }
}
