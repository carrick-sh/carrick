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
        core::mem::size_of::<CurrentTask>() as u64,
        core::mem::offset_of!(CurrentTask, file_table) as u64,
        core::mem::offset_of!(CurrentTask, pending_host_work) as u64,
        core::mem::offset_of!(CurrentTask, served_with_work) as u64,
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
}

pub use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Linux thread identity as published into a [`CurrentTask`] record.
///
/// The record stores a `u64` word; this newtype is the only way to produce or
/// compare that word, so a bare `tid as u64` (which sign-extends) can never
/// cross the host/EL1 boundary. `NONE` (0) means no task is bound.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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
    /// Reserved padding to align struct to 64 bytes (1 << 6).
    pub _reserved: [u64; 2],
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
            _reserved: [0; 2],
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
}

impl Counters {
    pub const fn new() -> Self {
        Self {
            served: [const { AtomicU64::new(0) }; 512],
            forwarded: [const { AtomicU64::new(0) }; 512],
        }
    }

    pub fn copy_snapshot(&self) -> Self {
        let snapshot = Self::new();
        for i in 0..512 {
            snapshot.served[i].store(self.served[i].load(Ordering::Relaxed), Ordering::Relaxed);
            snapshot.forwarded[i]
                .store(self.forwarded[i].load(Ordering::Relaxed), Ordering::Relaxed);
        }
        snapshot
    }
}

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

const _: () = assert!(EL1_REGION_BASE.is_multiple_of(0x0400_0000));
const _: () = assert!(EL1_REGION_SIZE == 64 * 1024 * 1024);
const _: () = assert!(EL1_IMAGE_OFFSET + EL1_IMAGE_SIZE <= EL1_COUNTERS_OFFSET);
const _: () = assert!(EL1_COUNTERS_OFFSET + EL1_COUNTERS_SIZE <= EL1_STACKS_OFFSET);
const _: () = assert!(
    EL1_STACKS_OFFSET + EL1_STACK_SLOTS * EL1_STACK_SIZE <= EL1_STACKS_OFFSET + EL1_STACKS_SIZE
);
const _: () = assert!(EL1_STACKS_OFFSET + EL1_STACKS_SIZE <= EL1_CURRENT_TASKS_OFFSET);
const _: () = assert!(EL1_CURRENT_TASKS_OFFSET + EL1_CURRENT_TASKS_SIZE <= EL1_HEAP_OFFSET);
const _: () = assert!(EL1_OBJECT_TABLE_OFFSET + EL1_OBJECT_TABLE_SIZE <= EL1_FD_MAP_OFFSET);
const _: () = assert!(EL1_FD_MAP_OFFSET + EL1_FD_MAP_SIZE <= EL1_CACHE_OFFSET);
const _: () = assert!(EL1_CACHE_OFFSET + EL1_CACHE_SIZE <= EL1_INOTIFY_TABLE_OFFSET);
const _: () = assert!(EL1_INOTIFY_TABLE_OFFSET + EL1_INOTIFY_TABLE_SIZE <= EL1_NAME_CACHE_OFFSET);
const _: () = assert!(EL1_NAME_CACHE_OFFSET + EL1_NAME_CACHE_SIZE <= EL1_REGION_SIZE);

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
        assert_eq!(core::mem::size_of::<TrapFrame>(), 280);
        assert_eq!(core::mem::align_of::<TrapFrame>(), 8);
        assert_eq!(core::mem::offset_of!(TrapFrame, x), 0);
        assert_eq!(core::mem::offset_of!(TrapFrame, elr), 31 * 8);
        assert_eq!(core::mem::offset_of!(TrapFrame, spsr), 32 * 8);
        assert_eq!(core::mem::offset_of!(TrapFrame, esr), 33 * 8);
        assert_eq!(core::mem::offset_of!(TrapFrame, slot), 34 * 8);
    }

    #[test]
    fn test_action_discriminants() {
        assert_eq!(Action::Served as u64, 0);
        assert_eq!(Action::Forward as u64, 1);
        assert_eq!(Action::ServedWithWork as u64, 2);
    }

    #[test]
    fn test_counters_layout() {
        assert_eq!(core::mem::size_of::<Counters>(), 1024 * 8);
        assert_eq!(core::mem::offset_of!(Counters, served), 0);
        assert_eq!(core::mem::offset_of!(Counters, forwarded), 512 * 8);
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
}
