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

/// Byte offset of the file page cache arena within the region.
pub const EL1_CACHE_OFFSET: u64 = EL1_HEAP_OFFSET + 0x10_0000; // 1 MiB into heap

/// Base guest virtual address of the file page cache arena.
pub const EL1_CACHE_BASE: u64 = EL1_REGION_BASE + EL1_CACHE_OFFSET;

/// Size of the file page cache arena (32 MiB).
pub const EL1_CACHE_SIZE: u64 = (MAX_DELEGATED_FILES as u64) * DELEGATED_FILE_MAX_SIZE;

/// Magic bytes at offset 0 of the EL1 image header: `CEL1`.
pub const IMAGE_MAGIC: [u8; 4] = *b"CEL1";

/// Current version of the EL1 image format.
pub const IMAGE_VERSION: u32 = 1;

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
        Some(Self {
            magic,
            version,
            entry_offset,
            image_size,
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

/// Per-vCPU slot task record published by the host runtime before running
/// a vCPU and cleared when unloaded.
#[repr(C, align(8))]
#[derive(Debug)]
pub struct CurrentTask {
    /// Host-managed generation of the currently loaded task.
    pub generation: AtomicU64,
    /// Task ID / LinuxTid of the currently loaded task.
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
    pub fn set(&self, task_id: u64, generation: u64, file_table: u64) {
        self.task_id.store(task_id, Ordering::Relaxed);
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
    /// Current logical file offset.
    pub offset: AtomicU64,
    /// Current file size in bytes.
    pub size: AtomicU64,
    /// File access flags (`DELEGATED_FLAG_*`).
    pub flags: AtomicU32,
    pub _reserved0: u32,
    /// 64-bit dirty page mask (bit i indicates 4 KiB page i is dirty).
    pub dirty_mask: AtomicU64,
    /// 64-bit zero-filled gap page mask (bit i indicates 4 KiB page i was zero-filled on extension and never written).
    pub zero_filled_mask: AtomicU64,
    pub _pad: [u8; 8],
}

impl DelegatedFile {
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(DELEGATED_STATE_DEAD),
            lock: AtomicU32::new(0),
            generation: AtomicU64::new(0),
            offset: AtomicU64::new(0),
            size: AtomicU64::new(0),
            flags: AtomicU32::new(0),
            _reserved0: 0,
            dirty_mask: AtomicU64::new(0),
            zero_filled_mask: AtomicU64::new(0),
            _pad: [0; 8],
        }
    }

    /// Try to acquire the spinlock without blocking.
    /// Guest calls this; if it returns `false`, guest must FORWARD.
    #[inline]
    pub fn try_lock(&self) -> bool {
        self.lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
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
            if self.try_lock() {
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
            if h != 0 {
                return Some((h, idx));
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
const _: () = assert!(EL1_CACHE_OFFSET + EL1_CACHE_SIZE <= EL1_REGION_SIZE);

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
pub fn mark_pending_host_work_for_task(tid: u64) {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 {
        return;
    }
    for slot in 0..EL1_STACK_SLOTS as usize {
        let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
        let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
        if current_task.task_id.load(Ordering::Relaxed) == tid {
            current_task.pending_host_work.store(1, Ordering::Release);
        }
    }
}

/// Update the file table for any vCPU slot running the given task identity (tid).
pub fn update_current_task_file_table_for_task(tid: u64, file_table: u64) {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 {
        return;
    }
    for slot in 0..EL1_STACK_SLOTS as usize {
        let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
        let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
        if current_task.task_id.load(Ordering::Relaxed) == tid {
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
        assert_eq!(core::mem::size_of::<ImageHeader>(), 24);
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
        assert_eq!(core::mem::size_of::<DelegatedFile>(), 64);
        assert_eq!(core::mem::align_of::<DelegatedFile>(), 64);
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
    fn test_current_task_operations() {
        let task = CurrentTask::new();
        assert_eq!(task.task_id.load(Ordering::Relaxed), 0);
        assert_eq!(task.generation.load(Ordering::Relaxed), 0);
        assert_eq!(task.file_table.load(Ordering::Relaxed), 0);

        task.set(7, 42, 100);
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
        mark_pending_host_work_for_task(42);
        assert!(task_5.has_pending_host_work());
        assert!(!task_6.has_pending_host_work()); // sibling task remains untouched

        task_5.file_table.store(100, Ordering::Relaxed);
        update_current_task_file_table_for_task(42, 200);
        assert_eq!(task_5.file_table.load(Ordering::Acquire), 200);
        assert_eq!(task_6.file_table.load(Ordering::Acquire), 0);

        task_5.served_with_work.store(1, Ordering::Relaxed);
        assert!(take_served_with_work(5));
        assert!(!take_served_with_work(5)); // cleared after take

        record_el1_region_host_ptr(0);
        assert_eq!(get_el1_region_host_ptr(), 0);
    }
}
