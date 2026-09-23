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

/// Byte offset of the EL1 kernel heap within the region.
pub const EL1_HEAP_OFFSET: u64 = 0x100_0000;

/// Base guest virtual address of the EL1 kernel heap.
pub const EL1_HEAP_BASE: u64 = EL1_REGION_BASE + EL1_HEAP_OFFSET;

/// Size of the EL1 kernel heap (48 MiB).
pub const EL1_HEAP_SIZE: u64 = EL1_REGION_SIZE - EL1_HEAP_OFFSET;

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

pub use core::sync::atomic::{AtomicU64, Ordering};

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
        const ZERO: AtomicU64 = AtomicU64::new(0);
        Self {
            served: [ZERO; 512],
            forwarded: [ZERO; 512],
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
const _: () = assert!(EL1_STACKS_OFFSET + EL1_STACKS_SIZE <= EL1_HEAP_OFFSET);
const _: () = assert!(EL1_HEAP_OFFSET + EL1_HEAP_SIZE <= EL1_REGION_SIZE);

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
}
