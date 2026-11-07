//! Address-domain admission for one carrier's shared IPC window.

use crate::{
    EL1_IPC_DIRECTORY_SPAN, EL1_IPC_POOL_SPAN, EL1_IPC_TABLE_MAP_OFFSET, EL1_REGION_SIZE,
    FileRegionBinding, FileRegionError,
};
use carrick_guest_arch::{FrameGpa, GuestLen, KernelLayout, KernelVa};

/// Guest-only geometry, bound to the carrier's existing file-region identity.
/// Constructing this value validates addresses; it does not grant mapping
/// custody or authorize dereferencing a guest VA from the host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcWindowBinding {
    region: FileRegionBinding,
    directory: KernelVa,
    directory_physical: FrameGpa,
    directory_bytes: GuestLen,
    pool: KernelVa,
    pool_physical: FrameGpa,
    pool_bytes: GuestLen,
}

impl IpcWindowBinding {
    pub fn new(
        region: FileRegionBinding,
        directory: KernelVa,
        directory_physical: FrameGpa,
        directory_bytes: GuestLen,
        pool: KernelVa,
        pool_physical: FrameGpa,
        pool_bytes: GuestLen,
    ) -> Result<Self, FileRegionError> {
        // Reuse the existing identity and region admission rather than minting
        // another IPC carrier identity or trusting UNPUBLISHED's zero fields.
        FileRegionBinding::new(
            region.identity(),
            region.guest(),
            region.physical(),
            region.bytes(),
        )?;
        let extent = |va: KernelVa, gpa: FrameGpa, bytes: GuestLen, expected| {
            va.raw() != 0
                && va.raw().is_multiple_of(0x20_0000)
                && gpa.raw().is_multiple_of(0x20_0000)
                && bytes.raw() == expected
                && va.raw().checked_add(bytes.raw()).is_some()
                && gpa.raw().checked_add(bytes.raw()).is_some()
        };
        if !extent(
            directory,
            directory_physical,
            directory_bytes,
            EL1_IPC_DIRECTORY_SPAN,
        ) || !extent(pool, pool_physical, pool_bytes, EL1_IPC_POOL_SPAN)
        {
            return Err(FileRegionError::Layout);
        }
        let overlaps = |a: u64, a_len: u64, b: u64, b_len: u64| a < b + b_len && b < a + a_len;
        if overlaps(
            directory.raw(),
            directory_bytes.raw(),
            pool.raw(),
            pool_bytes.raw(),
        ) || overlaps(
            directory_physical.raw(),
            directory_bytes.raw(),
            pool_physical.raw(),
            pool_bytes.raw(),
        ) || overlaps(
            directory.raw(),
            directory_bytes.raw(),
            region.guest().raw(),
            region.bytes().raw(),
        ) || overlaps(
            pool.raw(),
            pool_bytes.raw(),
            region.guest().raw(),
            region.bytes().raw(),
        ) || overlaps(
            directory_physical.raw(),
            directory_bytes.raw(),
            region.physical().raw(),
            region.bytes().raw(),
        ) || overlaps(
            pool_physical.raw(),
            pool_bytes.raw(),
            region.physical().raw(),
            region.bytes().raw(),
        ) {
            return Err(FileRegionError::Layout);
        }
        Ok(Self {
            region,
            directory,
            directory_physical,
            directory_bytes,
            pool,
            pool_physical,
            pool_bytes,
        })
    }

    pub const fn region(self) -> FileRegionBinding {
        self.region
    }
    pub const fn directory(self) -> KernelVa {
        self.directory
    }
    pub const fn directory_physical(self) -> FrameGpa {
        self.directory_physical
    }
    pub const fn directory_bytes(self) -> GuestLen {
        self.directory_bytes
    }
    pub const fn pool(self) -> KernelVa {
        self.pool
    }
    pub const fn pool_physical(self) -> FrameGpa {
        self.pool_physical
    }
    pub const fn pool_bytes(self) -> GuestLen {
        self.pool_bytes
    }

    /// The table map belongs to this layout's region, independently of ISA.
    pub fn table_map_address(self, layout: KernelLayout) -> Result<KernelVa, FileRegionError> {
        if layout.region != self.region.guest() {
            return Err(FileRegionError::Foreign);
        }
        let end = EL1_IPC_TABLE_MAP_OFFSET
            .checked_add(core::mem::size_of::<crate::ipc_tables::IpcTableMap>() as u64)
            .ok_or(FileRegionError::Layout)?;
        if end > EL1_REGION_SIZE {
            return Err(FileRegionError::Layout);
        }
        let address = layout
            .region
            .raw()
            .checked_add(EL1_IPC_TABLE_MAP_OFFSET)
            .ok_or(FileRegionError::Layout)?;
        Ok(KernelVa::new(address))
    }
}

#[cfg(test)]
mod tests;
