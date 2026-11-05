//! Imported vector headers belong to the operation slot, never a guest pointer.
use super::{
    AtomicU64, IPC_POOL_ALIGN, IpcError, IpcOpToken, IpcOperationSlot, IpcRegion, IpcUserVa,
    Ordering, fd, ipc_descriptor_area,
};

pub const IPC_MAX_IOVECS: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VectorImportError {
    Invalid,
    Fault,
    NoMemory,
    Storage(IpcError),
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct VectorStorage {
    offset: u64,
    bytes: u64,
    count: u64,
}

/// The word is a free-list link only while the slot is free, and a typed
/// allocation receipt only while its generation-authenticated token is live.
#[repr(transparent)]
pub(super) struct SlotCustody(AtomicU64);
const COUNT_BITS: u32 = 11;
const OFFSET_SHIFT: u32 = 16;
impl SlotCustody {
    pub(super) fn free_link(&self) -> &AtomicU64 {
        &self.0
    }
    pub(super) fn clear_live(&self) {
        self.0.store(0, Ordering::Relaxed);
    }
    fn live_vectors(&self) -> Result<VectorStorage, IpcError> {
        let raw = self.0.load(Ordering::Relaxed);
        if raw == 0 {
            return Ok(VectorStorage::default());
        }
        let page = (raw >> OFFSET_SHIFT)
            .checked_sub(1)
            .ok_or(IpcError::Corrupt)?;
        let order = ((raw >> COUNT_BITS) & 31) as u32;
        let count = raw & ((1 << COUNT_BITS) - 1);
        if order > 3 || count > IPC_MAX_IOVECS as u64 {
            return Err(IpcError::Corrupt);
        }
        Ok(VectorStorage {
            offset: page * IPC_POOL_ALIGN,
            bytes: IPC_POOL_ALIGN << order,
            count,
        })
    }
    fn publish_vectors(&self, storage: VectorStorage) -> Result<(), IpcError> {
        if storage.bytes == 0 {
            self.clear_live();
            return Ok(());
        }
        if !storage.offset.is_multiple_of(IPC_POOL_ALIGN)
            || !storage.bytes.is_power_of_two()
            || !(IPC_POOL_ALIGN..=IPC_POOL_ALIGN * 8).contains(&storage.bytes)
            || storage.count > IPC_MAX_IOVECS as u64
        {
            return Err(IpcError::Corrupt);
        }
        let page = storage.offset / IPC_POOL_ALIGN + 1;
        if page >= (1u64 << (64 - OFFSET_SHIFT)) {
            return Err(IpcError::Corrupt);
        }
        let order = storage.bytes.ilog2() - IPC_POOL_ALIGN.ilog2();
        self.0.store(
            (page << OFFSET_SHIFT) | (u64::from(order) << COUNT_BITS) | storage.count,
            Ordering::Relaxed,
        );
        Ok(())
    }
}
pub(super) const VECTOR_LAYOUT: &[u64] = &[
    IPC_MAX_IOVECS as u64,
    COUNT_BITS as u64,
    OFFSET_SHIFT as u64,
    core::mem::size_of::<SlotCustody>() as u64,
    core::mem::size_of::<Vector>() as u64,
    core::mem::offset_of!(Vector, base) as u64,
    core::mem::offset_of!(Vector, len) as u64,
    core::mem::offset_of!(Vector, prefix) as u64,
];

// Each imported header includes its exclusive prefix, allowing bounded binary
// search on resume instead of rescanning a potentially huge vector prefix.
#[repr(C)]
#[derive(Clone, Copy)]
struct Vector {
    base: IpcUserVa,
    len: u64,
    prefix: u64,
}

impl IpcRegion<'_> {
    /// Import all headers before the first effect. The token owns the backing
    /// even on an error: its normal finish/cancellation reclaims it.
    #[inline(never)]
    pub fn import_vectors(
        &self,
        token: &IpcOpToken,
        count: usize,
        mut read: impl FnMut(usize, &mut [u8; 16]) -> bool,
    ) -> Result<u64, VectorImportError> {
        if count > IPC_MAX_IOVECS {
            return Err(VectorImportError::Invalid);
        }
        let slot = self.op_slot(token).map_err(VectorImportError::Storage)?;
        let mut storage = slot
            .custody
            .live_vectors()
            .map_err(VectorImportError::Storage)?;
        if storage.bytes != 0 {
            return Err(VectorImportError::Storage(IpcError::Corrupt));
        }
        if count == 0 {
            return Ok(0);
        }
        let mut allocation = self
            .descriptor_storage()
            .allocate(
                (count * core::mem::size_of::<Vector>()) as u64,
                &carrick_sched_core::ShortLockSpin,
            )
            .map_err(|error| match error {
                fd::storage::StorageError::Exhausted => VectorImportError::NoMemory,
                fd::storage::StorageError::Contended => {
                    VectorImportError::Storage(IpcError::Contended)
                }
                fd::storage::StorageError::Invalid => VectorImportError::Storage(IpcError::Corrupt),
            })?;
        storage = VectorStorage {
            offset: ipc_descriptor_area(self.pool_len).start + allocation.offset,
            bytes: allocation.bytes,
            count: 0,
        };
        if let Err(error) = slot.custody.publish_vectors(storage) {
            self.descriptor_storage()
                .release(&mut allocation, &carrick_sched_core::ShortLockSpin)
                .map_err(|_| VectorImportError::Storage(IpcError::Corrupt))?;
            return Err(VectorImportError::Storage(error));
        }
        let mut total = 0u64;
        for index in 0..count {
            let mut header = [0; 16];
            if !read(index, &mut header) {
                return Err(VectorImportError::Fault);
            }
            let base = u64::from_ne_bytes(
                header[..8]
                    .try_into()
                    .map_err(|_| VectorImportError::Invalid)?,
            );
            let len = u64::from_ne_bytes(
                header[8..]
                    .try_into()
                    .map_err(|_| VectorImportError::Invalid)?,
            );
            let prefix = total;
            total = total
                .checked_add(len)
                .filter(|sum| *sum <= i64::MAX as u64)
                .ok_or(VectorImportError::Invalid)?;
            // Range admission precedes every pipe effect, including effects
            // from earlier vectors. This does not probe page presence: a
            // representable unmapped segment still faults during transfer and
            // preserves the delivered prefix. Empty vectors ignore their base.
            if len != 0
                && (base.checked_add(len).is_none_or(|end| end > (1u64 << 48))
                    || crate::user_range_overlaps_el1_kernel(base, len as usize))
            {
                return Err(VectorImportError::Fault);
            }
            let vector = Vector {
                base: IpcUserVa(base),
                len,
                prefix,
            };
            // SAFETY: this exclusively owned aligned allocation covers every
            // initialized header; no reference escapes the token's lifetime.
            unsafe {
                self.pool
                    .add(storage.offset as usize)
                    .cast::<Vector>()
                    .add(index)
                    .write(vector);
            }
            storage.count += 1;
            slot.custody
                .publish_vectors(storage)
                .map_err(VectorImportError::Storage)?;
        }
        Ok(total)
    }

    pub fn has_vectors(&self, token: &IpcOpToken) -> Result<bool, IpcError> {
        let slot = self.op_slot(token)?;
        Ok(slot.custody.live_vectors()?.bytes != 0)
    }

    /// Copy the logical byte range through immutable imported headers. Returns
    /// only the delivered prefix; no cursor advances past a failed user copy.
    #[inline(never)]
    pub fn copy_vector_input(
        &self,
        token: &IpcOpToken,
        at: u64,
        dst: &mut [u8],
        mut copy: impl FnMut(&mut [u8], IpcUserVa) -> usize,
    ) -> Result<usize, IpcError> {
        let slot = self.op_slot(token)?;
        // SAFETY: the token retains the allocation, fully initialized before
        // transfer. Import failures are finished without attempting transfer.
        let storage = slot.custody.live_vectors()?;
        let vectors = unsafe {
            core::slice::from_raw_parts(
                self.pool.add(storage.offset as usize).cast::<Vector>(),
                storage.count as usize,
            )
        };
        let mut index = vectors.partition_point(|v| v.prefix.saturating_add(v.len) <= at);
        let mut done = 0;
        while done < dst.len() {
            let Some(vector) = vectors.get(index) else {
                break;
            };
            let offset = (at + done as u64)
                .checked_sub(vector.prefix)
                .ok_or(IpcError::Corrupt)?;
            let len = (vector.len.saturating_sub(offset)).min((dst.len() - done) as u64) as usize;
            if len == 0 {
                index += 1;
                continue;
            }
            let Some(address) = vector.base.0.checked_add(offset) else {
                break;
            };
            let copied = copy(&mut dst[done..done + len], IpcUserVa(address)).min(len);
            done += copied;
            if copied != len {
                break;
            }
            index += 1;
        }
        Ok(done)
    }

    #[inline(never)]
    pub(super) fn reclaim_vectors(&self, slot: &IpcOperationSlot) -> Result<(), IpcError> {
        let storage = slot.custody.live_vectors()?;
        if storage.bytes != 0 {
            self.descriptor_storage()
                .release(
                    &mut fd::storage::Allocation {
                        offset: storage.offset - ipc_descriptor_area(self.pool_len).start,
                        bytes: storage.bytes,
                    },
                    &carrick_sched_core::ShortLockSpin,
                )
                .map_err(|_| IpcError::Corrupt)?;
            slot.custody.clear_live();
        }
        Ok(())
    }
}
