//! Guest memory I/O vector and buffer read/write helpers.

use carrick_abi::{LINUX_EFAULT, LINUX_EINVAL};
pub(crate) use carrick_abi::{LINUX_IOV_MAX, LinuxIovec, LinuxOpenHow};
use carrick_fatal::carrick_fatal;
use carrick_guest_mem::{CurrentMmMemory, GuestVa, GuestWriteRange, MemoryPrepareError};

use crate::dispatch::DispatchError;
use crate::dispatch::fd_table::FileContents;
use crate::dispatch::read_kernel_struct;
use crate::linux_abi::LinuxErrno;
use carrick_vfs::{SparseBuffer, SyntheticDeviceKind};

/// `len` fresh bytes from the host CSPRNG, for a guest read of `/dev/random` or
/// `/dev/urandom`.
///
/// Linux's `/dev/urandom` never short-reads and never fails once the pool is
/// seeded, and `/dev/random` on a running kernel behaves the same, so the
/// guest-visible contract is "always exactly `len` bytes". `getrandom` is the
/// portable spelling of "ask the host's own CSPRNG" — `getentropy(2)` on Darwin
/// and the BSDs, `getrandom(2)` on Linux — which keeps this crate free of the
/// Darwin-only `arc4random_buf` it used to name and so able to compile for a
/// host with no Hypervisor.framework at all (`just check-kernel-portable`).
///
/// A host CSPRNG that refuses to produce bytes is not a condition a guest read
/// can be told about honestly (there is no Linux errno for it, and returning
/// zeroes would hand the guest predictable "randomness"), so it is fatal.
pub(crate) fn random_device_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    if let Err(error) = getrandom::fill(&mut buf) {
        tracing::error!(%error, len, "host CSPRNG refused to fill a random-device read");
        carrick_fatal!(
            "dispatch::random_device",
            "host CSPRNG refused to fill a random-device read"
        );
    }
    buf
}

pub(crate) fn read_u64(memory: &impl CurrentMmMemory, address: u64) -> Result<u64, LinuxErrno> {
    let mut buf = [0u8; 8];
    memory
        .read_into(address, &mut buf)
        .map_err(|_| LINUX_EFAULT)?;
    Ok(u64::from_ne_bytes(buf))
}

pub(crate) fn read_u32(memory: &impl CurrentMmMemory, address: u64) -> Result<u32, LinuxErrno> {
    let mut buf = [0u8; 4];
    memory
        .read_into(address, &mut buf)
        .map_err(|_| LINUX_EFAULT)?;
    Ok(u32::from_ne_bytes(buf))
}

pub(crate) fn write_u32(
    memory: &mut impl CurrentMmMemory,
    address: u64,
    value: u32,
) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(address, &value.to_ne_bytes())
        .map_err(|_| LINUX_EFAULT)
}

pub(crate) fn read_open_how(
    memory: &impl CurrentMmMemory,
    address: u64,
) -> Result<LinuxOpenHow, LinuxErrno> {
    read_kernel_struct(memory, address)
}

pub(crate) fn read_iovecs(
    memory: &impl CurrentMmMemory,
    address: u64,
    count: usize,
) -> Result<Vec<LinuxIovec>, LinuxErrno> {
    if count > LINUX_IOV_MAX {
        return Err(LINUX_EINVAL);
    }

    let mut iovecs = Vec::with_capacity(count);
    let size = core::mem::size_of::<LinuxIovec>();
    // Linux validates the iov array at syscall entry (rw_copy_check_uvector):
    // each iov_len and the running total must stay within SSIZE_MAX, else
    // EINVAL — NOT EFAULT. carrick previously let an oversized iov_len fall
    // through to a `read_bytes(base, huge)` that EFAULTed (LTP writev01).
    const SSIZE_MAX: u64 = i64::MAX as u64;
    let mut total: u64 = 0;
    for index in 0..count {
        let offset = index
            .checked_mul(size)
            .and_then(|offset| u64::try_from(offset).ok())
            .ok_or(LINUX_EINVAL)?;
        let iovec_address = address.checked_add(offset).ok_or(LINUX_EFAULT)?;
        let iovec: LinuxIovec = read_kernel_struct(memory, iovec_address)?;
        if iovec.iov_len > SSIZE_MAX {
            return Err(LINUX_EINVAL);
        }
        total = total.checked_add(iovec.iov_len).ok_or(LINUX_EINVAL)?;
        if total > SSIZE_MAX {
            return Err(LINUX_EINVAL);
        }
        iovecs.push(iovec);
    }
    Ok(iovecs)
}

pub(crate) fn read_from_contents_at(
    memory: &mut impl CurrentMmMemory,
    contents: &[u8],
    mut offset: usize,
    iovecs: &[LinuxIovec],
) -> Result<usize, DispatchError> {
    let mut total = 0usize;
    for iovec in iovecs {
        let iov_base = iovec.iov_base;
        let iov_len = usize::try_from(iovec.iov_len)
            .map_err(|_| DispatchError::LengthTooLarge(iovec.iov_len))?;
        if iov_len == 0 {
            continue;
        }
        let remaining = contents.get(offset..).unwrap_or_default();
        let read_len = remaining.len().min(iov_len);
        if read_len == 0 {
            break;
        }
        let copied = copy_read_bytes(memory, iov_base, &remaining[..read_len]);
        offset += copied;
        total = total
            .checked_add(copied)
            .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
        if copied < read_len || read_len < iov_len {
            break;
        }
    }
    Ok(total)
}

pub(crate) fn read_from_sparse_buffer_at(
    memory: &mut impl CurrentMmMemory,
    buffer: &SparseBuffer,
    mut offset: usize,
    iovecs: &[LinuxIovec],
) -> Result<usize, DispatchError> {
    let mut total = 0usize;
    for iovec in iovecs {
        let iov_base = iovec.iov_base;
        let iov_len = usize::try_from(iovec.iov_len)
            .map_err(|_| DispatchError::LengthTooLarge(iovec.iov_len))?;
        if iov_len == 0 {
            continue;
        }
        if offset >= buffer.len() {
            break;
        }
        let read_len = iov_len.min(buffer.len().saturating_sub(offset));
        if read_len == 0 {
            break;
        }
        let bytes = buffer.read_range(offset, read_len);
        let copied = copy_read_bytes(memory, iov_base, &bytes);
        offset += copied;
        total = total
            .checked_add(copied)
            .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
        if copied < read_len || read_len < iov_len {
            break;
        }
    }
    Ok(total)
}

/// Copy a repeatable source through one owner permit at a time. A failure
/// after a committed prefix reports exactly that prefix to the caller, which
/// advances its file offset by the same count.
fn copy_read_bytes(memory: &mut impl CurrentMmMemory, address: u64, bytes: &[u8]) -> usize {
    if memory.user_memory_venue() != carrick_guest_mem::UserMemoryVenue::Owner {
        return if memory.write_bytes(address, bytes).is_ok() {
            bytes.len()
        } else {
            0
        };
    }
    let mut copied = 0usize;
    while copied < bytes.len() {
        let Some(at) = address.checked_add(copied as u64) else {
            break;
        };
        let step = (4096 - (at as usize & 4095)).min(bytes.len() - copied);
        if memory
            .write_bytes(at, &bytes[copied..copied + step])
            .is_err()
        {
            break;
        }
        copied += step;
    }
    copied
}

/// A repeatable source permits an exact restart after an owner refusal. Read
/// each bounded chunk before preparing its destination, then commit only the
/// bytes actually read. The caller owns the file offset and advances it by
/// `copied` even when the next chunk needs an owner supply or wait.
pub(in crate::dispatch) fn read_from_repeatable_owner_at(
    memory: &mut impl CurrentMmMemory,
    address: u64,
    length: usize,
    offset: usize,
    mut read_at: impl FnMut(usize, &mut [u8]) -> Result<usize, LinuxErrno>,
) -> Result<(usize, Option<MemoryPrepareError>), DispatchError> {
    let mut scratch = [0u8; 4096];
    let mut copied = 0usize;
    while copied < length {
        let at = address
            .checked_add(copied as u64)
            .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
        let source_offset = offset
            .checked_add(copied)
            .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
        let step = (4096 - (at as usize & 4095)).min(length - copied);
        let read_len = match read_at(source_offset, &mut scratch[..step]) {
            Ok(0) => break,
            Ok(read_len) => read_len,
            Err(_errno) if copied > 0 => break,
            Err(errno) => return Err(DispatchError::Errno(errno)),
        };
        let range = GuestWriteRange::new(GuestVa(at), read_len)
            .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
        let prepared = match memory.prepare_write(&[range]) {
            Ok(prepared) => prepared,
            Err(error) => return Ok((copied, Some(error))),
        };
        prepared.commit(&[&scratch[..read_len]]);
        copied += read_len;
    }
    Ok((copied, None))
}

pub(crate) fn read_from_synthetic_device_iovecs(
    memory: &mut impl CurrentMmMemory,
    kind: SyntheticDeviceKind,
    iovecs: &[LinuxIovec],
) -> Result<usize, DispatchError> {
    let mut total = 0usize;
    match kind {
        SyntheticDeviceKind::Null => {}
        SyntheticDeviceKind::Zero | SyntheticDeviceKind::Full => {
            for iovec in iovecs {
                let iov_len = usize::try_from(iovec.iov_len)
                    .map_err(|_| DispatchError::LengthTooLarge(iovec.iov_len))?;
                if iov_len == 0 {
                    continue;
                }
                let zeroes = vec![0u8; iov_len];
                if memory.write_bytes(iovec.iov_base, &zeroes).is_err() {
                    return Ok(total);
                }
                total += iov_len;
            }
        }
        SyntheticDeviceKind::Random | SyntheticDeviceKind::Urandom => {
            for iovec in iovecs {
                let iov_len = usize::try_from(iovec.iov_len)
                    .map_err(|_| DispatchError::LengthTooLarge(iovec.iov_len))?;
                if iov_len == 0 {
                    continue;
                }
                let buf = random_device_bytes(iov_len);
                if memory.write_bytes(iovec.iov_base, &buf).is_err() {
                    return Ok(total);
                }
                total += iov_len;
            }
        }
    }
    Ok(total)
}

pub(in crate::dispatch) fn read_from_file_contents_at(
    memory: &mut impl CurrentMmMemory,
    contents: &FileContents,
    mut offset: usize,
    iovecs: &[LinuxIovec],
) -> Result<usize, DispatchError> {
    let mut max_iov_len = 0usize;
    for iovec in iovecs {
        let iov_len = usize::try_from(iovec.iov_len)
            .map_err(|_| DispatchError::LengthTooLarge(iovec.iov_len))?;
        if iov_len > max_iov_len {
            max_iov_len = iov_len;
        }
    }
    if max_iov_len == 0 {
        return Ok(0);
    }
    // An EL1 owner issues at most one page of write permission per stream
    // step. Preparing the whole iovec makes untouched destinations fail the
    // bounded portal contract before any file byte can be delivered.
    let owner = memory.user_memory_venue() == carrick_guest_mem::UserMemoryVenue::Owner;
    let mut scratch = vec![
        0u8;
        if owner {
            max_iov_len.min(4096)
        } else {
            max_iov_len
        }
    ];
    let mut total = 0usize;
    for iovec in iovecs {
        let iov_base = iovec.iov_base;
        let iov_len = usize::try_from(iovec.iov_len)
            .map_err(|_| DispatchError::LengthTooLarge(iovec.iov_len))?;
        if iov_len == 0 {
            continue;
        }
        let mut iov_done = 0usize;
        while iov_done < iov_len {
            let address = iov_base
                .checked_add(iov_done as u64)
                .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
            let step = if owner {
                (4096 - (address as usize & 4095)).min(iov_len - iov_done)
            } else {
                iov_len - iov_done
            };
            let buf = &mut scratch[..step];
            match contents.read_at(offset as u64, buf) {
                Ok(0) => break,
                Ok(read_len) => {
                    if memory.write_bytes(address, &buf[..read_len]).is_err() {
                        return Ok(total);
                    }
                    offset += read_len;
                    iov_done += read_len;
                    total = total
                        .checked_add(read_len)
                        .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
                    if read_len < step {
                        break;
                    }
                }
                Err(errno) => {
                    if total > 0 {
                        return Ok(total);
                    }
                    return Err(DispatchError::Errno(errno));
                }
            }
        }
        if iov_done < iov_len {
            break;
        }
    }
    Ok(total)
}

#[cfg(test)]
mod owner_repeatable_read_tests {
    use super::*;
    use carrick_guest_mem::{GuestMemory, MemoryError, PreparedGuestWrite, UserMemoryVenue};
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    const BASE: u64 = 0x1000_0000;

    struct OwnerMemory {
        bytes: Arc<Mutex<Vec<u8>>>,
        prepared_lengths: Vec<usize>,
        prepare_count: usize,
        refuse_at: Option<usize>,
    }

    struct Permit {
        bytes: Arc<Mutex<Vec<u8>>>,
        offset: usize,
        len: usize,
    }

    impl PreparedGuestWrite for Permit {
        fn commit(self: Box<Self>, outputs: &[&[u8]]) {
            assert_eq!(outputs.len(), 1);
            assert!(outputs[0].len() <= self.len);
            self.bytes.lock().unwrap()[self.offset..self.offset + outputs[0].len()]
                .copy_from_slice(outputs[0]);
        }
    }

    impl GuestMemory for OwnerMemory {
        fn user_memory_venue(&self) -> UserMemoryVenue {
            UserMemoryVenue::Owner
        }

        fn prepare_write(
            &mut self,
            ranges: &[GuestWriteRange],
        ) -> Result<Box<dyn PreparedGuestWrite + '_>, MemoryPrepareError> {
            assert_eq!(ranges.len(), 1);
            let range = ranges[0];
            self.prepare_count += 1;
            self.prepared_lengths.push(range.len());
            if self.refuse_at == Some(self.prepare_count) {
                return Err(MemoryPrepareError::Fault(MemoryError::OutOfBounds {
                    address: range.address().raw(),
                    length: range.len(),
                }));
            }
            Ok(Box::new(Permit {
                bytes: Arc::clone(&self.bytes),
                offset: (range.address().raw() - BASE) as usize,
                len: range.len(),
            }))
        }

        fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
            let offset = (address - BASE) as usize;
            Ok(self.bytes.lock().unwrap()[offset..offset + length].to_vec())
        }

        fn write_bytes_raw(&mut self, _address: u64, _bytes: &[u8]) -> Result<(), MemoryError> {
            panic!("owner copyout bypassed its prepared permit")
        }
    }

    impl CurrentMmMemory for OwnerMemory {}

    #[test]
    fn regular_file_read_keeps_full_count_and_exact_offset_after_later_chunk_refusal() {
        let payload: Vec<u8> = (0..9000).map(|index| (index % 251) as u8).collect();
        let mut memory = OwnerMemory {
            bytes: Arc::new(Mutex::new(vec![0; 16 * 1024])),
            prepared_lengths: Vec::new(),
            prepare_count: 0,
            refuse_at: Some(2),
        };
        let address = BASE + 100;
        let source_offset = 50;
        let observed_offsets = RefCell::new(Vec::new());
        let mut read_at = |at: usize, bytes: &mut [u8]| {
            observed_offsets.borrow_mut().push(at);
            let source = payload.get(at - source_offset..).unwrap_or_default();
            let count =
                source
                    .len()
                    .min(bytes.len())
                    .min(if observed_offsets.borrow().len() == 1 {
                        1000
                    } else {
                        4096
                    });
            bytes[..count].copy_from_slice(&source[..count]);
            Ok(count)
        };
        let (prefix, refusal) = read_from_repeatable_owner_at(
            &mut memory,
            address,
            payload.len(),
            source_offset,
            &mut read_at,
        )
        .unwrap();
        assert_eq!(prefix, 1000);
        assert!(matches!(refusal, Some(MemoryPrepareError::Fault(_))));
        assert_eq!(*observed_offsets.borrow(), [50, 1050]);
        assert_eq!(&memory.bytes.lock().unwrap()[100..1100], &payload[..1000]);

        memory.refuse_at = None;
        let (remaining, refusal) = read_from_repeatable_owner_at(
            &mut memory,
            address + prefix as u64,
            payload.len() - prefix,
            source_offset + prefix,
            &mut read_at,
        )
        .unwrap();
        assert_eq!(remaining + prefix, payload.len());
        assert!(refusal.is_none());
        assert_eq!(observed_offsets.borrow()[2], 1050);
        assert!(memory.prepared_lengths.iter().all(|&len| len <= 4096));
        assert!(memory.prepared_lengths.contains(&4096));
        assert_eq!(
            &memory.bytes.lock().unwrap()[100..100 + payload.len()],
            payload.as_slice()
        );
    }
}
