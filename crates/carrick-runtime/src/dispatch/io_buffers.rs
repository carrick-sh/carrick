//! Guest memory I/O vector and buffer read/write helpers.

use carrick_abi::{LINUX_EFAULT, LINUX_EINVAL};
pub(crate) use carrick_abi::{LINUX_IOV_MAX, LinuxIovec, LinuxOpenHow};
use carrick_guest_mem::CurrentMmMemory;

use crate::dispatch::DispatchError;
use crate::dispatch::fd_table::FileContents;
use crate::dispatch::read_kernel_struct;
use crate::linux_abi::LinuxErrno;
use crate::vfs::{SparseBuffer, SyntheticDeviceKind};

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
        if memory
            .write_bytes(iov_base, &remaining[..read_len])
            .is_err()
        {
            return Ok(total);
        }
        offset += read_len;
        total = total
            .checked_add(read_len)
            .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
        if read_len < iov_len {
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
        if memory.write_bytes(iov_base, &bytes).is_err() {
            return Ok(total);
        }
        offset += read_len;
        total = total
            .checked_add(read_len)
            .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
        if read_len < iov_len {
            break;
        }
    }
    Ok(total)
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
                let mut buf = vec![0u8; iov_len];
                unsafe {
                    libc::arc4random_buf(buf.as_mut_ptr().cast(), iov_len);
                }
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
    let mut scratch = vec![0u8; max_iov_len];
    let mut total = 0usize;
    for iovec in iovecs {
        let iov_base = iovec.iov_base;
        let iov_len = usize::try_from(iovec.iov_len)
            .map_err(|_| DispatchError::LengthTooLarge(iovec.iov_len))?;
        if iov_len == 0 {
            continue;
        }
        let buf = &mut scratch[..iov_len];
        match contents.read_at(offset as u64, buf) {
            Ok(0) => break,
            Ok(read_len) => {
                if memory.write_bytes(iov_base, &buf[..read_len]).is_err() {
                    return Ok(total);
                }
                offset += read_len;
                total = total
                    .checked_add(read_len)
                    .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
                if read_len < iov_len {
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
    Ok(total)
}
