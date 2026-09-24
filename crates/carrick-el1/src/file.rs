//! File operations for delegated regular files at EL1.

use carrick_el1_abi::{
    Action, CurrentTask, DELEGATED_FILE_MAX_SIZE, DELEGATED_FLAG_APPEND, DELEGATED_FLAG_READABLE,
    DELEGATED_FLAG_WRITABLE, DELEGATED_PAGE_SIZE, DelegatedFile,
};
use core::sync::atomic::Ordering;

#[cfg(test)]
std::thread_local! {
    pub static SIMULATE_COPY_FAULT: core::sync::atomic::AtomicBool =
        const { core::sync::atomic::AtomicBool::new(false) };
}

/// Copy `len` bytes from `src` to `dest` (user virtual address), guarded by EL1 exception fixup.
/// Returns `true` if copy succeeded, `false` if a fault occurred and was intercepted by fixup.
///
/// # Safety
///
/// `dest` and `src` must be valid for pointer arithmetic. Faults on accessing user memory
/// are safely caught by the EL1 fixup mechanism.
#[inline(never)]
pub(crate) unsafe fn copy_to_user_guarded(
    cur_task: &CurrentTask,
    dest: *mut u8,
    src: *const u8,
    len: usize,
) -> bool {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        let fixup_ptr = &cur_task.fixup_pc as *const _ as *const u64;
        let mut success: u64 = 1;
        unsafe {
            core::arch::asm!(
                "adr {tmp}, 2f",
                "str {tmp}, [{fixup}]",
                "cbz {len}, 1f",
                "0:",
                "ldrb {tmp:w}, [{src}], #1",
                "sttrb {tmp:w}, [{dst}]",
                "add {dst}, {dst}, #1",
                "sub {len}, {len}, #1",
                "cbnz {len}, 0b",
                "1:",
                "str xzr, [{fixup}]",
                "b 3f",
                "2:",
                "str xzr, [{fixup}]",
                "mov {succ}, #0",
                "3:",
                tmp = out(reg) _,
                fixup = in(reg) fixup_ptr,
                dst = inout(reg) dest => _,
                src = inout(reg) src => _,
                len = inout(reg) len => _,
                succ = inout(reg) success,
                options(nostack)
            );
        }
        success != 0
    }
    #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
    {
        let _ = cur_task;
        #[cfg(test)]
        if SIMULATE_COPY_FAULT.with(|f| f.load(Ordering::Relaxed)) {
            return false;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(src, dest, len);
        }
        true
    }
}

/// Copy `len` bytes from `src` (user virtual address) to `dest`, guarded by EL1 exception fixup.
/// Returns `true` if copy succeeded, `false` if a fault occurred and was intercepted by fixup.
///
/// # Safety
///
/// `dest` and `src` must be valid for pointer arithmetic. Faults on accessing user memory
/// are safely caught by the EL1 fixup mechanism.
#[inline(never)]
pub(crate) unsafe fn copy_from_user_guarded(
    cur_task: &CurrentTask,
    dest: *mut u8,
    src: *const u8,
    len: usize,
) -> bool {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        let fixup_ptr = &cur_task.fixup_pc as *const _ as *const u64;
        let mut success: u64 = 1;
        unsafe {
            core::arch::asm!(
                "adr {tmp}, 2f",
                "str {tmp}, [{fixup}]",
                "cbz {len}, 1f",
                "0:",
                "ldtrb {tmp:w}, [{src}]",
                "add {src}, {src}, #1",
                "strb {tmp:w}, [{dst}], #1",
                "sub {len}, {len}, #1",
                "cbnz {len}, 0b",
                "1:",
                "str xzr, [{fixup}]",
                "b 3f",
                "2:",
                "str xzr, [{fixup}]",
                "mov {succ}, #0",
                "3:",
                tmp = out(reg) _,
                fixup = in(reg) fixup_ptr,
                dst = inout(reg) dest => _,
                src = inout(reg) src => _,
                len = inout(reg) len => _,
                succ = inout(reg) success,
                options(nostack)
            );
        }
        success != 0
    }
    #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
    {
        let _ = cur_task;
        #[cfg(test)]
        if SIMULATE_COPY_FAULT.with(|f| f.load(Ordering::Relaxed)) {
            return false;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(src, dest, len);
        }
        true
    }
}

pub const EBADF: i64 = -9;
pub const EFAULT: i64 = -14;
pub const EINVAL: i64 = -22;
pub const EFBIG: i64 = -27;
pub const ESPIPE: i64 = -29;
pub const EOVERFLOW: i64 = -75;

pub const SEEK_SET: u32 = 0;
pub const SEEK_CUR: u32 = 1;
pub const SEEK_END: u32 = 2;
pub const SEEK_DATA: u32 = 3;
pub const SEEK_HOLE: u32 = 4;

/// Abstraction for validating user memory permissions before access.
pub trait MemoryValidator {
    /// Return the number of contiguous bytes from `user_va` that EL0 can write.
    fn writable_bytes(&self, user_va: u64, len: usize) -> usize;

    /// Return the number of contiguous bytes from `user_va` that EL0 can read.
    fn readable_bytes(&self, user_va: u64, len: usize) -> usize;
}

#[cfg(not(target_os = "none"))]
pub struct HardwareValidator;

#[cfg(not(target_os = "none"))]
impl MemoryValidator for HardwareValidator {
    fn writable_bytes(&self, _user_va: u64, len: usize) -> usize {
        len
    }

    fn readable_bytes(&self, _user_va: u64, len: usize) -> usize {
        len
    }
}

#[cfg(target_os = "none")]
pub struct HardwareValidator;

#[cfg(target_os = "none")]
impl MemoryValidator for HardwareValidator {
    fn writable_bytes(&self, user_va: u64, len: usize) -> usize {
        if len == 0 {
            return 0;
        }
        let mut checked = 0;
        while checked < len {
            let cur_va = user_va + checked as u64;
            let mut par: u64;
            unsafe {
                core::arch::asm!(
                    "at s1e0w, {va}",
                    "isb",
                    "mrs {par}, par_el1",
                    va = in(reg) cur_va,
                    par = out(reg) par,
                    options(nostack)
                );
            }
            if (par & 1) != 0 {
                // Translation fault or permission failure
                break;
            }
            let next_page = (cur_va + 4096) & !4095;
            let page_remaining = (next_page - cur_va) as usize;
            checked += core::cmp::min(len - checked, page_remaining);
        }
        checked
    }

    fn readable_bytes(&self, user_va: u64, len: usize) -> usize {
        if len == 0 {
            return 0;
        }
        let mut checked = 0;
        while checked < len {
            let cur_va = user_va + checked as u64;
            let mut par: u64;
            unsafe {
                core::arch::asm!(
                    "at s1e0r, {va}",
                    "isb",
                    "mrs {par}, par_el1",
                    va = in(reg) cur_va,
                    par = out(reg) par,
                    options(nostack)
                );
            }
            if (par & 1) != 0 {
                // Translation fault or permission failure
                break;
            }
            let next_page = (cur_va + 4096) & !4095;
            let page_remaining = (next_page - cur_va) as usize;
            checked += core::cmp::min(len - checked, page_remaining);
        }
        checked
    }
}

/// How a file operation moves bytes between a user buffer and the object's
/// cache. EL1 checks stage-1 permissions and copies with fixup-guarded
/// unprivileged accesses; the host copies through the guest address space.
/// `false` means the copy cannot be done exactly here, and the caller takes its
/// fallback path (EL1 forwards to the host; the host recalls the object).
pub trait UserCopy {
    /// Copy `src` to the user buffer at `dst_va`.
    fn copy_out(&mut self, dst_va: u64, src: &[u8]) -> bool;
    /// Fill `dst` from the user buffer at `src_va`.
    fn copy_in(&mut self, dst: &mut [u8], src_va: u64) -> bool;
}

/// EL1's user copy: the whole range must pass the permission check, then the
/// copy runs with the exception fixup armed.
pub struct ValidatedCopy<'a, V: MemoryValidator> {
    pub task: &'a CurrentTask,
    pub validator: &'a V,
}

impl<V: MemoryValidator> UserCopy for ValidatedCopy<'_, V> {
    fn copy_out(&mut self, dst_va: u64, src: &[u8]) -> bool {
        if self.validator.writable_bytes(dst_va, src.len()) < src.len() {
            return false;
        }
        // SAFETY: faults on the user range are intercepted by the EL1 fixup.
        unsafe { copy_to_user_guarded(self.task, dst_va as *mut u8, src.as_ptr(), src.len()) }
    }

    fn copy_in(&mut self, dst: &mut [u8], src_va: u64) -> bool {
        if self.validator.readable_bytes(src_va, dst.len()) < dst.len() {
            return false;
        }
        // SAFETY: faults on the user range are intercepted by the EL1 fixup.
        unsafe {
            copy_from_user_guarded(self.task, dst.as_mut_ptr(), src_va as *const u8, dst.len())
        }
    }
}

/// Service `lseek` at EL1.
pub fn el1_lseek(file: &DelegatedFile, offset: i64, whence: u32) -> Result<i64, Action> {
    if whence == SEEK_DATA || whence == SEEK_HOLE {
        return Err(Action::Forward);
    }
    let cur_off = file.offset.load(Ordering::Acquire) as i64;
    let size = file.size.load(Ordering::Acquire) as i64;
    let target = match whence {
        SEEK_SET => offset,
        SEEK_CUR => match cur_off.checked_add(offset) {
            Some(t) => t,
            None => return Ok(EOVERFLOW),
        },
        SEEK_END => match size.checked_add(offset) {
            Some(t) => t,
            None => return Ok(EOVERFLOW),
        },
        _ => return Ok(EINVAL),
    };
    if target < 0 {
        return Ok(EINVAL);
    }
    file.offset.store(target as u64, Ordering::Release);
    Ok(target)
}

/// `read` on a delegated object, for any caller holding its lock.
///
/// # Safety
///
/// `cache_base` must point at this object's cache slot of
/// `DELEGATED_FILE_MAX_SIZE` bytes, and the caller must hold the object lock.
pub unsafe fn read_with(
    file: &DelegatedFile,
    cache_base: *const u8,
    buf_va: u64,
    count: usize,
    user: &mut impl UserCopy,
) -> Result<i64, Action> {
    let flags = file.flags.load(Ordering::Acquire);
    if (flags & DELEGATED_FLAG_READABLE) == 0 {
        return Ok(EBADF);
    }
    if count == 0 {
        return Ok(0);
    }
    let cur_off = file.offset.load(Ordering::Acquire);
    let size = file.size.load(Ordering::Acquire);
    if cur_off >= size {
        return Ok(0);
    }
    let avail = core::cmp::min(count, (size - cur_off) as usize);
    // SAFETY: [cur_off, cur_off + avail) lies below size <= the slot size.
    let src = unsafe { core::slice::from_raw_parts(cache_base.add(cur_off as usize), avail) };
    if !user.copy_out(buf_va, src) {
        return Err(Action::Forward);
    }
    file.offset.store(cur_off + avail as u64, Ordering::Release);
    Ok(avail as i64)
}

/// `pread64` on a delegated object, for any caller holding its lock.
///
/// # Safety
///
/// As for [`read_with`].
pub unsafe fn pread64_with(
    file: &DelegatedFile,
    cache_base: *const u8,
    buf_va: u64,
    count: usize,
    offset: i64,
    user: &mut impl UserCopy,
) -> Result<i64, Action> {
    if offset < 0 {
        return Ok(EINVAL);
    }
    let flags = file.flags.load(Ordering::Acquire);
    if (flags & DELEGATED_FLAG_READABLE) == 0 {
        return Ok(EBADF);
    }
    if count == 0 {
        return Ok(0);
    }
    let off = offset as u64;
    let size = file.size.load(Ordering::Acquire);
    if off >= size {
        return Ok(0);
    }
    let avail = core::cmp::min(count, (size - off) as usize);
    // SAFETY: [off, off + avail) lies below size <= the slot size.
    let src = unsafe { core::slice::from_raw_parts(cache_base.add(off as usize), avail) };
    if !user.copy_out(buf_va, src) {
        return Err(Action::Forward);
    }
    Ok(avail as i64)
}

/// Copy `count` user bytes into the cache at `at`, zero any gap past the old
/// size, and publish size, dirty and zero-filled state.
///
/// # Safety
///
/// As for [`read_with`]; `at + count` must not exceed the slot size.
unsafe fn store_at(
    file: &DelegatedFile,
    cache_base: *mut u8,
    at: u64,
    buf_va: u64,
    count: usize,
    user: &mut impl UserCopy,
) -> Result<u64, Action> {
    // SAFETY: [at, at + count) lies inside the slot (checked by the caller).
    let dst = unsafe { core::slice::from_raw_parts_mut(cache_base.add(at as usize), count) };
    if !user.copy_in(dst, buf_va) {
        return Err(Action::Forward);
    }
    let delivered_end = at + count as u64;
    let old_size = file.size.load(Ordering::Acquire);
    if at > old_size {
        // SAFETY: the gap [old_size, at) lies inside the slot.
        unsafe {
            core::ptr::write_bytes(
                cache_base.add(old_size as usize),
                0,
                (at - old_size) as usize,
            );
        }
        mark_gap_zero_pages(file, old_size, at);
    }
    mark_dirty_pages(file, at, delivered_end);
    if delivered_end > old_size {
        file.size.store(delivered_end, Ordering::Release);
    }
    Ok(delivered_end)
}

/// `write` on a delegated object, for any caller holding its lock.
///
/// # Safety
///
/// As for [`read_with`].
pub unsafe fn write_with(
    file: &DelegatedFile,
    cache_base: *mut u8,
    buf_va: u64,
    count: usize,
    user: &mut impl UserCopy,
) -> Result<i64, Action> {
    let flags = file.flags.load(Ordering::Acquire);
    if (flags & DELEGATED_FLAG_WRITABLE) == 0 {
        return Ok(EBADF);
    }
    if (flags & DELEGATED_FLAG_APPEND) != 0 {
        return Err(Action::Forward);
    }
    if count == 0 {
        return Ok(0);
    }
    let cur_off = file.offset.load(Ordering::Acquire);
    let Some(end_off) = cur_off.checked_add(count as u64) else {
        return Err(Action::Forward);
    };
    if end_off > DELEGATED_FILE_MAX_SIZE {
        return Err(Action::Forward);
    }
    // SAFETY: bounds checked above; the caller holds the lock.
    let delivered_end = unsafe { store_at(file, cache_base, cur_off, buf_va, count, user)? };
    file.offset.store(delivered_end, Ordering::Release);
    Ok(count as i64)
}

/// `pwrite64` on a delegated object, for any caller holding its lock.
///
/// # Safety
///
/// As for [`read_with`].
pub unsafe fn pwrite64_with(
    file: &DelegatedFile,
    cache_base: *mut u8,
    buf_va: u64,
    count: usize,
    offset: i64,
    user: &mut impl UserCopy,
) -> Result<i64, Action> {
    if offset < 0 {
        return Ok(EINVAL);
    }
    let flags = file.flags.load(Ordering::Acquire);
    if (flags & DELEGATED_FLAG_WRITABLE) == 0 {
        return Ok(EBADF);
    }
    if count == 0 {
        return Ok(0);
    }
    let off = offset as u64;
    let Some(end_off) = off.checked_add(count as u64) else {
        return Err(Action::Forward);
    };
    if end_off > DELEGATED_FILE_MAX_SIZE {
        return Err(Action::Forward);
    }
    // SAFETY: bounds checked above; the caller holds the lock.
    unsafe { store_at(file, cache_base, off, buf_va, count, user)? };
    Ok(count as i64)
}

#[cfg(test)]
/// Service `read` at EL1.
pub(crate) fn el1_read<V: MemoryValidator>(
    file: &DelegatedFile,
    cur_task: &CurrentTask,
    cache_base: *const u8,
    buf_va: u64,
    count: usize,
    validator: &V,
) -> Result<i64, Action> {
    let mut user = ValidatedCopy {
        task: cur_task,
        validator,
    };
    // SAFETY: EL1 callers pass this object's slot and hold its lock.
    unsafe { read_with(file, cache_base, buf_va, count, &mut user) }
}

#[cfg(test)]
/// Service `pread64` at EL1.
pub(crate) fn el1_pread64<V: MemoryValidator>(
    file: &DelegatedFile,
    cur_task: &CurrentTask,
    cache_base: *const u8,
    buf_va: u64,
    count: usize,
    offset: i64,
    validator: &V,
) -> Result<i64, Action> {
    let mut user = ValidatedCopy {
        task: cur_task,
        validator,
    };
    // SAFETY: EL1 callers pass this object's slot and hold its lock.
    unsafe { pread64_with(file, cache_base, buf_va, count, offset, &mut user) }
}

#[cfg(test)]
/// Service `write` at EL1.
pub(crate) fn el1_write<V: MemoryValidator>(
    file: &DelegatedFile,
    cur_task: &CurrentTask,
    cache_base: *mut u8,
    buf_va: u64,
    count: usize,
    validator: &V,
) -> Result<i64, Action> {
    let mut user = ValidatedCopy {
        task: cur_task,
        validator,
    };
    // SAFETY: EL1 callers pass this object's slot and hold its lock.
    unsafe { write_with(file, cache_base, buf_va, count, &mut user) }
}

#[cfg(test)]
/// Service `pwrite64` at EL1.
pub(crate) fn el1_pwrite64<V: MemoryValidator>(
    file: &DelegatedFile,
    cur_task: &CurrentTask,
    cache_base: *mut u8,
    buf_va: u64,
    count: usize,
    offset: i64,
    validator: &V,
) -> Result<i64, Action> {
    let mut user = ValidatedCopy {
        task: cur_task,
        validator,
    };
    // SAFETY: EL1 callers pass this object's slot and hold its lock.
    unsafe { pwrite64_with(file, cache_base, buf_va, count, offset, &mut user) }
}

fn mark_gap_zero_pages(file: &DelegatedFile, old_size: u64, cur_off: u64) {
    if cur_off <= old_size {
        return;
    }
    let partial_end = old_size.div_ceil(DELEGATED_PAGE_SIZE) * DELEGATED_PAGE_SIZE;
    if partial_end <= cur_off && !old_size.is_multiple_of(DELEGATED_PAGE_SIZE) {
        mark_dirty_pages(file, old_size, partial_end);
    } else if partial_end > cur_off {
        mark_dirty_pages(file, old_size, cur_off);
        return;
    }

    let start_p = old_size.div_ceil(DELEGATED_PAGE_SIZE) as usize;
    let end_p = (cur_off / DELEGATED_PAGE_SIZE) as usize;
    if end_p > start_p {
        let mut zero_mask = 0u64;
        for p in start_p..core::cmp::min(end_p, 64) {
            zero_mask |= 1u64 << p;
        }
        if zero_mask != 0 {
            file.zero_filled_mask.fetch_or(zero_mask, Ordering::Release);
            file.dirty_mask.fetch_and(!zero_mask, Ordering::Release);
        }
    }
}

fn mark_dirty_pages(file: &DelegatedFile, start: u64, end: u64) {
    if start >= end {
        return;
    }
    let start_p = (start / DELEGATED_PAGE_SIZE) as usize;
    let end_p = end.div_ceil(DELEGATED_PAGE_SIZE) as usize;
    let mut mask = 0u64;
    for p in start_p..core::cmp::min(end_p, 64) {
        mask |= 1u64 << p;
    }
    if mask != 0 {
        file.dirty_mask.fetch_or(mask, Ordering::Release);
        file.zero_filled_mask.fetch_and(!mask, Ordering::Release);
    }
}

#[cfg(test)]
#[allow(clippy::single_range_in_vec_init)]
mod tests {
    extern crate std;
    use super::*;
    use carrick_el1_abi::DELEGATED_STATE_GUEST;
    use std::vec;
    use std::vec::Vec;

    struct FakeOracleValidator {
        writable_regions: Vec<core::ops::Range<u64>>,
        readable_regions: Vec<core::ops::Range<u64>>,
    }

    impl MemoryValidator for FakeOracleValidator {
        fn writable_bytes(&self, user_va: u64, len: usize) -> usize {
            let mut checked = 0;
            while checked < len {
                let cur = user_va + checked as u64;
                let in_range = self.writable_regions.iter().find(|r| r.contains(&cur));
                match in_range {
                    Some(r) => {
                        let remaining_in_range = (r.end - cur) as usize;
                        checked += core::cmp::min(len - checked, remaining_in_range);
                    }
                    None => break,
                }
            }
            checked
        }

        fn readable_bytes(&self, user_va: u64, len: usize) -> usize {
            let mut checked = 0;
            while checked < len {
                let cur = user_va + checked as u64;
                let in_range = self.readable_regions.iter().find(|r| r.contains(&cur));
                match in_range {
                    Some(r) => {
                        let remaining_in_range = (r.end - cur) as usize;
                        checked += core::cmp::min(len - checked, remaining_in_range);
                    }
                    None => break,
                }
            }
            checked
        }
    }

    fn fixture_file(size: u64, offset: u64, flags: u32) -> (DelegatedFile, Vec<u8>) {
        let file = DelegatedFile::new();
        file.state.store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        file.size.store(size, Ordering::Relaxed);
        file.offset.store(offset, Ordering::Relaxed);
        file.flags.store(flags, Ordering::Relaxed);
        let cache = vec![0u8; DELEGATED_FILE_MAX_SIZE as usize];
        (file, cache)
    }

    #[test]
    fn test_lseek_model() {
        let (file, _) = fixture_file(100, 10, DELEGATED_FLAG_READABLE);

        // SEEK_SET
        assert_eq!(el1_lseek(&file, 50, SEEK_SET), Ok(50));
        assert_eq!(file.offset.load(Ordering::Relaxed), 50);

        // SEEK_SET negative -> EINVAL
        assert_eq!(el1_lseek(&file, -1, SEEK_SET), Ok(EINVAL));
        assert_eq!(file.offset.load(Ordering::Relaxed), 50);

        // SEEK_CUR
        assert_eq!(el1_lseek(&file, 20, SEEK_CUR), Ok(70));
        assert_eq!(file.offset.load(Ordering::Relaxed), 70);

        // SEEK_CUR negative
        assert_eq!(el1_lseek(&file, -30, SEEK_CUR), Ok(40));
        assert_eq!(file.offset.load(Ordering::Relaxed), 40);

        // SEEK_CUR past 0 -> EINVAL
        assert_eq!(el1_lseek(&file, -50, SEEK_CUR), Ok(EINVAL));
        assert_eq!(file.offset.load(Ordering::Relaxed), 40);

        // SEEK_END
        assert_eq!(el1_lseek(&file, 0, SEEK_END), Ok(100));
        assert_eq!(file.offset.load(Ordering::Relaxed), 100);

        // SEEK_END with positive offset (allowed in Linux)
        assert_eq!(el1_lseek(&file, 50, SEEK_END), Ok(150));
        assert_eq!(file.offset.load(Ordering::Relaxed), 150);

        // SEEK_DATA / SEEK_HOLE -> Action::Forward
        assert_eq!(el1_lseek(&file, 0, SEEK_DATA), Err(Action::Forward));
        assert_eq!(el1_lseek(&file, 0, SEEK_HOLE), Err(Action::Forward));
    }

    #[test]
    fn test_read_and_pread64_model() {
        let task = CurrentTask::new();
        let (file, mut cache) = fixture_file(200, 0, DELEGATED_FLAG_READABLE);
        for (i, byte) in cache.iter_mut().enumerate().take(200) {
            *byte = (i % 251) as u8;
        }

        let mut user_buf = vec![0u8; 100];
        let user_va = user_buf.as_mut_ptr() as u64;
        let validator = FakeOracleValidator {
            writable_regions: vec![user_va..user_va + 100],
            readable_regions: vec![],
        };

        // Read 50 bytes from offset 0
        let n = el1_read(&file, &task, cache.as_ptr(), user_va, 50, &validator).unwrap();
        assert_eq!(n, 50);
        assert_eq!(file.offset.load(Ordering::Relaxed), 50);
        assert_eq!(&user_buf[0..50], &cache[0..50]);

        // Pread 30 bytes from offset 100 (should not change file offset 50)
        let n = el1_pread64(&file, &task, cache.as_ptr(), user_va, 30, 100, &validator).unwrap();
        assert_eq!(n, 30);
        assert_eq!(file.offset.load(Ordering::Relaxed), 50);
        assert_eq!(&user_buf[0..30], &cache[100..130]);

        // Read past EOF
        file.offset.store(200, Ordering::Relaxed);
        let n = el1_read(&file, &task, cache.as_ptr(), user_va, 50, &validator).unwrap();
        assert_eq!(n, 0);

        // Pread negative offset -> EINVAL
        assert_eq!(
            el1_pread64(&file, &task, cache.as_ptr(), user_va, 30, -1, &validator),
            Ok(EINVAL)
        );
    }

    #[test]
    fn test_write_and_pwrite64_model() {
        let task = CurrentTask::new();
        let (file, mut cache) = fixture_file(0, 0, DELEGATED_FLAG_WRITABLE);
        let mut user_data = vec![0xABu8; 8192];
        let user_va = user_data.as_mut_ptr() as u64;
        let validator = FakeOracleValidator {
            writable_regions: vec![],
            readable_regions: vec![user_va..user_va + 8192],
        };

        // Write 4096 bytes: extends size from 0 to 4096, sets dirty bit 0
        let n = el1_write(&file, &task, cache.as_mut_ptr(), user_va, 4096, &validator).unwrap();
        assert_eq!(n, 4096);
        assert_eq!(file.size.load(Ordering::Relaxed), 4096);
        assert_eq!(file.offset.load(Ordering::Relaxed), 4096);
        assert_eq!(file.dirty_mask.load(Ordering::Relaxed), 1 << 0);
        assert_eq!(&cache[0..4096], &user_data[0..4096]);

        // Write another 4096 bytes: extends size from 4096 to 8192, sets dirty bit 1
        let n = el1_write(&file, &task, cache.as_mut_ptr(), user_va, 4096, &validator).unwrap();
        assert_eq!(n, 4096);
        assert_eq!(file.size.load(Ordering::Relaxed), 8192);
        assert_eq!(file.offset.load(Ordering::Relaxed), 8192);
        assert_eq!(file.dirty_mask.load(Ordering::Relaxed), (1 << 0) | (1 << 1));

        // Pwrite at offset 0 (does not change file offset 8192)
        let n = el1_pwrite64(
            &file,
            &task,
            cache.as_mut_ptr(),
            user_va,
            100,
            0,
            &validator,
        )
        .unwrap();
        assert_eq!(n, 100);
        assert_eq!(file.offset.load(Ordering::Relaxed), 8192);

        // Pwrite with negative offset -> EINVAL
        assert_eq!(
            el1_pwrite64(
                &file,
                &task,
                cache.as_mut_ptr(),
                user_va,
                100,
                -5,
                &validator
            ),
            Ok(EINVAL)
        );

        // Write beyond 256 KiB returns Action::Forward
        file.offset
            .store(DELEGATED_FILE_MAX_SIZE - 10, Ordering::Relaxed);
        assert_eq!(
            el1_write(&file, &task, cache.as_mut_ptr(), user_va, 100, &validator),
            Err(Action::Forward)
        );
    }

    #[test]
    fn test_efault_forward_semantics() {
        let task = CurrentTask::new();
        let (file, mut cache) = fixture_file(
            16384,
            8192,
            DELEGATED_FLAG_READABLE | DELEGATED_FLAG_WRITABLE,
        );
        for (i, byte) in cache.iter_mut().enumerate().take(16384) {
            *byte = (i % 251) as u8;
        }

        let mut user_buffer = vec![0u8; 8192];
        let user_va = user_buffer.as_mut_ptr() as u64;

        // Oracle: first 4096 bytes are writable, next 4096 bytes are denied/readonly
        let oracle = FakeOracleValidator {
            writable_regions: vec![user_va..user_va + 4096],
            readable_regions: vec![user_va..user_va + 4096],
        };

        // Read 8192 bytes into user_va: partial user range fails AT check.
        // EL1 must return Err(Action::Forward) without touching the file (no partial service).
        assert_eq!(
            el1_read(&file, &task, cache.as_ptr(), user_va, 8192, &oracle),
            Err(Action::Forward)
        );
        assert_eq!(file.offset.load(Ordering::Relaxed), 8192);

        // Read 4096 bytes: entire range is valid in AT check -> served at EL1!
        let n = el1_read(&file, &task, cache.as_ptr(), user_va, 4096, &oracle).unwrap();
        assert_eq!(n, 4096);
        assert_eq!(file.offset.load(Ordering::Relaxed), 8192 + 4096);
        assert_eq!(&user_buffer[0..4096], &cache[8192..8192 + 4096]);

        // Next read at readonly page: fails AT check -> Action::Forward, offset untouched.
        assert_eq!(
            el1_read(&file, &task, cache.as_ptr(), user_va + 4096, 4096, &oracle),
            Err(Action::Forward)
        );
        assert_eq!(file.offset.load(Ordering::Relaxed), 8192 + 4096);

        // Same for write: partial user range fails AT check -> Action::Forward, file untouched.
        file.offset.store(0, Ordering::Relaxed);
        assert_eq!(
            el1_write(&file, &task, cache.as_mut_ptr(), user_va, 8192, &oracle),
            Err(Action::Forward)
        );
        assert_eq!(file.offset.load(Ordering::Relaxed), 0);
        assert_eq!(file.size.load(Ordering::Relaxed), 16384);

        // Write 4096 bytes: entire range is readable in AT check -> served at EL1!
        let n = el1_write(&file, &task, cache.as_mut_ptr(), user_va, 4096, &oracle).unwrap();
        assert_eq!(n, 4096);
        assert_eq!(file.offset.load(Ordering::Relaxed), 4096);

        // Next write from denied address: fails AT check -> Action::Forward, offset untouched.
        assert_eq!(
            el1_write(
                &file,
                &task,
                cache.as_mut_ptr(),
                user_va + 4096,
                4096,
                &oracle
            ),
            Err(Action::Forward)
        );
        assert_eq!(file.offset.load(Ordering::Relaxed), 4096);
    }

    #[test]
    fn test_fixup_fault_interception() {
        let task = CurrentTask::new();
        let (file, mut cache) =
            fixture_file(4096, 0, DELEGATED_FLAG_READABLE | DELEGATED_FLAG_WRITABLE);
        let mut user_buffer = vec![0u8; 100];
        let user_va = user_buffer.as_mut_ptr() as u64;
        let oracle = FakeOracleValidator {
            writable_regions: vec![user_va..user_va + 100],
            readable_regions: vec![user_va..user_va + 100],
        };

        // When SIMULATE_COPY_FAULT is set (simulating concurrent unmap during copy):
        SIMULATE_COPY_FAULT.with(|f| f.store(true, Ordering::Relaxed));

        // Read must return Err(Action::Forward) and leave offset unchanged at 0
        assert_eq!(
            el1_read(&file, &task, cache.as_ptr(), user_va, 50, &oracle),
            Err(Action::Forward)
        );
        assert_eq!(file.offset.load(Ordering::Relaxed), 0);

        // Pread must return Err(Action::Forward) and leave offset unchanged
        assert_eq!(
            el1_pread64(&file, &task, cache.as_ptr(), user_va, 50, 0, &oracle),
            Err(Action::Forward)
        );
        assert_eq!(file.offset.load(Ordering::Relaxed), 0);

        // Write must return Err(Action::Forward) and leave offset/size/dirty_mask unchanged
        assert_eq!(
            el1_write(&file, &task, cache.as_mut_ptr(), user_va, 50, &oracle),
            Err(Action::Forward)
        );
        assert_eq!(file.offset.load(Ordering::Relaxed), 0);
        assert_eq!(file.size.load(Ordering::Relaxed), 4096);
        assert_eq!(file.dirty_mask.load(Ordering::Relaxed), 0);

        // Pwrite must return Err(Action::Forward) and leave offset/size/dirty_mask unchanged
        assert_eq!(
            el1_pwrite64(&file, &task, cache.as_mut_ptr(), user_va, 50, 0, &oracle),
            Err(Action::Forward)
        );
        assert_eq!(file.offset.load(Ordering::Relaxed), 0);
        assert_eq!(file.size.load(Ordering::Relaxed), 4096);
        assert_eq!(file.dirty_mask.load(Ordering::Relaxed), 0);

        // Clear fault simulation
        SIMULATE_COPY_FAULT.with(|f| f.store(false, Ordering::Relaxed));

        // Now read and write succeed
        let n = el1_read(&file, &task, cache.as_ptr(), user_va, 50, &oracle).unwrap();
        assert_eq!(n, 50);
        assert_eq!(file.offset.load(Ordering::Relaxed), 50);
    }

    #[test]
    fn test_write_extension_zeroes_hole() {
        let task = CurrentTask::new();
        let (file, mut cache) =
            fixture_file(10, 0, DELEGATED_FLAG_WRITABLE | DELEGATED_FLAG_READABLE);
        // Fill cache with non-zero garbage simulating previous file contents
        cache.fill(0xFE);

        let mut user_data = vec![b'x'];
        let user_va = user_data.as_mut_ptr() as u64;
        let validator = FakeOracleValidator {
            writable_regions: vec![],
            readable_regions: vec![user_va..user_va + 1],
        };

        // Pwrite at offset 8000: extends size from 10 to 8001
        let n = el1_pwrite64(
            &file,
            &task,
            cache.as_mut_ptr(),
            user_va,
            1,
            8000,
            &validator,
        )
        .unwrap();
        assert_eq!(n, 1);
        assert_eq!(file.size.load(Ordering::Relaxed), 8001);

        // Gap [10, 8000) must be zero-filled!
        for (i, &byte) in cache[10..8000].iter().enumerate() {
            assert_eq!(byte, 0, "byte at offset {} was not zeroed", 10 + i);
        }
        assert_eq!(cache[8000], b'x');
    }

    #[test]
    fn test_extension_gap_pages_tracked_in_zero_filled_mask() {
        let task = CurrentTask::new();
        let (file, mut cache) = fixture_file(0, 0, DELEGATED_FLAG_WRITABLE);
        let mut user_buf = vec![0x42u8; 128];
        let user_va = user_buf.as_mut_ptr() as u64;
        let validator = FakeOracleValidator {
            writable_regions: vec![user_va..user_va + 128],
            readable_regions: vec![user_va..user_va + 128],
        };

        // Write at offset 8192 (skipping 2 pages: page 0 and page 1)
        file.offset.store(8192, Ordering::Relaxed);
        let n = el1_write(&file, &task, cache.as_mut_ptr(), user_va, 128, &validator).unwrap();
        assert_eq!(n, 128);
        assert_eq!(file.offset.load(Ordering::Relaxed), 8192 + 128);
        assert_eq!(file.size.load(Ordering::Relaxed), 8192 + 128);

        // Page 0 and Page 1 must be in zero_filled_mask, NOT dirty_mask
        assert_eq!(
            file.zero_filled_mask.load(Ordering::Relaxed),
            (1 << 0) | (1 << 1)
        );
        assert_eq!(file.dirty_mask.load(Ordering::Relaxed), (1 << 2));

        // Now write into page 1: it must be removed from zero_filled_mask and added to dirty_mask!
        file.offset.store(4096, Ordering::Relaxed);
        let n = el1_write(&file, &task, cache.as_mut_ptr(), user_va, 64, &validator).unwrap();
        assert_eq!(n, 64);
        assert_eq!(file.zero_filled_mask.load(Ordering::Relaxed), (1 << 0));
        assert_eq!(file.dirty_mask.load(Ordering::Relaxed), (1 << 1) | (1 << 2));
    }
}
