//! File operations for delegated regular files at EL1.

use carrick_el1_abi::{
    CurrentTask, DELEGATED_FILE_MAX_SIZE, DELEGATED_FLAG_APPEND, DELEGATED_FLAG_READABLE,
    DELEGATED_FLAG_WRITABLE, DELEGATED_PAGE_SIZE, DELEGATED_STATE_GUEST, DelegatedFile,
    DelegatedInotify, DelegatedOpenFile, EL1_GUEST_LOCK_SPINS, MAX_DELEGATED_MARKS_PER_FILE,
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
        let fixup_ptr = &cur_task.linux.fixup_pc as *const _ as *const u64;
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
    #[cfg(not(target_os = "none"))]
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
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    {
        // SAFETY: `dest` is the guarded user operand and `src` is retained
        // kernel memory for the duration of the copy.
        unsafe { crate::isa::x86::user_access::copy(cur_task, dest, src, len, dest as u64, true) }
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
        let fixup_ptr = &cur_task.linux.fixup_pc as *const _ as *const u64;
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
    #[cfg(not(target_os = "none"))]
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
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    {
        // SAFETY: `src` is the guarded user operand and `dest` is retained
        // kernel memory for the duration of the copy.
        unsafe { crate::isa::x86::user_access::copy(cur_task, dest, src, len, src as u64, false) }
    }
}

/// Abstraction for validating user memory permissions before access.
pub trait MemoryValidator {
    /// Return the number of contiguous bytes from `user_va` that EL0 can write.
    fn writable_bytes(&self, user_va: u64, len: usize) -> usize;

    /// Return the number of contiguous bytes from `user_va` that EL0 can read.
    fn readable_bytes(&self, user_va: u64, len: usize) -> usize;
}

#[cfg(test)]
mod range_tests {
    use super::{HardwareValidator, MemoryValidator};

    #[test]
    fn hardware_validator_rejects_overflowing_and_upper_half_ranges() {
        let validator = HardwareValidator;
        assert_eq!(validator.readable_bytes(u64::MAX - 3, 8), 0);
        assert_eq!(validator.writable_bytes(u64::MAX - 3, 8), 0);
        assert_eq!(validator.readable_bytes(1 << 63, 1), 0);
        assert_eq!(validator.writable_bytes((1 << 63) - 4, 8), 0);
        assert_eq!(
            validator.readable_bytes(carrick_guest_arch::USER_CEILING - 4, 8),
            0
        );
        assert_eq!(
            validator.writable_bytes(carrick_guest_arch::USER_CEILING, 1),
            0
        );
    }
}

/// Reject an entire invalid user range before probing or copying any byte.
fn valid_lower_half_range(user_va: u64, len: usize) -> bool {
    let Ok(len) = u64::try_from(len) else {
        return false;
    };
    carrick_guest_arch::lower_half_range(user_va, len)
}

#[cfg(not(target_os = "none"))]
pub struct HardwareValidator;

#[cfg(not(target_os = "none"))]
impl MemoryValidator for HardwareValidator {
    fn writable_bytes(&self, user_va: u64, len: usize) -> usize {
        if valid_lower_half_range(user_va, len) {
            len
        } else {
            0
        }
    }

    fn readable_bytes(&self, user_va: u64, len: usize) -> usize {
        if valid_lower_half_range(user_va, len) {
            len
        } else {
            0
        }
    }
}

#[cfg(target_os = "none")]
pub struct HardwareValidator;

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
impl MemoryValidator for HardwareValidator {
    fn writable_bytes(&self, user_va: u64, len: usize) -> usize {
        if len == 0 || !valid_lower_half_range(user_va, len) {
            return 0;
        }
        let mut checked = 0;
        while checked < len {
            let cur_va = user_va + checked as u64; // range checked above
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
            let page_remaining = 4096 - (cur_va as usize & 4095);
            checked += core::cmp::min(len - checked, page_remaining);
        }
        checked
    }

    fn readable_bytes(&self, user_va: u64, len: usize) -> usize {
        if len == 0 || !valid_lower_half_range(user_va, len) {
            return 0;
        }
        let mut checked = 0;
        while checked < len {
            let cur_va = user_va + checked as u64; // range checked above
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
            let page_remaining = 4096 - (cur_va as usize & 4095);
            checked += core::cmp::min(len - checked, page_remaining);
        }
        checked
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl MemoryValidator for HardwareValidator {
    fn writable_bytes(&self, user_va: u64, len: usize) -> usize {
        if !valid_lower_half_range(user_va, len) {
            return 0;
        }
        crate::isa::x86::user_access::accessible_bytes(user_va, len, true)
    }
    fn readable_bytes(&self, user_va: u64, len: usize) -> usize {
        if !valid_lower_half_range(user_va, len) {
            return 0;
        }
        crate::isa::x86::user_access::accessible_bytes(user_va, len, false)
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

/// One open description of an in-zone inode, as the file operations see it:
/// the inode's bytes, size and dirty state, and this description's offset and
/// access flags (open(2): each open file description has its own offset; all
/// share the inode). The caller holds the inode's lock.
#[derive(Clone, Copy)]
pub struct ZoneFile<'a> {
    pub inode: &'a DelegatedFile,
    pub open: &'a DelegatedOpenFile,
}

/// Service `lseek` at EL1.
pub fn seek(zf: &ZoneFile<'_>, offset: i64, whence: SeekFrom) -> Result<i64, FileError> {
    let (file, open) = (zf.inode, zf.open);
    let cur_off = open.offset.load(Ordering::Acquire) as i64;
    let size = file.size.load(Ordering::Acquire) as i64;
    let target = match whence {
        SeekFrom::Start => offset,
        SeekFrom::Current => match cur_off.checked_add(offset) {
            Some(t) => t,
            None => return Err(FileError::OffsetOverflow),
        },
        SeekFrom::End => match size.checked_add(offset) {
            Some(t) => t,
            None => return Err(FileError::OffsetOverflow),
        },
    };
    if target < 0 {
        return Err(FileError::InvalidOffset);
    }
    open.offset.store(target as u64, Ordering::Release);
    Ok(target)
}

/// `read` on a delegated object, for any caller holding its lock.
///
/// # Safety
///
/// `cache_base` must point at this object's cache slot of
/// `DELEGATED_FILE_MAX_SIZE` bytes, and the caller must hold the object lock.
pub unsafe fn read_with(
    zf: &ZoneFile<'_>,
    cache_base: *const u8,
    buf_va: u64,
    count: usize,
    user: &mut impl UserCopy,
) -> Result<i64, FileError> {
    let (file, open) = (zf.inode, zf.open);
    let flags = open.flags.load(Ordering::Acquire);
    if (flags & DELEGATED_FLAG_READABLE) == 0 {
        return Err(FileError::AccessDenied);
    }
    if count == 0 {
        return Ok(0);
    }
    let cur_off = open.offset.load(Ordering::Acquire);
    // SAFETY: forwarded from the caller.
    let src = unsafe { resident_at(file, cache_base, cur_off, count) };
    if src.is_empty() {
        return Ok(0);
    }
    if !user.copy_out(buf_va, src) {
        return Err(FileError::Forward);
    }
    open.offset
        .store(cur_off + src.len() as u64, Ordering::Release);
    Ok(src.len() as i64)
}

/// `pread64` on a delegated object, for any caller holding its lock.
///
/// # Safety
///
/// As for [`read_with`].
pub unsafe fn pread64_with(
    zf: &ZoneFile<'_>,
    cache_base: *const u8,
    buf_va: u64,
    count: usize,
    offset: i64,
    user: &mut impl UserCopy,
) -> Result<i64, FileError> {
    let (file, open) = (zf.inode, zf.open);
    if offset < 0 {
        return Err(FileError::InvalidOffset);
    }
    let flags = open.flags.load(Ordering::Acquire);
    if (flags & DELEGATED_FLAG_READABLE) == 0 {
        return Err(FileError::AccessDenied);
    }
    if count == 0 {
        return Ok(0);
    }
    // SAFETY: forwarded from the caller.
    let src = unsafe { resident_at(file, cache_base, offset as u64, count) };
    if src.is_empty() {
        return Ok(0);
    }
    if !user.copy_out(buf_va, src) {
        return Err(FileError::Forward);
    }
    Ok(src.len() as i64)
}

/// The resident bytes at `offset`: at most `count`, none at or beyond EOF.
///
/// # Safety
///
/// As for [`read_with`]; the borrow ends before the object lock is released.
pub unsafe fn resident_at<'c>(
    file: &DelegatedFile,
    cache_base: *const u8,
    offset: u64,
    count: usize,
) -> &'c [u8] {
    let size = file.size.load(Ordering::Acquire);
    if offset >= size {
        return &[];
    }
    let avail = core::cmp::min(count, (size - offset) as usize);
    // SAFETY: [offset, offset + avail) lies below size <= the slot size.
    unsafe { core::slice::from_raw_parts(cache_base.add(offset as usize), avail) }
}

/// Where a positional store lands. `End` is selected from the size published
/// under the same object lock as the store, so concurrent appenders cannot
/// overwrite each other.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreAt {
    Offset(u64),
    End,
}

/// Store `count` bytes produced by `fill` at `at`, for any caller holding the
/// object lock. Returns the selected offset. A store past the resident slot is
/// `Forward`: the host owns bytes the zone cannot hold.
///
/// # Safety
///
/// As for [`read_with`].
pub unsafe fn store_with(
    file: &DelegatedFile,
    cache_base: *mut u8,
    at: StoreAt,
    count: usize,
    fill: impl FnOnce(&mut [u8]) -> bool,
) -> Result<u64, FileError> {
    let start = match at {
        StoreAt::Offset(offset) => offset,
        StoreAt::End => file.size.load(Ordering::Acquire),
    };
    if count == 0 {
        return Ok(start);
    }
    let Some(end) = start.checked_add(count as u64) else {
        return Err(FileError::OffsetOverflow);
    };
    if end > DELEGATED_FILE_MAX_SIZE {
        return Err(FileError::Forward);
    }
    // SAFETY: bounds checked above; the caller holds the lock.
    unsafe { store_at(file, cache_base, start, count, fill)? };
    Ok(start)
}

/// Copy `count` bytes from `fill` into the cache at `at`, zero any gap past
/// the old size, and publish size, dirty and zero-filled state.
///
/// # Safety
///
/// As for [`read_with`]; `at + count` must not exceed the slot size.
unsafe fn store_at(
    file: &DelegatedFile,
    cache_base: *mut u8,
    at: u64,
    count: usize,
    fill: impl FnOnce(&mut [u8]) -> bool,
) -> Result<u64, FileError> {
    // SAFETY: [at, at + count) lies inside the slot (checked by the caller).
    let dst = unsafe { core::slice::from_raw_parts_mut(cache_base.add(at as usize), count) };
    if !fill(dst) {
        return Err(FileError::Forward);
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
    zf: &ZoneFile<'_>,
    cache_base: *mut u8,
    buf_va: u64,
    count: usize,
    user: &mut impl UserCopy,
) -> Result<i64, FileError> {
    let (file, open) = (zf.inode, zf.open);
    let flags = open.flags.load(Ordering::Acquire);
    if (flags & DELEGATED_FLAG_WRITABLE) == 0 {
        return Err(FileError::AccessDenied);
    }
    if (flags & DELEGATED_FLAG_APPEND) != 0 {
        return Err(FileError::Forward);
    }
    if count == 0 {
        return Ok(0);
    }
    let cur_off = open.offset.load(Ordering::Acquire);
    let Some(end_off) = cur_off.checked_add(count as u64) else {
        return Err(FileError::Forward);
    };
    if end_off > DELEGATED_FILE_MAX_SIZE {
        return Err(FileError::Forward);
    }
    // SAFETY: bounds checked above; the caller holds the lock.
    let delivered_end = unsafe {
        store_at(file, cache_base, cur_off, count, |dst| {
            user.copy_in(dst, buf_va)
        })?
    };
    open.offset.store(delivered_end, Ordering::Release);
    Ok(count as i64)
}

/// `pwrite64` on a delegated object, for any caller holding its lock.
///
/// # Safety
///
/// As for [`read_with`].
pub unsafe fn pwrite64_with(
    zf: &ZoneFile<'_>,
    cache_base: *mut u8,
    buf_va: u64,
    count: usize,
    offset: i64,
    user: &mut impl UserCopy,
) -> Result<i64, FileError> {
    let (file, open) = (zf.inode, zf.open);
    if offset < 0 {
        return Err(FileError::InvalidOffset);
    }
    let flags = open.flags.load(Ordering::Acquire);
    if (flags & DELEGATED_FLAG_WRITABLE) == 0 {
        return Err(FileError::AccessDenied);
    }
    if count == 0 {
        return Ok(0);
    }
    let off = offset as u64;
    let Some(end_off) = off.checked_add(count as u64) else {
        return Err(FileError::Forward);
    };
    if end_off > DELEGATED_FILE_MAX_SIZE {
        return Err(FileError::Forward);
    }
    // SAFETY: bounds checked above; the caller holds the lock.
    unsafe {
        store_at(file, cache_base, off, count, |dst| {
            user.copy_in(dst, buf_va)
        })?
    };
    Ok(count as i64)
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

/// Failure of a delegated cache operation, before ABI result encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileError {
    Forward,
    AccessDenied,
    InvalidOffset,
    OffsetOverflow,
}
/// Origin for an offset calculation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeekFrom {
    Start,
    Current,
    End,
}

/// How a file operation acquires the watch instances that mark the inode.
/// The guest tries for a bounded spin budget and refuses if contended; the host
/// waits because it is the terminal fallback.
pub trait InstanceLockPolicy {
    fn acquire(&self, instance: &DelegatedInotify) -> bool;
}

/// Guest policy: take the watch instance lock only if it becomes free within
/// the bounded spin budget.
pub struct TryInstanceLock;

impl InstanceLockPolicy for TryInstanceLock {
    fn acquire(&self, instance: &DelegatedInotify) -> bool {
        instance.lock_guest_bounded(EL1_GUEST_LOCK_SPINS)
    }
}

/// Data notification event produced when a file operation moves bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileDataEvent {
    None,
    Access,
    Modify,
}

impl FileDataEvent {
    const fn mask(self) -> u32 {
        match self {
            Self::None => 0,
            Self::Access => 0x01,
            Self::Modify => 0x02,
        }
    }
}

/// Run `op` on a locked `file` while holding every watch instance that marks it
/// for `event`, then queue `event` on each matching watch if `op` moved bytes.
/// If any matching watch instance is not guest-resident, has spilled, or cannot
/// be locked under `locks`, releases any acquired locks and returns
/// `Err(unsupported)` before `op` runs.
pub fn with_data_marks<T, E: Copy>(
    file: &DelegatedFile,
    watches: &[DelegatedInotify],
    event: FileDataEvent,
    locks: &impl InstanceLockPolicy,
    unsupported: E,
    moved: impl FnOnce(&T) -> bool,
    op: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let mask = event.mask();
    let mut locked = [0u32; MAX_DELEGATED_MARKS_PER_FILE];
    let mut num_locked = 0;
    let mut lock_failed = false;
    if mask != 0 && file.has_marks() {
        file.for_each_mark(|m| {
            if lock_failed || m.inotify_handle == 0 {
                return;
            }
            if (m.mask & mask) == 0 || locked[..num_locked].contains(&m.inotify_handle) {
                return;
            }
            match watches.get((m.inotify_handle - 1) as usize) {
                Some(watch)
                    if watch.state.load(Ordering::Acquire) == DELEGATED_STATE_GUEST
                        && watch.spilled.load(Ordering::Acquire) == 0
                        && locks.acquire(watch) =>
                {
                    locked[num_locked] = m.inotify_handle;
                    num_locked += 1;
                }
                _ => lock_failed = true,
            }
        });
    }
    let release = |locked: &[u32]| {
        for &h in locked {
            if let Some(watch) = watches.get((h - 1) as usize) {
                watch.unlock();
            }
        }
    };
    if lock_failed {
        release(&locked[..num_locked]);
        return Err(unsupported);
    }
    let outcome = op();
    if mask != 0
        && let Ok(ref value) = outcome
        && moved(value)
    {
        file.for_each_mark(|m| {
            if (m.mask & mask) != 0
                && m.inotify_handle != 0
                && let Some(watch) = watches.get((m.inotify_handle - 1) as usize)
            {
                watch.push_record(m.wd, mask, 0, None);
            }
        });
    }
    release(&locked[..num_locked]);
    outcome
}
