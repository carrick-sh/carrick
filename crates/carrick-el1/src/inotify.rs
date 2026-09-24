//! In-guest inotify operations for delegated inotify instances at EL1.

use carrick_el1_abi::{
    Action, CurrentTask, DELEGATED_STATE_GUEST, DelegatedFile, DelegatedInotify, DelegatedMark,
    EL1_GUEST_LOCK_SPINS, FdMapSlot, InotifyNameCache, MAX_DELEGATED_FILES, MAX_DELEGATED_INOTIFY,
    MAX_NAME_CACHE_PATH_LEN, fd_map_lookup_inotify, hash_path,
};
use carrick_inotify_core::{
    LINUX_IN_DONT_FOLLOW, LINUX_IN_EXCL_UNLINK, LINUX_IN_IGNORED, LINUX_IN_MASK_ADD,
    LINUX_IN_MASK_CREATE, LINUX_IN_ONESHOT, LINUX_IN_ONLYDIR,
};
use core::sync::atomic::Ordering;

use crate::file::{MemoryValidator, copy_from_user_guarded, copy_to_user_guarded};

/// Non-blocking flag for inotify file descriptor (O_NONBLOCK = 04000 octal = 0x800).
pub const O_NONBLOCK: u32 = 0x0000_0800;

/// Unsupported mask flags in-guest that require host forwarding / recall.
pub const UNSUPPORTED_INOTIFY_MASK_FLAGS: u32 = LINUX_IN_MASK_ADD
    | LINUX_IN_MASK_CREATE
    | LINUX_IN_ONESHOT
    | LINUX_IN_EXCL_UNLINK
    | LINUX_IN_DONT_FOLLOW
    | LINUX_IN_ONLYDIR;

/// Service `inotify_add_watch(fd, pathname, mask)` (nr 27) at EL1.
#[allow(clippy::too_many_arguments)]
pub fn el1_inotify_add_watch(
    inotify_fd: i32,
    pathname_va: u64,
    mask: u32,
    cur_task: &CurrentTask,
    fd_map: &[FdMapSlot],
    object_table: &[DelegatedFile],
    inotify_table: &[DelegatedInotify],
    name_cache: &InotifyNameCache,
    validator: &impl MemoryValidator,
) -> Result<i64, Action> {
    // If mask includes unsupported modifier bits, forward to host
    if mask & UNSUPPORTED_INOTIFY_MASK_FLAGS != 0 {
        return Err(Action::Forward);
    }

    let file_table = cur_task.file_table.load(Ordering::Acquire);
    if file_table == 0 {
        return Err(Action::Forward);
    }

    // Read pathname from user memory
    let readable = validator.readable_bytes(pathname_va, MAX_NAME_CACHE_PATH_LEN);
    if readable == 0 {
        return Err(Action::Forward);
    }
    let mut path_buf = [0u8; MAX_NAME_CACHE_PATH_LEN];
    let to_copy = readable.min(MAX_NAME_CACHE_PATH_LEN);
    let ok = unsafe {
        copy_from_user_guarded(
            cur_task,
            path_buf.as_mut_ptr(),
            pathname_va as *const u8,
            to_copy,
        )
    };
    if !ok {
        return Err(Action::Forward);
    }

    // Find null terminator
    let mut path_len = None;
    for (i, &b) in path_buf[..to_copy].iter().enumerate() {
        if b == 0 {
            path_len = Some(i);
            break;
        }
    }
    let path_len = match path_len {
        Some(l) if l > 0 => l,
        _ => return Err(Action::Forward),
    };
    let path_bytes = &path_buf[..path_len];

    // Lookup path in inotify name cache
    let path_hash = hash_path(path_bytes);
    let target_file_handle = match name_cache.lookup(file_table, path_bytes, path_hash) {
        Some(h) if h > 0 && (h as usize) <= MAX_DELEGATED_FILES => h,
        _ => return Err(Action::Forward), // Cache miss => host resolves and populates
    };

    // Lookup inotify instance in fd_map
    let (inotify_handle, _) = match fd_map_lookup_inotify(fd_map, file_table, inotify_fd) {
        Some((h, idx)) if h > 0 && (h as usize) <= MAX_DELEGATED_INOTIFY => (h, idx),
        _ => return Err(Action::Forward),
    };

    let inotify = match inotify_table.get((inotify_handle - 1) as usize) {
        Some(ino) if ino.state.load(Ordering::Acquire) == DELEGATED_STATE_GUEST => ino,
        _ => return Err(Action::Forward),
    };

    let file = match object_table.get((target_file_handle - 1) as usize) {
        Some(f) if f.state.load(Ordering::Acquire) == DELEGATED_STATE_GUEST => f,
        _ => return Err(Action::Forward),
    };

    // Lock hierarchy: file lock first, then inotify lock (bounded retry before forward)
    let file_locked = file.lock_guest_bounded(EL1_GUEST_LOCK_SPINS);
    if !file_locked {
        return Err(Action::Forward);
    }

    let inotify_locked = inotify.lock_guest_bounded(EL1_GUEST_LOCK_SPINS);
    if !inotify_locked {
        file.unlock();
        return Err(Action::Forward);
    }

    // Check if watch already exists on this inotify instance for this file
    let mut existing_wd = None;
    let watches = unsafe { &mut *inotify.watches.get() };
    for w in watches.iter_mut() {
        if w.alive != 0 && w.file_handle == target_file_handle {
            w.mask = mask;
            existing_wd = Some(w.wd);
            break;
        }
    }

    let res = if let Some(wd) = existing_wd {
        file.add_mark(DelegatedMark {
            inotify_handle,
            wd,
            mask,
            _pad: 0,
        });
        Ok(wd as i64)
    } else {
        match inotify.alloc_wd() {
            Ok(wd) => {
                if inotify.add_watch(wd, target_file_handle, mask) {
                    file.add_mark(DelegatedMark {
                        inotify_handle,
                        wd,
                        mask,
                        _pad: 0,
                    });
                    Ok(wd as i64)
                } else {
                    Err(Action::Forward)
                }
            }
            Err(_) => Err(Action::Forward),
        }
    };

    inotify.unlock();
    file.unlock();
    res
}

/// Service `inotify_rm_watch(fd, wd)` (nr 28) at EL1.
pub fn el1_inotify_rm_watch(
    inotify_fd: i32,
    wd: i32,
    cur_task: &CurrentTask,
    fd_map: &[FdMapSlot],
    object_table: &[DelegatedFile],
    inotify_table: &[DelegatedInotify],
) -> Result<i64, Action> {
    let file_table = cur_task.file_table.load(Ordering::Acquire);
    if file_table == 0 {
        return Err(Action::Forward);
    }

    // Lookup inotify instance in fd_map
    let (inotify_handle, _) = match fd_map_lookup_inotify(fd_map, file_table, inotify_fd) {
        Some((h, idx)) if h > 0 && (h as usize) <= MAX_DELEGATED_INOTIFY => (h, idx),
        _ => return Err(Action::Forward),
    };

    let inotify = match inotify_table.get((inotify_handle - 1) as usize) {
        Some(ino) if ino.state.load(Ordering::Acquire) == DELEGATED_STATE_GUEST => ino,
        _ => return Err(Action::Forward),
    };

    // Optimistically inspect wd. If not found in-guest, forward to host to inspect host model.
    let target_file_handle = match inotify.find_watch(wd) {
        Some((_, w)) => w.file_handle,
        None => return Err(Action::Forward),
    };

    if target_file_handle == 0 || (target_file_handle as usize) > MAX_DELEGATED_FILES {
        return Err(Action::Forward);
    }

    let file = match object_table.get((target_file_handle - 1) as usize) {
        Some(f) if f.state.load(Ordering::Acquire) == DELEGATED_STATE_GUEST => f,
        _ => return Err(Action::Forward),
    };

    // Lock hierarchy: file lock first, then inotify lock (bounded retry before forward)
    let file_locked = file.lock_guest_bounded(EL1_GUEST_LOCK_SPINS);
    if !file_locked {
        return Err(Action::Forward);
    }

    let inotify_locked = inotify.lock_guest_bounded(EL1_GUEST_LOCK_SPINS);
    if !inotify_locked {
        file.unlock();
        return Err(Action::Forward);
    }

    // Re-verify under locks
    let watch_matches = match inotify.find_watch(wd) {
        Some((_, w)) => w.file_handle == target_file_handle,
        None => false,
    };
    if !watch_matches {
        inotify.unlock();
        file.unlock();
        return Err(Action::Forward);
    }

    // Remove mark from file
    file.remove_mark(inotify_handle, wd);
    // Remove watch from inotify
    inotify.remove_watch(wd);
    // Push IN_IGNORED as last event for this wd
    inotify.push_record(wd, LINUX_IN_IGNORED, 0, None);

    inotify.unlock();
    file.unlock();
    Ok(0)
}

/// Service `read(inotify_fd, buf, count)` (nr 63) on a delegated inotify instance at EL1.
pub fn el1_inotify_read(
    inotify_fd: i32,
    buf_va: u64,
    count: usize,
    cur_task: &CurrentTask,
    fd_map: &[FdMapSlot],
    inotify_table: &[DelegatedInotify],
    validator: &impl MemoryValidator,
) -> Result<i64, Action> {
    let file_table = cur_task.file_table.load(Ordering::Acquire);
    if file_table == 0 {
        return Err(Action::Forward);
    }

    let (inotify_handle, _) = match fd_map_lookup_inotify(fd_map, file_table, inotify_fd) {
        Some((h, idx)) if h > 0 && (h as usize) <= MAX_DELEGATED_INOTIFY => (h, idx),
        _ => return Err(Action::Forward),
    };

    let inotify = match inotify_table.get((inotify_handle - 1) as usize) {
        Some(ino) if ino.state.load(Ordering::Acquire) == DELEGATED_STATE_GUEST => ino,
        _ => return Err(Action::Forward),
    };

    // A buffer too small for one event is the host's to answer: Linux blocks
    // or returns EAGAIN on an empty queue and EINVAL only when the next event
    // does not fit. This check must follow the fd lookup, since `read` falls
    // back to this path for every fd that is not an in-zone file.
    if count < 16 {
        return Err(Action::Forward);
    }

    if validator.writable_bytes(buf_va, 16) < 16 {
        return Err(Action::Forward);
    }

    // A host spill holds records queued after the zone's, in order: the host
    // serves reads until it drains (and refills the zone).
    if inotify.spilled.load(Ordering::Acquire) != 0 {
        return Err(Action::Forward);
    }

    if !inotify.lock_guest_bounded(EL1_GUEST_LOCK_SPINS) {
        return Err(Action::Forward);
    }

    if !inotify.has_records() {
        inotify.unlock();
        let flags = inotify.flags.load(Ordering::Relaxed);
        if flags & O_NONBLOCK != 0 {
            return Ok(-11); // -EAGAIN
        } else {
            return Err(Action::Forward); // The host blocks.
        }
    }

    // Validate the whole destination before consuming anything: a record
    // drained from the queue must reach the guest or not leave the queue.
    let want = count.min(inotify.queued_bytes.load(Ordering::Acquire));
    if validator.writable_bytes(buf_va, want) < want {
        inotify.unlock();
        return Err(Action::Forward);
    }

    // Return every whole record that fits `count` (inotify(7)), staged through
    // a bounded buffer that holds at least one maximal record.
    let mut temp = [0u8; 512];
    let mut copied = 0usize;
    while copied < count && inotify.has_records() {
        let room = (count - copied).min(temp.len());
        let drained = match inotify.drain_into(&mut temp[..room]) {
            Ok(0) => break,
            Ok(n) => n,
            // The next record does not fit what is left: a short read, or
            // (nothing copied) the host's exact EINVAL.
            Err(_) if copied > 0 => break,
            Err(_) => {
                inotify.unlock();
                return Err(Action::Forward);
            }
        };
        // SAFETY: `buf_va + copied .. + drained` lies inside the range
        // validated above; a concurrent unmap faults into the fixup.
        let ok = unsafe {
            copy_to_user_guarded(
                cur_task,
                (buf_va + copied as u64) as *mut u8,
                temp.as_ptr(),
                drained,
            )
        };
        if !ok {
            // The records are consumed, as Linux consumes an event whose copy
            // faults: report what reached the guest, or EFAULT.
            inotify.unlock();
            return Ok(if copied > 0 { copied as i64 } else { -14 });
        }
        copied += drained;
    }
    inotify.unlock();
    Ok(copied as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_el1_abi::El1TaskId;

    struct AllWritable;

    impl MemoryValidator for AllWritable {
        fn writable_bytes(&self, _user_va: u64, len: usize) -> usize {
            len
        }

        fn readable_bytes(&self, _user_va: u64, len: usize) -> usize {
            len
        }
    }

    fn live_instance(fd_map: &[FdMapSlot], table: u64, fd: i32) -> DelegatedInotify {
        let instance = DelegatedInotify::new();
        instance
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Release);
        instance.flags.store(O_NONBLOCK, Ordering::Release);
        fd_map[0].file_table.store(table, Ordering::Relaxed);
        fd_map[0].fd.store(fd as u32, Ordering::Relaxed);
        fd_map[0].handle.store(
            carrick_el1_abi::FD_HANDLE_INOTIFY_TAG | 1,
            Ordering::Relaxed,
        );
        fd_map[0].incarnation.store(1, Ordering::Release);
        instance
    }

    /// A buffer whose first record's worth of bytes is mapped and the rest is
    /// not.
    struct OneRecordWritable;

    impl MemoryValidator for OneRecordWritable {
        fn writable_bytes(&self, _user_va: u64, len: usize) -> usize {
            len.min(16)
        }

        fn readable_bytes(&self, _user_va: u64, len: usize) -> usize {
            len.min(16)
        }
    }

    #[test]
    fn a_large_read_returns_every_whole_record_that_fits() {
        extern crate std;
        let fd_map = [FdMapSlot::new(), FdMapSlot::new()];
        let task = CurrentTask::new();
        task.set(El1TaskId::from_linux_tid(1), 1, 7);
        let instance = std::boxed::Box::new(live_instance(&fd_map, 7, 4));
        for wd in 1..=128 {
            let _ = instance.push_record(wd, 0x8000, 0, None);
        }
        let table = core::slice::from_ref(&*instance);
        let mut buf = std::vec![0u8; 65536];
        let got = el1_inotify_read(
            4,
            buf.as_mut_ptr() as u64,
            buf.len(),
            &task,
            &fd_map,
            table,
            &AllWritable,
        );
        assert_eq!(got, Ok(128 * 16));
        assert_eq!(
            i32::from_ne_bytes([
                buf[127 * 16],
                buf[127 * 16 + 1],
                buf[127 * 16 + 2],
                buf[127 * 16 + 3]
            ]),
            128
        );
        assert!(!instance.has_records());
    }

    #[test]
    fn an_unwritable_buffer_forwards_without_consuming_records() {
        extern crate std;
        let fd_map = [FdMapSlot::new(), FdMapSlot::new()];
        let task = CurrentTask::new();
        task.set(El1TaskId::from_linux_tid(1), 1, 7);
        let instance = std::boxed::Box::new(live_instance(&fd_map, 7, 4));
        let _ = instance.push_record(1, 0x2, 0, None);
        let _ = instance.push_record(2, 0x2, 0, None);
        let table = core::slice::from_ref(&*instance);
        assert_eq!(
            el1_inotify_read(4, 0x1000, 64, &task, &fd_map, table, &OneRecordWritable),
            Err(Action::Forward)
        );
        // Both records are still queued for the host to deliver exactly.
        assert_eq!(instance.queued_bytes.load(Ordering::Acquire), 32);
    }

    #[test]
    fn a_spilled_instance_forwards_reads_to_the_host() {
        extern crate std;
        let fd_map = [FdMapSlot::new(), FdMapSlot::new()];
        let task = CurrentTask::new();
        task.set(El1TaskId::from_linux_tid(1), 1, 7);
        let instance = std::boxed::Box::new(live_instance(&fd_map, 7, 4));
        instance.spilled.store(1, Ordering::Release);
        let table = core::slice::from_ref(&*instance);
        let mut buf = [0u8; 64];
        assert_eq!(
            el1_inotify_read(
                4,
                buf.as_mut_ptr() as u64,
                buf.len(),
                &task,
                &fd_map,
                table,
                &AllWritable
            ),
            Err(Action::Forward)
        );
    }

    /// `read` falls back to the inotify path for every fd that is not an
    /// in-zone file. A short read of a pipe, tty or synthetic file is not an
    /// inotify read and must forward, never fail with inotify's EINVAL.
    #[test]
    fn a_short_read_of_a_non_inotify_fd_forwards() {
        let task = CurrentTask::new();
        task.set(El1TaskId::from_linux_tid(1), 1, 7);
        for count in [1usize, 4, 15, 16, 64] {
            assert_eq!(
                el1_inotify_read(3, 0x1000, count, &task, &[], &[], &AllWritable),
                Err(Action::Forward),
                "count={count}"
            );
        }
    }
}
