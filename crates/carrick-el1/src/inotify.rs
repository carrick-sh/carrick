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
    if count < 16 {
        return Ok(-22); // -EINVAL
    }

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

    if validator.writable_bytes(buf_va, 16) < 16 {
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
            return Err(Action::Forward); // Host recalls and blocks
        }
    }

    let mut temp = [0u8; 512];
    let to_drain = count.min(temp.len());
    let drained = match inotify.drain_into(&mut temp[..to_drain]) {
        Ok(n) => n,
        Err(_) => {
            inotify.unlock();
            return Err(Action::Forward);
        }
    };
    inotify.unlock();

    let writable = validator.writable_bytes(buf_va, drained);
    if writable < drained {
        return Err(Action::Forward);
    }

    let ok = unsafe { copy_to_user_guarded(cur_task, buf_va as *mut u8, temp.as_ptr(), drained) };
    if !ok {
        return Err(Action::Forward);
    }
    Ok(drained as i64)
}
