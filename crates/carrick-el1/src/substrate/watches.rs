//! Bounded watch-table mutation. Event bits are supplied by the caller.
use carrick_el1_abi::{
    Action, DelegatedFile, DelegatedInotify, DelegatedMark, EL1_GUEST_LOCK_SPINS,
};
pub fn add<'a>(
    access: super::file_notification::FileAccess<'a>,
    file: &'a DelegatedFile,
    instance: &DelegatedInotify,
    inotify_handle: u32,
    target_file_handle: u32,
    mask: u32,
) -> Result<i64, Action> {
    // Lock hierarchy: file lock first, then instance lock (bounded retry before forward)
    let Some(file_guard) = access.lock(file, target_file_handle) else {
        return Err(Action::Forward);
    };

    let inotify_locked = instance.lock_guest_bounded(EL1_GUEST_LOCK_SPINS);
    if !inotify_locked {
        drop(file_guard);
        return Err(Action::Forward);
    }

    // Check if watch already exists on this instance instance for this file
    let mut existing_wd = None;
    let watches = unsafe { &mut *instance.watches.get() };
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
        match instance.alloc_wd() {
            Ok(wd) => {
                if instance.add_watch(wd, target_file_handle, mask) {
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

    instance.unlock();
    drop(file_guard);
    res
}
pub fn remove<'a>(
    access: super::file_notification::FileAccess<'a>,
    file: &'a DelegatedFile,
    instance: &DelegatedInotify,
    inotify_handle: u32,
    target_file_handle: u32,
    wd: i32,
    removed_event: u32,
) -> Result<i64, Action> {
    // Lock hierarchy: file lock first, then instance lock (bounded retry before forward)
    let Some(file_guard) = access.lock(file, target_file_handle) else {
        return Err(Action::Forward);
    };

    let inotify_locked = instance.lock_guest_bounded(EL1_GUEST_LOCK_SPINS);
    if !inotify_locked {
        drop(file_guard);
        return Err(Action::Forward);
    }

    // Re-verify under locks
    let watch_matches = match instance.find_watch(wd) {
        Some((_, w)) => w.file_handle == target_file_handle,
        None => false,
    };
    if !watch_matches {
        instance.unlock();
        drop(file_guard);
        return Err(Action::Forward);
    }

    // Remove mark from file
    file.remove_mark(inotify_handle, wd);
    // Remove watch from instance
    instance.remove_watch(wd);
    // Push IN_IGNORED as last event for this wd
    instance.push_record(wd, removed_event, 0, None);

    instance.unlock();
    drop(file_guard);
    Ok(0)
}
