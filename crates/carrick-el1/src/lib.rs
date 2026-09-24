//! Carrick in-guest EL1 kernel foundation.
//!
//! Provides the entry point, dispatch logic, and foundations for in-guest
//! execution at EL1.

#![cfg_attr(target_os = "none", no_std)]

pub mod alloc;
pub mod file;
pub mod inotify;
pub mod lock;

use carrick_el1_abi::{
    Action, Counters, CurrentTask, DELEGATED_STATE_GUEST, DelegatedFile, DelegatedInotify,
    DelegatedOpenFile, EL1_GUEST_LOCK_SPINS, FdMapSlot, InotifyNameCache, MAX_DELEGATED_FILES,
    MAX_DELEGATED_MARKS_PER_FILE, MAX_ZONE_OPEN_FILES, TrapFrame, fd_map_lookup,
};
#[cfg(target_os = "none")]
use carrick_el1_abi::{
    EL1_CURRENT_TASKS_BASE, EL1_FD_MAP_BASE, EL1_INOTIFY_TABLE_BASE, EL1_NAME_CACHE_BASE,
    EL1_OBJECT_TABLE_BASE, EL1_OPEN_FILE_TABLE_BASE, EL1_STACK_SLOTS, FD_MAP_CAPACITY,
    MAX_DELEGATED_INOTIFY,
};
use core::sync::atomic::Ordering;

/// The shared-record layout this image was built against; the image header
/// points at it and the host refuses an image whose value differs
/// (`carrick_el1_abi::check_image_abi`).
#[unsafe(no_mangle)]
#[used]
pub static CARRICK_EL1_ABI_HASH: u64 = carrick_el1_abi::EL1_ABI_LAYOUT_HASH;

/// Dispatch an in-guest Linux syscall at EL1.
pub fn dispatch_syscall(frame: &mut TrapFrame, counters: &Counters) -> Action {
    #[cfg(target_os = "none")]
    {
        let current_tasks =
            unsafe { &*(EL1_CURRENT_TASKS_BASE as *const [CurrentTask; EL1_STACK_SLOTS as usize]) };
        let fd_map = unsafe { &*(EL1_FD_MAP_BASE as *const [FdMapSlot; FD_MAP_CAPACITY]) };
        let object_table =
            unsafe { &*(EL1_OBJECT_TABLE_BASE as *const [DelegatedFile; MAX_DELEGATED_FILES]) };
        let open_table = unsafe {
            &*(EL1_OPEN_FILE_TABLE_BASE as *const [DelegatedOpenFile; MAX_ZONE_OPEN_FILES])
        };
        let inotify_table = unsafe {
            &*(EL1_INOTIFY_TABLE_BASE as *const [DelegatedInotify; MAX_DELEGATED_INOTIFY])
        };
        let name_cache = unsafe { &*(EL1_NAME_CACHE_BASE as *const InotifyNameCache) };
        dispatch_syscall_with_regions(
            frame,
            counters,
            current_tasks,
            fd_map,
            object_table,
            open_table,
            inotify_table,
            name_cache,
            |handle| carrick_el1_abi::delegated_file_cache_va(handle) as *mut u8,
        )
    }
    #[cfg(not(target_os = "none"))]
    {
        let nr = frame.x[8] as usize;
        if nr < 512 {
            counters.forwarded[nr].fetch_add(1, Ordering::Relaxed);
        }
        Action::Forward
    }
}

/// Dispatch syscall with explicitly supplied tables (used at EL1 and for host tests).
#[allow(clippy::too_many_arguments)]
pub fn dispatch_syscall_with_regions<F>(
    frame: &mut TrapFrame,
    counters: &Counters,
    current_tasks: &[CurrentTask],
    fd_map: &[FdMapSlot],
    object_table: &[DelegatedFile],
    open_table: &[DelegatedOpenFile],
    inotify_table: &[DelegatedInotify],
    name_cache: &InotifyNameCache,
    cache_lookup: F,
) -> Action
where
    F: Fn(u32) -> *mut u8,
{
    let slot = frame.slot as usize;
    let cur_task = current_tasks.get(slot);

    // Entry check: if pending_host_work is set, forward immediately without serving.
    if let Some(task) = cur_task
        && task.has_pending_host_work()
    {
        let nr = frame.x[8] as usize;
        if nr < 512 {
            counters.forwarded[nr].fetch_add(1, Ordering::Relaxed);
        }
        return Action::Forward;
    }

    let nr = frame.x[8] as usize;
    match nr {
        27 => {
            let orig_x0 = frame.x[0];
            if let Some(task) = cur_task {
                let validator = file::HardwareValidator;
                if let Ok(res) = inotify::el1_inotify_add_watch(
                    frame.x[0] as i32,
                    frame.x[1],
                    frame.x[2] as u32,
                    task,
                    fd_map,
                    object_table,
                    inotify_table,
                    name_cache,
                    &validator,
                ) {
                    frame.x[0] = res as u64;
                    counters.served[27].fetch_add(1, Ordering::Relaxed);
                    task.orig_arg0.store(orig_x0, Ordering::Relaxed);
                    if task.has_pending_host_work() {
                        task.served_with_work.store(1, Ordering::Release);
                        return Action::ServedWithWork;
                    }
                    return Action::Served;
                }
            }
        }
        28 => {
            let orig_x0 = frame.x[0];
            if let Some(task) = cur_task
                && let Ok(res) = inotify::el1_inotify_rm_watch(
                    frame.x[0] as i32,
                    frame.x[1] as i32,
                    task,
                    fd_map,
                    object_table,
                    inotify_table,
                )
            {
                frame.x[0] = res as u64;
                counters.served[28].fetch_add(1, Ordering::Relaxed);
                task.orig_arg0.store(orig_x0, Ordering::Relaxed);
                claim_owed_inotify_wake(task, inotify_table);
                if task.has_pending_host_work() {
                    task.served_with_work.store(1, Ordering::Release);
                    return Action::ServedWithWork;
                }
                return Action::Served;
            }
        }
        63 => {
            let orig_x0 = frame.x[0];
            let res = try_serve_file_syscall(
                frame,
                nr,
                current_tasks,
                fd_map,
                object_table,
                open_table,
                inotify_table,
                &cache_lookup,
            )
            .or_else(|| {
                if let Some(task) = cur_task {
                    let validator = file::HardwareValidator;
                    inotify::el1_inotify_read(
                        frame.x[0] as i32,
                        frame.x[1],
                        frame.x[2] as usize,
                        task,
                        fd_map,
                        inotify_table,
                        &validator,
                    )
                    .ok()
                } else {
                    None
                }
            });
            if let Some(res) = res {
                frame.x[0] = res as u64;
                counters.served[63].fetch_add(1, Ordering::Relaxed);
                if let Some(task) = cur_task {
                    task.orig_arg0.store(orig_x0, Ordering::Relaxed);
                    claim_owed_inotify_wake(task, inotify_table);
                    if task.has_pending_host_work() {
                        task.served_with_work.store(1, Ordering::Release);
                        return Action::ServedWithWork;
                    }
                }
                return Action::Served;
            }
        }
        62 | 64 | 67 | 68 => {
            let orig_x0 = frame.x[0];
            if let Some(res) = try_serve_file_syscall(
                frame,
                nr,
                current_tasks,
                fd_map,
                object_table,
                open_table,
                inotify_table,
                &cache_lookup,
            ) {
                frame.x[0] = res as u64;
                if nr < 512 {
                    counters.served[nr].fetch_add(1, Ordering::Relaxed);
                }
                if let Some(task) = cur_task {
                    task.orig_arg0.store(orig_x0, Ordering::Relaxed);
                    if matches!(nr, 63 | 64 | 67 | 68) {
                        claim_owed_inotify_wake(task, inotify_table);
                    }
                    if task.has_pending_host_work() {
                        task.served_with_work.store(1, Ordering::Release);
                        return Action::ServedWithWork;
                    }
                }
                return Action::Served;
            }
        }
        _ => {}
    }

    if nr < 512 {
        counters.forwarded[nr].fetch_add(1, Ordering::Relaxed);
    }
    Action::Forward
}

/// An in-guest enqueue that owes a host waiter a wake cannot deliver it
/// from EL1: return through the host boundary, which delivers it.
#[inline]
fn claim_owed_inotify_wake(task: &CurrentTask, inotify_table: &[DelegatedInotify]) {
    if inotify_table.iter().any(DelegatedInotify::wake_is_owed) {
        task.mark_pending_host_work();
    }
}

#[allow(clippy::too_many_arguments)]
fn try_serve_file_syscall<F>(
    frame: &TrapFrame,
    nr: usize,
    current_tasks: &[CurrentTask],
    fd_map: &[FdMapSlot],
    object_table: &[DelegatedFile],
    open_table: &[DelegatedOpenFile],
    inotify_table: &[DelegatedInotify],
    cache_lookup: &F,
) -> Option<i64>
where
    F: Fn(u32) -> *mut u8,
{
    let slot = frame.slot as usize;
    let cur_task = current_tasks.get(slot)?;
    let file_table = cur_task.file_table.load(Ordering::Acquire);
    if file_table == 0 {
        return None;
    }
    let fd = frame.x[0] as i32;
    // fd -> open file (this description's offset and flags) -> inode (bytes).
    let (handle, slot_idx) = fd_map_lookup(fd_map, file_table, fd)?;
    if handle == 0 || handle as usize > MAX_ZONE_OPEN_FILES {
        return None;
    }
    let open = open_table.get((handle - 1) as usize)?;
    let inode_handle = open.inode_handle.load(Ordering::Acquire);
    if inode_handle == 0 || inode_handle as usize > MAX_DELEGATED_FILES {
        return None;
    }
    let file = object_table.get((inode_handle - 1) as usize)?;
    if file.state.load(Ordering::Acquire) != DELEGATED_STATE_GUEST {
        return None;
    }
    if !file.lock_guest_bounded(EL1_GUEST_LOCK_SPINS) {
        return None;
    }
    // Re-validate the fd-map slot, the open file and its inode under the
    // inode's lock (which also guards the open-file record).
    let map_slot = fd_map.get(slot_idx)?;
    let slot_incarnation = map_slot.incarnation.load(Ordering::Acquire);
    if slot_incarnation == 0
        || map_slot.handle.load(Ordering::Relaxed) != handle
        || map_slot.fd.load(Ordering::Relaxed) != fd as u32
        || map_slot.file_table.load(Ordering::Relaxed) != file_table
        || slot_incarnation != open.generation.load(Ordering::Acquire)
        || open.inode_handle.load(Ordering::Acquire) != inode_handle
        || !open.is_bound_to(file)
    {
        file.unlock();
        return None;
    }

    let cache_ptr = cache_lookup(inode_handle);
    let mut user = file::ValidatedCopy {
        task: cur_task,
        validator: &file::HardwareValidator,
    };
    let args = [frame.x[1], frame.x[2], frame.x[3]];
    let zone_file = file::ZoneFile { inode: file, open };
    // SAFETY: the inode is locked and revalidated; `cache_ptr` is its slot.
    let outcome = unsafe {
        serve_locked_file_op(
            &zone_file,
            inotify_table,
            nr,
            args,
            cache_ptr,
            &mut user,
            &TryInstanceLock,
        )
    };
    file.unlock();
    outcome.ok()
}

/// How the caller acquires the inotify instances that mark a file it is
/// writing. EL1 never waits (a busy instance forwards the syscall); the host
/// waits, because it has nowhere else to send the operation.
pub trait InstanceLockPolicy {
    fn acquire(&self, instance: &DelegatedInotify) -> bool;
}

/// EL1: take the instance lock only if it is free.
pub struct TryInstanceLock;

impl InstanceLockPolicy for TryInstanceLock {
    fn acquire(&self, instance: &DelegatedInotify) -> bool {
        instance.lock_guest_bounded(EL1_GUEST_LOCK_SPINS)
    }
}

/// Serve one read, write, lseek, pread64 or pwrite64 on a delegated file whose
/// object lock the caller holds, running the single implementation shared by
/// EL1 and the host: lock the marking inotify instances for a write, run the
/// operation, count it, queue IN_MODIFY for each marking watch, release the
/// instances. `args` are the syscall's x1..x3. `Err(Action::Forward)` means
/// this caller cannot serve it exactly (EL1 forwards; the host recalls).
///
/// # Safety
///
/// The caller holds `file`'s lock, has revalidated it as live, and
/// `cache_ptr` is its cache slot.
pub unsafe fn serve_locked_file_op(
    zone_file: &file::ZoneFile<'_>,
    inotify_table: &[DelegatedInotify],
    nr: usize,
    args: [u64; 3],
    cache_ptr: *mut u8,
    user: &mut impl file::UserCopy,
    locks: &impl InstanceLockPolicy,
) -> Result<i64, Action> {
    let file = zone_file.inode;
    // The data event this operation produces on a marking watch: IN_MODIFY
    // for a write, IN_ACCESS for a read (inotify(7)), each only when bytes
    // moved.
    let event: u32 = match nr {
        64 | 68 => 0x02, // LINUX_IN_MODIFY
        63 | 67 => 0x01, // LINUX_IN_ACCESS
        _ => 0,
    };
    let mut locked = [0u32; MAX_DELEGATED_MARKS_PER_FILE];
    let mut num_locked = 0;
    let mut lock_failed = false;
    if event != 0 && file.has_marks() {
        file.for_each_mark(|m| {
            if lock_failed
                || (m.mask & event) == 0
                || m.inotify_handle == 0
                || locked[..num_locked].contains(&m.inotify_handle)
            {
                return;
            }
            match inotify_table.get((m.inotify_handle - 1) as usize) {
                Some(ino)
                    if ino.state.load(Ordering::Acquire) == DELEGATED_STATE_GUEST
                        && ino.spilled.load(Ordering::Acquire) == 0
                        && locks.acquire(ino) =>
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
            if let Some(ino) = inotify_table.get((h - 1) as usize) {
                ino.unlock();
            }
        }
    };
    if lock_failed {
        release(&locked[..num_locked]);
        return Err(Action::Forward);
    }
    // SAFETY: forwarded from the caller's contract.
    let outcome = unsafe {
        match nr {
            62 => file::el1_lseek(zone_file, args[0] as i64, args[1] as u32),
            63 => file::read_with(zone_file, cache_ptr, args[0], args[1] as usize, user),
            64 => file::write_with(zone_file, cache_ptr, args[0], args[1] as usize, user),
            67 => file::pread64_with(
                zone_file,
                cache_ptr,
                args[0],
                args[1] as usize,
                args[2] as i64,
                user,
            ),
            68 => file::pwrite64_with(
                zone_file,
                cache_ptr,
                args[0],
                args[1] as usize,
                args[2] as i64,
                user,
            ),
            _ => Err(Action::Forward),
        }
    };
    if event != 0
        && let Ok(moved) = outcome
        && moved > 0
    {
        file.for_each_mark(|m| {
            if (m.mask & event) != 0
                && m.inotify_handle != 0
                && let Some(ino) = inotify_table.get((m.inotify_handle - 1) as usize)
            {
                ino.push_record(m.wd, event, 0, None);
            }
        });
    }
    release(&locked[..num_locked]);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering;

    #[test]
    fn test_dispatch_forwards_all_and_counts() {
        let mut frame = TrapFrame::default();
        let counters = Counters::default();

        frame.x[8] = 64; // write
        let action = dispatch_syscall(&mut frame, &counters);
        assert_eq!(action, Action::Forward);
        assert_eq!(counters.forwarded[64].load(Ordering::Relaxed), 1);
        assert_eq!(counters.served[64].load(Ordering::Relaxed), 0);

        frame.x[8] = 172; // getpid
        let action = dispatch_syscall(&mut frame, &counters);
        assert_eq!(action, Action::Forward);
        assert_eq!(counters.forwarded[172].load(Ordering::Relaxed), 1);
        assert_eq!(counters.forwarded[64].load(Ordering::Relaxed), 1);

        // Out-of-bounds syscall nr
        frame.x[8] = 999;
        let action = dispatch_syscall(&mut frame, &counters);
        assert_eq!(action, Action::Forward);
    }

    #[test]
    fn test_concurrent_dispatch_increments() {
        extern crate std;
        let counters = Counters::default();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    let mut frame = TrapFrame::default();
                    frame.x[8] = 64; // write
                    for _ in 0..1000 {
                        let action = dispatch_syscall(&mut frame, &counters);
                        assert_eq!(action, Action::Forward);
                    }
                });
            }
        });

        assert_eq!(counters.forwarded[64].load(Ordering::Relaxed), 8000);
    }

    #[test]
    fn test_dispatch_syscall_with_regions_served() {
        let counters = Counters::default();
        let tasks = [CurrentTask::new()];
        tasks[0].set(carrick_el1_abi::El1TaskId::from_linux_tid(1), 1, 100); // slot 0: task_id 1, generation 1, file_table 100

        let fd_map = [FdMapSlot::new()];
        fd_map[0].set(100, 3, 1, 42); // file_table 100, fd 3 -> handle 1, incarnation 42

        let object_table = [DelegatedFile::new()];
        let open_table = [DelegatedOpenFile::new()];
        open_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        open_table[0].inode_handle.store(1, Ordering::Relaxed);
        object_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        object_table[0].generation.store(42, Ordering::Relaxed);
        open_table[0].generation.store(42, Ordering::Relaxed);
        open_table[0].inode_generation.store(42, Ordering::Relaxed);
        object_table[0].size.store(100, Ordering::Relaxed);
        open_table[0].offset.store(10, Ordering::Relaxed);
        open_table[0]
            .flags
            .store(carrick_el1_abi::DELEGATED_FLAG_READABLE, Ordering::Relaxed);

        let mut frame = TrapFrame::default();
        frame.x[0] = 3; // fd
        frame.x[1] = 50; // offset
        frame.x[2] = 0; // SEEK_SET
        frame.x[8] = 62; // lseek

        let inotify_table = [DelegatedInotify::new()];
        let name_cache = InotifyNameCache::new();

        let action = dispatch_syscall_with_regions(
            &mut frame,
            &counters,
            &tasks,
            &fd_map,
            &object_table,
            &open_table,
            &inotify_table,
            &name_cache,
            |_| core::ptr::null_mut(),
        );

        assert_eq!(action, Action::Served);
        assert_eq!(frame.x[0], 50);
        assert_eq!(counters.served[62].load(Ordering::Relaxed), 1);
        assert_eq!(counters.forwarded[62].load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_dispatch_syscall_with_regions_entry_pending_work() {
        let counters = Counters::default();
        let tasks = [CurrentTask::new()];
        tasks[0].set(carrick_el1_abi::El1TaskId::from_linux_tid(1), 1, 100);
        tasks[0].mark_pending_host_work(); // pending host work set at entry

        let fd_map = [FdMapSlot::new()];
        fd_map[0].set(100, 3, 1, 42);

        let object_table = [DelegatedFile::new()];
        let open_table = [DelegatedOpenFile::new()];
        open_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        open_table[0].inode_handle.store(1, Ordering::Relaxed);
        object_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        object_table[0].generation.store(42, Ordering::Relaxed);
        open_table[0].generation.store(42, Ordering::Relaxed);
        open_table[0].inode_generation.store(42, Ordering::Relaxed);
        object_table[0].size.store(100, Ordering::Relaxed);
        open_table[0].offset.store(10, Ordering::Relaxed);

        let inotify_table = [DelegatedInotify::new()];
        let name_cache = InotifyNameCache::new();

        let mut frame = TrapFrame::default();
        frame.x[0] = 3;
        frame.x[1] = 50;
        frame.x[2] = 0;
        frame.x[8] = 62; // lseek

        let action = dispatch_syscall_with_regions(
            &mut frame,
            &counters,
            &tasks,
            &fd_map,
            &object_table,
            &open_table,
            &inotify_table,
            &name_cache,
            |_| core::ptr::null_mut(),
        );

        // Entry check: must forward immediately without modifying file state
        assert_eq!(action, Action::Forward);
        assert_eq!(open_table[0].offset.load(Ordering::Relaxed), 10);
        assert_eq!(counters.served[62].load(Ordering::Relaxed), 0);
        assert_eq!(counters.forwarded[62].load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_dispatch_syscall_with_regions_exit_pending_work() {
        let counters = Counters::default();
        let tasks = [CurrentTask::new()];
        tasks[0].set(carrick_el1_abi::El1TaskId::from_linux_tid(1), 1, 100);

        let fd_map = [FdMapSlot::new()];
        fd_map[0].set(100, 3, 1, 42);

        let object_table = [DelegatedFile::new()];
        let open_table = [DelegatedOpenFile::new()];
        open_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        open_table[0].inode_handle.store(1, Ordering::Relaxed);
        object_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        object_table[0].generation.store(42, Ordering::Relaxed);
        open_table[0].generation.store(42, Ordering::Relaxed);
        open_table[0].inode_generation.store(42, Ordering::Relaxed);
        object_table[0].size.store(100, Ordering::Relaxed);
        open_table[0].offset.store(10, Ordering::Relaxed);
        open_table[0]
            .flags
            .store(carrick_el1_abi::DELEGATED_FLAG_READABLE, Ordering::Relaxed);

        let inotify_table = [DelegatedInotify::new()];
        let name_cache = InotifyNameCache::new();

        let mut frame = TrapFrame::default();
        frame.x[0] = 3;
        frame.x[1] = 50;
        frame.x[2] = 0;
        frame.x[8] = 62; // lseek

        // Simulate host marking pending work while/right before syscall exit
        tasks[0].mark_pending_host_work();

        // At entry, pending_host_work is already set, so it forwards
        let action = dispatch_syscall_with_regions(
            &mut frame,
            &counters,
            &tasks,
            &fd_map,
            &object_table,
            &open_table,
            &inotify_table,
            &name_cache,
            |_| core::ptr::null_mut(),
        );
        assert_eq!(action, Action::Forward);

        // Now test exit check: pending_host_work starts clear, then gets set during operation
        tasks[0].clear_pending_host_work();
        let mut frame2 = TrapFrame::default();
        frame2.x[0] = 3;
        frame2.x[1] = 50;
        frame2.x[2] = 0;
        frame2.x[8] = 62;

        let action2 = dispatch_syscall_with_regions(
            &mut frame2,
            &counters,
            &tasks,
            &fd_map,
            &object_table,
            &open_table,
            &inotify_table,
            &name_cache,
            |_| core::ptr::null_mut(),
        );
        assert_eq!(action2, Action::Served);
        assert_eq!(frame2.x[0], 50);

        // Exit check test: operation succeeds, but host marked pending work during the operation.
        tasks[0].clear_pending_host_work();
        tasks[0].served_with_work.store(0, Ordering::Relaxed);
        let mut buf = [0u8; 16];
        let mut cache_mem = [0u8; 4096];
        let cache_ptr = cache_mem.as_mut_ptr();
        let task_ref = &tasks[0];
        open_table[0]
            .flags
            .store(carrick_el1_abi::DELEGATED_FLAG_WRITABLE, Ordering::Relaxed);
        open_table[0].offset.store(0, Ordering::Relaxed);

        let mut frame_write = TrapFrame::default();
        frame_write.x[0] = 3; // fd
        frame_write.x[1] = buf.as_mut_ptr() as u64; // buf
        frame_write.x[2] = 16; // count
        frame_write.x[8] = 64; // SYS_write

        let action_write = dispatch_syscall_with_regions(
            &mut frame_write,
            &counters,
            &tasks,
            &fd_map,
            &object_table,
            &open_table,
            &inotify_table,
            &name_cache,
            move |_| {
                // Host marks pending work during write operation
                task_ref.mark_pending_host_work();
                cache_ptr
            },
        );

        assert_eq!(action_write, Action::ServedWithWork);
        assert_eq!(frame_write.x[0], 16);
        assert_eq!(tasks[0].served_with_work.load(Ordering::Relaxed), 1);
        assert_eq!(counters.served[64].load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_stale_handle_interleaving_forwards() {
        let counters = Counters::default();
        let tasks = [CurrentTask::new()];
        tasks[0].set(carrick_el1_abi::El1TaskId::from_linux_tid(1), 1, 100); // task_id 1, generation 1, file_table 100

        let fd_map = [FdMapSlot::new()];
        // Initially: table 100, fd 3 -> handle 1, incarnation 10
        fd_map[0].set(100, 3, 1, 10);

        let object_table = [DelegatedFile::new()];
        let open_table = [DelegatedOpenFile::new()];
        open_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        open_table[0].inode_handle.store(1, Ordering::Relaxed);
        // Suppose between fd_map_lookup and try_lock / re-validation,
        // the handle is recalled, freed, and re-delegated to another file with incarnation 11!
        object_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        object_table[0].generation.store(11, Ordering::Relaxed); // new incarnation!
        // The open file still names the inode incarnation it joined (10).
        open_table[0].generation.store(10, Ordering::Relaxed);
        open_table[0].inode_generation.store(10, Ordering::Relaxed);
        object_table[0].size.store(100, Ordering::Relaxed);
        open_table[0].offset.store(10, Ordering::Relaxed);
        open_table[0]
            .flags
            .store(carrick_el1_abi::DELEGATED_FLAG_READABLE, Ordering::Relaxed);

        let inotify_table = [DelegatedInotify::new()];
        let name_cache = InotifyNameCache::new();

        let mut frame = TrapFrame::default();
        frame.x[0] = 3; // fd 3
        frame.x[1] = 50;
        frame.x[2] = 0;
        frame.x[8] = 62; // lseek

        let action = dispatch_syscall_with_regions(
            &mut frame,
            &counters,
            &tasks,
            &fd_map,
            &object_table,
            &open_table,
            &inotify_table,
            &name_cache,
            |_| core::ptr::null_mut(),
        );

        // Must detect incarnation mismatch and FORWARD, not serve against the new object!
        assert_eq!(action, Action::Forward);
        assert_eq!(counters.served[62].load(Ordering::Relaxed), 0);
        assert_eq!(counters.forwarded[62].load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_thread_sleep_survives_task_generation_bump() {
        let counters = Counters::default();
        let tasks = [CurrentTask::new()];
        // Task has been switched out multiple times, so its scheduling generation is 5
        tasks[0].set(carrick_el1_abi::El1TaskId::from_linux_tid(1), 5, 100);

        let fd_map = [FdMapSlot::new()];
        fd_map[0].set(100, 3, 1, 42); // incarnation 42

        let object_table = [DelegatedFile::new()];
        let open_table = [DelegatedOpenFile::new()];
        open_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        open_table[0].inode_handle.store(1, Ordering::Relaxed);
        object_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        object_table[0].generation.store(42, Ordering::Relaxed);
        open_table[0].generation.store(42, Ordering::Relaxed);
        open_table[0].inode_generation.store(42, Ordering::Relaxed); // object incarnation 42
        object_table[0].size.store(100, Ordering::Relaxed);
        open_table[0].offset.store(10, Ordering::Relaxed);
        open_table[0]
            .flags
            .store(carrick_el1_abi::DELEGATED_FLAG_READABLE, Ordering::Relaxed);

        let inotify_table = [DelegatedInotify::new()];
        let name_cache = InotifyNameCache::new();

        let mut frame = TrapFrame::default();
        frame.x[0] = 3;
        frame.x[1] = 50;
        frame.x[2] = 0;
        frame.x[8] = 62; // lseek

        // Syscall must succeed even though task.generation (5) != object.generation (42)
        let action = dispatch_syscall_with_regions(
            &mut frame,
            &counters,
            &tasks,
            &fd_map,
            &object_table,
            &open_table,
            &inotify_table,
            &name_cache,
            |_| core::ptr::null_mut(),
        );

        assert_eq!(action, Action::Served);
        assert_eq!(frame.x[0], 50);
        assert_eq!(counters.served[62].load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_in_guest_read_queues_in_access_and_owes_an_observed_waiter_a_wake() {
        use carrick_el1_abi::{FD_HANDLE_INOTIFY_TAG, hash_path};

        let counters = Counters::default();
        let tasks = [CurrentTask::new()];
        tasks[0].set(carrick_el1_abi::El1TaskId::from_linux_tid(1), 1, 100);

        let fd_map = [FdMapSlot::new(), FdMapSlot::new()];
        fd_map[0].set(100, 3, 1, 42); // fd 3 -> delegated file handle 1
        fd_map[1].set(100, 4, FD_HANDLE_INOTIFY_TAG | 1, 42); // fd 4 -> delegated inotify handle 1

        let object_table = [DelegatedFile::new()];
        let open_table = [DelegatedOpenFile::new()];
        open_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        open_table[0].inode_handle.store(1, Ordering::Relaxed);
        object_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        object_table[0].generation.store(42, Ordering::Relaxed);
        open_table[0].generation.store(42, Ordering::Relaxed);
        open_table[0].inode_generation.store(42, Ordering::Relaxed);
        object_table[0].size.store(100, Ordering::Relaxed);
        open_table[0].offset.store(0, Ordering::Relaxed);
        open_table[0].flags.store(
            carrick_el1_abi::DELEGATED_FLAG_READABLE | carrick_el1_abi::DELEGATED_FLAG_WRITABLE,
            Ordering::Relaxed,
        );

        let inotify_table = [DelegatedInotify::new()];
        inotify_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        inotify_table[0].generation.store(42, Ordering::Relaxed);
        inotify_table[0]
            .flags
            .store(inotify::O_NONBLOCK, Ordering::Relaxed);

        let name_cache = InotifyNameCache::new();
        let path = b"test.txt";
        let path_hash = hash_path(path);
        name_cache.insert(100, name_cache.cwd_generation(), path, path_hash, 1);

        let mut path_str = *b"test.txt\0";
        let mut frame_add = TrapFrame::default();
        frame_add.x[0] = 4; // inotify fd
        frame_add.x[1] = path_str.as_mut_ptr() as u64; // pathname
        frame_add.x[2] = 0x01; // IN_ACCESS
        frame_add.x[8] = 27; // inotify_add_watch

        let mut cache_mem = [0u8; 4096];
        let cache_ptr = cache_mem.as_mut_ptr();

        let action = dispatch_syscall_with_regions(
            &mut frame_add,
            &counters,
            &tasks,
            &fd_map,
            &object_table,
            &open_table,
            &inotify_table,
            &name_cache,
            |_| cache_ptr,
        );
        assert_eq!(action, Action::Served);
        let wd = frame_add.x[0] as i32;
        assert_eq!(wd, 1);
        assert_eq!(counters.served[27].load(Ordering::Relaxed), 1);
        assert!(object_table[0].has_marks());

        // A host thread waits on the (empty) instance.
        inotify_table[0].host_observed.store(1, Ordering::SeqCst);

        // A read of the watched file, served in-guest, queues IN_ACCESS and
        // returns through the host boundary to deliver the owed wake.
        let mut read_buf = [0u8; 16];
        let mut frame_read = TrapFrame::default();
        frame_read.x[0] = 3; // file fd
        frame_read.x[1] = read_buf.as_mut_ptr() as u64;
        frame_read.x[2] = 16;
        frame_read.x[8] = 63; // read

        let action = dispatch_syscall_with_regions(
            &mut frame_read,
            &counters,
            &tasks,
            &fd_map,
            &object_table,
            &open_table,
            &inotify_table,
            &name_cache,
            |_| cache_ptr,
        );
        assert_eq!(action, Action::ServedWithWork);
        assert_eq!(frame_read.x[0], 16);
        assert!(inotify_table[0].wake_is_owed());
        let mut records = [0u8; 64];
        assert_eq!(inotify_table[0].drain_into(&mut records), Ok(16));
        assert_eq!(
            u32::from_ne_bytes([records[4], records[5], records[6], records[7]]),
            0x01
        );
    }

    #[test]
    fn test_two_open_files_share_one_inode_with_independent_offsets() {
        let counters = Counters::default();
        let tasks = [CurrentTask::new()];
        tasks[0].set(carrick_el1_abi::El1TaskId::from_linux_tid(1), 1, 100);
        let fd_map = [FdMapSlot::new(), FdMapSlot::new()];
        fd_map[0].set(100, 3, 1, 7); // fd 3 -> open file 1
        fd_map[1].set(100, 4, 2, 8); // fd 4 -> open file 2
        let object_table = [DelegatedFile::new()];
        object_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        object_table[0].generation.store(42, Ordering::Relaxed);
        let open_table = [DelegatedOpenFile::new(), DelegatedOpenFile::new()];
        for (i, generation) in [(0usize, 7u64), (1, 8)] {
            open_table[i]
                .state
                .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
            open_table[i]
                .generation
                .store(generation, Ordering::Relaxed);
            open_table[i].inode_handle.store(1, Ordering::Relaxed);
            open_table[i].inode_generation.store(42, Ordering::Relaxed);
            open_table[i].flags.store(
                carrick_el1_abi::DELEGATED_FLAG_READABLE | carrick_el1_abi::DELEGATED_FLAG_WRITABLE,
                Ordering::Relaxed,
            );
        }
        let inotify_table = [DelegatedInotify::new()];
        let name_cache = InotifyNameCache::new();
        let mut cache_mem = [0u8; 4096];
        let cache_ptr = cache_mem.as_mut_ptr();
        let run = |fd: u64, nr: u64, a1: u64, a2: u64| {
            let mut frame = TrapFrame::default();
            frame.x[0] = fd;
            frame.x[1] = a1;
            frame.x[2] = a2;
            frame.x[8] = nr;
            let action = dispatch_syscall_with_regions(
                &mut frame,
                &counters,
                &tasks,
                &fd_map,
                &object_table,
                &open_table,
                &inotify_table,
                &name_cache,
                |_| cache_ptr,
            );
            assert_eq!(action, Action::Served, "fd {fd} nr {nr}");
            frame.x[0] as i64
        };
        let mut hello = *b"hello";
        assert_eq!(run(3, 64, hello.as_mut_ptr() as u64, 5), 5); // write via fd 3
        let mut out = [0u8; 5];
        // fd 4 has its own offset (0) and sees fd 3's bytes.
        assert_eq!(run(4, 63, out.as_mut_ptr() as u64, 5), 5);
        assert_eq!(&out, b"hello");
        assert_eq!(open_table[0].offset.load(Ordering::Relaxed), 5);
        assert_eq!(open_table[1].offset.load(Ordering::Relaxed), 5);
        assert_eq!(run(3, 62, 1, 0), 1); // lseek fd 3 to 1 leaves fd 4 at 5
        assert_eq!(open_table[1].offset.load(Ordering::Relaxed), 5);
        assert_eq!(object_table[0].size.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn test_inotify_add_watch_write_rm_watch_read_served() {
        use carrick_el1_abi::{FD_HANDLE_INOTIFY_TAG, hash_path};

        let counters = Counters::default();
        let tasks = [CurrentTask::new()];
        tasks[0].set(carrick_el1_abi::El1TaskId::from_linux_tid(1), 1, 100);

        let fd_map = [FdMapSlot::new(), FdMapSlot::new()];
        fd_map[0].set(100, 3, 1, 42); // fd 3 -> delegated file handle 1
        fd_map[1].set(100, 4, FD_HANDLE_INOTIFY_TAG | 1, 42); // fd 4 -> delegated inotify handle 1

        let object_table = [DelegatedFile::new()];
        let open_table = [DelegatedOpenFile::new()];
        open_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        open_table[0].inode_handle.store(1, Ordering::Relaxed);
        object_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        object_table[0].generation.store(42, Ordering::Relaxed);
        open_table[0].generation.store(42, Ordering::Relaxed);
        open_table[0].inode_generation.store(42, Ordering::Relaxed);
        object_table[0].size.store(100, Ordering::Relaxed);
        open_table[0].offset.store(0, Ordering::Relaxed);
        open_table[0].flags.store(
            carrick_el1_abi::DELEGATED_FLAG_READABLE | carrick_el1_abi::DELEGATED_FLAG_WRITABLE,
            Ordering::Relaxed,
        );

        let inotify_table = [DelegatedInotify::new()];
        inotify_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        inotify_table[0].generation.store(42, Ordering::Relaxed);
        inotify_table[0]
            .flags
            .store(inotify::O_NONBLOCK, Ordering::Relaxed);

        let name_cache = InotifyNameCache::new();
        let path = b"test.txt";
        let path_hash = hash_path(path);
        name_cache.insert(100, name_cache.cwd_generation(), path, path_hash, 1);

        let mut path_str = *b"test.txt\0";
        let mut frame_add = TrapFrame::default();
        frame_add.x[0] = 4; // inotify fd
        frame_add.x[1] = path_str.as_mut_ptr() as u64; // pathname
        frame_add.x[2] = 0x02; // IN_MODIFY
        frame_add.x[8] = 27; // inotify_add_watch

        let mut cache_mem = [0u8; 4096];
        let cache_ptr = cache_mem.as_mut_ptr();

        // 1. inotify_add_watch should be served at EL1
        let action = dispatch_syscall_with_regions(
            &mut frame_add,
            &counters,
            &tasks,
            &fd_map,
            &object_table,
            &open_table,
            &inotify_table,
            &name_cache,
            |_| cache_ptr,
        );
        assert_eq!(action, Action::Served);
        let wd = frame_add.x[0] as i32;
        assert_eq!(wd, 1);
        assert_eq!(counters.served[27].load(Ordering::Relaxed), 1);
        assert!(object_table[0].has_marks());

        // 2. write to file should be served at EL1 and enqueue IN_MODIFY
        let mut write_buf = [0x55u8; 16];
        let mut frame_write = TrapFrame::default();
        frame_write.x[0] = 3; // file fd
        frame_write.x[1] = write_buf.as_mut_ptr() as u64;
        frame_write.x[2] = 16;
        frame_write.x[8] = 64; // write

        let action = dispatch_syscall_with_regions(
            &mut frame_write,
            &counters,
            &tasks,
            &fd_map,
            &object_table,
            &open_table,
            &inotify_table,
            &name_cache,
            |_| cache_ptr,
        );
        assert_eq!(action, Action::Served);
        assert_eq!(frame_write.x[0], 16);
        assert_eq!(counters.served[64].load(Ordering::Relaxed), 1);
        assert!(inotify_table[0].has_records());

        // 3. inotify_rm_watch should be served at EL1 and enqueue IN_IGNORED
        let mut frame_rm = TrapFrame::default();
        frame_rm.x[0] = 4; // inotify fd
        frame_rm.x[1] = wd as u64;
        frame_rm.x[8] = 28; // inotify_rm_watch

        let action = dispatch_syscall_with_regions(
            &mut frame_rm,
            &counters,
            &tasks,
            &fd_map,
            &object_table,
            &open_table,
            &inotify_table,
            &name_cache,
            |_| cache_ptr,
        );
        assert_eq!(action, Action::Served);
        assert_eq!(frame_rm.x[0], 0);
        assert_eq!(counters.served[28].load(Ordering::Relaxed), 1);
        assert!(!object_table[0].has_marks());
        assert_eq!(inotify_table[0].queued_bytes.load(Ordering::Relaxed), 32); // IN_MODIFY + IN_IGNORED

        // 4. read from inotify fd should be served at EL1 and drain 2 events (32 bytes)
        let mut read_buf = [0u8; 64];
        let mut frame_read = TrapFrame::default();
        frame_read.x[0] = 4; // inotify fd
        frame_read.x[1] = read_buf.as_mut_ptr() as u64;
        frame_read.x[2] = 64;
        frame_read.x[8] = 63; // read

        let action = dispatch_syscall_with_regions(
            &mut frame_read,
            &counters,
            &tasks,
            &fd_map,
            &object_table,
            &open_table,
            &inotify_table,
            &name_cache,
            |_| cache_ptr,
        );
        assert_eq!(action, Action::Served);
        assert_eq!(frame_read.x[0], 32);
        assert_eq!(counters.served[63].load(Ordering::Relaxed), 1);
        assert!(!inotify_table[0].has_records());
    }

    #[test]
    fn test_inotify_cache_miss_forwards() {
        let counters = Counters::default();
        let tasks = [CurrentTask::new()];
        tasks[0].set(carrick_el1_abi::El1TaskId::from_linux_tid(1), 1, 100);

        let fd_map = [FdMapSlot::new()];
        fd_map[0].set(100, 4, carrick_el1_abi::FD_HANDLE_INOTIFY_TAG | 1, 42);

        let object_table = [DelegatedFile::new()];
        let open_table = [DelegatedOpenFile::new()];
        open_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        open_table[0].inode_handle.store(1, Ordering::Relaxed);
        let inotify_table = [DelegatedInotify::new()];
        inotify_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);

        let name_cache = InotifyNameCache::new(); // empty name cache -> miss!

        let mut path_str = *b"unknown.txt\0";
        let mut frame = TrapFrame::default();
        frame.x[0] = 4;
        frame.x[1] = path_str.as_mut_ptr() as u64;
        frame.x[2] = 0x02; // IN_MODIFY
        frame.x[8] = 27; // inotify_add_watch

        let action = dispatch_syscall_with_regions(
            &mut frame,
            &counters,
            &tasks,
            &fd_map,
            &object_table,
            &open_table,
            &inotify_table,
            &name_cache,
            |_| core::ptr::null_mut(),
        );

        assert_eq!(action, Action::Forward);
        assert_eq!(counters.forwarded[27].load(Ordering::Relaxed), 1);
        assert_eq!(counters.served[27].load(Ordering::Relaxed), 0);
    }
}
