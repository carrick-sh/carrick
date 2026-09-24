//! Carrick in-guest EL1 kernel foundation.
//!
//! Provides the entry point, dispatch logic, and foundations for in-guest
//! execution at EL1.

#![cfg_attr(target_os = "none", no_std)]

pub mod alloc;
pub mod file;
pub mod lock;

use carrick_el1_abi::{
    Action, Counters, CurrentTask, DELEGATED_STATE_GUEST, DelegatedFile, FdMapSlot,
    MAX_DELEGATED_FILES, TrapFrame, fd_map_lookup,
};
#[cfg(target_os = "none")]
use carrick_el1_abi::{
    EL1_CURRENT_TASKS_BASE, EL1_FD_MAP_BASE, EL1_OBJECT_TABLE_BASE, EL1_STACK_SLOTS,
    FD_MAP_CAPACITY,
};
use core::sync::atomic::Ordering;

/// Dispatch an in-guest Linux syscall at EL1.
pub fn dispatch_syscall(frame: &mut TrapFrame, counters: &Counters) -> Action {
    #[cfg(target_os = "none")]
    {
        let current_tasks =
            unsafe { &*(EL1_CURRENT_TASKS_BASE as *const [CurrentTask; EL1_STACK_SLOTS as usize]) };
        let fd_map = unsafe { &*(EL1_FD_MAP_BASE as *const [FdMapSlot; FD_MAP_CAPACITY]) };
        let object_table =
            unsafe { &*(EL1_OBJECT_TABLE_BASE as *const [DelegatedFile; MAX_DELEGATED_FILES]) };
        dispatch_syscall_with_regions(
            frame,
            counters,
            current_tasks,
            fd_map,
            object_table,
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
pub fn dispatch_syscall_with_regions<F>(
    frame: &mut TrapFrame,
    counters: &Counters,
    current_tasks: &[CurrentTask],
    fd_map: &[FdMapSlot],
    object_table: &[DelegatedFile],
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
        62 | 63 | 64 | 67 | 68 => {
            let orig_x0 = frame.x[0];
            if let Some(res) = try_serve_file_syscall(
                frame,
                nr,
                current_tasks,
                fd_map,
                object_table,
                &cache_lookup,
            ) {
                frame.x[0] = res as u64;
                if nr < 512 {
                    counters.served[nr].fetch_add(1, Ordering::Relaxed);
                }
                if let Some(task) = cur_task {
                    task.orig_arg0.store(orig_x0, Ordering::Relaxed);
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

fn try_serve_file_syscall<F>(
    frame: &TrapFrame,
    nr: usize,
    current_tasks: &[CurrentTask],
    fd_map: &[FdMapSlot],
    object_table: &[DelegatedFile],
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
    let (handle, slot_idx) = fd_map_lookup(fd_map, file_table, fd)?;
    if handle == 0 || handle as usize > MAX_DELEGATED_FILES {
        return None;
    }
    let file = object_table.get((handle - 1) as usize)?;
    if file.state.load(Ordering::Acquire) != DELEGATED_STATE_GUEST {
        return None;
    }
    if !file.try_lock() {
        return None;
    }
    // Re-validate fd_map slot and object incarnation after taking the lock
    let map_slot = fd_map.get(slot_idx)?;
    let slot_incarnation = map_slot.incarnation.load(Ordering::Acquire);
    let slot_handle = map_slot.handle.load(Ordering::Relaxed);
    let slot_fd = map_slot.fd.load(Ordering::Relaxed);
    let slot_file_table = map_slot.file_table.load(Ordering::Relaxed);
    let file_incarnation = file.generation.load(Ordering::Acquire);
    let file_state = file.state.load(Ordering::Acquire);

    if slot_incarnation == 0
        || slot_handle != handle
        || slot_fd != fd as u32
        || slot_file_table != file_table
        || slot_incarnation != file_incarnation
        || file_state != DELEGATED_STATE_GUEST
    {
        file.unlock();
        return None;
    }

    let cache_ptr = cache_lookup(handle);
    let validator = file::HardwareValidator;
    let outcome = match nr {
        62 => file::el1_lseek(file, frame.x[1] as i64, frame.x[2] as u32),
        63 => file::el1_read(
            file,
            cur_task,
            cache_ptr as *const u8,
            frame.x[1],
            frame.x[2] as usize,
            &validator,
        ),
        64 => file::el1_write(
            file,
            cur_task,
            cache_ptr,
            frame.x[1],
            frame.x[2] as usize,
            &validator,
        ),
        67 => file::el1_pread64(
            file,
            cur_task,
            cache_ptr as *const u8,
            frame.x[1],
            frame.x[2] as usize,
            frame.x[3] as i64,
            &validator,
        ),
        68 => file::el1_pwrite64(
            file,
            cur_task,
            cache_ptr,
            frame.x[1],
            frame.x[2] as usize,
            frame.x[3] as i64,
            &validator,
        ),
        _ => Err(Action::Forward),
    };
    if outcome.is_ok() {
        file.served_ops.fetch_add(1, Ordering::Relaxed);
    }
    file.unlock();
    outcome.ok()
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
        tasks[0].set(1, 1, 100); // slot 0: task_id 1, generation 1, file_table 100

        let fd_map = [FdMapSlot::new()];
        fd_map[0].set(100, 3, 1, 42); // file_table 100, fd 3 -> handle 1, incarnation 42

        let object_table = [DelegatedFile::new()];
        object_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        object_table[0].generation.store(42, Ordering::Relaxed);
        object_table[0].size.store(100, Ordering::Relaxed);
        object_table[0].offset.store(10, Ordering::Relaxed);
        object_table[0]
            .flags
            .store(carrick_el1_abi::DELEGATED_FLAG_READABLE, Ordering::Relaxed);

        let mut frame = TrapFrame::default();
        frame.x[0] = 3; // fd
        frame.x[1] = 50; // offset
        frame.x[2] = 0; // SEEK_SET
        frame.x[8] = 62; // lseek

        let action = dispatch_syscall_with_regions(
            &mut frame,
            &counters,
            &tasks,
            &fd_map,
            &object_table,
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
        tasks[0].set(1, 1, 100);
        tasks[0].mark_pending_host_work(); // pending host work set at entry

        let fd_map = [FdMapSlot::new()];
        fd_map[0].set(100, 3, 1, 42);

        let object_table = [DelegatedFile::new()];
        object_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        object_table[0].generation.store(42, Ordering::Relaxed);
        object_table[0].size.store(100, Ordering::Relaxed);
        object_table[0].offset.store(10, Ordering::Relaxed);

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
            |_| core::ptr::null_mut(),
        );

        // Entry check: must forward immediately without modifying file state
        assert_eq!(action, Action::Forward);
        assert_eq!(object_table[0].offset.load(Ordering::Relaxed), 10);
        assert_eq!(counters.served[62].load(Ordering::Relaxed), 0);
        assert_eq!(counters.forwarded[62].load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_dispatch_syscall_with_regions_exit_pending_work() {
        let counters = Counters::default();
        let tasks = [CurrentTask::new()];
        tasks[0].set(1, 1, 100);

        let fd_map = [FdMapSlot::new()];
        fd_map[0].set(100, 3, 1, 42);

        let object_table = [DelegatedFile::new()];
        object_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        object_table[0].generation.store(42, Ordering::Relaxed);
        object_table[0].size.store(100, Ordering::Relaxed);
        object_table[0].offset.store(10, Ordering::Relaxed);
        object_table[0]
            .flags
            .store(carrick_el1_abi::DELEGATED_FLAG_READABLE, Ordering::Relaxed);

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
        object_table[0]
            .flags
            .store(carrick_el1_abi::DELEGATED_FLAG_WRITABLE, Ordering::Relaxed);
        object_table[0].offset.store(0, Ordering::Relaxed);

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
        tasks[0].set(1, 1, 100); // task_id 1, generation 1, file_table 100

        let fd_map = [FdMapSlot::new()];
        // Initially: table 100, fd 3 -> handle 1, incarnation 10
        fd_map[0].set(100, 3, 1, 10);

        let object_table = [DelegatedFile::new()];
        // Suppose between fd_map_lookup and try_lock / re-validation,
        // the handle is recalled, freed, and re-delegated to another file with incarnation 11!
        object_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        object_table[0].generation.store(11, Ordering::Relaxed); // new incarnation!
        object_table[0].size.store(100, Ordering::Relaxed);
        object_table[0].offset.store(10, Ordering::Relaxed);
        object_table[0]
            .flags
            .store(carrick_el1_abi::DELEGATED_FLAG_READABLE, Ordering::Relaxed);

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
        tasks[0].set(1, 5, 100);

        let fd_map = [FdMapSlot::new()];
        fd_map[0].set(100, 3, 1, 42); // incarnation 42

        let object_table = [DelegatedFile::new()];
        object_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        object_table[0].generation.store(42, Ordering::Relaxed); // object incarnation 42
        object_table[0].size.store(100, Ordering::Relaxed);
        object_table[0].offset.store(10, Ordering::Relaxed);
        object_table[0]
            .flags
            .store(carrick_el1_abi::DELEGATED_FLAG_READABLE, Ordering::Relaxed);

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
            |_| core::ptr::null_mut(),
        );

        assert_eq!(action, Action::Served);
        assert_eq!(frame.x[0], 50);
        assert_eq!(counters.served[62].load(Ordering::Relaxed), 1);
    }
}
