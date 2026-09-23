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
    let nr = frame.x[8] as usize;
    match nr {
        62 | 63 | 64 | 67 | 68 => {
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
    let handle = fd_map_lookup(fd_map, file_table, fd)?;
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
    if file.state.load(Ordering::Relaxed) != DELEGATED_STATE_GUEST {
        file.unlock();
        return None;
    }
    if file.generation.load(Ordering::Relaxed) != cur_task.generation.load(Ordering::Relaxed) {
        file.unlock();
        return None;
    }

    let cache_ptr = cache_lookup(handle);
    let validator = file::HardwareValidator;
    let outcome = match nr {
        62 => file::el1_lseek(file, frame.x[1] as i64, frame.x[2] as u32),
        63 => file::el1_read(
            file,
            cache_ptr as *const u8,
            frame.x[1],
            frame.x[2] as usize,
            &validator,
        ),
        64 => file::el1_write(file, cache_ptr, frame.x[1], frame.x[2] as usize, &validator),
        67 => file::el1_pread64(
            file,
            cache_ptr as *const u8,
            frame.x[1],
            frame.x[2] as usize,
            frame.x[3] as i64,
            &validator,
        ),
        68 => file::el1_pwrite64(
            file,
            cache_ptr,
            frame.x[1],
            frame.x[2] as usize,
            frame.x[3] as i64,
            &validator,
        ),
        _ => Err(Action::Forward),
    };
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
        tasks[0].set(1, 100); // slot 0: generation 1, file_table 100

        let fd_map = [FdMapSlot::new()];
        fd_map[0].set(100, 3, 1); // file_table 100, fd 3 -> handle 1

        let object_table = [DelegatedFile::new()];
        object_table[0]
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Relaxed);
        object_table[0].generation.store(1, Ordering::Relaxed);
        object_table[0].size.store(100, Ordering::Relaxed);
        object_table[0].offset.store(10, Ordering::Relaxed);
        object_table[0]
            .flags
            .store(carrick_el1_abi::DELEGATED_FLAG_READABLE, Ordering::Relaxed);

        let mut frame = TrapFrame::default();
        frame.slot = 0;
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
}
