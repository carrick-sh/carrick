//! Dispatch-policy assertions moved with the single Linux owner.
use super::NoCpu;
use carrick_el1::personality::{
    dispatch::{El1PendingFamilies, Zone, dispatch_syscall_with_regions},
    inotify, sched,
};
use carrick_el1_abi::{
    Action, Counters, CurrentTask, DELEGATED_STATE_GUEST, DelegatedFile, DelegatedInotify,
    DelegatedOpenFile, FdMapSlot, InotifyNameCache, TrapFrame,
};
use core::sync::atomic::Ordering;

#[test]
fn anonymous_reservation_routing_counts_two_mm_fallback_without_effects() {
    // Exercise the production dispatcher, not dispatch_syscall's host-only
    // fallback. Both live tasks deliberately use the same guest addresses.
    for rounds in [1, 8, 64] {
        let counters = Counters::default();
        let tasks = [CurrentTask::new(), CurrentTask::new()];
        for (slot, task) in tasks.iter().enumerate() {
            task.set(
                carrick_el1_abi::El1TaskId::from_linux_tid(slot as i32 + 1),
                1,
                slot as u64 + 1,
            );
            task.mm.key.store(slot as u64 + 17, Ordering::Release);
        }
        for _ in 0..rounds {
            for slot in 0..tasks.len() {
                for nr in [214, 222] {
                    let mut frame = TrapFrame {
                        slot: slot as u64,
                        ..TrapFrame::default()
                    };
                    frame.x[..6].copy_from_slice(&[0x60_0000_0000, 0x3000, 3, 0x22, u64::MAX, 0]);
                    frame.x[8] = nr;
                    let original = frame.x;
                    let action = dispatch_syscall_with_regions(
                        &mut frame,
                        &counters,
                        &tasks,
                        &[],
                        &[],
                        &[],
                        &[],
                        &InotifyNameCache::new(),
                        None::<Zone<'_, NoCpu, sched::HardwareUserWord>>,
                        |_| core::ptr::null_mut(),
                    );
                    assert_eq!(action, Action::Forward);
                    assert_eq!(frame.x, original, "forwarding cannot consume arguments");
                    assert_eq!(
                        tasks[slot].linux.served_with_work.load(Ordering::Acquire),
                        0
                    );
                }
            }
        }
        for nr in [214, 222] {
            assert_eq!(counters.forwarded[nr].load(Ordering::Relaxed), 2 * rounds);
            assert_eq!(counters.served[nr].load(Ordering::Relaxed), 0);
        }
    }
}

#[test]
fn unmigrated_family_completes_once_through_linux_owner() {
    fn requires_real_family<'a, T: carrick_personality_linux::dispatch::PendingFamilies<'a>>() {}
    requires_real_family::<
        El1PendingFamilies<'_, fn(u32) -> *mut u8, NoCpu, sched::HardwareUserWord>,
    >();
    test_thread_sleep_survives_task_generation_bump();
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
        None::<Zone<'_, NoCpu, sched::HardwareUserWord>>,
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
    tasks[0].linux.mark_pending_host_work(); // pending host work set at entry

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
        None::<Zone<'_, NoCpu, sched::HardwareUserWord>>,
        |_| core::ptr::null_mut(),
    );

    // Owed work leaves through WithWork with original-argument replay, without
    // modifying file state or claiming the syscall completed.
    assert_eq!(action, Action::ServedWithWork);
    assert_eq!(
        tasks[0].linux.take_served_boundary(),
        Some(carrick_el1_abi::ServedBoundary::ReplayOriginal { x0: 3 })
    );
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
    tasks[0].linux.mark_pending_host_work();

    // At entry, pending host work must publish before replaying this call
    let action = dispatch_syscall_with_regions(
        &mut frame,
        &counters,
        &tasks,
        &fd_map,
        &object_table,
        &open_table,
        &inotify_table,
        &name_cache,
        None::<Zone<'_, NoCpu, sched::HardwareUserWord>>,
        |_| core::ptr::null_mut(),
    );
    assert_eq!(action, Action::ServedWithWork);

    // Now test exit check: pending_host_work starts clear, then gets set during operation
    tasks[0].linux.clear_pending_host_work();
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
        None::<Zone<'_, NoCpu, sched::HardwareUserWord>>,
        |_| core::ptr::null_mut(),
    );
    assert_eq!(action2, Action::Served);
    assert_eq!(frame2.x[0], 50);

    // Exit check test: operation succeeds, but host marked pending work during the operation.
    tasks[0].linux.clear_pending_host_work();
    tasks[0].linux.served_with_work.store(0, Ordering::Relaxed);
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
        None::<Zone<'_, NoCpu, sched::HardwareUserWord>>,
        move |_| {
            // Host marks pending work during write operation
            task_ref.linux.mark_pending_host_work();
            cache_ptr
        },
    );

    assert_eq!(action_write, Action::ServedWithWork);
    assert_eq!(frame_write.x[0], 16);
    assert_eq!(tasks[0].linux.served_with_work.load(Ordering::Relaxed), 1);
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
        None::<Zone<'_, NoCpu, sched::HardwareUserWord>>,
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
        None::<Zone<'_, NoCpu, sched::HardwareUserWord>>,
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
        None::<Zone<'_, NoCpu, sched::HardwareUserWord>>,
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
        None::<Zone<'_, NoCpu, sched::HardwareUserWord>>,
        |_| cache_ptr,
    );
    assert_eq!(action, Action::ServedWithWork);
    assert_eq!(frame_read.x[0], 16);
    assert_eq!(tasks[0].linux.orig_arg0.load(Ordering::Relaxed), 3);
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
            None::<Zone<'_, NoCpu, sched::HardwareUserWord>>,
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
        None::<Zone<'_, NoCpu, sched::HardwareUserWord>>,
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
        None::<Zone<'_, NoCpu, sched::HardwareUserWord>>,
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
        None::<Zone<'_, NoCpu, sched::HardwareUserWord>>,
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
        None::<Zone<'_, NoCpu, sched::HardwareUserWord>>,
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
        None::<Zone<'_, NoCpu, sched::HardwareUserWord>>,
        |_| core::ptr::null_mut(),
    );

    assert_eq!(action, Action::Forward);
    assert_eq!(counters.forwarded[27].load(Ordering::Relaxed), 1);
    assert_eq!(counters.served[27].load(Ordering::Relaxed), 0);
}
