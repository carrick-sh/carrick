//! EL1 delegated regular files host authority.
//!
//! Controls whole-object delegation of eligible regular files to the in-guest
//! EL1 kernel, and manages recall back to the host whenever host code touches
//! the description or its authority.

use parking_lot::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use carrick_abi::*;
use carrick_el1_abi::*;

use crate::dispatch::fd_table::{OpenDescription, OpenFile};
use crate::dispatch::fs::FsState;
use crate::kernel::objects::FileDescription;
use crate::kernel::{FileTableId, RlimitSet};

static EL1_REGION_HOST_PTR: AtomicUsize = AtomicUsize::new(0);

/// Record the host virtual address of the shared 64 MiB EL1 kernel aperture.
pub fn record_el1_region_host_ptr(ptr: usize) {
    EL1_REGION_HOST_PTR.store(ptr, Ordering::Release);
}

/// Clear the recorded host virtual address of the EL1 kernel aperture.
pub fn clear_el1_region_host_ptr() {
    EL1_REGION_HOST_PTR.store(0, Ordering::Release);
}

/// Retrieve the host virtual address of the EL1 kernel aperture, or 0 if not mapped.
pub fn get_el1_region_host_ptr() -> usize {
    EL1_REGION_HOST_PTR.load(Ordering::Acquire)
}

/// Publish the current task binding for an executor vCPU mailbox slot into the EL1 aperture.
pub fn publish_current_task(slot: usize, generation: u64, file_table: u64) {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 || slot >= 256 {
        return;
    }
    let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
    let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
    current_task.file_table.store(file_table, Ordering::Relaxed);
    current_task.generation.store(generation, Ordering::Release);
}

/// Clear the current task binding for an executor vCPU mailbox slot.
pub fn clear_current_task(slot: usize) {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 || slot >= 256 {
        return;
    }
    let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
    let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
    current_task.file_table.store(0, Ordering::Relaxed);
    current_task.generation.store(0, Ordering::Release);
}

static ALLOCATED_HANDLES: Mutex<[bool; MAX_DELEGATED_FILES]> =
    Mutex::new([false; MAX_DELEGATED_FILES]);

fn allocate_handle() -> Option<u32> {
    let mut handles = ALLOCATED_HANDLES.lock();
    for (i, in_use) in handles.iter_mut().enumerate() {
        if !*in_use {
            *in_use = true;
            return Some((i + 1) as u32);
        }
    }
    None
}

fn free_handle(handle: u32) {
    if handle >= 1 && (handle as usize) <= MAX_DELEGATED_FILES {
        let mut handles = ALLOCATED_HANDLES.lock();
        handles[handle as usize - 1] = false;
    }
}

/// Reasons why a file description cannot be delegated to EL1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotEligible {
    Disabled,
    NoRegion,
    NotRegularFile,
    NotRootfs,
    Watched,
    UnsupportedFlags,
    FileTooLarge,
    MultipleReferences,
    FsizeLimited,
    Mapped,
    RecordLocks,
    TableFull,
    AlreadyDelegated,
    IoError,
}

/// Delegate an open file to EL1 if all eligibility rules pass.
pub(crate) fn delegate(
    open_file: &OpenFile,
    file_table: FileTableId,
    fd: i32,
    fs: &FsState,
    rlimits: Option<&RlimitSet>,
) -> Result<u32, NotEligible> {
    if std::env::var_os("CARRICK_EL1").map_or(false, |val| val == "0") {
        return Err(NotEligible::Disabled);
    }
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 {
        return Err(NotEligible::NoRegion);
    }
    if open_file.description.delegation_handle() != 0 {
        return Err(NotEligible::AlreadyDelegated);
    }
    if open_file.description.common().fd_refs() != 1 {
        return Err(NotEligible::MultipleReferences);
    }
    if open_file.description.has_active_mappings() {
        return Err(NotEligible::Mapped);
    }
    if let Some(limits) = rlimits {
        let lim = limits.get(LinuxResource::Fsize);
        if lim.rlim_cur != LINUX_RLIM_INFINITY {
            return Err(NotEligible::FsizeLimited);
        }
    }
    if !fs.classic_record_locks.is_empty() {
        return Err(NotEligible::RecordLocks);
    }
    if !fs.fanotify_registry.is_empty() {
        return Err(NotEligible::Watched);
    }

    let Some(d) = open_file.description.open_description() else {
        return Err(NotEligible::NotRegularFile);
    };
    let open = d.write();

    let status = open_file.description.common().status_flags();
    let open_flags = LinuxOpenFlags::from_bits_truncate(status);
    if open_flags.intersects(
        LinuxOpenFlags::APPEND
            | LinuxOpenFlags::DIRECT
            | LinuxOpenFlags::SYNC
            | LinuxOpenFlags::DSYNC,
    ) {
        return Err(NotEligible::UnsupportedFlags);
    }

    let acc = status & LINUX_O_ACCMODE;
    let readable = acc == LINUX_O_RDONLY || acc == LINUX_O_RDWR;
    let writable_flag = acc == LINUX_O_WRONLY || acc == LINUX_O_RDWR;

    let (_path_str, size, offset, writable) = match &*open {
        OpenDescription::HostFile {
            host_fd,
            metadata,
            writable: w,
            ..
        } => {
            let path = metadata.path.to_str().unwrap_or("");
            if fs.vfs_mounts.resolve(path).is_some() {
                return Err(NotEligible::NotRootfs);
            }
            if !fs.inotify_registry.is_empty() && fs.inotify_registry.has_watches_covering(path) {
                return Err(NotEligible::Watched);
            }
            let mut st: libc::stat = unsafe { core::mem::zeroed() };
            if unsafe { libc::fstat(host_fd.raw(), &mut st) } != 0 {
                return Err(NotEligible::IoError);
            }
            if st.st_size < 0 || (st.st_size as u64) > DELEGATED_FILE_MAX_SIZE {
                return Err(NotEligible::FileTooLarge);
            }
            let cur_offset = unsafe { libc::lseek(host_fd.raw(), 0, libc::SEEK_CUR) };
            if cur_offset < 0 {
                return Err(NotEligible::IoError);
            }
            (
                path,
                st.st_size as u64,
                cur_offset as u64,
                *w && writable_flag,
            )
        }
        OpenDescription::File {
            path,
            contents,
            offset,
            writable: w,
            ..
        } => {
            if fs.vfs_mounts.resolve(path.as_str()).is_some() {
                return Err(NotEligible::NotRootfs);
            }
            if !fs.inotify_registry.is_empty()
                && fs.inotify_registry.has_watches_covering(path.as_str())
            {
                return Err(NotEligible::Watched);
            }
            let cur_len = contents.len().map_err(|_| NotEligible::IoError)?;
            if cur_len > DELEGATED_FILE_MAX_SIZE {
                return Err(NotEligible::FileTooLarge);
            }
            (path.as_str(), cur_len, *offset as u64, *w && writable_flag)
        }
        _ => return Err(NotEligible::NotRegularFile),
    };

    let handle = allocate_handle().ok_or(NotEligible::TableFull)?;

    let cache_ptr = (region_ptr
        + EL1_CACHE_OFFSET as usize
        + (handle as usize - 1) * DELEGATED_FILE_MAX_SIZE as usize) as *mut u8;

    if size > 0 {
        match &*open {
            OpenDescription::HostFile { host_fd, .. } => {
                let n = unsafe {
                    libc::pread(
                        host_fd.raw(),
                        cache_ptr as *mut libc::c_void,
                        size as usize,
                        0,
                    )
                };
                if n < 0 || (n as u64) != size {
                    free_handle(handle);
                    return Err(NotEligible::IoError);
                }
            }
            OpenDescription::File { contents, .. } => {
                let cache_slice =
                    unsafe { std::slice::from_raw_parts_mut(cache_ptr, size as usize) };
                if contents.read_at(0, cache_slice).is_err() {
                    free_handle(handle);
                    return Err(NotEligible::IoError);
                }
            }
            _ => unreachable!(),
        }
    }

    let file_ptr = (region_ptr
        + EL1_OBJECT_TABLE_OFFSET as usize
        + (handle as usize - 1) * core::mem::size_of::<DelegatedFile>())
        as *mut DelegatedFile;
    let file = unsafe { &mut *file_ptr };
    file.host_lock();
    file.generation.store(1, Ordering::Relaxed);
    file.offset.store(offset, Ordering::Relaxed);
    file.size.store(size, Ordering::Relaxed);
    let mut flags_val = 0;
    if readable {
        flags_val |= DELEGATED_FLAG_READABLE;
    }
    if writable {
        flags_val |= DELEGATED_FLAG_WRITABLE;
    }
    file.flags.store(flags_val, Ordering::Relaxed);
    file.dirty_mask.store(0, Ordering::Relaxed);
    file.state.store(DELEGATED_STATE_GUEST, Ordering::Release);
    file.unlock();

    let fd_map_base = (region_ptr + EL1_FD_MAP_OFFSET as usize) as *const FdMapSlot;
    let mut slot_found = false;
    for slot_idx in 0..FD_MAP_CAPACITY {
        let slot = unsafe { &*fd_map_base.add(slot_idx) };
        if slot.handle.load(Ordering::Relaxed) == 0 {
            slot.file_table.store(file_table.raw(), Ordering::Relaxed);
            slot.fd.store(fd as u32, Ordering::Relaxed);
            slot.handle.store(handle, Ordering::Release);
            slot_found = true;
            break;
        }
    }

    if !slot_found {
        file.host_lock();
        file.state.store(DELEGATED_STATE_DEAD, Ordering::Release);
        file.unlock();
        free_handle(handle);
        return Err(NotEligible::TableFull);
    }

    open_file.description.set_delegation_handle(handle);
    Ok(handle)
}

/// Helper for tests to delegate with default/mocked environment.
#[cfg(test)]
pub fn delegate_for_test(
    open_file: &OpenFile,
    file_table: FileTableId,
    fd: i32,
) -> Result<u32, NotEligible> {
    let fs = FsState::new_with_host_resolver(None);
    delegate(open_file, file_table, fd, &fs, None)
}

/// Recall a delegated file description back to host authority.
pub(crate) fn recall(description: &FileDescription) {
    let handle = description.delegation_handle();
    if handle == 0 {
        return;
    }
    let Some(d) = description.open_description() else {
        return;
    };
    let mut guard = d.write();
    let handle = description.delegation_handle();
    if handle == 0 {
        return;
    }
    recall_locked(description, &mut guard, handle);
}

/// Recall a file description if it is currently delegated.
pub(crate) fn recall_if_delegated(description: &FileDescription) {
    if description.delegation_handle() != 0 {
        recall(description);
    }
}

fn recall_locked(description: &FileDescription, open: &mut OpenDescription, handle: u32) {
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 {
        description.set_delegation_handle(0);
        free_handle(handle);
        return;
    }
    let file_ptr = (region_ptr
        + EL1_OBJECT_TABLE_OFFSET as usize
        + (handle as usize - 1) * core::mem::size_of::<DelegatedFile>())
        as *mut DelegatedFile;
    let file = unsafe { &mut *file_ptr };
    file.host_lock();
    file.state
        .store(DELEGATED_STATE_RECALLING, Ordering::Release);

    let guest_offset = file.offset.load(Ordering::Acquire);
    let guest_size = file.size.load(Ordering::Acquire);
    let dirty_mask = file.dirty_mask.swap(0, Ordering::AcqRel);

    let cache_ptr = (region_ptr
        + EL1_CACHE_OFFSET as usize
        + (handle as usize - 1) * DELEGATED_FILE_MAX_SIZE as usize) as *mut u8;

    if dirty_mask != 0 {
        for i in 0..64 {
            if (dirty_mask & (1 << i)) != 0 {
                let page_offset = i as u64 * 4096;
                if page_offset < guest_size {
                    let page_len = std::cmp::min(4096, (guest_size - page_offset) as usize);
                    let page_slice =
                        unsafe { std::slice::from_raw_parts(cache_ptr.add(i * 4096), page_len) };
                    match open {
                        OpenDescription::HostFile { host_fd, .. } => unsafe {
                            libc::pwrite(
                                host_fd.raw(),
                                page_slice.as_ptr() as *const libc::c_void,
                                page_len,
                                page_offset as libc::off_t,
                            );
                        },
                        OpenDescription::File { contents, .. } => {
                            let _ = contents.write_at(page_offset, page_slice);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    match open {
        OpenDescription::HostFile {
            host_fd, metadata, ..
        } => {
            unsafe {
                libc::lseek(host_fd.raw(), guest_offset as libc::off_t, libc::SEEK_SET);
                libc::ftruncate(host_fd.raw(), guest_size as libc::off_t);
            }
            metadata.size = guest_size as usize;
        }
        OpenDescription::File {
            contents,
            offset,
            metadata,
            ..
        } => {
            let _ = contents.resize(guest_size);
            *offset = guest_offset as usize;
            metadata.size = guest_size as usize;
        }
        _ => {}
    }

    let fd_map_base = (region_ptr + EL1_FD_MAP_OFFSET as usize) as *const FdMapSlot;
    for slot_idx in 0..FD_MAP_CAPACITY {
        let slot = unsafe { &*fd_map_base.add(slot_idx) };
        if slot.handle.load(Ordering::Acquire) == handle {
            slot.handle.store(0, Ordering::Release);
            slot.file_table.store(0, Ordering::Release);
            slot.fd.store(0, Ordering::Release);
        }
    }

    free_handle(handle);

    file.state.store(DELEGATED_STATE_DEAD, Ordering::Release);
    file.unlock();

    description.set_delegation_handle(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::fd_table::{FileContents, HostFdRef, OpenDescriptionBase};
    use crate::kernel::objects::{FileSlot, FileTable};
    use carrick_vfs::rootfs::RootFsMetadata;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::sync::Arc;
    use tempfile::NamedTempFile;

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    struct TestEl1Region {
        _lock: parking_lot::MutexGuard<'static, ()>,
        buffer: Vec<u8>,
    }

    impl TestEl1Region {
        fn new() -> Self {
            let lock = TEST_LOCK.lock();
            let buffer = vec![0u8; EL1_REGION_SIZE as usize];
            record_el1_region_host_ptr(buffer.as_ptr() as usize);
            Self {
                _lock: lock,
                buffer,
            }
        }
    }

    impl Drop for TestEl1Region {
        fn drop(&mut self) {
            clear_el1_region_host_ptr();
            let mut handles = ALLOCATED_HANDLES.lock();
            *handles = [false; MAX_DELEGATED_FILES];
        }
    }

    fn test_metadata(path: impl Into<std::path::PathBuf>, size: usize) -> RootFsMetadata {
        RootFsMetadata {
            path: path.into(),
            kind: carrick_vfs::rootfs::RootFsEntryKind::File,
            mode: 0o644,
            size,
        }
    }

    fn create_test_host_file(initial_data: &[u8]) -> (NamedTempFile, OpenFile) {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(initial_data).unwrap();
        tmp.flush().unwrap();
        let raw_fd = unsafe { libc::dup(tmp.as_raw_fd()) };
        let host_fd = HostFdRef::new(raw_fd);
        let desc = OpenDescription::HostFile {
            base: OpenDescriptionBase::new(LINUX_O_RDWR),
            host_fd,
            metadata: test_metadata(tmp.path(), initial_data.len()),
            writable: true,
        };
        let file_desc = crate::dispatch::fd_table::kernel_file_description(
            Arc::new(parking_lot::RwLock::new(desc)),
            LINUX_O_RDWR,
        );
        file_desc.common().retain_fd_ref();
        let open_file = OpenFile::new(file_desc, 0);
        (tmp, open_file)
    }

    fn create_test_in_memory_file(initial_data: &[u8]) -> OpenFile {
        let desc = OpenDescription::File {
            base: OpenDescriptionBase::new(LINUX_O_RDWR),
            path: "/test_file.txt".to_string(),
            metadata: test_metadata("/test_file.txt", initial_data.len()),
            contents: FileContents::dense(initial_data.to_vec()),
            offset: 0,
            writable: true,
        };
        let file_desc = crate::dispatch::fd_table::kernel_file_description(
            Arc::new(parking_lot::RwLock::new(desc)),
            LINUX_O_RDWR,
        );
        file_desc.common().retain_fd_ref();
        OpenFile::new(file_desc, 0)
    }

    #[test]
    fn test_eligibility_matrix() {
        let _region = TestEl1Region::new();
        let table_id = FileTableId::from_raw_u64(1).unwrap();

        // 1. Valid file delegates successfully
        let (_tmp, valid_file) = create_test_host_file(b"hello world");
        let res = delegate_for_test(&valid_file, table_id, 3);
        assert!(res.is_ok(), "expected valid file to delegate: {res:?}");
        let handle = res.unwrap();
        assert_eq!(valid_file.description.delegation_handle(), handle);
        recall(&valid_file.description);
        assert_eq!(valid_file.description.delegation_handle(), 0);

        // 2. Already delegated
        let (_tmp, file2) = create_test_host_file(b"test");
        assert!(delegate_for_test(&file2, table_id, 4).is_ok());
        assert_eq!(
            delegate_for_test(&file2, table_id, 4),
            Err(NotEligible::AlreadyDelegated)
        );
        recall(&file2.description);

        // 3. File too large (> 256 KiB)
        let large_data = vec![0xAAu8; (DELEGATED_FILE_MAX_SIZE + 1) as usize];
        let (_tmp, large_file) = create_test_host_file(&large_data);
        assert_eq!(
            delegate_for_test(&large_file, table_id, 5),
            Err(NotEligible::FileTooLarge)
        );

        // 4. Multiple references
        let (_tmp, multi_ref_file) = create_test_host_file(b"multi");
        multi_ref_file.description.common().retain_fd_ref();
        assert_eq!(
            delegate_for_test(&multi_ref_file, table_id, 6),
            Err(NotEligible::MultipleReferences)
        );
        multi_ref_file.description.common().release_fd_ref();

        // 5. Unsupported flags (O_APPEND)
        let desc_append = OpenDescription::File {
            base: OpenDescriptionBase::new(LINUX_O_RDWR | LINUX_O_APPEND),
            path: "/append.txt".to_string(),
            metadata: test_metadata("/append.txt", 10),
            contents: FileContents::dense(vec![0; 10]),
            offset: 0,
            writable: true,
        };
        let file_desc = crate::dispatch::fd_table::kernel_file_description(
            Arc::new(parking_lot::RwLock::new(desc_append)),
            LINUX_O_RDWR | LINUX_O_APPEND,
        );
        file_desc.common().retain_fd_ref();
        let append_file = OpenFile::new(file_desc, 0);
        assert_eq!(
            delegate_for_test(&append_file, table_id, 7),
            Err(NotEligible::UnsupportedFlags)
        );

        // 6. Active mapping
        let (_tmp, mapped_file) = create_test_host_file(b"mapped");
        let mapping = mapped_file.description.retain_mapping();
        assert_eq!(
            delegate_for_test(&mapped_file, table_id, 8),
            Err(NotEligible::Mapped)
        );
        drop(mapping);
    }

    #[test]
    fn test_recall_host_file_round_trip() {
        let region = TestEl1Region::new();
        let table_id = FileTableId::from_raw_u64(1).unwrap();
        let (_tmp, host_file) = create_test_host_file(b"initial data");

        let handle = delegate_for_test(&host_file, table_id, 3).expect("delegate");
        assert_eq!(host_file.description.delegation_handle(), handle);

        // Simulate guest writing 5 bytes at offset 12 (extending file to 17 bytes)
        let region_ptr = region.buffer.as_ptr() as usize;
        let file_ptr = (region_ptr
            + EL1_OBJECT_TABLE_OFFSET as usize
            + (handle as usize - 1) * core::mem::size_of::<DelegatedFile>())
            as *mut DelegatedFile;
        let file = unsafe { &mut *file_ptr };
        let cache_ptr = (region_ptr
            + EL1_CACHE_OFFSET as usize
            + (handle as usize - 1) * DELEGATED_FILE_MAX_SIZE as usize)
            as *mut u8;

        unsafe {
            let write_slice = std::slice::from_raw_parts_mut(cache_ptr.add(12), 5);
            write_slice.copy_from_slice(b"world");
        }
        file.offset.store(17, Ordering::Release);
        file.size.store(17, Ordering::Release);
        file.dirty_mask.store(1, Ordering::Release); // page 0 dirty

        // Recall back to host
        recall(&host_file.description);
        assert_eq!(host_file.description.delegation_handle(), 0);

        // Verify host file contents, size, and offset
        let mut buf = [0u8; 17];
        let open_desc = host_file.description.open_description().unwrap().read();
        let OpenDescription::HostFile {
            host_fd, metadata, ..
        } = &*open_desc
        else {
            panic!("expected HostFile");
        };
        assert_eq!(metadata.size, 17);
        let n = unsafe { libc::pread(host_fd.raw(), buf.as_mut_ptr() as *mut libc::c_void, 17, 0) };
        assert_eq!(n, 17);
        assert_eq!(&buf, b"initial dataworld");
        let cur_offset = unsafe { libc::lseek(host_fd.raw(), 0, libc::SEEK_CUR) };
        assert_eq!(cur_offset, 17);
    }

    #[test]
    fn test_recall_in_memory_file_round_trip() {
        let region = TestEl1Region::new();
        let table_id = FileTableId::from_raw_u64(1).unwrap();
        let mem_file = create_test_in_memory_file(b"in-memory data");

        let handle = delegate_for_test(&mem_file, table_id, 3).expect("delegate");
        assert_eq!(mem_file.description.delegation_handle(), handle);

        // Simulate guest writing 6 bytes at offset 14
        let region_ptr = region.buffer.as_ptr() as usize;
        let file_ptr = (region_ptr
            + EL1_OBJECT_TABLE_OFFSET as usize
            + (handle as usize - 1) * core::mem::size_of::<DelegatedFile>())
            as *mut DelegatedFile;
        let file = unsafe { &mut *file_ptr };
        let cache_ptr = (region_ptr
            + EL1_CACHE_OFFSET as usize
            + (handle as usize - 1) * DELEGATED_FILE_MAX_SIZE as usize)
            as *mut u8;

        unsafe {
            let write_slice = std::slice::from_raw_parts_mut(cache_ptr.add(14), 6);
            write_slice.copy_from_slice(b"-extra");
        }
        file.offset.store(20, Ordering::Release);
        file.size.store(20, Ordering::Release);
        file.dirty_mask.store(1, Ordering::Release);

        // Recall back to host
        recall(&mem_file.description);
        assert_eq!(mem_file.description.delegation_handle(), 0);

        let open_desc = mem_file.description.open_description().unwrap().read();
        let OpenDescription::File {
            contents,
            offset,
            metadata,
            ..
        } = &*open_desc
        else {
            panic!("expected File");
        };
        assert_eq!(*offset, 20);
        assert_eq!(metadata.size, 20);
        let mut buf = [0u8; 20];
        contents.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"in-memory data-extra");
    }

    #[test]
    fn test_description_guard_recalls() {
        let _region = TestEl1Region::new();
        let table_id = FileTableId::from_raw_u64(1).unwrap();
        let (_tmp, host_file) = create_test_host_file(b"test guard");

        assert!(delegate_for_test(&host_file, table_id, 3).is_ok());
        assert_ne!(host_file.description.delegation_handle(), 0);

        // Touching description.read() automatically recalls
        let guard = host_file.description.read().unwrap();
        assert_eq!(host_file.description.delegation_handle(), 0);
        drop(guard);

        // Re-delegate
        assert!(delegate_for_test(&host_file, table_id, 3).is_ok());
        assert_ne!(host_file.description.delegation_handle(), 0);

        // Touching description.write() automatically recalls
        let guard = host_file.description.write().unwrap();
        assert_eq!(host_file.description.delegation_handle(), 0);
        drop(guard);
    }

    #[test]
    fn test_fork_recalls() {
        let _region = TestEl1Region::new();
        let parent_table_id = FileTableId::from_raw_u64(1).unwrap();
        let child_table_id = FileTableId::from_raw_u64(2).unwrap();
        let (_tmp, host_file) = create_test_host_file(b"fork test");

        let parent_table = Arc::new(FileTable::new(parent_table_id));
        let reservation = parent_table.reserve_exact_target(3, 1024).unwrap();
        let slot = FileSlot::new(Arc::clone(&host_file.description), 0);
        reservation.commit(slot).unwrap();

        assert!(delegate_for_test(&host_file, parent_table_id, 3).is_ok());
        assert_ne!(host_file.description.delegation_handle(), 0);

        // Fork copies file table
        let child_table = FileTable::for_fork_copy(child_table_id, &parent_table);
        assert_eq!(
            host_file.description.delegation_handle(),
            0,
            "fork must recall delegated description"
        );
        drop(child_table);
    }

    #[test]
    fn test_dup_recalls() {
        let _region = TestEl1Region::new();
        let table_id = FileTableId::from_raw_u64(1).unwrap();
        let (_tmp, host_file) = create_test_host_file(b"dup test");

        assert!(delegate_for_test(&host_file, table_id, 3).is_ok());
        assert_ne!(host_file.description.delegation_handle(), 0);

        // Calling retain_fd_ref (e.g. from dup) recalls the description
        host_file.description.retain_fd_ref();
        assert_eq!(
            host_file.description.delegation_handle(),
            0,
            "dup must recall delegated description"
        );
        host_file.description.release_fd_ref();
    }
}
