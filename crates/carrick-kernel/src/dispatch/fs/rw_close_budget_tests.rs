//! Deterministic per-call budget tests for forwarded read, write, and close syscalls.
//!
//! Measures and asserts on:
//! - table_read_locks
//! - table_write_locks
//! - table_lookups
//! - authority_checks
//! - host_reads / host_writes / host_closes
//! - allocations / allocated_bytes
//!
//! Ensures forwarded host operations do not pay non-essential per-call work
//! (repeated lookups, lock ping-pong, allocations).

use parking_lot::RwLock;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use crate::compat::CompatReporter;
use crate::dispatch::budget_meter;
use crate::dispatch::fd_table::{HostFdRef, kernel_file_description};
use crate::dispatch::outcome::LinearMemory;
use crate::dispatch::{
    DispatchOutcome, OpenDescription, OpenDescriptionBase, OpenFile, SyscallArgs,
    SyscallDispatcher, SyscallRequest,
};
use carrick_vfs::rootfs::{RootFsEntryKind, RootFsMetadata};

const SYS_CLOSE: u64 = 57;
const SYS_READ: u64 = 63;
const SYS_WRITE: u64 = 64;
const MEM_BASE: u64 = 0x1000_0000;
const MEM_LEN: usize = 0x10_0000; // 1 MiB

fn create_host_file_open_file(file: &std::fs::File) -> OpenFile {
    let raw_fd = unsafe { libc::dup(file.as_raw_fd()) };
    assert!(raw_fd >= 0, "dup host fd failed");
    let description = kernel_file_description(
        Arc::new(RwLock::new(OpenDescription::HostFile {
            base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDWR),
            host_fd: HostFdRef::new(raw_fd),
            metadata: RootFsMetadata {
                path: std::path::PathBuf::from("/tmp/budget-test"),
                kind: RootFsEntryKind::File,
                mode: 0o644,
                size: 0,
            },
            writable: true,
        })),
        crate::linux_abi::LINUX_O_RDWR,
    );
    OpenFile::new(description, 0)
}

#[test]
fn forwarded_read_per_call_budget() {
    let mut file = tempfile::tempfile().expect("tempfile");
    let data = vec![0x42u8; 16384];
    file.write_all(&data).expect("write data");
    file.seek(SeekFrom::Start(0)).expect("seek to start");

    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
    let reporter = CompatReporter::default();
    let context = dispatcher.capture_one_task_context().expect("task context");

    let open_file = create_host_file_open_file(&file);
    let guest_fd = dispatcher
        .install_fd_at_or_above(3, open_file)
        .expect("install fd");

    let buf_addr = MEM_BASE + 0x1000;
    let count = 16384u64;

    let (outcome, snapshot) = budget_meter::measure_no_allocations(|| {
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(
                    SYS_READ,
                    SyscallArgs([guest_fd as u64, buf_addr, count, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .expect("dispatch read")
    });

    assert_eq!(outcome, DispatchOutcome::Returned { value: 16384 });
    assert_eq!(snapshot.host_reads, 1, "expected 1 host read");
    assert_eq!(
        snapshot.table_lookups, 1,
        "table_lookups budget exceeded: got {}, expected 1",
        snapshot.table_lookups
    );
    assert!(
        snapshot.table_read_locks <= 1,
        "table_read_locks budget exceeded: got {}, expected <= 1",
        snapshot.table_read_locks
    );
    assert_eq!(
        snapshot.table_write_locks, 0,
        "table_write_locks should be 0 on read: got {}",
        snapshot.table_write_locks
    );
    assert_eq!(
        snapshot.authority_checks, 1,
        "authority_checks budget exceeded: got {}, expected 1",
        snapshot.authority_checks
    );
    assert_eq!(
        snapshot.allocations, 0,
        "allocations budget exceeded: got {} ({} bytes), expected 0",
        snapshot.allocations, snapshot.allocated_bytes
    );
}

#[test]
fn forwarded_write_per_call_budget() {
    assert_forwarded_write_per_call_budget(|_| {});
}

mod serial_host {
    #[test]
    fn forwarded_write_after_foreign_namespace_bump_per_call_budget() {
        super::assert_forwarded_write_per_call_budget(|dispatcher| {
            // Publish through the same backing cohort used by production.
            dispatcher
                .fs
                .rootfs_vfs
                .dentry_cache
                .coherence
                .bump_generation();
        });
    }
}

fn assert_forwarded_write_per_call_budget(before_write: impl FnOnce(&SyscallDispatcher)) {
    let file = tempfile::tempfile().expect("tempfile");

    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = LinearMemory::new(MEM_BASE, vec![0x55u8; MEM_LEN]);
    let reporter = CompatReporter::default();
    let context = dispatcher.capture_one_task_context().expect("task context");

    let open_file = create_host_file_open_file(&file);
    let guest_fd = dispatcher
        .install_fd_at_or_above(3, open_file)
        .expect("install fd");

    let buf_addr = MEM_BASE + 0x1000;
    let count = 8192u64;
    // Inject a mutation between cache construction and this first write.
    // No inode has been cached here, even when the namespace generation moves.
    before_write(&dispatcher);

    let (outcome, snapshot) = budget_meter::measure_no_allocations(|| {
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(
                    SYS_WRITE,
                    SyscallArgs([guest_fd as u64, buf_addr, count, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .expect("dispatch write")
    });

    assert_eq!(outcome, DispatchOutcome::Returned { value: 8192 });
    assert_eq!(snapshot.host_writes, 1, "expected 1 host write");
    assert_eq!(
        snapshot.table_lookups, 1,
        "table_lookups budget exceeded: got {}, expected 1",
        snapshot.table_lookups
    );
    assert!(
        snapshot.table_read_locks <= 1,
        "table_read_locks budget exceeded: got {}, expected <= 1",
        snapshot.table_read_locks
    );
    assert_eq!(
        snapshot.table_write_locks, 0,
        "table_write_locks should be 0 on write: got {}",
        snapshot.table_write_locks
    );
    assert_eq!(
        snapshot.authority_checks, 1,
        "authority_checks budget exceeded: got {}, expected 1",
        snapshot.authority_checks
    );
    assert_eq!(
        snapshot.allocations, 0,
        "allocations budget exceeded: got {} ({} bytes), expected 0",
        snapshot.allocations, snapshot.allocated_bytes
    );
}

#[test]
fn forwarded_close_per_call_budget() {
    let file = tempfile::tempfile().expect("tempfile");

    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
    let reporter = CompatReporter::default();
    let context = dispatcher.capture_one_task_context().expect("task context");

    let open_file = create_host_file_open_file(&file);
    let guest_fd = dispatcher
        .install_fd_at_or_above(3, open_file)
        .expect("install fd");

    let (outcome, snapshot) = budget_meter::measure_no_allocations(|| {
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(SYS_CLOSE, SyscallArgs([guest_fd as u64, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .expect("dispatch close")
    });

    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
    assert_eq!(snapshot.host_closes, 1, "expected 1 host close");
    assert_eq!(
        snapshot.table_lookups, 1,
        "table_lookups budget exceeded: got {}, expected 1",
        snapshot.table_lookups
    );
    assert_eq!(
        snapshot.table_read_locks, 0,
        "table_read_locks should be 0 on close: got {}",
        snapshot.table_read_locks
    );
    assert_eq!(
        snapshot.table_write_locks, 1,
        "table_write_locks should be 1 on close: got {}",
        snapshot.table_write_locks
    );
    assert_eq!(
        snapshot.allocations, 0,
        "allocations budget exceeded: got {} ({} bytes), expected 0",
        snapshot.allocations, snapshot.allocated_bytes
    );
}
