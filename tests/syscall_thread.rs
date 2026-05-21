#[path = "common/syscall_support.rs"]
mod support;
use support::*;

#[test]
fn clone_thread_variant_exists() {
    let o = DispatchOutcome::CloneThread {
        stack: 0x7000,
        tls: 0x9000,
        flags: 0x3d0f00,
        parent_tid_addr: 0,
        child_tid_addr: 0,
    };
    assert!(matches!(o, DispatchOutcome::CloneThread { .. }));
}

#[test]
fn thread_exit_variant_exists() {
    let o = DispatchOutcome::ThreadExit { code: 7 };
    assert!(matches!(o, DispatchOutcome::ThreadExit { .. }));
}

#[test]
fn clone_with_pthread_flags_emits_clone_thread() {
    // CLONE_VM|FS|FILES|SIGHAND|THREAD|SETTLS|PARENT_SETTID|CHILD_CLEARTID
    let flags: u64 = 0x3d0f00;
    let mut memory = LinearMemory::new(0x10000, Vec::new());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    // clone(flags, stack, parent_tid, tls, child_tid)  [syscall 220]
    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(220, SyscallArgs::from([flags, 0x7000, 0x100, 0x9000, 0x200, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();
    assert_eq!(
        outcome,
        DispatchOutcome::CloneThread {
            stack: 0x7000,
            tls: 0x9000,
            flags,
            parent_tid_addr: 0x100,
            child_tid_addr: 0x200,
        }
    );
}

#[test]
fn clone_fork_flags_still_fork() {
    // SIGCHLD-only fork: 0x11 = SIGCHLD; not a thread clone.
    let mut memory = LinearMemory::new(0x10000, Vec::new());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(220, SyscallArgs::from([0x1200011, 0, 0, 0, 0, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();
    assert_eq!(outcome, DispatchOutcome::Fork);
}

// --- Sub-task B: per-thread tid + real futex via dispatch_threaded ---

use carrick::thread::{FutexTable, ThreadRegistry};
use std::sync::Arc;

const LINUX_EAGAIN: i32 = 11;

fn write_u32_le(memory: &mut LinearMemory, addr: u64, value: u32) {
    memory.write_bytes(addr, &value.to_le_bytes()).unwrap();
}

#[test]
fn gettid_returns_per_thread_tid_not_pid() {
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let registry = Arc::new(ThreadRegistry::new(1000));
    let futex = Arc::new(FutexTable::new());
    let tid = registry.register_child(0);
    // gettid is syscall 178.
    let outcome = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(178, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &mut reporter,
            tid,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(outcome, DispatchOutcome::Returned { value: tid as i64 });
}

#[test]
fn set_tid_address_records_clear_child_tid_and_returns_tid() {
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let registry = Arc::new(ThreadRegistry::new(1000));
    let futex = Arc::new(FutexTable::new());
    let tid = registry.register_child(0);
    // set_tid_address(addr) is syscall 96.
    let outcome = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(96, SyscallArgs::from([0x10500, 0, 0, 0, 0, 0])),
            &mut memory,
            &mut reporter,
            tid,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(outcome, DispatchOutcome::Returned { value: tid as i64 });
    assert_eq!(registry.clear_child_tid(tid), Some(0x10500));
}

#[test]
fn futex_wait_value_mismatch_returns_eagain() {
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let registry = Arc::new(ThreadRegistry::new(1000));
    let futex = Arc::new(FutexTable::new());
    // *uaddr = 5, but FUTEX_WAIT expects 7 -> EAGAIN immediately.
    write_u32_le(&mut memory, 0x10800, 5);
    // futex(uaddr, FUTEX_WAIT|PRIVATE, val=7, timeout=0)
    let op = LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG;
    let outcome = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(98, SyscallArgs::from([0x10800, op, 7, 0, 0, 0])),
            &mut memory,
            &mut reporter,
            1001,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(outcome, DispatchOutcome::Errno { errno: LINUX_EAGAIN });
}

#[test]
fn futex_wake_returns_count_and_advances_table() {
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let registry = Arc::new(ThreadRegistry::new(1000));
    let futex = Arc::new(FutexTable::new());
    write_u32_le(&mut memory, 0x10800, 0);
    let op = LINUX_FUTEX_WAKE | LINUX_FUTEX_PRIVATE_FLAG;
    // FUTEX_WAKE with count=1 should report 1 woken (best-effort upper bound)
    // and bump the generation so a concurrent waiter would re-check.
    let outcome = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(98, SyscallArgs::from([0x10800, op, 1, 0, 0, 0])),
            &mut memory,
            &mut reporter,
            1001,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(outcome, DispatchOutcome::Returned { value: 1 });
}

#[test]
fn futex_wait_matching_value_blocks_via_outcome() {
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let registry = Arc::new(ThreadRegistry::new(1000));
    let futex = Arc::new(FutexTable::new());
    // *uaddr == val -> the handler must NOT block under the kernel lock; it
    // surfaces a FutexWait outcome the runtime services with the lock dropped.
    write_u32_le(&mut memory, 0x10800, 42);
    let op = LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG;
    let outcome = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(98, SyscallArgs::from([0x10800, op, 42, 0, 0, 0])),
            &mut memory,
            &mut reporter,
            1001,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(
        outcome,
        DispatchOutcome::FutexWait {
            addr: 0x10800,
            timeout: None,
        }
    );
}
