#![allow(clippy::unwrap_used)]
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
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    // clone(flags, stack, parent_tid, tls, child_tid)  [syscall 220]
    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                220,
                SyscallArgs::from([flags, 0x7000, 0x100, 0x9000, 0x200, 0]),
            ),
            &mut memory,
            &reporter,
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
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(220, SyscallArgs::from([0x1200011, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    // No CLONE_PIDFD in these flags, so no pidfd-out pointer. The low byte
    // (0x11 = SIGCHLD) is threaded through as the child-exit signal.
    assert_eq!(
        outcome,
        DispatchOutcome::Fork {
            pidfd_out: None,
            exit_signal: 0x11,
        }
    );
}

// --- Sub-task B: per-thread tid + real futex via dispatch_threaded ---

use carrick_runtime::thread::{FutexTable, ThreadRegistry};
use std::sync::Arc;

const LINUX_EAGAIN: i32 = 11;
const LINUX_SCHED_OTHER: i64 = 0;
const SYS_SCHED_GETSCHEDULER: u64 = 120;
const SYS_SCHED_GETPARAM: u64 = 121;

fn write_u32_le(memory: &mut LinearMemory, addr: u64, value: u32) {
    memory.write_bytes(addr, &value.to_le_bytes()).unwrap();
}

#[test]
fn gettid_returns_per_thread_tid_not_pid() {
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
    let reporter = CompatReporter::default();
    let dispatcher = SyscallDispatcher::new();
    let registry = Arc::new(ThreadRegistry::new(1000));
    let futex = Arc::new(FutexTable::new());
    let tid = registry.register_child(0);
    // gettid is syscall 178.
    let outcome = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(178, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
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
    let reporter = CompatReporter::default();
    let dispatcher = SyscallDispatcher::new();
    let registry = Arc::new(ThreadRegistry::new(1000));
    let futex = Arc::new(FutexTable::new());
    let tid = registry.register_child(0);
    // set_tid_address(addr) is syscall 96.
    let outcome = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(96, SyscallArgs::from([0x10500, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
            tid,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(outcome, DispatchOutcome::Returned { value: tid as i64 });
    assert_eq!(registry.clear_child_tid(tid), Some(0x10500));
}

#[test]
fn sched_getscheduler_accepts_live_sibling_tid() {
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
    let reporter = CompatReporter::default();
    let dispatcher = SyscallDispatcher::new();
    let registry = Arc::new(ThreadRegistry::new(1000));
    let futex = Arc::new(FutexTable::new());
    let sibling = registry.register_child(0);

    let outcome = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(
                SYS_SCHED_GETSCHEDULER,
                SyscallArgs::from([sibling as u64, 0, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
            1000,
            &registry,
            &futex,
        )
        .unwrap();

    assert_eq!(
        outcome,
        DispatchOutcome::Returned {
            value: LINUX_SCHED_OTHER
        }
    );
}

#[test]
fn sched_getparam_accepts_live_sibling_tid() {
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
    let reporter = CompatReporter::default();
    let dispatcher = SyscallDispatcher::new();
    let registry = Arc::new(ThreadRegistry::new(1000));
    let futex = Arc::new(FutexTable::new());
    let sibling = registry.register_child(0);

    let outcome = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(
                SYS_SCHED_GETPARAM,
                SyscallArgs::from([sibling as u64, 0x10800, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
            1000,
            &registry,
            &futex,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
    assert_eq!(read_i32_le(&memory, 0x10800), 0);
}

#[test]
fn sched_getscheduler_unknown_sibling_tid_is_esrch() {
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
    let reporter = CompatReporter::default();
    let dispatcher = SyscallDispatcher::new();
    let registry = Arc::new(ThreadRegistry::new(1000));
    let futex = Arc::new(FutexTable::new());

    let outcome = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(
                SYS_SCHED_GETSCHEDULER,
                SyscallArgs::from([424242, 0, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
            1000,
            &registry,
            &futex,
        )
        .unwrap();

    assert_eq!(
        outcome,
        DispatchOutcome::Errno {
            errno: LINUX_ESRCH
        }
    );
}

#[test]
fn futex_wait_value_mismatch_returns_eagain() {
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
    let reporter = CompatReporter::default();
    let dispatcher = SyscallDispatcher::new();
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
            &reporter,
            1001,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(
        outcome,
        DispatchOutcome::Errno {
            errno: LINUX_EAGAIN
        }
    );
}

#[test]
fn futex_wake_returns_count_and_advances_table() {
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
    let reporter = CompatReporter::default();
    let dispatcher = SyscallDispatcher::new();
    let registry = Arc::new(ThreadRegistry::new(1000));
    let futex = Arc::new(FutexTable::new());
    write_u32_le(&mut memory, 0x10800, 0);
    let op = LINUX_FUTEX_WAKE | LINUX_FUTEX_PRIVATE_FLAG;
    // FUTEX_WAKE with no parked waiter reports the actual wake count: zero.
    let outcome = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(98, SyscallArgs::from([0x10800, op, 1, 0, 0, 0])),
            &mut memory,
            &reporter,
            1001,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
}

#[test]
fn futex_wait_matching_value_blocks_via_outcome() {
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
    let reporter = CompatReporter::default();
    let dispatcher = SyscallDispatcher::new();
    let registry = Arc::new(ThreadRegistry::new(1000));
    let futex = Arc::new(FutexTable::new());
    // *uaddr == val -> the handler must NOT block under the dispatcher lock; it
    // surfaces a FutexWait outcome the runtime services with the lock dropped.
    write_u32_le(&mut memory, 0x10800, 42);
    let op = LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG;
    let outcome = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(98, SyscallArgs::from([0x10800, op, 42, 0, 0, 0])),
            &mut memory,
            &reporter,
            1001,
            &registry,
            &futex,
        )
        .unwrap();
    match outcome {
        DispatchOutcome::FutexWait { wait, timeout } => {
            assert_eq!(wait.addr, 0x10800);
            assert_eq!(timeout, None);
        }
        other => panic!("expected FutexWait, got {other:?}"),
    }
}

#[test]
fn futex_requeue_private_no_waiters_returns_zero() {
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
    let reporter = CompatReporter::default();
    let dispatcher = SyscallDispatcher::new();
    let registry = Arc::new(ThreadRegistry::new(1000));
    let futex = Arc::new(FutexTable::new());
    write_u32_le(&mut memory, 0x10800, 0);
    write_u32_le(&mut memory, 0x10900, 0);

    let op = LINUX_FUTEX_REQUEUE | LINUX_FUTEX_PRIVATE_FLAG;
    let outcome = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(98, SyscallArgs::from([0x10800, op, 1, 8, 0x10900, 0])),
            &mut memory,
            &reporter,
            1001,
            &registry,
            &futex,
        )
        .unwrap();

    // Real Linux FUTEX_REQUEUE returns the count of waiters woken+requeued
    // (0 with no waiters parked) and SUCCEEDS — verified vs docker linux/arm64
    // (rc=0 errno=0). It is no longer an ENOSYS stub (impl: parking_lot
    // unpark_requeue, commit 1372821); a PRIVATE futex records NO compat gap.
    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
    let report = reporter.finish();
    assert_eq!(report.summary.distinct_partial_syscalls, 0);
    assert_eq!(report.summary.partial_syscall_invocations, 0);
}

#[test]
fn futex_cmp_requeue_matching_val3_no_waiters_returns_zero() {
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
    let reporter = CompatReporter::default();
    let dispatcher = SyscallDispatcher::new();
    let registry = Arc::new(ThreadRegistry::new(1000));
    let futex = Arc::new(FutexTable::new());
    write_u32_le(&mut memory, 0x10800, 77);
    write_u32_le(&mut memory, 0x10900, 0);

    let op = LINUX_FUTEX_CMP_REQUEUE | LINUX_FUTEX_PRIVATE_FLAG;
    let outcome = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(98, SyscallArgs::from([0x10800, op, 1, 8, 0x10900, 77])),
            &mut memory,
            &reporter,
            1001,
            &registry,
            &futex,
        )
        .unwrap();

    // FUTEX_CMP_REQUEUE is implemented: *uaddr1 (77) == val3 (77), so the
    // compare passes; with no waiters parked it wakes+requeues 0 and returns 0
    // -- matching real Linux (verified on the docker linux/arm64 oracle:
    // ret=0/errno=0; a val3 MISMATCH instead returns EAGAIN).
    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
    // Private futex with the requeue primitive implemented records no compat gap.
    let report = reporter.finish();
    assert_eq!(report.summary.distinct_partial_syscalls, 0);
    assert_eq!(report.summary.partial_syscall_invocations, 0);
}

// --- Sub-task B (P3): tgkill/tkill cross-thread routing ---

const LINUX_ESRCH: i32 = 3;
const LINUX_SIG_BLOCK: u64 = 0;
const LINUX_SIG_UNBLOCK: u64 = 1;
const SIGUSR1: u64 = 10;

#[test]
fn tgkill_to_sibling_emits_signalthread() {
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
    let reporter = CompatReporter::default();
    let dispatcher = SyscallDispatcher::new();
    let registry = Arc::new(ThreadRegistry::new(1000));
    let futex = Arc::new(FutexTable::new());
    let sibling = registry.register_child(0);
    // tgkill(tgid, tid=sibling, SIGUSR1) issued by the main thread (tid 1000).
    let outcome = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(
                131,
                SyscallArgs::from([1000, sibling as u64, SIGUSR1, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
            1000,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(
        outcome,
        DispatchOutcome::SignalThread {
            tid: sibling,
            signum: SIGUSR1 as i32,
        }
    );
}

#[test]
fn tgkill_to_self_raises_locally() {
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
    let reporter = CompatReporter::default();
    let dispatcher = SyscallDispatcher::new();
    let registry = Arc::new(ThreadRegistry::new(1000));
    let futex = Arc::new(FutexTable::new());
    // Targeting our own tid is a local raise, not a cross-thread kick.
    let outcome = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(131, SyscallArgs::from([1000, 1000, SIGUSR1, 0, 0, 0])),
            &mut memory,
            &reporter,
            1000,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
}

#[test]
fn tgkill_to_masked_sibling_queues_without_signalthread() {
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x2000]);
    let reporter = CompatReporter::default();
    let dispatcher = SyscallDispatcher::new();
    let registry = Arc::new(ThreadRegistry::new(1000));
    let futex = Arc::new(FutexTable::new());
    let sibling = registry.register_child(0);

    memory
        .write_bytes(0x10000, &(1_u64 << (SIGUSR1 as i32 - 1)).to_le_bytes())
        .unwrap();
    assert_eq!(
        dispatcher
            .dispatch_threaded(
                SyscallRequest::new(
                    135,
                    SyscallArgs::from([LINUX_SIG_BLOCK, 0x10000, 0, 8, 0, 0])
                ),
                &mut memory,
                &reporter,
                sibling,
                &registry,
                &futex,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    let outcome = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(
                131,
                SyscallArgs::from([1000, sibling as u64, SIGUSR1, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
            1000,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
    assert_eq!(dispatcher.take_deliverable_pending(sibling), None);
    assert_eq!(
        dispatcher
            .dispatch_threaded(
                SyscallRequest::new(
                    135,
                    SyscallArgs::from([LINUX_SIG_UNBLOCK, 0x10000, 0, 8, 0, 0]),
                ),
                &mut memory,
                &reporter,
                sibling,
                &registry,
                &futex,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher.take_deliverable_pending(sibling),
        Some(SIGUSR1 as i32)
    );
}

#[test]
fn tkill_to_unknown_tid_is_esrch() {
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
    let reporter = CompatReporter::default();
    let dispatcher = SyscallDispatcher::new();
    let registry = Arc::new(ThreadRegistry::new(1000));
    let futex = Arc::new(FutexTable::new());
    // tkill(tid=424242, SIGUSR1): not a live sibling, not self (pid), not the
    // bootstrap pid -> ESRCH.
    let outcome = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(130, SyscallArgs::from([424242, SIGUSR1, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
            1000,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(outcome, DispatchOutcome::Errno { errno: LINUX_ESRCH });
}
