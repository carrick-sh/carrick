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
