use std::sync::Arc;

use carrick_runtime::compat::{CompatEvent, CompatReporter, SyscallArgs};
use carrick_runtime::dispatch::{
    DispatchOutcome, GuestMemory, LinearMemory, SyscallDispatcher, SyscallRequest,
};
use carrick_runtime::memory::LINUX_HEAP_BASE;
use carrick_runtime::rootfs::{LayerSource, RootFs};
use carrick_runtime::thread::{FutexTable, ThreadRegistry};

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn dispatcher_and_reporter_are_send_sync() {
    assert_send_sync::<SyscallDispatcher>();
    assert_send_sync::<CompatReporter>();
}

#[test]
fn compat_reporter_records_from_shared_threads() {
    const THREADS: usize = 4;
    const RECORDS_PER_THREAD: usize = 128;

    let reporter = Arc::new(CompatReporter::default());
    let mut handles = Vec::new();

    for _ in 0..THREADS {
        let reporter = Arc::clone(&reporter);
        handles.push(std::thread::spawn(move || {
            for _ in 0..RECORDS_PER_THREAD {
                reporter.record(CompatEvent::unhandled_syscall(
                    999,
                    "imaginary",
                    SyscallArgs::from([0, 0, 0, 0, 0, 0]),
                ));
            }
        }));
    }

    for handle in handles {
        match handle.join() {
            Ok(()) => {}
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    let report = reporter.snapshot();
    assert_eq!(
        report.summary.unhandled_syscall_invocations,
        (THREADS * RECORDS_PER_THREAD) as u64
    );
    assert_eq!(report.unhandled_syscalls[0].count, 512);
}

#[test]
fn shared_dispatcher_services_syscalls_from_multiple_host_threads() {
    let dispatcher = Arc::new(SyscallDispatcher::new());
    let reporter = Arc::new(CompatReporter::default());
    let registry = Arc::new(ThreadRegistry::new(1));
    let futex = Arc::new(FutexTable::new());
    assert_eq!(registry.register_child(0), 2);

    let handles: Vec<_> = [1, 2]
        .into_iter()
        .map(|tid| {
            let dispatcher = Arc::clone(&dispatcher);
            let reporter = Arc::clone(&reporter);
            let registry = Arc::clone(&registry);
            let futex = Arc::clone(&futex);
            std::thread::spawn(move || {
                let mut memory = LinearMemory::new(0x4000, Vec::new());
                dispatcher
                    .dispatch_threaded(
                        SyscallRequest::new(178, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                        &mut memory,
                        &reporter,
                        tid,
                        &registry,
                        &futex,
                    )
                    .unwrap()
            })
        })
        .collect();

    let mut outcomes = Vec::new();
    for handle in handles {
        outcomes.push(match handle.join() {
            Ok(outcome) => outcome,
            Err(payload) => std::panic::resume_unwind(payload),
        });
    }

    outcomes.sort_by_key(|outcome| match outcome {
        DispatchOutcome::Returned { value } => *value,
        other => panic!("expected gettid return, got {other:?}"),
    });
    assert_eq!(
        outcomes,
        vec![
            DispatchOutcome::Returned { value: 1 },
            DispatchOutcome::Returned { value: 2 }
        ]
    );
}

#[test]
fn shared_dispatcher_services_thread_registry_and_futex_syscalls() {
    const LINUX_FUTEX_WAIT: u64 = 0;
    const LINUX_FUTEX_PRIVATE_FLAG: u64 = 128;
    const LINUX_EAGAIN: i32 = 11;

    let dispatcher = Arc::new(SyscallDispatcher::new());
    let reporter = CompatReporter::default();
    let registry = ThreadRegistry::new(10);
    let futex = FutexTable::new();
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
    memory.write_bytes(0x10800, &0u32.to_le_bytes()).unwrap();

    let set_tid = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(96, SyscallArgs::from([0x10840, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(set_tid, DispatchOutcome::Returned { value: 10 });
    assert_eq!(registry.clear_child_tid(10), Some(0x10840));

    let futex_wait = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(
                98,
                SyscallArgs::from([
                    0x10800,
                    LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG,
                    1,
                    0,
                    0,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(
        futex_wait,
        DispatchOutcome::Errno {
            errno: LINUX_EAGAIN
        }
    );
}

#[test]
fn shared_dispatcher_routes_sibling_thread_signals() {
    let dispatcher = Arc::new(SyscallDispatcher::new());
    let reporter = CompatReporter::default();
    let registry = ThreadRegistry::new(10);
    let futex = FutexTable::new();
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
    assert_eq!(registry.register_child(0), 11);

    let routed = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(131, SyscallArgs::from([10, 11, 10, 0, 0, 0])),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(
        routed,
        DispatchOutcome::SignalThread {
            tid: 11,
            signum: 10
        }
    );
}

#[test]
fn shared_dispatcher_services_credential_state() {
    let dispatcher = Arc::new(SyscallDispatcher::new());
    let reporter = CompatReporter::default();
    let registry = ThreadRegistry::new(10);
    let futex = FutexTable::new();
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);

    let setresuid = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(147, SyscallArgs::from([100, 101, 102, 0, 0, 0])),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(setresuid, DispatchOutcome::Returned { value: 0 });

    let getuid = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(174, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(getuid, DispatchOutcome::Returned { value: 100 });

    let geteuid = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(175, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(geteuid, DispatchOutcome::Returned { value: 101 });
}

#[test]
fn shared_dispatcher_services_process_state() {
    const LINUX_PERSONALITY_QUERY: u64 = 0xffff_ffff;
    const LINUX_ADDR_NO_RANDOMIZE: u64 = 0x0040_0000;

    let dispatcher = Arc::new(SyscallDispatcher::new());
    let reporter = CompatReporter::default();
    let registry = ThreadRegistry::new(10);
    let futex = FutexTable::new();
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);

    let previous = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(
                92,
                SyscallArgs::from([LINUX_ADDR_NO_RANDOMIZE, 0, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(previous, DispatchOutcome::Returned { value: 0 });

    let current = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(
                92,
                SyscallArgs::from([LINUX_PERSONALITY_QUERY, 0, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(
        current,
        DispatchOutcome::Returned {
            value: LINUX_ADDR_NO_RANDOMIZE as i64
        }
    );
}

#[test]
fn shared_dispatcher_services_thread_lifecycle_syscalls() {
    const CLONE_VM: u64 = 0x00000100;
    const CLONE_FS: u64 = 0x00000200;
    const CLONE_FILES: u64 = 0x00000400;
    const CLONE_SIGHAND: u64 = 0x00000800;
    const CLONE_THREAD: u64 = 0x00010000;
    const CLONE_SETTLS: u64 = 0x00080000;
    const CLONE_PARENT_SETTID: u64 = 0x00100000;
    const CLONE_CHILD_CLEARTID: u64 = 0x00200000;
    const CLONE_CHILD_SETTID: u64 = 0x01000000;

    let dispatcher = Arc::new(SyscallDispatcher::new());
    let reporter = CompatReporter::default();
    let registry = ThreadRegistry::new(10);
    let futex = FutexTable::new();
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x4000]);

    let flags = CLONE_VM
        | CLONE_FS
        | CLONE_FILES
        | CLONE_SIGHAND
        | CLONE_THREAD
        | CLONE_SETTLS
        | CLONE_PARENT_SETTID
        | CLONE_CHILD_CLEARTID
        | CLONE_CHILD_SETTID;
    let cloned = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(
                220,
                SyscallArgs::from([flags, 0x20000, 0x10800, 0x30000, 0x10808, 0]),
            ),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(
        cloned,
        DispatchOutcome::CloneThread {
            stack: 0x20000,
            tls: 0x30000,
            flags,
            parent_tid_addr: 0x10800,
            child_tid_addr: 0x10808
        }
    );

    assert_eq!(registry.register_child(0), 11);
    let thread_exit = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(93, SyscallArgs::from([7, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(thread_exit, DispatchOutcome::ThreadExit { code: 7 });

    let exit_group = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(94, SyscallArgs::from([9, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(exit_group, DispatchOutcome::Exit { code: 9 });
}

#[test]
fn shared_dispatcher_services_execve_request_without_serialized_fallback() {
    let dispatcher = Arc::new(SyscallDispatcher::new());
    let reporter = CompatReporter::default();
    let registry = ThreadRegistry::new(10);
    let futex = FutexTable::new();
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x4000]);

    memory.write_bytes(0x10800, b"/bin/echo\0").unwrap();
    memory
        .write_bytes(0x10820, &0x10800_u64.to_le_bytes())
        .unwrap();
    memory.write_bytes(0x10828, &0_u64.to_le_bytes()).unwrap();
    memory.write_bytes(0x10840, &0_u64.to_le_bytes()).unwrap();

    let exec = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(221, SyscallArgs::from([0x10800, 0x10820, 0x10840, 0, 0, 0])),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(
        exec,
        DispatchOutcome::Execve {
            path: "/bin/echo".to_owned(),
            argv: vec!["/bin/echo".to_owned()],
            env: Vec::new(),
        }
    );
    assert!(reporter.snapshot().unhandled_syscalls.is_empty());
}

#[test]
fn shared_dispatcher_services_memory_state() {
    let dispatcher = Arc::new(SyscallDispatcher::new());
    let reporter = CompatReporter::default();
    let registry = ThreadRegistry::new(10);
    let futex = FutexTable::new();
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);

    let initial = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(214, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(
        initial,
        DispatchOutcome::Returned {
            value: LINUX_HEAP_BASE as i64
        }
    );

    let next = LINUX_HEAP_BASE + 0x1000;
    let updated = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(214, SyscallArgs::from([next, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(updated, DispatchOutcome::Returned { value: next as i64 });
}

#[test]
fn shared_dispatcher_services_readonly_fs_state() {
    let dispatcher = Arc::new(SyscallDispatcher::new());
    let reporter = CompatReporter::default();
    let registry = ThreadRegistry::new(10);
    let futex = FutexTable::new();
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x4000]);

    let getcwd = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(17, SyscallArgs::from([0x10800, 64, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(getcwd, DispatchOutcome::Returned { value: 2 });
    assert_eq!(memory.read_bytes(0x10800, 2).unwrap(), b"/\0");

    memory.write_bytes(0x10900, b"/proc/self/status\0").unwrap();
    let stat = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(79, SyscallArgs::from([0, 0x10900, 0x10a00, 0, 0, 0])),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(stat, DispatchOutcome::Returned { value: 0 });
}

#[test]
fn shared_dispatcher_services_fd_table_open_read_close() {
    let dispatcher = Arc::new(SyscallDispatcher::new());
    let reporter = CompatReporter::default();
    let registry = ThreadRegistry::new(10);
    let futex = FutexTable::new();
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x4000]);
    memory.write_bytes(0x10800, b"/proc/self/status\0").unwrap();

    let opened = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x10800, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: fd } = opened else {
        panic!("expected shared openat success, got {opened:?}");
    };
    assert!(fd >= 3);

    let read = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(63, SyscallArgs::from([fd as u64, 0x10900, 0x100, 0, 0, 0])),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: read_len } = read else {
        panic!("expected shared read success, got {read:?}");
    };
    assert!(read_len > 0);

    let closed = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(57, SyscallArgs::from([fd as u64, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(closed, DispatchOutcome::Returned { value: 0 });
}

#[test]
fn shared_dispatcher_services_nested_pipe_redirect_syscalls() {
    let dispatcher = Arc::new(SyscallDispatcher::new());
    let reporter = CompatReporter::default();
    let registry = ThreadRegistry::new(10);
    let futex = FutexTable::new();
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x4000]);

    let pipe_addr = 0x10800;
    let pipe2 = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(59, SyscallArgs::from([pipe_addr, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(pipe2, DispatchOutcome::Returned { value: 0 });

    let pair = memory.read_bytes(pipe_addr, 8).unwrap();
    let read_fd = i32::from_le_bytes(pair[0..4].try_into().unwrap());
    let write_fd = i32::from_le_bytes(pair[4..8].try_into().unwrap());

    let dup_stderr = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(24, SyscallArgs::from([write_fd as u64, 2, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(dup_stderr, DispatchOutcome::Returned { value: 2 });

    memory.write_bytes(0x10820, b"hi").unwrap();
    let write = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(64, SyscallArgs::from([2, 0x10820, 2, 0, 0, 0])),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(write, DispatchOutcome::Returned { value: 2 });

    let read = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(63, SyscallArgs::from([read_fd as u64, 0x10840, 8, 0, 0, 0])),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(read, DispatchOutcome::Returned { value: 2 });
    assert_eq!(memory.read_bytes(0x10840, 2).unwrap(), b"hi");
    assert!(reporter.snapshot().unhandled_syscalls.is_empty());
}

#[test]
fn shared_dispatcher_opens_rootfs_file_without_serialized_fallback() {
    let rootfs = RootFs::from_layers([LayerSource::Tar(
        tar_layer([("etc/motd", b"rootfs shared\n".as_slice())]).unwrap(),
    )])
    .unwrap();
    let dispatcher = Arc::new(SyscallDispatcher::with_rootfs(rootfs));
    let reporter = CompatReporter::default();
    let registry = ThreadRegistry::new(10);
    let futex = FutexTable::new();
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x4000]);
    memory.write_bytes(0x10800, b"/etc/motd\0").unwrap();

    let opened = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x10800, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: fd } = opened else {
        panic!("expected shared rootfs openat success, got {opened:?}");
    };
    assert!(fd >= 3);

    let read = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(63, SyscallArgs::from([fd as u64, 0x10900, 0x100, 0, 0, 0])),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(read, DispatchOutcome::Returned { value: 14 });
    assert_eq!(memory.read_bytes(0x10900, 14).unwrap(), b"rootfs shared\n");

    let closed = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(57, SyscallArgs::from([fd as u64, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(closed, DispatchOutcome::Returned { value: 0 });
}

#[test]
fn shared_dispatcher_services_stdio_write_buffers() {
    let dispatcher = Arc::new(SyscallDispatcher::new());
    let reporter = CompatReporter::default();
    let registry = ThreadRegistry::new(10);
    let futex = FutexTable::new();
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
    memory.write_bytes(0x10800, b"shared\n").unwrap();

    let written = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(64, SyscallArgs::from([1, 0x10800, 7, 0, 0, 0])),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(written, DispatchOutcome::Returned { value: 7 });
    assert_eq!(dispatcher.stdout(), b"shared\n");
}

#[test]
fn shared_dispatcher_reports_unknown_syscalls_without_serialized_fallback() {
    let dispatcher = Arc::new(SyscallDispatcher::new());
    let reporter = CompatReporter::default();
    let registry = ThreadRegistry::new(10);
    let futex = FutexTable::new();
    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);

    let outcome = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(9999, SyscallArgs::from([1, 2, 3, 4, 5, 6])),
            &mut memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    assert_eq!(outcome, DispatchOutcome::Errno { errno: 38 });
    assert_eq!(reporter.snapshot().summary.unhandled_syscall_invocations, 1);
}

fn tar_layer<const N: usize>(files: [(&str, &[u8]); N]) -> std::io::Result<Vec<u8>> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (path, contents) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, contents)?;
        }
        builder.finish()?;
    }
    Ok(tar_bytes)
}
