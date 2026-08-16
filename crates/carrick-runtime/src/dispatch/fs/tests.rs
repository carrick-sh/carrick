use super::*;

fn logical_lock_request(
    owner: (i32, u64),
    range: (u64, u64),
    write: bool,
) -> LogicalRecordLockRequest {
    LogicalRecordLockRequest {
        file: LeaseFileId::Path("/logical-lock".to_owned()),
        owner: LogicalRecordLockOwner {
            pid: owner.0,
            serial: owner.1,
        },
        range: LogicalRecordLockRange {
            start: range.0,
            end: range.1,
        },
        write,
    }
}

#[test]
fn hvpatch_classic_record_locks_conflict_by_task_generation_and_release_on_close() {
    let locks = LogicalRecordLocks::default();
    let parent = logical_lock_request((41, 1), (0, 10), true);
    let child = logical_lock_request((42, 2), (0, 10), true);

    assert_eq!(locks.try_set(parent.clone()), Ok(()));
    assert_eq!(locks.try_set(child.clone()), Err(LINUX_EAGAIN));
    let conflict = locks.conflict(&child).expect("parent conflict");
    assert_eq!(conflict.owner, parent.owner);
    assert!(conflict.write);

    locks.release_file_owner(&parent.file, parent.owner);
    assert_eq!(locks.try_set(child), Ok(()));
}

#[test]
fn hvpatch_classic_record_lock_replacement_splits_only_the_callers_range() {
    let locks = LogicalRecordLocks::default();
    let whole = logical_lock_request((41, 1), (0, 30), true);
    assert_eq!(locks.try_set(whole.clone()), Ok(()));

    locks.unlock(
        &whole.file,
        whole.owner,
        LogicalRecordLockRange { start: 10, end: 20 },
    );
    let state = locks.state.lock();
    assert_eq!(state.locks.len(), 2);
    assert_eq!(
        state.locks[0].range,
        LogicalRecordLockRange { start: 0, end: 10 }
    );
    assert_eq!(
        state.locks[1].range,
        LogicalRecordLockRange { start: 20, end: 30 }
    );
}

/// fcntl(2): "EDEADLK — It was detected that the specified F_SETLKW command
/// would cause a deadlock." LTP fcntl17 builds exactly this cycle with three
/// processes and reports `TFAIL: Alarm expired, deadlock not detected` when the
/// kernel never returns EDEADLK — carrick had no wait-for graph at all, so the
/// waiters simply parked forever and the suite TIMEOUTed.
#[test]
fn f_setlkw_cycle_reports_edeadlk_instead_of_parking_forever() {
    let locks = Arc::new(LogicalRecordLocks::default());
    let a = logical_lock_request((41, 1), (0, 10), true);
    let b = logical_lock_request((42, 1), (10, 20), true);
    assert_eq!(locks.try_set(a.clone()), Ok(()));
    assert_eq!(locks.try_set(b.clone()), Ok(()));

    // Owner A blocks waiting for B's range. Park it on a helper thread so the
    // wait-for edge is live while the main thread closes the cycle.
    let waiter = {
        let locks = Arc::clone(&locks);
        let a_wants_b = logical_lock_request((41, 1), (10, 20), true);
        std::thread::spawn(move || {
            locks
                .wait_set_interruptibly(&a_wants_b, crate::thread::ThreadId::synthetic_for_tests(1))
        })
    };
    // Wait for A's edge to appear rather than sleeping a fixed amount.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if locks.state.lock().waiting_on.contains_key(&a.owner) {
            break;
        }
        std::thread::yield_now();
    }
    assert!(
        locks.state.lock().waiting_on.contains_key(&a.owner),
        "owner A should have published a wait-for edge"
    );

    // B now wants A's range: A waits on B, B would wait on A. That is a cycle.
    let b_wants_a = logical_lock_request((42, 1), (0, 10), true);
    assert_eq!(
        locks.wait_set_interruptibly(&b_wants_a, crate::thread::ThreadId::synthetic_for_tests(2)),
        Err(crate::linux_abi::LINUX_EDEADLK),
        "closing the cycle must be EDEADLK, not an unbounded park"
    );

    // Releasing B lets A through, proving the edge was retracted, not leaked.
    locks.unlock(&b.file, b.owner, b.range);
    assert_eq!(waiter.join().expect("waiter thread"), Ok(()));
    assert!(locks.state.lock().waiting_on.is_empty());
}

#[test]
fn hvpatch_blocking_classic_record_lock_wakes_after_unlock() {
    let locks = Arc::new(LogicalRecordLocks::default());
    let parent = logical_lock_request((41, 1), (0, 10), true);
    let child = logical_lock_request((42, 2), (0, 10), true);
    assert_eq!(locks.try_set(parent.clone()), Ok(()));

    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker_locks = Arc::clone(&locks);
    let worker = std::thread::spawn(move || {
        started_tx.send(()).expect("publish waiter start");
        let result = worker_locks
            .wait_set_interruptibly(&child, crate::thread::ThreadId::synthetic_for_tests(42));
        done_tx.send(result).expect("publish waiter result");
    });
    started_rx.recv().expect("waiter started");
    assert!(
        done_rx
            .recv_timeout(std::time::Duration::from_millis(20))
            .is_err(),
        "conflicting F_SETLKW must remain parked"
    );

    locks.unlock(&parent.file, parent.owner, parent.range);
    assert_eq!(
        done_rx.recv_timeout(std::time::Duration::from_secs(1)),
        Ok(Ok(()))
    );
    worker.join().expect("logical record-lock waiter");
}

#[derive(Default)]
struct HostWriteEvents {
    begins: Vec<Vec<(u64, usize)>>,
    finishes: Vec<Vec<(u64, usize)>>,
}

impl GuestMemory for HostWriteEvents {
    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        Err(MemoryError::OutOfBounds { address, length })
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        Err(MemoryError::OutOfBounds {
            address,
            length: bytes.len(),
        })
    }

    fn begin_host_write(&mut self, ranges: &[(u64, usize)]) {
        self.begins.push(ranges.to_vec());
    }

    fn finish_host_write(&mut self, ranges: &[(u64, usize)]) {
        self.finishes.push(ranges.to_vec());
    }
}

fn fail_with_readv_host_write_guard(memory: &mut HostWriteEvents) -> Result<(), LinuxErrno> {
    let ranges = [(0x1000, 0x1000), (0x5000, 0x1000)];
    let _guard = carrick_guest_mem::HostWriteGuard::new(memory, &ranges);
    Err(LINUX_EINVAL)
}

#[test]
fn readv_host_write_guard_finishes_every_exposed_range_on_error() {
    let mut events = HostWriteEvents::default();

    assert_eq!(
        fail_with_readv_host_write_guard(&mut events),
        Err(LINUX_EINVAL)
    );

    let expected = vec![(0x1000, 0x1000), (0x5000, 0x1000)];
    assert_eq!(events.begins.as_slice(), std::slice::from_ref(&expected));
    assert_eq!(events.finishes.as_slice(), std::slice::from_ref(&expected));
}

#[test]
fn inet4_ioctl_view_uses_linux_interface_names() {
    let ifaces = vec![
        HostInet4Iface {
            name: "lo0".to_owned(),
            flags_host: libc::IFF_UP as u32 | libc::IFF_LOOPBACK as u32,
            addr_be: [127, 0, 0, 1],
        },
        HostInet4Iface {
            name: "utun0".to_owned(),
            flags_host: libc::IFF_UP as u32,
            addr_be: [10, 0, 0, 1],
        },
        HostInet4Iface {
            name: "en4".to_owned(),
            flags_host: libc::IFF_UP as u32 | libc::IFF_MULTICAST as u32,
            addr_be: [192, 0, 2, 4],
        },
        HostInet4Iface {
            name: "en0".to_owned(),
            flags_host: libc::IFF_UP as u32 | libc::IFF_MULTICAST as u32,
            addr_be: [192, 0, 2, 1],
        },
    ];

    let ifaces = linux_guest_inet4_interfaces(ifaces);
    let names: Vec<_> = ifaces.iter().map(|iface| iface.name.as_str()).collect();
    assert_eq!(names, ["lo", "eth0"]);
    assert_eq!(ifaces[1].addr_be, [192, 0, 2, 1]);
    assert_eq!(linux_if_nametoindex("lo"), Some(1));
    assert_eq!(linux_if_indextoname(2), Some("eth0"));
}

#[test]
fn fasync_signal_target_drops_on_ns_translation_miss() {
    // A translation MISS (no host mapping for the owner's ns id) must DROP the
    // SIGIO — returning None — never fall back to the raw ns value reinterpreted
    // as a host pid (which would signal an unrelated process). Matches the
    // kill-path ESRCH intent.
    assert_eq!(
        SyscallDispatcher::fasync_signal_target(LINUX_F_OWNER_TID, None),
        None,
        "an owner whose ns-pid has no host mapping must not deliver to a bogus pid"
    );
    assert_eq!(
        SyscallDispatcher::fasync_signal_target(LINUX_F_OWNER_PGRP, None),
        None
    );
    assert_eq!(
        SyscallDispatcher::fasync_signal_target(LINUX_F_OWNER_PID, None),
        None
    );
}

#[test]
fn fasync_signal_target_resolves_by_owner_kind() {
    use crate::dispatch::signal::SignalTarget;
    // A successful translation routes by owner kind: PID (and the default)
    // target that host pid; TID targets that host tid; PGRP targets the
    // host process group (bootstrap_signal_send_as reconstructs the
    // kill(2) negated-pgid encoding).
    assert_eq!(
        SyscallDispatcher::fasync_signal_target(LINUX_F_OWNER_PID, Some(42)),
        Some(SignalTarget::HostProcess(HostPid(42)))
    );
    assert_eq!(
        SyscallDispatcher::fasync_signal_target(LINUX_F_OWNER_TID, Some(42)),
        Some(SignalTarget::HostThread(HostPid(42)))
    );
    assert_eq!(
        SyscallDispatcher::fasync_signal_target(LINUX_F_OWNER_PGRP, Some(7)),
        Some(SignalTarget::HostProcessGroup(HostPid(7)))
    );
}

fn test_directory_open_file(path: &str) -> OpenFile {
    let metadata = RootFsMetadata {
        path: Path::new(path).to_path_buf(),
        kind: RootFsEntryKind::Directory,
        mode: 0o755,
        size: 0,
    };
    OpenFile::from_open_description(
        Arc::new(RwLock::new(OpenDescription::Directory {
            path: path.to_owned(),
            metadata,
            entries: Vec::new(),
            offset: 0,
            base: OpenDescriptionBase::new(0),
            trusted_host_dir: None,
        })),
        0,
    )
}

#[test]
fn chroot_rebases_absolute_resolution() {
    let backend = crate::fs_backend::MemoryBackend::new();
    backend.make_dir("/jail").unwrap();
    backend
        .set_file_contents("/jail/chroot02_testfile", b"payload".to_vec())
        .unwrap();

    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    dispatcher
        .capture_one_task_context()
        .unwrap()
        .resources()
        .fs_context()
        .set_chroot_root(Some("/jail".to_owned()));

    assert_eq!(
        dispatcher
            .resolve_at_path(LINUX_AT_FDCWD, "/chroot02_testfile")
            .unwrap(),
        "/jail/chroot02_testfile"
    );
    assert!(
        dispatcher
            .layered_metadata("/jail/chroot02_testfile")
            .is_ok()
    );
}

#[test]
fn chroot_no_search_permission_precedes_capability_error() {
    let scratch = tempfile::tempdir().unwrap();
    let dir =
        cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority()).unwrap();
    let backend = crate::fs_backend::HostFsBackend::from_existing_dir(dir);
    backend.make_dir("/jail").unwrap();
    backend.set_mode("/jail", 0o600).unwrap();

    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    dispatcher.set_credentials(carrick_abi::NsUid::new(1000), carrick_abi::NsGid::new(1000));
    let reporter = CompatReporter::default();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    memory.write_bytes(0x4000, b"/jail\0").unwrap();

    assert_eq!(
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(51, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::errno(LINUX_EACCES)
    );
}

// === Trusted-dirfd fast lane (`--fs host`) ===

/// Host-backend dispatcher over a fixture walk tree:
/// `/walk/{file.txt, sub/deep.txt, link -> file.txt, fifo,
/// .carrick-lnkown.ghost}`. The sidecar name must stay invisible to the
/// guest; the FIFO exercises the never-blocking-open invariant.
#[cfg(target_os = "macos")]
fn trusted_lane_fixture() -> (tempfile::TempDir, SyscallDispatcher) {
    let scratch = tempfile::tempdir().unwrap();
    let dir =
        cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority()).unwrap();
    let backend = crate::fs_backend::HostFsBackend::from_existing_dir(dir);
    backend.make_dir("/walk").unwrap();
    backend.make_dir("/walk/sub").unwrap();
    backend
        .set_file_contents("/walk/file.txt", b"hello lane".to_vec())
        .unwrap();
    backend
        .set_file_contents("/walk/sub/deep.txt", b"deep".to_vec())
        .unwrap();
    backend.symlink("file.txt", "/walk/link").unwrap();
    backend.create_fifo("/walk/fifo", 0o644).unwrap();
    backend
        .set_file_contents("/walk/.carrick-lnkown.ghost", b"sidecar".to_vec())
        .unwrap();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    (scratch, dispatcher)
}

/// Cached-lower form of the walk fixture: the immutable image tree is a
/// real host directory and the writable host overlay starts sparse.
#[cfg(target_os = "macos")]
fn trusted_lower_lane_fixture() -> (tempfile::TempDir, tempfile::TempDir, SyscallDispatcher) {
    let lower = tempfile::tempdir().unwrap();
    let upper = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(lower.path().join("walk/sub")).unwrap();
    std::fs::write(lower.path().join("walk/file.txt"), b"lower file").unwrap();
    std::fs::write(lower.path().join("walk/sub/deep.txt"), b"deep").unwrap();
    std::os::unix::fs::symlink("file.txt", lower.path().join("walk/link")).unwrap();
    let lower_metadata = crate::fs_backend::HostFsBackend::attach(lower.path()).unwrap();
    lower_metadata.set_mode("/walk/file.txt", 0o4711).unwrap();
    lower_metadata
        .set_owner(
            "/walk/file.txt",
            Some(carrick_abi::NsUid::new(7)),
            Some(carrick_abi::NsGid::new(9)),
        )
        .unwrap();
    drop(lower_metadata);

    let rootfs = RootFs::from_immutable_host_dir(lower.path()).unwrap();
    let upper_dir =
        cap_std::fs::Dir::open_ambient_dir(upper.path(), cap_std::ambient_authority()).unwrap();
    let mut overlay = crate::fs_backend::HostFsBackend::from_existing_dir(upper_dir);
    overlay.enable_sparse_upper_fast_miss();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(overlay));
    dispatcher.set_rootfs_layer(rootfs);
    (lower, upper, dispatcher)
}

#[cfg(target_os = "macos")]
fn lane_syscall(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut LinearMemory,
    nr: u64,
    args: [u64; 6],
) -> i64 {
    let reporter = CompatReporter::default();
    match dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            memory,
            &reporter,
        )
        .unwrap()
    {
        DispatchOutcome::Returned { value } => value,
        DispatchOutcome::Errno { errno } => -i64::from(errno.get()),
        other => panic!("unexpected dispatch outcome: {other:?}"),
    }
}

#[cfg(target_os = "macos")]
fn lane_openat(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut LinearMemory,
    dirfd: u64,
    path: &str,
    flags: u64,
) -> i64 {
    memory
        .write_bytes(0x4000, format!("{path}\0").as_bytes())
        .unwrap();
    lane_syscall(dispatcher, memory, 56, [dirfd, 0x4000, flags, 0, 0, 0])
}

#[cfg(target_os = "macos")]
fn lane_dir_is_trusted(dispatcher: &SyscallDispatcher, fd: i64) -> bool {
    let open_file = dispatcher.open_file(fd as i32).unwrap();
    let open = open_file.description.read();
    matches!(
        &*open,
        OpenDescription::Directory {
            trusted_host_dir: Some(_),
            ..
        }
    )
}

/// Drain getdents64 through the dispatcher and parse the guest-visible
/// `(name, d_type)` records (dot entries included).
#[cfg(target_os = "macos")]
fn lane_getdents(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut LinearMemory,
    fd: i64,
) -> Vec<(String, u8)> {
    let mut out = Vec::new();
    loop {
        let n = lane_syscall(dispatcher, memory, 61, [fd as u64, 0x8000, 4096, 0, 0, 0]);
        assert!(n >= 0, "getdents64 failed: {n}");
        if n == 0 {
            break;
        }
        let buf = memory.read_bytes(0x8000, n as usize).unwrap();
        let mut pos = 0usize;
        while pos < buf.len() {
            let reclen = u16::from_le_bytes([buf[pos + 16], buf[pos + 17]]) as usize;
            let d_type = buf[pos + 18];
            let name_bytes = &buf[pos + LINUX_DIRENT64_HEADER_SIZE..pos + reclen];
            let end = name_bytes.iter().position(|&b| b == 0).unwrap();
            out.push((
                String::from_utf8(name_bytes[..end].to_vec()).unwrap(),
                d_type,
            ));
            pos += reclen;
        }
    }
    out
}

/// `lane_getdents`'s identity twin: the guest-visible `(name, d_ino)` records.
#[cfg(target_os = "macos")]
fn lane_getdents_inos(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut LinearMemory,
    fd: i64,
) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    loop {
        let n = lane_syscall(dispatcher, memory, 61, [fd as u64, 0x8000, 4096, 0, 0, 0]);
        assert!(n >= 0, "getdents64 failed: {n}");
        if n == 0 {
            break;
        }
        let buf = memory.read_bytes(0x8000, n as usize).unwrap();
        let mut pos = 0usize;
        while pos < buf.len() {
            let d_ino = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
            let reclen = u16::from_le_bytes([buf[pos + 16], buf[pos + 17]]) as usize;
            let name_bytes = &buf[pos + LINUX_DIRENT64_HEADER_SIZE..pos + reclen];
            let end = name_bytes.iter().position(|&b| b == 0).unwrap();
            out.push((
                String::from_utf8(name_bytes[..end].to_vec()).unwrap(),
                d_ino,
            ));
            pos += reclen;
        }
    }
    out
}

#[cfg(target_os = "macos")]
#[test]
fn trusted_dirfd_lane_serves_walk_and_recurses() {
    let (_scratch, mut dispatcher) = trusted_lane_fixture();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);

    let root = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk",
        LINUX_O_DIRECTORY,
    );
    assert!(root >= 0, "open /walk: {root}");
    assert!(
        lane_dir_is_trusted(&dispatcher, root),
        "absolute O_DIRECTORY open must seed the trusted lane"
    );

    let sub = lane_openat(
        &mut dispatcher,
        &mut memory,
        root as u64,
        "sub",
        LINUX_O_DIRECTORY,
    );
    assert!(sub >= 0, "openat(root, sub): {sub}");
    assert!(
        lane_dir_is_trusted(&dispatcher, sub),
        "a lane-served child directory must itself be trusted (walk recursion)"
    );

    let file = lane_openat(&mut dispatcher, &mut memory, sub as u64, "deep.txt", 0);
    assert!(file >= 0, "openat(sub, deep.txt): {file}");
    {
        let open_file = dispatcher.open_file(file as i32).unwrap();
        let open = open_file.description.read();
        assert!(
            matches!(&*open, OpenDescription::HostFile { .. }),
            "lane-served regular file must be a HostFile, got {open:?}"
        );
    }
    // The served fd carries the real bytes.
    let n = lane_syscall(
        &mut dispatcher,
        &mut memory,
        63,
        [file as u64, 0x9000, 64, 0, 0, 0],
    );
    assert_eq!(n, 4);
    assert_eq!(memory.read_bytes(0x9000, 4).unwrap(), b"deep");

    // A missing single component is authoritative ENOENT from the lane.
    assert_eq!(
        lane_openat(&mut dispatcher, &mut memory, root as u64, "nope", 0),
        -i64::from(LINUX_ENOENT.get())
    );
    // O_DIRECTORY of a regular child is authoritative ENOTDIR.
    assert_eq!(
        lane_openat(
            &mut dispatcher,
            &mut memory,
            root as u64,
            "file.txt",
            LINUX_O_DIRECTORY
        ),
        -i64::from(LINUX_ENOTDIR.get())
    );
}

#[cfg(target_os = "macos")]
#[test]
fn trusted_immutable_lower_serves_walk_recursively_while_upper_is_unchanged() {
    let (_lower, _upper, mut dispatcher) = trusted_lower_lane_fixture();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);

    let root = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk",
        LINUX_O_DIRECTORY,
    );
    assert!(root >= 0, "open lower /walk: {root}");
    assert!(
        lane_dir_is_trusted(&dispatcher, root),
        "an upper-absent immutable-lower directory must seed the trusted lane"
    );

    let sub = lane_openat(
        &mut dispatcher,
        &mut memory,
        root as u64,
        "sub",
        LINUX_O_DIRECTORY,
    );
    assert!(sub >= 0, "open lower sub: {sub}");
    assert!(
        lane_dir_is_trusted(&dispatcher, sub),
        "unchanged sparse-upper state must propagate lower trust"
    );

    let file = lane_openat(&mut dispatcher, &mut memory, sub as u64, "deep.txt", 0);
    assert!(file >= 0, "open lower deep.txt: {file}");
    let n = lane_syscall(
        &mut dispatcher,
        &mut memory,
        63,
        [file as u64, 0x9000, 64, 0, 0, 0],
    );
    assert_eq!(n, 4);
    assert_eq!(memory.read_bytes(0x9000, 4).unwrap(), b"deep");
}

#[cfg(target_os = "macos")]
#[test]
fn trusted_immutable_lower_falls_back_after_an_upper_shadow() {
    let (_lower, _upper, mut dispatcher) = trusted_lower_lane_fixture();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);
    let root = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk",
        LINUX_O_DIRECTORY,
    );
    assert!(root >= 0 && lane_dir_is_trusted(&dispatcher, root));

    dispatcher
        .fs
        .rootfs_vfs
        .overlay
        .set_file_contents("/walk/file.txt", b"upper file".to_vec())
        .unwrap();

    let file = lane_openat(&mut dispatcher, &mut memory, root as u64, "file.txt", 0);
    assert!(file >= 0, "open upper shadow through lower dirfd: {file}");
    let n = lane_syscall(
        &mut dispatcher,
        &mut memory,
        63,
        [file as u64, 0x9000, 64, 0, 0, 0],
    );
    assert_eq!(n, 10);
    assert_eq!(
        memory.read_bytes(0x9000, 10).unwrap(),
        b"upper file",
        "a stale lower anchor must not bypass the writable shadow"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn trusted_immutable_lower_stat_preserves_layered_guest_identity() {
    let (_lower, _upper, mut dispatcher) = trusted_lower_lane_fixture();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);
    let root = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk",
        LINUX_O_DIRECTORY,
    );
    assert!(root >= 0 && lane_dir_is_trusted(&dispatcher, root));

    let fast = dispatcher
        .path_stat_record(
            &dispatcher.exact_signal_context_for_test(),
            root as u64,
            "file.txt",
            LINUX_AT_SYMLINK_NOFOLLOW,
        )
        .unwrap();
    let slow = dispatcher
        .path_stat_record(
            &dispatcher.exact_signal_context_for_test(),
            LINUX_AT_FDCWD,
            "/walk/file.txt",
            LINUX_AT_SYMLINK_NOFOLLOW,
        )
        .unwrap();
    assert_eq!(fast, slow, "trusted lower stat must equal layered stat");
    assert_eq!(fast.mode & 0o7777, 0o4711);
}

/// The three lanes that publish a file's identity — `stat(path)`,
/// `fstat(open(path))` and `getdents64`'s `d_ino` — must agree for an entry
/// only the immutable cache lower holds.
///
/// The fd lane opens the lower's REAL host file and reports its APFS inode,
/// and `getdents64` already publishes that same inode, but the path lane
/// dropped it at the `RootFsMetadata` boundary and hashed the path instead.
/// GNU coreutils `cp` stats its source through the path AND the fd it opened,
/// and refuses the copy when the two disagree — `cp: skipping file '…', as it
/// was replaced while being copied` — which broke LTP `execve02`'s setup with
/// TBROK the moment the cached lower was enabled for HvPatch.
#[cfg(target_os = "macos")]
#[test]
fn immutable_lower_reports_one_inode_through_stat_fstat_and_getdents() {
    let (_lower, _upper, mut dispatcher) = trusted_lower_lane_fixture();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);

    for (dir, name) in [("/walk", "file.txt"), ("/walk/sub", "deep.txt")] {
        let full = format!("{dir}/{name}");
        let by_path = dispatcher
            .path_stat_record(
                &dispatcher.exact_signal_context_for_test(),
                LINUX_AT_FDCWD,
                &full,
                LINUX_AT_SYMLINK_NOFOLLOW,
            )
            .unwrap();

        let fd = lane_openat(&mut dispatcher, &mut memory, LINUX_AT_FDCWD, &full, 0);
        assert!(fd >= 0, "open lower-only {full}: {fd}");
        let by_fd = dispatcher.fd_stat_record(fd as i32).unwrap();
        assert_eq!(
            by_path.ino, by_fd.ino,
            "stat({full}).st_ino must equal fstat(open({full})).st_ino"
        );

        let dirfd = lane_openat(
            &mut dispatcher,
            &mut memory,
            LINUX_AT_FDCWD,
            dir,
            LINUX_O_DIRECTORY,
        );
        assert!(dirfd >= 0, "open lower-only dir {dir}: {dirfd}");
        let d_ino = lane_getdents_inos(&mut dispatcher, &mut memory, dirfd)
            .into_iter()
            .find(|(entry, _)| entry == name)
            .unwrap_or_else(|| panic!("{name} missing from getdents64 of {dir}"))
            .1;
        assert_eq!(
            d_ino, by_path.ino,
            "getdents64 d_ino for {full} must equal its stat st_ino"
        );
    }
}

/// A lower-only DIRECTORY must satisfy the same identity invariant: Python's
/// `shutil.rmtree` and Go's `os.SameFile` compare `lstat(dir)` against
/// `fstat(open(dir))` and refuse to recurse when they differ.
#[cfg(target_os = "macos")]
#[test]
fn immutable_lower_directory_path_stat_matches_its_fd_stat() {
    let (_lower, _upper, mut dispatcher) = trusted_lower_lane_fixture();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);

    let by_path = dispatcher
        .path_stat_record(
            &dispatcher.exact_signal_context_for_test(),
            LINUX_AT_FDCWD,
            "/walk/sub",
            LINUX_AT_SYMLINK_NOFOLLOW,
        )
        .unwrap();
    let dirfd = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk/sub",
        LINUX_O_DIRECTORY,
    );
    assert!(dirfd >= 0, "open lower-only directory: {dirfd}");
    let by_fd = dispatcher.fd_stat_record(dirfd as i32).unwrap();
    assert_eq!(
        by_path.ino, by_fd.ino,
        "lstat(dir).st_ino must equal fstat(open(dir)).st_ino"
    );
}

/// A lower-only file's `st_mtime`/`st_nlink` must come from the real host
/// inode too. The path lane reported `mtime=0`/`nlink=1` for every untouched
/// image file, so `make`-style newer-than comparisons saw the epoch.
#[cfg(target_os = "macos")]
#[test]
fn immutable_lower_path_stat_reports_real_mtime_and_nlink() {
    let (lower, _upper, dispatcher) = trusted_lower_lane_fixture();
    let host = std::fs::metadata(lower.path().join("walk/sub/deep.txt")).unwrap();

    let record = dispatcher
        .path_stat_record(
            &dispatcher.exact_signal_context_for_test(),
            LINUX_AT_FDCWD,
            "/walk/sub/deep.txt",
            LINUX_AT_SYMLINK_NOFOLLOW,
        )
        .unwrap();

    use std::os::unix::fs::MetadataExt as _;
    assert_eq!(
        record.mtime.0,
        host.mtime(),
        "an untouched lower file must not report the epoch as its mtime"
    );
    assert_eq!(record.nlink, host.nlink() as u32);
}

#[cfg(target_os = "macos")]
#[test]
fn absolute_readonly_open_can_install_an_upper_absent_lower_file_directly() {
    let (_lower, _upper, mut dispatcher) = trusted_lower_lane_fixture();
    let outcome = dispatcher
        .try_immutable_lower_absolute_open(LINUX_AT_FDCWD, "/walk/file.txt", LINUX_O_RDONLY)
        .expect("eligible absolute lower open should take the direct lane");
    let DispatchOutcome::Returned { value: fd } = outcome else {
        panic!("unexpected direct-open outcome: {outcome:?}");
    };

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);
    let n = lane_syscall(
        &mut dispatcher,
        &mut memory,
        63,
        [fd as u64, 0x9000, 64, 0, 0, 0],
    );
    assert_eq!(n, 10);
    assert_eq!(memory.read_bytes(0x9000, 10).unwrap(), b"lower file");
}

#[cfg(target_os = "macos")]
#[test]
fn absolute_lower_fast_open_refuses_nofollow_symlink_semantics() {
    let (_lower, _upper, dispatcher) = trusted_lower_lane_fixture();
    assert!(
        dispatcher
            .try_immutable_lower_absolute_open(
                LINUX_AT_FDCWD,
                "/walk/link",
                LINUX_O_RDONLY | LinuxOpenFlags::NOFOLLOW.bits(),
            )
            .is_none(),
        "O_NOFOLLOW must reach the layered lstat path and return ELOOP"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn trusted_dirfd_lane_falls_back_for_special_shapes() {
    let (_scratch, mut dispatcher) = trusted_lane_fixture();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);
    let root = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk",
        LINUX_O_DIRECTORY,
    );
    assert!(lane_dir_is_trusted(&dispatcher, root));

    // Multi-component and ".." names take (and succeed via) the full path.
    let multi = lane_openat(&mut dispatcher, &mut memory, root as u64, "sub/deep.txt", 0);
    assert!(multi >= 0, "multi-component openat: {multi}");
    let up = lane_openat(
        &mut dispatcher,
        &mut memory,
        root as u64,
        "..",
        LINUX_O_DIRECTORY,
    );
    assert!(up >= 0, "dotdot openat: {up}");

    // A symlink child falls back and is FOLLOWED (the lane would ELOOP).
    let via_link = lane_openat(&mut dispatcher, &mut memory, root as u64, "link", 0);
    assert!(via_link >= 0, "symlink-child openat: {via_link}");
    let n = lane_syscall(
        &mut dispatcher,
        &mut memory,
        63,
        [via_link as u64, 0x9000, 64, 0, 0, 0],
    );
    assert_eq!(n, 10);
    assert_eq!(memory.read_bytes(0x9000, 10).unwrap(), b"hello lane");

    // O_CREAT falls back and actually creates.
    let created = lane_openat(
        &mut dispatcher,
        &mut memory,
        root as u64,
        "made.txt",
        LINUX_O_CREAT | LINUX_O_WRONLY,
    );
    assert!(created >= 0, "O_CREAT openat: {created}");
    assert!(dispatcher.layered_metadata("/walk/made.txt").is_ok());

    // A FIFO child must route to the non-blocking FIFO machinery — a
    // HostPipe, never a HostFile, and never a blocking open.
    let fifo = lane_openat(
        &mut dispatcher,
        &mut memory,
        root as u64,
        "fifo",
        LINUX_O_RDWR,
    );
    assert!(fifo >= 0, "fifo openat: {fifo}");
    {
        let open_file = dispatcher.open_file(fifo as i32).unwrap();
        let open = open_file.description.read();
        assert!(
            matches!(&*open, OpenDescription::HostPipe { .. }),
            "FIFO child must be a HostPipe, got {open:?}"
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn trusted_dirfd_stat_matches_slow_path() {
    let (_scratch, mut dispatcher) = trusted_lane_fixture();
    // A carrick mode xattr (setuid bits) + owner xattrs must merge into
    // the fast-lane record exactly as the slow path merges them.
    dispatcher
        .fs
        .rootfs_vfs
        .overlay
        .set_mode("/walk/file.txt", 0o4711)
        .unwrap();
    dispatcher
        .fs
        .rootfs_vfs
        .overlay
        .set_owner(
            "/walk/file.txt",
            Some(carrick_abi::NsUid::new(7)),
            Some(carrick_abi::NsGid::new(9)),
        )
        .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);
    let root = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk",
        LINUX_O_DIRECTORY,
    );
    assert!(lane_dir_is_trusted(&dispatcher, root));

    // A mknod device MARKER: the mode xattr carries the S_IFCHR type bits
    // verbatim and the rdev xattr the raw dev_t — the fast lane must
    // recover both through `stat_record_with_device` like the slow path.
    dispatcher
        .fs
        .rootfs_vfs
        .overlay
        .create_device("/walk/dev0", LINUX_S_IFCHR | 0o600, 0x0103)
        .unwrap();

    for name in ["file.txt", "sub", "link", "fifo", "dev0"] {
        let fast = dispatcher.path_stat_record(
            &dispatcher.exact_signal_context_for_test(),
            root as u64,
            name,
            LINUX_AT_SYMLINK_NOFOLLOW,
        );
        let slow = dispatcher.path_stat_record(
            &dispatcher.exact_signal_context_for_test(),
            LINUX_AT_FDCWD,
            &format!("/walk/{name}"),
            LINUX_AT_SYMLINK_NOFOLLOW,
        );
        assert_eq!(fast, slow, "fast/slow stat divergence for {name:?}");
    }
    let dev = dispatcher
        .path_stat_record(
            &dispatcher.exact_signal_context_for_test(),
            root as u64,
            "dev0",
            LINUX_AT_SYMLINK_NOFOLLOW,
        )
        .unwrap();
    assert_eq!(dev.mode & LINUX_S_IFMT, LINUX_S_IFCHR);
    assert_eq!(dev.rdev, 0x0103);
    // Missing child: authoritative ENOENT, identical to the slow path.
    assert_eq!(
        dispatcher.path_stat_record(
            &dispatcher.exact_signal_context_for_test(),
            root as u64,
            "gone",
            0
        ),
        Err(LINUX_ENOENT)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn trusted_getdents_streams_layered_identical_entries() {
    let (_scratch, mut dispatcher) = trusted_lane_fixture();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);
    let root = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk",
        LINUX_O_DIRECTORY,
    );
    assert!(lane_dir_is_trusted(&dispatcher, root));
    // Streaming preconditions hold on this fixture (a real FIFO is not
    // interference; the sidecar is name-filtered by the stream itself).
    assert!(
        !dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .dir_has_overlay_interference("/walk")
    );

    let mut streamed = lane_getdents(&mut dispatcher, &mut memory, root);
    assert_eq!(streamed.first().map(|(n, _)| n.as_str()), Some("."));
    assert_eq!(streamed.get(1).map(|(n, _)| n.as_str()), Some(".."));
    streamed.retain(|(n, _)| n != "." && n != "..");
    streamed.sort();

    let mut layered: Vec<(String, u8)> = crate::overlay::layered_directory_entries(
        dispatcher.fs.rootfs_vfs.overlay.as_ref(),
        None,
        "/walk",
    )
    .unwrap()
    .into_iter()
    .map(|e| (e.name, linux_dirent_type(e.metadata.kind)))
    .collect();
    layered.sort();

    assert_eq!(streamed, layered);
    assert!(
        !streamed.iter().any(|(n, _)| n.starts_with(".carrick-")),
        "sidecar names must never reach the guest: {streamed:?}"
    );
    assert!(
        streamed
            .iter()
            .any(|(n, t)| n == "fifo" && *t == linux_dirent_type(RootFsEntryKind::Fifo)),
        "FIFO child must stream as DT_FIFO without being opened"
    );
    assert!(
        streamed
            .iter()
            .any(|(n, t)| n == "link" && *t == linux_dirent_type(RootFsEntryKind::Symlink))
    );
    assert!(
        streamed
            .iter()
            .any(|(n, t)| n == "sub" && *t == linux_dirent_type(RootFsEntryKind::Directory))
    );

    // Rewind refreshes: a child created AFTER the first drain appears on
    // the re-read (Linux rewinddir semantics).
    dispatcher
        .fs
        .rootfs_vfs
        .overlay
        .set_file_contents("/walk/late.txt", b"x".to_vec())
        .unwrap();
    let seek = lane_syscall(
        &mut dispatcher,
        &mut memory,
        62,
        [root as u64, 0, 0, 0, 0, 0],
    );
    assert_eq!(seek, 0);
    let refreshed = lane_getdents(&mut dispatcher, &mut memory, root);
    assert!(
        refreshed.iter().any(|(n, _)| n == "late.txt"),
        "rewound trusted getdents must take a fresh snapshot: {refreshed:?}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn socket_marker_disables_streaming_and_keeps_layered_parity() {
    let (_scratch, mut dispatcher) = trusted_lane_fixture();
    // A bound AF_UNIX socket node is a MARKER regular file whose guest
    // TYPE lives in an xattr; its presence must disable streaming (fail
    // closed to the layered path) so getdents can never diverge from the
    // layered truth.
    dispatcher
        .fs
        .rootfs_vfs
        .overlay
        .create_socket("/walk/sock", 0o755)
        .unwrap();
    assert!(
        dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .dir_has_overlay_interference("/walk")
    );
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);
    let root = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk",
        LINUX_O_DIRECTORY,
    );
    assert!(lane_dir_is_trusted(&dispatcher, root));
    // getdents through the trusted fd equals the layered merge exactly.
    // (Note the HOST layered path itself reports a socket MARKER as
    // DT_REG — child_names cannot classify markers without a per-child
    // open; stat is where S_IFSOCK is recovered. The lane preserves that
    // behavior bit-for-bit.)
    let mut entries = lane_getdents(&mut dispatcher, &mut memory, root);
    entries.retain(|(n, _)| n != "." && n != "..");
    entries.sort();
    let mut layered: Vec<(String, u8)> = crate::overlay::layered_directory_entries(
        dispatcher.fs.rootfs_vfs.overlay.as_ref(),
        None,
        "/walk",
    )
    .unwrap()
    .into_iter()
    .map(|e| (e.name, linux_dirent_type(e.metadata.kind)))
    .collect();
    layered.sort();
    assert_eq!(entries, layered);
    assert!(entries.iter().any(|(n, _)| n == "sock"));

    // The fast STAT lane recovers S_IFSOCK from the marker xattr exactly
    // like the slow path.
    let fast = dispatcher
        .path_stat_record(
            &dispatcher.exact_signal_context_for_test(),
            root as u64,
            "sock",
            LINUX_AT_SYMLINK_NOFOLLOW,
        )
        .unwrap();
    assert_eq!(fast.mode & LINUX_S_IFMT, LINUX_S_IFSOCK);
    let slow = dispatcher
        .path_stat_record(
            &dispatcher.exact_signal_context_for_test(),
            LINUX_AT_FDCWD,
            "/walk/sock",
            LINUX_AT_SYMLINK_NOFOLLOW,
        )
        .unwrap();
    assert_eq!(fast, slow);
}

#[test]
fn fd_allocator_cursor_reuses_closed_hole_then_advances() {
    let mut dispatcher = SyscallDispatcher::new();
    let reporter = CompatReporter::default();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    let base_fd = dispatcher
        .install_fd_at_or_above(3, test_directory_open_file("/base"))
        .unwrap();
    assert_eq!(base_fd, 3);

    for expected in 4..36 {
        assert_eq!(
            dispatcher
                .dispatch(
                    &dispatcher.capture_one_task_context().unwrap(),
                    SyscallRequest::new(23, SyscallArgs::from([base_fd as u64, 0, 0, 0, 0, 0])),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { value: expected }
        );
    }

    assert_eq!(
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(57, SyscallArgs::from([10, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(23, SyscallArgs::from([base_fd as u64, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 10 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(23, SyscallArgs::from([base_fd as u64, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 36 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

fn sigpoll_fd(info: carrick_abi::LinuxSiginfo) -> i32 {
    i32::from_le_bytes(info._pad[0..4].try_into().unwrap())
}

#[test]
fn dnotify_child_attrib_queues_parent_before_child() {
    let dispatcher = SyscallDispatcher::new();
    let tid = dispatcher
        .capture_one_task_context()
        .unwrap()
        .thread()
        .registry_id();
    let signum = 34;

    let parent_fd = dispatcher
        .install_fd_at_or_above(3, test_directory_open_file("/watched"))
        .unwrap();
    let child_fd = dispatcher
        .install_fd_at_or_above(3, test_directory_open_file("/watched/child"))
        .unwrap();
    dispatcher
        .open_file(parent_fd)
        .unwrap()
        .description
        .write()
        .set_async_sig(signum);
    dispatcher
        .open_file(child_fd)
        .unwrap()
        .description
        .write()
        .set_async_sig(signum);

    dispatcher
        .dnotify_register(
            parent_fd,
            LinuxDnotifyMask::ATTRIB | LinuxDnotifyMask::MULTISHOT,
            tid,
        )
        .unwrap();
    dispatcher
        .dnotify_register(
            child_fd,
            LinuxDnotifyMask::ATTRIB | LinuxDnotifyMask::MULTISHOT,
            tid,
        )
        .unwrap();

    dispatcher.dnotify_attrib(
        &dispatcher.exact_signal_context_for_test(),
        "/watched/child",
    );

    assert_eq!(
        sigpoll_fd(
            dispatcher
                .take_pending_siginfo(&dispatcher.exact_signal_context_for_test(), tid, signum)
                .unwrap()
        ),
        parent_fd
    );
    assert_eq!(
        sigpoll_fd(
            dispatcher
                .take_pending_siginfo(&dispatcher.exact_signal_context_for_test(), tid, signum)
                .unwrap()
        ),
        child_fd
    );
}

#[test]
fn dnotify_child_attrib_matches_macos_private_tmp_alias() {
    let dispatcher = SyscallDispatcher::new();
    let tid = dispatcher
        .capture_one_task_context()
        .unwrap()
        .thread()
        .registry_id();
    let signum = 34;

    let parent_fd = dispatcher
        .install_fd_at_or_above(3, test_directory_open_file("/private/tmp/watched"))
        .unwrap();
    dispatcher
        .open_file(parent_fd)
        .unwrap()
        .description
        .write()
        .set_async_sig(signum);

    dispatcher
        .dnotify_register(
            parent_fd,
            LinuxDnotifyMask::ATTRIB | LinuxDnotifyMask::MULTISHOT,
            tid,
        )
        .unwrap();

    dispatcher.dnotify_attrib(
        &dispatcher.exact_signal_context_for_test(),
        "/tmp/watched/child",
    );

    assert_eq!(
        sigpoll_fd(
            dispatcher
                .take_pending_siginfo(&dispatcher.exact_signal_context_for_test(), tid, signum)
                .unwrap()
        ),
        parent_fd
    );
}

#[test]
fn staged_splice_pipe_bytes_preserve_fifo_order() {
    let mut host_fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe(host_fds.as_mut_ptr()) }, 0);

    let dispatcher = SyscallDispatcher::new();
    let read_open = OpenFile::from_open_description(
        Arc::new(RwLock::new(OpenDescription::HostPipe {
            host_fd: HostFdRef::new(host_fds[0]),
            is_read_end: true,
            pipe_id: 42,
            base: OpenDescriptionBase::new(0),
            pty: None,
            bidirectional: false,
            write_kind: HostWriteKind::PipeLike,
        })),
        0,
    );
    let write_open = OpenFile::from_open_description(
        Arc::new(RwLock::new(OpenDescription::HostPipe {
            host_fd: HostFdRef::new(host_fds[1]),
            is_read_end: false,
            pipe_id: 42,
            base: OpenDescriptionBase::new(0),
            pty: None,
            bidirectional: false,
            write_kind: HostWriteKind::PipeLike,
        })),
        0,
    );
    let (read_fd, _write_fd) = dispatcher
        .install_fd_pair_at_or_above(3, read_open, write_open)
        .expect("install host pipe pair");
    let host_read = dispatcher
        .host_pipe_read_fd(read_fd)
        .expect("host pipe read fd");

    dispatcher.stage_splice_pipe_bytes_owned(read_fd, b"abc".to_vec());
    dispatcher.stage_splice_pipe_bytes_owned(read_fd, b"def".to_vec());

    let bytes = dispatcher
        .take_splice_pipe_bytes(read_fd, host_read, None, 6, false)
        .expect("take staged bytes")
        .expect("staged bytes are available without waiting");
    assert_eq!(bytes, b"abcdef");
}

#[test]
fn staged_splice_pipe_bytes_are_visible_to_read() {
    let mut host_fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe(host_fds.as_mut_ptr()) }, 0);
    for host_fd in host_fds {
        assert_ne!(
            unsafe { libc::fcntl(host_fd, libc::F_SETFL, libc::O_NONBLOCK) },
            -1
        );
    }

    let mut dispatcher = SyscallDispatcher::new();
    let read_open = OpenFile::from_open_description(
        Arc::new(RwLock::new(OpenDescription::HostPipe {
            host_fd: HostFdRef::new(host_fds[0]),
            is_read_end: true,
            pipe_id: 43,
            base: OpenDescriptionBase::new(0),
            pty: None,
            bidirectional: false,
            write_kind: HostWriteKind::PipeLike,
        })),
        0,
    );
    let write_open = OpenFile::from_open_description(
        Arc::new(RwLock::new(OpenDescription::HostPipe {
            host_fd: HostFdRef::new(host_fds[1]),
            is_read_end: false,
            pipe_id: 43,
            base: OpenDescriptionBase::new(0),
            pty: None,
            bidirectional: false,
            write_kind: HostWriteKind::PipeLike,
        })),
        0,
    );
    let (read_fd, _write_fd) = dispatcher
        .install_fd_pair_at_or_above(3, read_open, write_open)
        .expect("install host pipe pair");

    dispatcher.stage_splice_pipe_bytes_owned(read_fd, b"AAAABBBB".to_vec());
    let reporter = CompatReporter::default();
    let mut memory = LinearMemory::new(0x1000, vec![0; 0x1000]);
    let outcome = dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(63, SyscallArgs::from([read_fd as u64, 0x1000, 4, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .expect("read dispatch");

    assert_eq!(outcome, DispatchOutcome::Returned { value: 4 });
    assert_eq!(memory.read_bytes(0x1000, 4).unwrap(), b"AAAA");
    assert_eq!(dispatcher.staged_splice_pipe_bytes(read_fd), 4);
}

/// `splice(2)` from a host-backed file into a pipe must BOTH advance the
/// source's kernel offset when `off_in` is NULL AND return a SHORT count
/// bounded by the destination pipe. `write(2)` may block until every byte
/// lands; `splice(2)` may not — and coreutils `cat` drains its bounce pipe
/// only AFTER the splice returns, so a "deliver it all" splice deadlocks a
/// single-threaded guest, while a non-advancing offset re-sends byte 0
/// forever. Both shapes hung `cat` on `ubuntu:latest` (uutils).
#[test]
fn splice_host_file_to_pipe_returns_short_and_advances_offset() {
    let mut path = std::env::temp_dir();
    path.push(format!("carrick-splice-loop-{}", std::process::id()));
    // Larger than any pipe buffer, so one splice CANNOT move it all.
    let contents = vec![0xa5u8; 512 * 1024];
    std::fs::write(&path, &contents).expect("write splice source");

    let c_path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    let host_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY) };
    assert!(host_fd >= 0, "open splice source");

    let dispatcher = SyscallDispatcher::new();
    let source = OpenFile::from_open_description(
        Arc::new(RwLock::new(OpenDescription::HostFile {
            host_fd: HostFdRef::new(host_fd),
            metadata: RootFsMetadata {
                path: path.clone(),
                kind: RootFsEntryKind::File,
                mode: 0o644,
                size: contents.len(),
            },
            base: OpenDescriptionBase::new(0),
            writable: false,
        })),
        0,
    );
    let in_fd = dispatcher
        .install_fd_at_or_above(3, source)
        .expect("install splice source fd");

    let mut host_pipe = [-1; 2];
    assert_eq!(unsafe { libc::pipe(host_pipe.as_mut_ptr()) }, 0);
    let read_open = OpenFile::from_open_description(
        Arc::new(RwLock::new(OpenDescription::HostPipe {
            host_fd: HostFdRef::new(host_pipe[0]),
            is_read_end: true,
            pipe_id: 4242,
            base: OpenDescriptionBase::new(0),
            pty: None,
            bidirectional: false,
            write_kind: HostWriteKind::PipeLike,
        })),
        0,
    );
    let write_open = OpenFile::from_open_description(
        Arc::new(RwLock::new(OpenDescription::HostPipe {
            host_fd: HostFdRef::new(host_pipe[1]),
            is_read_end: false,
            pipe_id: 4242,
            base: OpenDescriptionBase::new(0),
            pty: None,
            bidirectional: false,
            write_kind: HostWriteKind::PipeLike,
        })),
        0,
    );
    let (_read_fd, write_fd) = dispatcher
        .install_fd_pair_at_or_above(4, read_open, write_open)
        .expect("install host pipe pair");

    let reporter = CompatReporter::default();
    let mut memory = LinearMemory::new(0x1000, vec![0; 0x1000]);
    let outcome = dispatcher
        .dispatch_normalized(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(
                76,
                SyscallArgs::from([
                    in_fd as u64,
                    0,
                    write_fd as u64,
                    0,
                    contents.len() as u64,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
            None,
        )
        .expect("splice is a claimed syscall")
        .expect("splice must not be a fatal DispatchError");

    let DispatchOutcome::Returned { value } = outcome else {
        let _ = std::fs::remove_file(&path);
        panic!(
            "splice into a pipe must return a count, got {outcome:?}: a \
                 write(2)-style transfer that parks until every byte lands \
                 deadlocks a single-threaded guest"
        );
    };
    let moved = usize::try_from(value).expect("non-negative splice count");
    assert!(moved > 0, "splice moved nothing");
    assert!(
        moved < contents.len(),
        "expected a SHORT transfer bounded by the pipe, moved all {moved}"
    );

    // `off_in` was NULL, so the source's kernel offset must have advanced by
    // exactly what moved; otherwise the next iteration re-reads byte 0.
    let pos = unsafe { libc::lseek(host_fd, 0, libc::SEEK_CUR) };
    assert_eq!(
        pos, moved as i64,
        "a NULL off_in splice must advance the source offset"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn splice_pushback_keeps_large_stages_chunked() {
    let mut pushback = fs::SplicePushback::default();
    let bytes = vec![0x5a; 1024 * 1024];

    pushback.push_front(&bytes);

    assert_eq!(pushback.len(), bytes.len());
    assert_eq!(pushback.chunk_count_for_tests(), 1);

    let mut drained = Vec::new();
    pushback.take_into(4096, &mut drained);

    assert_eq!(drained, &bytes[..4096]);
    assert_eq!(pushback.len(), bytes.len() - 4096);
    assert_eq!(pushback.chunk_count_for_tests(), 1);
}

#[test]
fn splice_pushback_moves_owned_full_chunks_without_copy() {
    let mut pushback = fs::SplicePushback::default();
    let bytes = vec![0x33; 1024 * 1024];
    let ptr = bytes.as_ptr();

    pushback.push_back_owned(bytes);
    let drained = pushback.take_vec(1024 * 1024);

    assert_eq!(drained.as_ptr(), ptr);
    assert_eq!(drained.len(), 1024 * 1024);
    assert!(pushback.is_empty());
}

#[test]
fn vfs_open_fallthrough_does_not_build_open_context() {
    fd_helpers::reset_open_fd_numbers_calls();

    let dispatcher = SyscallDispatcher::new();
    let outcome = dispatcher.try_vfs_open(
        &dispatcher.exact_signal_context_for_test(),
        None,
        "/tmp/not-a-vfs-mount",
        LINUX_O_RDWR,
        0,
        0,
    );

    assert_eq!(outcome, VfsOpenAttempt::FallThrough);
    assert_eq!(
        fd_helpers::open_fd_numbers_calls(),
        0,
        "unmounted rootfs/overlay opens should fall through before building OpenContext"
    );
}

#[test]
fn bind_mount_rejects_o_directory_for_regular_file() {
    let host = tempfile::tempdir().unwrap();
    std::fs::write(host.path().join("target"), b"old").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        "/bind",
        Box::new(crate::vfs::BindVfs::new("/bind", host.path(), false)),
    );

    let before = dispatcher.open_fd_numbers();
    for flags in [
        crate::linux_abi::LINUX_O_PATH | LINUX_O_DIRECTORY,
        LINUX_O_WRONLY | LINUX_O_TRUNC | LINUX_O_DIRECTORY,
    ] {
        let outcome = dispatcher
            .open_at_path_string(
                &dispatcher.exact_signal_context_for_test(),
                None,
                LINUX_AT_FDCWD,
                "/bind/target",
                flags,
                0,
                &reporter,
            )
            .unwrap();
        assert_eq!(outcome, DispatchOutcome::errno(LINUX_ENOTDIR));
        assert_eq!(dispatcher.open_fd_numbers(), before);
        assert_eq!(std::fs::read(host.path().join("target")).unwrap(), b"old");
    }
    let create = dispatcher
        .open_at_path_string(
            &dispatcher.exact_signal_context_for_test(),
            None,
            LINUX_AT_FDCWD,
            "/bind/missing",
            LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_DIRECTORY,
            0o600,
            &reporter,
        )
        .unwrap();
    assert_eq!(create, DispatchOutcome::errno(LINUX_EINVAL));
    assert!(!host.path().join("missing").exists());

    assert!(matches!(
        dispatcher
            .open_at_path_string(
                &dispatcher.exact_signal_context_for_test(),
                None,
                LINUX_AT_FDCWD,
                "/bind",
                crate::linux_abi::LINUX_O_PATH | LINUX_O_DIRECTORY,
                0,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { .. }
    ));
}

#[test]
fn f_add_seals_waits_for_alias_dispatch_and_publishes_under_same_exclusion() {
    let dispatcher = std::sync::Arc::new(SyscallDispatcher::new());
    let mut base = OpenDescriptionBase::new(LINUX_O_RDWR);
    base.set_seals(Some(0));
    let description = std::sync::Arc::new(RwLock::new(OpenDescription::SyntheticFile {
        base,
        path: "/memfd:test".to_string(),
        contents: Vec::new(),
        offset: 0,
    }));
    let fd = dispatcher
        .install_fd_at_or_above(
            3,
            OpenFile::from_open_description(std::sync::Arc::clone(&description), 0),
        )
        .expect("install sealable fd");

    let guard = dispatcher.begin_host_alias_dispatch();
    let sibling = std::sync::Arc::clone(&dispatcher);
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    let (outcome_tx, outcome_rx) = std::sync::mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        let reporter = CompatReporter::default();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x1000]);
        started_tx.send(()).expect("report F_ADD_SEALS start");
        let outcome = sibling
            .dispatch_normalized(
                &sibling.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    25,
                    SyscallArgs::from([
                        fd as u64,
                        LINUX_F_ADD_SEALS,
                        u64::from(carrick_abi::LinuxMemfdSeals::SHRINK.bits()),
                        0,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
                None,
            )
            .expect("fcntl is a claimed syscall")
            .expect("F_ADD_SEALS must not be a fatal DispatchError");
        outcome_tx
            .send(outcome)
            .expect("report F_ADD_SEALS outcome");
    });

    started_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("F_ADD_SEALS thread reached dispatch");
    assert!(
        outcome_rx
            .recv_timeout(std::time::Duration::from_millis(25))
            .is_err(),
        "F_ADD_SEALS raced an in-flight alias dispatch"
    );
    assert_eq!(
        description.read().seals(),
        Some(carrick_abi::LinuxMemfdSeals::empty().bits())
    );

    drop(guard);

    assert_eq!(
        outcome_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("F_ADD_SEALS resumes after alias dispatch exits"),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        description.read().seals(),
        Some(carrick_abi::LinuxMemfdSeals::SHRINK.bits())
    );
    thread.join().expect("join F_ADD_SEALS thread");
}

#[test]
fn bind_mount_setxattr_reports_unsupported_instead_of_missing() {
    let host = tempfile::tempdir().unwrap();
    std::fs::write(host.path().join("target"), b"payload").unwrap();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        "/bind",
        Box::new(crate::vfs::BindVfs::new("/bind", host.path(), false)),
    );
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/bind/target\0").unwrap();
    memory.write_bytes(0x4100, b"security.test\0").unwrap();
    memory.write_bytes(0x4200, b"x").unwrap();

    let target = XattrTarget::Path {
        path: GuestPtr(0x4000),
        follow: true,
    };
    let outcome = dispatcher
        .setxattr(
            &mut memory,
            target,
            GuestPtr(0x4100),
            GuestPtr(0x4200),
            1,
            0,
        )
        .unwrap();
    assert_eq!(outcome, DispatchOutcome::errno(LINUX_ENOTSUP));

    let invalid = dispatcher
        .setxattr(
            &mut memory,
            target,
            GuestPtr(0x4100),
            GuestPtr(0x4200),
            1,
            (crate::linux_abi::LINUX_XATTR_CREATE | crate::linux_abi::LINUX_XATTR_REPLACE) as u64,
        )
        .unwrap();
    assert_eq!(invalid, DispatchOutcome::errno(LINUX_EINVAL));

    let mut readonly = SyscallDispatcher::new();
    readonly.register_mount(
        "/bind",
        Box::new(crate::vfs::BindVfs::new("/bind", host.path(), true)),
    );
    let readonly_result = readonly
        .setxattr(
            &mut memory,
            target,
            GuestPtr(0x4100),
            GuestPtr(0x4200),
            1,
            0,
        )
        .unwrap();
    assert_eq!(readonly_result, DispatchOutcome::errno(LINUX_EROFS));

    memory.write_bytes(0x4000, b"/dev/null\0").unwrap();
    memory.write_bytes(0x4100, b"user.test\0").unwrap();
    let device = SyscallDispatcher::new()
        .setxattr(
            &mut memory,
            XattrTarget::Path {
                path: GuestPtr(0x4000),
                follow: true,
            },
            GuestPtr(0x4100),
            GuestPtr(0x4200),
            1,
            0,
        )
        .unwrap();
    assert_eq!(device, DispatchOutcome::errno(LINUX_EPERM));
}

#[test]
fn memory_file_open_does_not_duplicate_path_record_for_proc_fd() {
    reset_fd_open_path_inserts();

    let backend = crate::fs_backend::MemoryBackend::new();
    backend
        .set_file_contents("/regular.bin", b"payload".to_vec())
        .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/regular.bin\0").unwrap();

    assert_eq!(
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(56, SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, 0, 0, 0, 0]),),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );

    memory.write_bytes(0x4100, b"/proc/self/fd/3\0").unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    78,
                    SyscallArgs::from([LINUX_AT_FDCWD, 0x4100, 0x4200, 64, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 12 }
    );
    assert_eq!(
        memory.read_bytes(0x4200, 12).unwrap(),
        b"/regular.bin".to_vec()
    );
    assert_eq!(
        fd_open_path_inserts(),
        0,
        "fd_open_paths insertions should be 0 for memory OpenDescription::File"
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

/// `close(2)` must retire the descriptor's `fd_open_paths` entry.
///
/// Only one close path used to clear it, so a path-opened descriptor left
/// a permanent entry claiming a freed fd number. The K1 coherent snapshot
/// refuses such a table, which is how this surfaced: a live
/// `carrick debug hvpatch-kernel` against `sleep` under HVPatch reported
/// "file-table open-path index names no live slot" with the orphan
/// `(3, "/usr/lib/locale/C.utf8/LC_CTYPE")` — glibc's locale file, opened,
/// mapped, and closed during startup.
#[test]
fn close_retires_the_fd_open_path_entry() {
    let scratch = tempfile::tempdir().unwrap();
    let dir =
        cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority()).unwrap();
    let backend = crate::fs_backend::HostFsBackend::from_existing_dir(dir);
    backend
        .set_file_contents("/locale.bin", b"payload".to_vec())
        .unwrap();

    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/locale.bin\0").unwrap();

    let context = dispatcher.capture_one_task_context().unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(56, SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, 0, 0, 0, 0]),),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert!(
        context
            .resources()
            .files()
            .read_fd_open_paths()
            .contains_key(&3),
        "a path-opened host descriptor must record its open path"
    );

    assert_eq!(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(57, SyscallArgs::from([3, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(
        context.resources().files().read_fd_open_paths().is_empty(),
        "close must retire the open-path entry; a freed fd cannot own a path"
    );
}

#[test]
fn openat2_resolve_no_symlinks_rejects_link_path() {
    let scratch = tempfile::tempdir().unwrap();
    let dir =
        cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority()).unwrap();
    let backend = crate::fs_backend::HostFsBackend::from_existing_dir(dir);
    backend
        .set_file_contents("/target", b"payload".to_vec())
        .unwrap();
    backend.symlink("target", "/link").unwrap();

    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    memory.write_bytes(0x4000, b"/link\0").unwrap();

    assert_eq!(
        dispatch_openat2_for_test(
            &mut dispatcher,
            &mut memory,
            LINUX_AT_FDCWD,
            0x4000,
            LINUX_O_RDONLY,
            0,
            LINUX_RESOLVE_NO_SYMLINKS,
        )
        .unwrap(),
        DispatchOutcome::errno(crate::linux_abi::LINUX_ELOOP)
    );
}

#[test]
fn openat2_resolve_beneath_rejects_dotdot_escape() {
    let backend = crate::fs_backend::MemoryBackend::new();
    backend.make_dir("/root").unwrap();
    backend.make_dir("/root/dir").unwrap();
    backend
        .set_file_contents("/root/outside", b"payload".to_vec())
        .unwrap();

    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    let reporter = CompatReporter::default();
    memory.write_bytes(0x4000, b"/root/dir\0").unwrap();
    let dirfd = match dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(
                56,
                SyscallArgs::from([
                    LINUX_AT_FDCWD,
                    0x4000,
                    LINUX_O_RDONLY | crate::linux_abi::LINUX_O_DIRECTORY,
                    0,
                    0,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap()
    {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("directory open failed: {other:?}"),
    };
    memory.write_bytes(0x4100, b"../outside\0").unwrap();

    assert_eq!(
        dispatch_openat2_for_test(
            &mut dispatcher,
            &mut memory,
            dirfd,
            0x4100,
            LINUX_O_RDONLY,
            0,
            LINUX_RESOLVE_BENEATH,
        )
        .unwrap(),
        DispatchOutcome::errno(crate::linux_abi::LINUX_EXDEV)
    );
}

#[test]
fn openat2_resolve_no_xdev_rejects_proc_mount_crossing() {
    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    memory.write_bytes(0x4000, b"/proc/self/status\0").unwrap();

    assert_eq!(
        dispatch_openat2_for_test(
            &mut dispatcher,
            &mut memory,
            LINUX_AT_FDCWD,
            0x4000,
            LINUX_O_RDONLY,
            0,
            LINUX_RESOLVE_NO_XDEV,
        )
        .unwrap(),
        DispatchOutcome::errno(crate::linux_abi::LINUX_EXDEV)
    );
}

#[test]
fn openat2_resolve_no_magiclinks_rejects_proc_fd_reopen() {
    let backend = crate::fs_backend::MemoryBackend::new();
    backend
        .set_file_contents("/regular.bin", b"payload".to_vec())
        .unwrap();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let reporter = CompatReporter::default();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    memory.write_bytes(0x4000, b"/regular.bin\0").unwrap();
    let fd = match dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(
                56,
                SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, LINUX_O_RDONLY, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap()
    {
        DispatchOutcome::Returned { value } => value,
        other => panic!("regular open failed: {other:?}"),
    };
    let proc_fd_path = format!("/proc/self/fd/{fd}\0");
    memory.write_bytes(0x4100, proc_fd_path.as_bytes()).unwrap();

    assert_eq!(
        dispatch_openat2_for_test(
            &mut dispatcher,
            &mut memory,
            LINUX_AT_FDCWD,
            0x4100,
            LINUX_O_RDONLY,
            0,
            LINUX_RESOLVE_NO_MAGICLINKS,
        )
        .unwrap(),
        DispatchOutcome::errno(crate::linux_abi::LINUX_ELOOP)
    );
}

#[test]
fn openat2_resolve_in_root_rejects_absolute_escape() {
    let backend = crate::fs_backend::MemoryBackend::new();
    backend.make_dir("/root").unwrap();
    backend
        .set_file_contents("/outside", b"payload".to_vec())
        .unwrap();

    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    let reporter = CompatReporter::default();
    memory.write_bytes(0x4000, b"/root\0").unwrap();
    let dirfd = match dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(
                56,
                SyscallArgs::from([
                    LINUX_AT_FDCWD,
                    0x4000,
                    LINUX_O_RDONLY | crate::linux_abi::LINUX_O_DIRECTORY,
                    0,
                    0,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap()
    {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("root dir open failed: {other:?}"),
    };
    memory.write_bytes(0x4100, b"/outside\0").unwrap();

    assert_eq!(
        dispatch_openat2_for_test(
            &mut dispatcher,
            &mut memory,
            dirfd,
            0x4100,
            LINUX_O_RDONLY,
            0,
            LINUX_RESOLVE_IN_ROOT,
        )
        .unwrap(),
        DispatchOutcome::errno(crate::linux_abi::LINUX_ENOENT)
    );
}

const LINUX_RESOLVE_NO_XDEV: u64 = 0x01;
const LINUX_RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const LINUX_RESOLVE_NO_SYMLINKS: u64 = 0x04;
const LINUX_RESOLVE_BENEATH: u64 = 0x08;
const LINUX_RESOLVE_IN_ROOT: u64 = 0x10;

fn dispatch_openat2_for_test(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut LinearMemory,
    dirfd: u64,
    path_addr: u64,
    flags: u64,
    mode: u64,
    resolve: u64,
) -> Result<DispatchOutcome, DispatchError> {
    const HOW_ADDR: u64 = 0x4f00;
    memory.write_bytes(HOW_ADDR, &flags.to_le_bytes()).unwrap();
    memory
        .write_bytes(HOW_ADDR + 8, &mode.to_le_bytes())
        .unwrap();
    memory
        .write_bytes(HOW_ADDR + 16, &resolve.to_le_bytes())
        .unwrap();
    dispatcher.dispatch(
        &dispatcher.capture_one_task_context().unwrap(),
        SyscallRequest::new(
            437,
            SyscallArgs::from([
                dirfd,
                path_addr,
                HOW_ADDR,
                crate::linux_abi::LINUX_OPEN_HOW_SIZE,
                0,
                0,
            ]),
        ),
        memory,
        &CompatReporter::default(),
    )
}
