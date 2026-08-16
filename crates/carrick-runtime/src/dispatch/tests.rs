#[cfg(test)]
mod overlay_dispatch_tests {
    //! End-to-end overlay tests that drive the public `dispatch` entry
    //! point. The fixture builds a tiny tar-backed RootFs holding one
    //! directory and one file, then exercises the syscall path the same
    //! way the runtime does (SyscallRequest + LinearMemory + compat
    //! reporter). The assertions are what `apt update` needs to keep
    //! working: writable mkdirat, openat O_CREAT + write + read,
    //! unlink-then-ENOENT, rename-moves-overlay-content.
    //!
    //! Keep these tests minimal — there's no need to exercise every
    //! flag combination here, just the four scenarios called out in the
    //! task spec.
    use super::*;
    use crate::compat::CompatReporter;
    use crate::rootfs::LayerSource;
    use tar::{Builder, EntryType, Header};
    const SYS_OPENAT: u64 = 56;
    const SYS_CLOSE: u64 = 57;
    const SYS_READ: u64 = 63;
    const SYS_WRITE: u64 = 64;
    const SYS_NEWFSTATAT: u64 = 79;
    const SYS_CLONE: u64 = 220;
    const SYS_CLONE3: u64 = 435;
    const SYS_MKDIRAT: u64 = 34;
    const SYS_UNLINKAT: u64 = 35;
    const SYS_RENAMEAT: u64 = 38;
    const O_CREAT: u64 = 0o100;
    const O_WRONLY: u64 = 1;
    const O_RDONLY: u64 = 0;

    fn eventfd_open_file(counter: u64) -> OpenFile {
        OpenFile::from_open_description(
            Arc::new(RwLock::new(OpenDescription::EventFd {
                state: Arc::new(EventFdState::new(counter)),
                semaphore: false,
                base: OpenDescriptionBase::new(0),
            })),
            0,
        )
    }

    #[test]
    fn eventfd_write_records_the_host_readiness_transition() {
        const EVENTFD_WRITE_EVENT: u8 = 21;
        let dispatcher = SyscallDispatcher::new();
        let state = EventFdState::new(0x0102_0304);
        let host_read_fd = state.read_fd.as_ref().expect("readiness pipe").raw();
        let increment = LinuxEventfdValue { value: 7 };

        assert!(matches!(
            write_eventfd(&dispatcher, increment.as_bytes(), &state),
            DispatchOutcome::Returned { value: 8 }
        ));
        assert!(
            crate::event_ring::contains_event(
                EVENTFD_WRITE_EVENT,
                host_read_fd,
                0x0102_0304,
                0x0102_030b,
            ),
            "the always-on ring must bind an eventfd write to its host readiness fd"
        );
    }

    #[test]
    fn fd_install_helpers_reserve_single_and_pair_slots_atomically() {
        let dispatcher = SyscallDispatcher::new();

        let first = match dispatcher.install_fd_at_or_above(3, eventfd_open_file(1)) {
            Ok(fd) => fd,
            Err(_) => panic!("expected first fd install to succeed"),
        };
        assert_eq!(first, 3);

        let pair = match dispatcher.install_fd_pair_at_or_above(
            3,
            eventfd_open_file(2),
            eventfd_open_file(3),
        ) {
            Ok(pair) => pair,
            Err(_) => panic!("expected pair install to succeed"),
        };
        assert_eq!(pair, (4, 5));

        let next = match dispatcher.install_fd_at_or_above(3, eventfd_open_file(4)) {
            Ok(fd) => fd,
            Err(_) => panic!("expected next fd install to succeed"),
        };
        assert_eq!(next, 6);
    }

    #[test]
    fn host_write_kind_classifies_common_host_fds() {
        use std::os::fd::AsRawFd;

        let mut pipe_fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        assert_eq!(
            HostWriteKind::for_host_fd(pipe_fds[0]),
            HostWriteKind::PipeLike
        );

        let mut socket_fds = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, socket_fds.as_mut_ptr())
            },
            0
        );
        assert_eq!(
            HostWriteKind::for_host_fd(socket_fds[0]),
            HostWriteKind::SocketLike
        );

        let file = tempfile::tempfile().expect("tempfile");
        assert_eq!(
            HostWriteKind::for_host_fd(file.as_raw_fd()),
            HostWriteKind::RegularFile
        );

        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
            libc::close(socket_fds[0]);
            libc::close(socket_fds[1]);
        }
    }

    #[test]
    fn large_blocking_host_pipe_write_hands_off_after_partial_progress() {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        crate::dispatch::net::set_host_nonblocking(fds[1]);

        let bytes = vec![0xA5; 4 * 1024 * 1024];
        let outcome = write_host_pipe(
            &bytes,
            HostPipeWriteTarget {
                host_fd: fds[1],
                host_fd_owner: None,
                nonblocking: false,
                write_kind: HostWriteKind::PipeLike,
                pipe_state: None,
                tid: crate::thread::ThreadId::synthetic_for_tests(0x7FFE_0101),
                sigpipe_on_epipe: true,
            },
        );

        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }

        let DispatchOutcome::BlockingHostWrite(write) = outcome else {
            panic!("large pipe write should hand off after partial progress, got {outcome:?}");
        };
        assert!(
            write.offset() > 0 && write.offset() < bytes.len(),
            "expected a positive partial offset after filling the pipe, got {}",
            write.offset()
        );
        assert!(write.sigpipe_on_epipe());
    }

    #[test]
    fn large_nonblocking_host_pipe_write_uses_small_ready_window() {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        crate::dispatch::net::set_host_nonblocking(fds[1]);

        let chunk = [0xA5; 4096];
        loop {
            let n = unsafe { libc::write(fds[1], chunk.as_ptr().cast(), chunk.len()) };
            if n > 0 {
                continue;
            }
            let errno = std::io::Error::last_os_error().raw_os_error();
            assert!(matches!(
                errno,
                Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK
            ));
            break;
        }

        let mut byte = [0u8; 1];
        assert_eq!(
            unsafe { libc::read(fds[0], byte.as_mut_ptr().cast(), 1) },
            1
        );

        let bytes = vec![0x5A; 64 * 1024];
        let outcome = write_host_pipe(
            &bytes,
            HostPipeWriteTarget {
                host_fd: fds[1],
                host_fd_owner: None,
                nonblocking: true,
                write_kind: HostWriteKind::PipeLike,
                pipe_state: None,
                tid: crate::thread::ThreadId::synthetic_for_tests(0x7FFE_0103),
                sigpipe_on_epipe: false,
            },
        );

        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }

        let DispatchOutcome::Returned { value } = outcome else {
            panic!("large nonblocking write should make partial progress, got {outcome:?}");
        };
        assert!(
            value > 0 && (value as usize) < bytes.len(),
            "expected a positive partial write, got {value}"
        );
    }

    #[test]
    fn large_nonblocking_host_socket_write_uses_small_ready_window() {
        let mut fds = [-1; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
            0
        );
        crate::dispatch::net::set_host_nonblocking(fds[0]);

        let chunk = [0xA5; 4096];
        loop {
            let n = unsafe { libc::write(fds[0], chunk.as_ptr().cast(), chunk.len()) };
            if n > 0 {
                continue;
            }
            let errno = std::io::Error::last_os_error().raw_os_error();
            assert!(matches!(
                errno,
                Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK
            ));
            break;
        }

        let mut byte = [0u8; 1];
        assert_eq!(
            unsafe { libc::read(fds[1], byte.as_mut_ptr().cast(), 1) },
            1
        );

        let bytes = vec![0x5A; 64 * 1024];
        let outcome = write_host_pipe(
            &bytes,
            HostPipeWriteTarget {
                host_fd: fds[0],
                host_fd_owner: None,
                nonblocking: true,
                write_kind: HostWriteKind::SocketLike,
                pipe_state: None,
                tid: crate::thread::ThreadId::synthetic_for_tests(0x7FFE_0104),
                sigpipe_on_epipe: false,
            },
        );

        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }

        let DispatchOutcome::Returned { value } = outcome else {
            panic!("large nonblocking socket write should make partial progress, got {outcome:?}");
        };
        assert!(
            value > 0 && (value as usize) < bytes.len(),
            "expected a positive partial socket write, got {value}"
        );
    }

    #[test]
    fn anchored_wait_fds_keep_host_fd_live_after_open_file_drop() {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let owner = HostFdRef::new(fds[0]);
        let open_file = OpenFile::from_open_description(
            Arc::new(RwLock::new(OpenDescription::HostPipe {
                base: OpenDescriptionBase::new(0),
                host_fd: owner.clone(),
                is_read_end: true,
                pipe_id: 0,
                pty: None,
                bidirectional: false,
                write_kind: HostWriteKind::PipeLike,
            })),
            0,
        );
        let wait_fds = WaitFds::anchored_one(fds[0], libc::POLLIN, Some(owner));
        drop(open_file);

        let mut pollfd = libc::pollfd {
            fd: wait_fds[0].fd(),
            events: wait_fds[0].events(),
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut pollfd, 1, 0) }, 0);
        // BLOCKING-IO-OK: test-only 1-byte write to a freshly created, empty pipe
        // to make its read end readable; an empty pipe buffer cannot block here.
        assert_eq!(unsafe { libc::write(fds[1], b"x".as_ptr().cast(), 1) }, 1);
        assert_eq!(unsafe { libc::poll(&mut pollfd, 1, 0) }, 1);
        assert_ne!(pollfd.revents & libc::POLLIN, 0);

        drop(wait_fds);
        unsafe {
            libc::close(fds[1]);
        }
    }

    #[test]
    fn blocking_host_write_from_owned_bytes_reuses_buffer_storage() {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);

        let bytes = vec![0x5A; 4096];
        let expected_ptr = bytes.as_ptr();
        let expected_capacity = bytes.capacity();
        let write = BlockingHostWrite::from_vec(
            fds[1],
            bytes,
            128,
            crate::thread::ThreadId::synthetic_for_tests(0x7FFE_0102),
            true,
        )
        .expect("blocking write continuation should be created");

        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }

        assert_eq!(
            write.bytes.as_ptr(),
            expected_ptr,
            "owned handoff should move the staged write buffer without cloning it"
        );
        assert_eq!(write.bytes.capacity(), expected_capacity);
        assert_eq!(write.offset(), 128);
        assert!(write.sigpipe_on_epipe());
    }

    fn child_can_acquire_classic_write_lock(host_fd: i32) -> bool {
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork lock observer");
        if child == 0 {
            let mut lock = unsafe { std::mem::zeroed::<libc::flock>() };
            lock.l_type = libc::F_WRLCK as _;
            lock.l_whence = libc::SEEK_SET as _;
            let result = unsafe { libc::fcntl(host_fd, libc::F_SETLK, &raw mut lock) };
            unsafe { libc::_exit(i32::from(result < 0)) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &raw mut status, 0) }, child);
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }

    #[test]
    fn kernel_exec_publication_filters_cloexec_descriptors() {
        let dispatcher = SyscallDispatcher::new();
        let keep_fd = match dispatcher.install_fd_at_or_above(3, eventfd_open_file(1)) {
            Ok(fd) => fd,
            Err(_) => panic!("expected keep fd install to succeed"),
        };
        let cloexec_fd = match dispatcher.install_fd_at_or_above(
            3,
            OpenFile::from_open_description(
                Arc::new(RwLock::new(OpenDescription::EventFd {
                    state: Arc::new(EventFdState::new(2)),
                    semaphore: false,
                    base: OpenDescriptionBase::new(0),
                })),
                LINUX_FD_CLOEXEC,
            ),
        ) {
            Ok(fd) => fd,
            Err(_) => panic!("expected cloexec fd install to succeed"),
        };

        let context = dispatcher.capture_one_task_context().unwrap();
        let prepared = dispatcher.prepare_one_task_kernel_exec(&context).unwrap();
        dispatcher.commit_one_task_kernel_exec(prepared).unwrap();

        assert!(dispatcher.fd_is_valid(keep_fd));
        assert!(!dispatcher.fd_is_valid(cloexec_fd));
    }

    #[test]
    fn non_cloexec_classic_record_lock_survives_exec_transfer() {
        let dispatcher = SyscallDispatcher::new();
        let named = tempfile::NamedTempFile::new().unwrap();
        let host_fd = std::os::fd::IntoRawFd::into_raw_fd(named.reopen().unwrap());
        let observer_fd = std::os::fd::IntoRawFd::into_raw_fd(named.reopen().unwrap());
        let mut lock = unsafe { std::mem::zeroed::<libc::flock>() };
        lock.l_type = libc::F_WRLCK as _;
        lock.l_whence = libc::SEEK_SET as _;
        assert_eq!(
            unsafe { libc::fcntl(host_fd, libc::F_SETLK, &raw mut lock) },
            0
        );
        let description =
            kernel_file_description(Arc::new(RwLock::new(OpenDescription::HostFile {
                base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDWR),
                host_fd: HostFdRef::new(host_fd),
                metadata: RootFsMetadata {
                    path: std::path::PathBuf::from("/tmp/exec-lock"),
                    kind: RootFsEntryKind::File,
                    mode: 0o600,
                    size: 0,
                },
                writable: true,
            })));
        let fd = dispatcher
            .install_fd_at_or_above(3, OpenFile::new(Arc::clone(&description), 0))
            .unwrap();
        assert!(!child_can_acquire_classic_write_lock(observer_fd));

        let context = dispatcher.capture_one_task_context().unwrap();
        let prepared = dispatcher.prepare_one_task_kernel_exec(&context).unwrap();
        dispatcher.commit_one_task_kernel_exec(prepared).unwrap();
        assert!(!child_can_acquire_classic_write_lock(observer_fd));

        let removed = dispatcher
            .captured_file_table()
            .write_open_files()
            .remove(&fd)
            .expect("surviving lock fd");
        dispatcher.close_open_file_and_free_pty(&removed);
        assert!(child_can_acquire_classic_write_lock(observer_fd));
        unsafe { libc::close(observer_fd) };
    }

    #[test]
    fn dropping_drained_exec_generation_does_not_release_surviving_slot_twice() {
        let dispatcher = SyscallDispatcher::new();
        let description =
            kernel_file_description(Arc::new(RwLock::new(OpenDescription::EventFd {
                state: Arc::new(EventFdState::new(1)),
                semaphore: false,
                base: OpenDescriptionBase::new(0),
            })));
        let fd = dispatcher
            .install_fd_at_or_above(3, OpenFile::new(Arc::clone(&description), 0))
            .unwrap();
        let old_context = dispatcher.capture_one_task_context().unwrap();
        let old_files = old_context.resources().files();
        let prepared = dispatcher
            .prepare_one_task_kernel_exec(&old_context)
            .unwrap();
        dispatcher.commit_one_task_kernel_exec(prepared).unwrap();

        assert_eq!(description.fd_ref_count(), 1);
        assert!(!old_files.functional_refs_active());
        drop(old_context);
        drop(old_files);
        assert_eq!(description.fd_ref_count(), 1);
        assert!(dispatcher.fd_is_valid(fd));

        let removed = dispatcher
            .captured_file_table()
            .write_open_files()
            .remove(&fd)
            .expect("surviving slot");
        dispatcher.close_open_file_and_free_pty(&removed);
        assert_eq!(description.fd_ref_count(), 0);
        assert!(matches!(
            &*description.read(),
            OpenDescription::Closed { .. }
        ));
    }

    #[test]
    fn retained_exec_generation_does_not_keep_cloexec_pipe_writer_alive() {
        let dispatcher = SyscallDispatcher::new();
        let mut host_fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(host_fds.as_mut_ptr()) }, 0);
        let read_host_fd = host_fds[0];
        let writer = kernel_file_description(Arc::new(RwLock::new(OpenDescription::HostPipe {
            host_fd: HostFdRef::new(host_fds[1]),
            is_read_end: false,
            pipe_id: 0x51,
            base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_WRONLY),
            pty: None,
            bidirectional: false,
            write_kind: HostWriteKind::PipeLike,
        })));
        let writer_fd = dispatcher
            .install_fd_at_or_above(3, OpenFile::new(Arc::clone(&writer), LINUX_FD_CLOEXEC))
            .unwrap();
        let old_context = dispatcher.capture_one_task_context().unwrap();
        let old_files = old_context.resources().files();
        let prepared = dispatcher
            .prepare_one_task_kernel_exec(&old_context)
            .unwrap();
        let replacement = dispatcher.commit_one_task_kernel_exec(prepared).unwrap();

        assert!(!old_files.functional_refs_active());
        assert!(old_files.read_open_files().contains_key(&writer_fd));
        assert!(replacement.resources().files().slot_count() == 0);
        assert!(matches!(&*writer.read(), OpenDescription::Closed { .. }));

        let mut pollfd = libc::pollfd {
            fd: read_host_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut pollfd, 1, 0) }, 1);
        assert_ne!(pollfd.revents & libc::POLLHUP, 0);

        unsafe { libc::close(read_host_fd) };
    }

    #[test]
    fn threaded_independent_dispatch_support_matches_handler_table() {
        let supported: Vec<u64> = crate::syscall::aarch64_table()
            .iter()
            .filter(|syscall| threaded_independent_dispatch_supports(syscall.number))
            .map(|syscall| syscall.number)
            .collect();
        // Exact equality gates every independent entry, including the
        // deliberate Process/Deferred exceptions (getpid and futex_waitv),
        // while the loop below proves every ThreadLocal entry is included.
        assert_eq!(supported, vec![96, 98, 99, 124, 172, 178, 449]);

        for syscall in crate::syscall::aarch64_table() {
            if syscall.handler == crate::syscall::SyscallHandler::ThreadLocal {
                assert!(
                    threaded_independent_dispatch_supports(syscall.number),
                    "thread-local syscall {} ({}) must be handled without panicking",
                    syscall.number,
                    syscall.name
                );
            }
        }
    }

    #[test]
    fn join_rootfs_path_normalizes_relative_components() {
        assert_eq!(join_rootfs_path("/", "."), "/");
        assert_eq!(join_rootfs_path("/", ".."), "/");
        assert_eq!(join_rootfs_path("/tmp/work", ".."), "/tmp");
        assert_eq!(join_rootfs_path("/tmp/work", "../other/."), "/tmp/other");
        assert_eq!(join_rootfs_path("/tmp/work", "../../.."), "/");
    }

    #[test]
    fn exec_host_fs_fallback_off_for_container_dispatchers() {
        // A bare run-elf dispatcher (no container fs) may fall back to the host
        // filesystem for an execve target (host-staged RunElf fixtures).
        assert!(
            SyscallDispatcher::new().exec_host_fs_fallback(),
            "bare new() dispatcher must allow the host-fs execve fallback"
        );
        // A container dispatcher must NOT: a target absent from the rootfs must
        // ENOENT, never escape to the matching host binary (the containment hole
        // that loaded host glibc /usr/bin/echo into a musl rootfs mid-execvp).
        assert!(
            !SyscallDispatcher::with_rootfs(empty_rootfs()).exec_host_fs_fallback(),
            "with_rootfs dispatcher must forbid the host-fs execve fallback"
        );
        assert!(
            !SyscallDispatcher::with_rootfs_and_executable(empty_rootfs(), "/bin/sh")
                .exec_host_fs_fallback(),
            "with_rootfs_and_executable dispatcher must forbid the host-fs execve fallback"
        );
        // The overlay-only container path (run-oci / --fs host use new() +
        // set_fs_backend, not with_rootfs) opts in explicitly.
        let mut d = SyscallDispatcher::new();
        d.sandbox_exec_to_container();
        assert!(
            !d.exec_host_fs_fallback(),
            "sandbox_exec_to_container() must forbid the host-fs execve fallback"
        );
    }

    #[test]
    fn inode_for_path_reflects_identity_not_textual_spelling() {
        // The same file reached via different textual spellings must map to
        // ONE inode, or TOCTOU identity checks abort: dpkg-preconfigure stats
        // a dir, chdirs in, re-stats ".", and aborts if the inode changed
        // ("directory /var/cache/debconf/tmp.ci changed before chdir").
        // "." after chdir resolves to "/dir/.", so that must hash the same as
        // "/dir".
        let canonical = inode_for_path(Path::new("/tmp/d"));
        assert_eq!(canonical, inode_for_path(Path::new("/tmp/d/.")));
        assert_eq!(canonical, inode_for_path(Path::new("/tmp/d/")));
        assert_eq!(canonical, inode_for_path(Path::new("/tmp//d")));
        assert_eq!(canonical, inode_for_path(Path::new("/tmp/d/sub/..")));
        // Distinct files still get distinct inodes.
        assert_ne!(canonical, inode_for_path(Path::new("/tmp/e")));
        // Never zero — some tools treat st_ino == 0 as "no such entry".
        assert_ne!(inode_for_path(Path::new("/")), 0);
        assert_ne!(inode_for_path(Path::new("/tmp/d")), 0);
    }

    /// 16 KiB scratch buffer at virtual base 0x4000_0000. Tests pack
    /// pathnames + read/write buffers into this. The dispatcher itself
    /// only needs valid byte addresses for the syscalls under test —
    /// stat/statx writes a small fixed-size struct into the buffer.
    const MEM_BASE: u64 = 0x4000_0000;
    const MEM_LEN: usize = 16 * 1024;

    fn empty_rootfs() -> RootFs {
        // Bake a single layer containing /etc/motd and the directories
        // it lives under, so we can exercise both the rootfs-backed and
        // overlay-backed lookup paths.
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut builder = Builder::new(&mut buf);
            for dir in ["etc", "var", "var/lib", "var/lib/apt"] {
                let mut h = Header::new_gnu();
                h.set_path(format!("{}/", dir)).unwrap();
                h.set_entry_type(EntryType::Directory);
                h.set_size(0);
                h.set_mode(0o755);
                h.set_cksum();
                builder.append(&h, std::io::empty()).unwrap();
            }
            let body: &[u8] = b"hello, world\n";
            let mut h = Header::new_gnu();
            h.set_path("etc/motd").unwrap();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            builder.append(&h, body).unwrap();
            builder.finish().unwrap();
        }
        RootFs::from_layers(std::iter::once(LayerSource::Tar(buf))).unwrap()
    }

    #[cfg(target_os = "macos")]
    fn dispatcher_with_host_lower(
        lower: &std::path::Path,
        upper: &std::path::Path,
    ) -> SyscallDispatcher {
        let rootfs = RootFs::from_immutable_host_dir(lower).unwrap();
        let upper_dir =
            cap_std::fs::Dir::open_ambient_dir(upper, cap_std::ambient_authority()).unwrap();
        let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);
        dispatcher.set_fs_backend(Box::new(
            crate::fs_backend::HostFsBackend::from_existing_dir(upper_dir),
        ));
        dispatcher
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn exec_helpers_use_bounded_reads_and_host_files_from_immutable_lower() {
        use std::io::Read as _;

        let lower = tempfile::TempDir::new().unwrap();
        let upper = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(lower.path().join("bin")).unwrap();
        let mut payload = b"#!/bin/sh\n".to_vec();
        payload.resize(2 * 1024 * 1024, b'x');
        std::fs::write(lower.path().join("bin/tool"), &payload).unwrap();

        let dispatcher = dispatcher_with_host_lower(lower.path(), upper.path());
        assert_eq!(
            dispatcher.read_exec_file_head("/bin/tool", 4).as_deref(),
            Some(&b"#!/b"[..])
        );
        let mut file = dispatcher
            .open_exec_host_file("/bin/tool")
            .expect("lower executable should remain file-backed");
        let mut head = [0_u8; 4];
        file.read_exact(&mut head).unwrap();
        assert_eq!(&head, b"#!/b");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn exec_helpers_never_resurrect_a_shadowed_or_tombstoned_lower() {
        use std::io::Read as _;

        let lower = tempfile::TempDir::new().unwrap();
        let upper = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(lower.path().join("bin")).unwrap();
        std::fs::write(lower.path().join("bin/tool"), b"lower").unwrap();
        let dispatcher = dispatcher_with_host_lower(lower.path(), upper.path());

        dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .set_file_contents("/bin/tool", b"upper".to_vec())
            .unwrap();
        assert_eq!(
            dispatcher.read_exec_file("/bin/tool").as_deref(),
            Some(&b"upper"[..])
        );
        let mut upper_file = dispatcher.open_exec_host_file("/bin/tool").unwrap();
        let mut bytes = Vec::new();
        upper_file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"upper");

        dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .mark_deleted("/bin/tool")
            .unwrap();
        assert!(dispatcher.read_exec_file("/bin/tool").is_none());
        assert!(dispatcher.read_exec_file_head("/bin/tool", 4).is_none());
        assert!(dispatcher.open_exec_host_file("/bin/tool").is_none());
        assert_eq!(
            std::fs::read(lower.path().join("bin/tool")).unwrap(),
            b"lower"
        );
    }

    struct Harness {
        dispatcher: SyscallDispatcher,
        memory: LinearMemory,
        reporter: CompatReporter,
        cursor: u64,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                dispatcher: SyscallDispatcher::with_rootfs(empty_rootfs()),
                memory: LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]),
                reporter: CompatReporter::default(),
                cursor: MEM_BASE + 4096, // leave the first page for stat bufs etc
            }
        }

        /// Copy `s` (NUL-terminated) into the guest scratch region and
        /// return its address.
        fn put_str(&mut self, s: &str) -> u64 {
            let addr = self.cursor;
            let mut bytes = s.as_bytes().to_vec();
            bytes.push(0);
            self.memory.write_bytes(addr, &bytes).unwrap();
            self.cursor += bytes.len() as u64;
            // 8-byte align for the next allocation.
            self.cursor = (self.cursor + 7) & !7;
            addr
        }

        fn put_bytes(&mut self, b: &[u8]) -> u64 {
            let addr = self.cursor;
            self.memory.write_bytes(addr, b).unwrap();
            self.cursor += b.len() as u64;
            self.cursor = (self.cursor + 7) & !7;
            addr
        }

        fn reserve(&mut self, n: usize) -> u64 {
            let addr = self.cursor;
            self.cursor += n as u64;
            self.cursor = (self.cursor + 7) & !7;
            addr
        }

        fn call(&mut self, number: u64, args: [u64; 6]) -> DispatchOutcome {
            let request = SyscallRequest::new(number, SyscallArgs(args));
            self.dispatcher
                .dispatch(
                    &self.dispatcher.capture_one_task_context().unwrap(),
                    request,
                    &mut self.memory,
                    &self.reporter,
                )
                .expect("dispatch must not surface a fatal error")
        }
    }

    fn returned(outcome: DispatchOutcome) -> i64 {
        match outcome {
            DispatchOutcome::Returned { value } => value,
            other => panic!("expected Returned, got {other:?}"),
        }
    }

    fn errno(outcome: DispatchOutcome) -> i32 {
        match outcome {
            DispatchOutcome::Errno { errno } => errno.get(),
            other => panic!("expected Errno, got {other:?}"),
        }
    }

    #[test]
    fn host_alias_transaction_id_overflow_aborts() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let no_core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) };
            let dispatcher = SyscallDispatcher::new();
            dispatcher
                .host_alias_transactions
                .next_id
                .store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
            let guard = dispatcher.begin_host_alias_dispatch();
            let _ = guard.publish(HostAliasCommit::mmap(mem::HostAliasMmapCommit {
                start: crate::memory::LINUX_HIGH_VA_THRESHOLD,
                len: LINUX_PAGE_SIZE,
                prot: LinuxProtFlags::READ,
                sharing: ProcMapSharing::Private,
                path: String::new(),
                file_page_offset: None,
                locked: None,
                resident: false,
                bus_fault: None,
                write_sealed_shared: false,
                read_only_shared_file: false,
                writable_memfd: None,
            }));
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFSIGNALED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[allow(dead_code)]
    fn host_alias_test_commit() -> HostAliasCommit {
        HostAliasCommit::mmap(mem::HostAliasMmapCommit {
            start: crate::memory::LINUX_HIGH_VA_THRESHOLD,
            len: LINUX_PAGE_SIZE,
            prot: LinuxProtFlags::READ,
            sharing: ProcMapSharing::Private,
            path: String::new(),
            file_page_offset: None,
            locked: None,
            resident: false,
            bus_fault: None,
            write_sealed_shared: false,
            read_only_shared_file: false,
            writable_memfd: None,
        })
    }

    #[test]
    fn epoll_et_repolls_host_level_when_mux_misses_wake() {
        let mut h = Harness::new();
        let epfd = returned(h.call(20, [0, 0, 0, 0, 0, 0])) as u64;

        let pair_addr = h.reserve(8);
        assert_eq!(
            returned(h.call(
                199,
                [
                    LINUX_AF_UNIX as u64,
                    LINUX_SOCK_STREAM as u64 | LINUX_O_NONBLOCK,
                    0,
                    pair_addr,
                    0,
                    0,
                ],
            )),
            0
        );
        let pair = h.memory.read_bytes(pair_addr, 8).unwrap();
        let reader = i32::from_le_bytes(pair[0..4].try_into().unwrap());
        let writer = i32::from_le_bytes(pair[4..8].try_into().unwrap());

        let ev_addr = h.reserve(16);
        let mut ev = [0u8; 16];
        ev[0..4].copy_from_slice(&(LINUX_EPOLLIN | LINUX_EPOLLET).to_le_bytes());
        ev[8..16].copy_from_slice(&(reader as u64).to_le_bytes());
        h.memory.write_bytes(ev_addr, &ev).unwrap();
        assert_eq!(
            returned(h.call(
                21,
                [epfd, LINUX_EPOLL_CTL_ADD, reader as u64, ev_addr, 0, 0],
            )),
            0
        );

        let byte_addr = h.put_bytes(b"x");
        assert_eq!(
            returned(h.call(64, [writer as u64, byte_addr, 1, 0, 0, 0])),
            1
        );

        let epoll_open = h.dispatcher.open_file(epfd as i32).expect("epoll fd");
        {
            let open = epoll_open.description.read();
            let OpenDescription::Epoll { kqueue, .. } = &*open else {
                panic!("epfd should be an epoll description");
            };
            let host_fd = h
                .dispatcher
                .host_fd_for_poll(reader)
                .expect("reader should be host-backed");
            kqueue.with_mux(|mux| {
                mux.deregister(host_fd.get())
                    .expect("test setup should remove host wake filter");
            });
        }

        let out_addr = h.reserve(16);
        let n = returned(h.call(22, [epfd, out_addr, 1, 0, 0, 0]));
        assert_eq!(
            n, 1,
            "epoll_pwait must resample host fd levels when the host wake edge is stale"
        );
        let out = h.memory.read_bytes(out_addr, 16).unwrap();
        let events = u32::from_le_bytes(out[0..4].try_into().unwrap());
        let data = u64::from_le_bytes(out[8..16].try_into().unwrap());
        assert_ne!(events & LINUX_EPOLLIN, 0);
        assert_eq!(data, reader as u64);
    }

    #[test]
    fn epoll_et_delivers_new_host_edge_while_level_still_ready() {
        let mut h = Harness::new();
        let epfd = returned(h.call(20, [0, 0, 0, 0, 0, 0])) as u64;

        let pair_addr = h.reserve(8);
        assert_eq!(
            returned(h.call(
                199,
                [
                    LINUX_AF_UNIX as u64,
                    LINUX_SOCK_STREAM as u64 | LINUX_O_NONBLOCK,
                    0,
                    pair_addr,
                    0,
                    0,
                ],
            )),
            0
        );
        let pair = h.memory.read_bytes(pair_addr, 8).unwrap();
        let reader = i32::from_le_bytes(pair[0..4].try_into().unwrap());
        let writer = i32::from_le_bytes(pair[4..8].try_into().unwrap());

        let ev_addr = h.reserve(16);
        let mut ev = [0u8; 16];
        ev[0..4].copy_from_slice(&(LINUX_EPOLLIN | LINUX_EPOLLET).to_le_bytes());
        ev[8..16].copy_from_slice(&(reader as u64).to_le_bytes());
        h.memory.write_bytes(ev_addr, &ev).unwrap();
        assert_eq!(
            returned(h.call(
                21,
                [epfd, LINUX_EPOLL_CTL_ADD, reader as u64, ev_addr, 0, 0],
            )),
            0
        );

        let first_addr = h.put_bytes(b"a");
        assert_eq!(
            returned(h.call(64, [writer as u64, first_addr, 1, 0, 0, 0])),
            1
        );
        let out_addr = h.reserve(16);
        assert_eq!(returned(h.call(22, [epfd, out_addr, 1, 0, 0, 0])), 1);

        let second_addr = h.put_bytes(b"b");
        assert_eq!(
            returned(h.call(64, [writer as u64, second_addr, 1, 0, 0, 0])),
            1
        );
        let n = returned(h.call(22, [epfd, out_addr, 1, 0, 0, 0]));
        assert_eq!(
            n, 1,
            "a new host ET edge must be delivered even while the fd remains level-readable"
        );
        let out = h.memory.read_bytes(out_addr, 16).unwrap();
        let events = u32::from_le_bytes(out[0..4].try_into().unwrap());
        let data = u64::from_le_bytes(out[8..16].try_into().unwrap());
        assert_ne!(events & LINUX_EPOLLIN, 0);
        assert_eq!(data, reader as u64);
    }

    #[test]
    fn io_uring_fd_generic_operations_match_linux_anonymous_inode_semantics() {
        let mut h = Harness::new();
        let params = h.reserve(core::mem::size_of::<crate::linux_abi::LinuxIoUringParams>());
        let ring_fd = returned(h.call(425, [8, params, 0, 0, 0, 0])) as i32;

        let stat = h.reserve(core::mem::size_of::<crate::linux_abi::LinuxStat>());
        assert_eq!(returned(h.call(80, [ring_fd as u64, stat, 0, 0, 0, 0])), 0);
        assert_eq!(
            returned(h.call(25, [ring_fd as u64, LINUX_F_GETFL, 0, 0, 0, 0])),
            LINUX_O_RDWR as i64
        );
        let byte = h.put_bytes(&[0]);
        assert_eq!(
            errno(h.call(63, [ring_fd as u64, byte, 1, 0, 0, 0])),
            LINUX_EINVAL.get()
        );
        assert_eq!(
            errno(h.call(64, [ring_fd as u64, byte, 1, 0, 0, 0])),
            LINUX_EINVAL.get()
        );

        let path = h.put_str(&format!("/proc/self/fd/{ring_fd}"));
        let link = h.reserve(64);
        let link_len = returned(h.call(78, [LINUX_AT_FDCWD, path, link, 64, 0, 0])) as usize;
        assert_eq!(
            h.memory.read_bytes(link, link_len).unwrap(),
            b"anon_inode:[io_uring]"
        );

        let pollfd = h.put_bytes(
            &[
                (ring_fd as u32).to_le_bytes().as_slice(),
                LINUX_POLLOUT.to_le_bytes().as_slice(),
                0_i16.to_le_bytes().as_slice(),
            ]
            .concat(),
        );
        assert_eq!(returned(h.call(73, [pollfd, 1, 0, 0, 0, 0])), 1);
        let observed = h.memory.read_bytes(pollfd, 8).unwrap();
        assert_ne!(
            i16::from_le_bytes(observed[6..8].try_into().unwrap()) & LINUX_POLLOUT,
            0
        );

        let epfd = returned(h.call(20, [0, 0, 0, 0, 0, 0])) as i32;
        let event = h.put_bytes(
            &[
                LINUX_EPOLLIN.to_le_bytes().as_slice(),
                0_u32.to_le_bytes().as_slice(),
                1_u64.to_le_bytes().as_slice(),
            ]
            .concat(),
        );
        assert_eq!(
            returned(h.call(
                21,
                [
                    epfd as u64,
                    LINUX_EPOLL_CTL_ADD,
                    ring_fd as u64,
                    event,
                    0,
                    0,
                ],
            )),
            0
        );
    }

    #[test]
    fn epoll_et_read_via_dup_rearms_registered_sibling() {
        let mut h = Harness::new();
        let epfd = returned(h.call(20, [0, 0, 0, 0, 0, 0])) as u64;

        let pair_addr = h.reserve(8);
        assert_eq!(
            returned(h.call(
                199,
                [
                    LINUX_AF_UNIX as u64,
                    LINUX_SOCK_STREAM as u64 | LINUX_O_NONBLOCK,
                    0,
                    pair_addr,
                    0,
                    0,
                ],
            )),
            0
        );
        let pair = h.memory.read_bytes(pair_addr, 8).unwrap();
        let reader = i32::from_le_bytes(pair[0..4].try_into().unwrap());
        let writer = i32::from_le_bytes(pair[4..8].try_into().unwrap());
        let registered_reader = returned(h.call(23, [reader as u64, 0, 0, 0, 0, 0])) as i32;
        assert_eq!(
            h.dispatcher.host_fd_for_poll(reader),
            h.dispatcher.host_fd_for_poll(registered_reader),
            "dup siblings should share the same host fd"
        );

        let ev_addr = h.reserve(16);
        let mut ev = [0u8; 16];
        ev[0..4].copy_from_slice(&(LINUX_EPOLLIN | LINUX_EPOLLET).to_le_bytes());
        ev[8..16].copy_from_slice(&(registered_reader as u64).to_le_bytes());
        h.memory.write_bytes(ev_addr, &ev).unwrap();
        assert_eq!(
            returned(h.call(
                21,
                [
                    epfd,
                    LINUX_EPOLL_CTL_ADD,
                    registered_reader as u64,
                    ev_addr,
                    0,
                    0,
                ],
            )),
            0
        );
        let epoll_description = h
            .dispatcher
            .open_file(epfd as i32)
            .expect("epoll description")
            .description;
        let target_description = h
            .dispatcher
            .open_file(registered_reader)
            .expect("registered description")
            .description;
        let (_, is_epoll, interests, backing, owners) = epoll_description
            .snapshot_for_test(std::time::Instant::now() + std::time::Duration::from_secs(1))
            .expect("concrete epoll snapshot");
        assert!(is_epoll);
        assert_eq!(interests, vec![target_description.id()]);
        assert!(owners.is_empty());
        let backing = backing.expect("concrete backing summary");
        assert_eq!(
            backing.kind(),
            crate::kernel::FileDescriptionBackingKind::Epoll
        );
        assert_eq!(backing.epoll_interests(), interests);

        let out_addr = h.reserve(16);
        let first_addr = h.put_bytes(b"a");
        assert_eq!(
            returned(h.call(64, [writer as u64, first_addr, 1, 0, 0, 0])),
            1
        );
        assert_eq!(returned(h.call(22, [epfd, out_addr, 1, 0, 0, 0])), 1);

        let read_addr = h.reserve(1);
        let read_args = SyscallArgs::from([reader as u64, read_addr, 1, 0, 0, 0]);
        let read_request = SyscallRequest::new(63, read_args);
        let read_outcome = h
            .dispatcher
            .dispatch(
                &h.dispatcher.capture_one_task_context().unwrap(),
                read_request,
                &mut h.memory,
                &h.reporter,
            )
            .expect("read dispatch");
        assert!(matches!(
            read_outcome,
            DispatchOutcome::Returned { value: 1 }
        ));
        assert!(
            h.dispatcher
                .captured_file_table()
                .read_epoll_fds()
                .contains(&(epfd as i32)),
            "epoll fd should be tracked for rearm"
        );
        h.dispatcher
            .epoll_rearm_after_io(&read_request, &read_outcome);
        {
            let epoll_open = h.dispatcher.open_file(epfd as i32).expect("epoll fd");
            let open = epoll_open.description.read();
            let OpenDescription::Epoll { interest, .. } = &*open else {
                panic!("epfd should be an epoll description");
            };
            let slot = interest
                .get(&registered_reader)
                .expect("registered dup interest");
            assert_eq!(
                slot.last_ready & LINUX_EPOLLIN,
                0,
                "read through a dup sibling must clear the registered fd latch"
            );
        }

        let second_addr = h.put_bytes(b"b");
        assert_eq!(
            returned(h.call(64, [writer as u64, second_addr, 1, 0, 0, 0])),
            1
        );
        let host_fd = h
            .dispatcher
            .host_fd_for_poll(registered_reader)
            .expect("registered reader host fd");
        let mut pfd = libc::pollfd {
            fd: host_fd.get(),
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_rc = unsafe { libc::poll(&mut pfd, 1, 0) };
        assert_eq!(poll_rc, 1, "second write should make host fd readable");
        assert_ne!(pfd.revents & libc::POLLIN, 0);
        let n = returned(h.call(22, [epfd, out_addr, 1, 0, 0, 0]));
        assert_eq!(
            n, 1,
            "consuming readiness through a dup sibling must re-arm ET interest"
        );
        let out = h.memory.read_bytes(out_addr, 16).unwrap();
        let events = u32::from_le_bytes(out[0..4].try_into().unwrap());
        let data = u64::from_le_bytes(out[8..16].try_into().unwrap());
        assert_ne!(events & LINUX_EPOLLIN, 0);
        assert_eq!(data, registered_reader as u64);
    }

    // The host TCP handshake that completes a listening socket's accept queue
    // is asynchronous relative to `connect()` returning on the client side: the
    // client-side call can return before the LISTENER side's kernel state (and
    // thus carrick's epoll/kqueue bridge) has observed the new connection. A
    // single immediate `epoll_wait` can therefore race a real, still-in-flight
    // host completion (a time-assumption, not a dispatcher correctness issue —
    // once the edge is observed it is never re-delivered, so retrying only
    // gives the async completion a bounded, unhurried chance to land before
    // failing the assertion for real).
    fn epoll_wait_ready(h: &mut Harness, epfd: u64, out_addr: u64) -> i64 {
        let start = std::time::Instant::now();
        loop {
            let n = returned(h.call(22, [epfd, out_addr, 1, 0, 0, 0]));
            if n != 0 || start.elapsed() >= std::time::Duration::from_millis(200) {
                return n;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    #[test]
    fn epoll_et_delivers_listener_edge_without_read_byte_growth() {
        let mut h = Harness::new();
        let epfd = returned(h.call(20, [0, 0, 0, 0, 0, 0])) as u64;

        let listener = returned(h.call(
            198,
            [LINUX_AF_INET as u64, LINUX_SOCK_STREAM as u64, 0, 0, 0, 0],
        )) as i32;

        let bind_addr = h.reserve(16);
        let mut sockaddr = [0u8; 16];
        sockaddr[0..2].copy_from_slice(&(LINUX_AF_INET as u16).to_ne_bytes());
        sockaddr[2..4].copy_from_slice(&0u16.to_be_bytes());
        sockaddr[4..8].copy_from_slice(&[127, 0, 0, 1]);
        h.memory.write_bytes(bind_addr, &sockaddr).unwrap();
        assert_eq!(
            returned(h.call(200, [listener as u64, bind_addr, 16, 0, 0, 0])),
            0
        );
        assert_eq!(returned(h.call(201, [listener as u64, 8, 0, 0, 0, 0])), 0);

        let name_addr = h.reserve(16);
        let name_len_addr = h.reserve(4);
        h.memory
            .write_bytes(name_len_addr, &(16u32).to_ne_bytes())
            .unwrap();
        assert_eq!(
            returned(h.call(204, [listener as u64, name_addr, name_len_addr, 0, 0, 0],)),
            0
        );
        let bound = h.memory.read_bytes(name_addr, 16).unwrap();
        let port = u16::from_be_bytes([bound[2], bound[3]]);
        assert_ne!(port, 0);

        let ev_addr = h.reserve(16);
        let mut ev = [0u8; 16];
        ev[0..4].copy_from_slice(&(LINUX_EPOLLIN | LINUX_EPOLLET).to_le_bytes());
        ev[8..16].copy_from_slice(&(listener as u64).to_le_bytes());
        h.memory.write_bytes(ev_addr, &ev).unwrap();
        assert_eq!(
            returned(h.call(
                21,
                [epfd, LINUX_EPOLL_CTL_ADD, listener as u64, ev_addr, 0, 0],
            )),
            0
        );

        let mut host_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        #[cfg(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        ))]
        {
            host_addr.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        }
        host_addr.sin_family = libc::AF_INET as libc::sa_family_t;
        host_addr.sin_port = port.to_be();
        host_addr.sin_addr = libc::in_addr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        };
        let connect_client = || {
            let client = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            assert!(client >= 0, "host client socket");
            let rc = unsafe {
                libc::connect(
                    client,
                    &host_addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            assert_eq!(rc, 0, "host client connect");
            client
        };

        let out_addr = h.reserve(16);
        let client1 = connect_client();
        assert_eq!(epoll_wait_ready(&mut h, epfd, out_addr), 1);
        assert_eq!(
            returned(h.call(22, [epfd, out_addr, 1, 0, 0, 0])),
            0,
            "EPOLLET must not blindly redeliver a still-unaccepted listener level"
        );

        let client2 = connect_client();
        let n = epoll_wait_ready(&mut h, epfd, out_addr);
        unsafe {
            libc::close(client1);
            libc::close(client2);
        }
        assert_eq!(
            n, 1,
            "a later listener EPOLLET edge must be delivered even though FIONREAD stays zero"
        );
        let out = h.memory.read_bytes(out_addr, 16).unwrap();
        let events = u32::from_le_bytes(out[0..4].try_into().unwrap());
        let data = u64::from_le_bytes(out[8..16].try_into().unwrap());
        assert_ne!(events & LINUX_EPOLLIN, 0);
        assert_eq!(data, listener as u64);
    }

    // A listener's ET readiness is "a connection ARRIVED since you last
    // drained", NOT "the accept queue got deeper": its readiness COUNT (the
    // kqueue `EVFILT_READ` `data` = pending accept-queue depth, which is the
    // only count a listener has — FIONREAD is always 0) is not monotonic,
    // because accepting drains it. So the low-rate SEQUENTIAL-connect shape
    // below cycles the depth 0 -> 1 -> 0 and every arrival after the first is
    // reported at a depth EQUAL to (never greater than) the depth the previous
    // edge was reported at:
    //
    //   connN arrives (depth 1) -> epoll_wait MUST deliver the edge
    //   accept to EAGAIN        (depth 0)
    //
    // `epoll_pwait`'s depth-growth term (`observed > last_read_avail`) cannot
    // see that arrival — it is the CONSUMPTION re-arm (`epoll_rearm_after_io`:
    // an accept-family syscall on the listener clears the read latch AND zeroes
    // the count baseline) that turns it back into a fresh `raw & !last_ready`
    // edge. This test pins that contract from the guest's side: if the drain
    // ever stopped resetting the latch/baseline (e.g. by decrementing the depth
    // instead of clearing it), connection N would stall until connection N+1
    // pushed the depth to 2 — a real hang for an ET accept loop.
    // (Sibling test `..._without_read_byte_growth` drives the depth
    // MONOTONICALLY 1 -> 2 without ever accepting, so it covers only the
    // growth term and cannot see this.)
    #[test]
    fn epoll_et_delivers_listener_edge_after_accept_drain() {
        let mut h = Harness::new();
        let epfd = returned(h.call(20, [0, 0, 0, 0, 0, 0])) as u64;

        // Non-blocking listener: the ET contract is "accept until EAGAIN".
        let listener = returned(h.call(
            198,
            [
                LINUX_AF_INET as u64,
                LINUX_SOCK_STREAM as u64 | LINUX_O_NONBLOCK,
                0,
                0,
                0,
                0,
            ],
        )) as i32;

        let bind_addr = h.reserve(16);
        let mut sockaddr = [0u8; 16];
        sockaddr[0..2].copy_from_slice(&(LINUX_AF_INET as u16).to_ne_bytes());
        sockaddr[2..4].copy_from_slice(&0u16.to_be_bytes());
        sockaddr[4..8].copy_from_slice(&[127, 0, 0, 1]);
        h.memory.write_bytes(bind_addr, &sockaddr).unwrap();
        assert_eq!(
            returned(h.call(200, [listener as u64, bind_addr, 16, 0, 0, 0])),
            0
        );
        assert_eq!(returned(h.call(201, [listener as u64, 8, 0, 0, 0, 0])), 0);

        let name_addr = h.reserve(16);
        let name_len_addr = h.reserve(4);
        h.memory
            .write_bytes(name_len_addr, &(16u32).to_ne_bytes())
            .unwrap();
        assert_eq!(
            returned(h.call(204, [listener as u64, name_addr, name_len_addr, 0, 0, 0],)),
            0
        );
        let bound = h.memory.read_bytes(name_addr, 16).unwrap();
        let port = u16::from_be_bytes([bound[2], bound[3]]);
        assert_ne!(port, 0);

        let ev_addr = h.reserve(16);
        let mut ev = [0u8; 16];
        ev[0..4].copy_from_slice(&(LINUX_EPOLLIN | LINUX_EPOLLET).to_le_bytes());
        ev[8..16].copy_from_slice(&(listener as u64).to_le_bytes());
        h.memory.write_bytes(ev_addr, &ev).unwrap();
        assert_eq!(
            returned(h.call(
                21,
                [epfd, LINUX_EPOLL_CTL_ADD, listener as u64, ev_addr, 0, 0],
            )),
            0
        );

        let listener_host_fd = h
            .dispatcher
            .host_fd_for_poll(listener)
            .expect("listener host fd")
            .get();

        let mut host_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        #[cfg(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        ))]
        {
            host_addr.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        }
        host_addr.sin_family = libc::AF_INET as libc::sa_family_t;
        host_addr.sin_port = port.to_be();
        host_addr.sin_addr = libc::in_addr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        };
        // The TCP handshake is asynchronous relative to the client's connect()
        // returning, so BLOCK (bounded) on the listener's host readability
        // instead of sleeping: once poll(2) reports POLLIN the connection is in
        // the accept queue and every assertion below is deterministic.
        let connect_client = || {
            let client = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            assert!(client >= 0, "host client socket");
            let rc = unsafe {
                libc::connect(
                    client,
                    &host_addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            assert_eq!(rc, 0, "host client connect");
            let mut pfd = libc::pollfd {
                fd: listener_host_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let poll_rc = unsafe { libc::poll(&mut pfd, 1, 10_000) };
            assert_eq!(poll_rc, 1, "listener must become readable after connect");
            assert_ne!(pfd.revents & libc::POLLIN, 0);
            client
        };

        let out_addr = h.reserve(16);
        let accepted_addr = h.reserve(16);
        let accepted_len_addr = h.reserve(4);
        let accept_once = |h: &mut Harness| {
            h.memory
                .write_bytes(accepted_len_addr, &(16u32).to_ne_bytes())
                .unwrap();
            h.call(
                202,
                [listener as u64, accepted_addr, accepted_len_addr, 0, 0, 0],
            )
        };
        let listener_latch = |h: &Harness| {
            let epoll_open = h.dispatcher.open_file(epfd as i32).expect("epoll fd");
            let open = epoll_open.description.read();
            let OpenDescription::Epoll { interest, .. } = &*open else {
                panic!("epfd should be an epoll description");
            };
            let slot = interest.get(&listener).expect("listener interest");
            (slot.last_ready, slot.last_read_avail)
        };

        let mut clients = Vec::new();
        let mut accepted = Vec::new();
        let mut latch_after_drain = Vec::new();
        // Three sequential arrivals. Round 1 is the only one a "count grew"
        // predicate could carry; rounds 2 and 3 arrive at the SAME depth (1)
        // round 1 was reported at.
        for round in 1..=3 {
            clients.push(connect_client());

            let n = returned(h.call(22, [epfd, out_addr, 1, 0, 0, 0]));
            assert_eq!(
                n, 1,
                "round {round}: the listener EPOLLET edge for a connection that \
                 arrived after an accept-drain must be delivered — the depth is \
                 back at 1, so growth-over-baseline cannot see it"
            );
            let out = h.memory.read_bytes(out_addr, 16).unwrap();
            let events = u32::from_le_bytes(out[0..4].try_into().unwrap());
            let data = u64::from_le_bytes(out[8..16].try_into().unwrap());
            assert_ne!(events & LINUX_EPOLLIN, 0, "round {round}: EPOLLIN");
            assert_eq!(data, listener as u64, "round {round}: epoll_data");
            let (last_ready, _) = listener_latch(&h);
            assert_ne!(
                last_ready & LINUX_EPOLLIN,
                0,
                "round {round}: delivery must latch the reported readiness"
            );

            // The same, still-unaccepted connection must NOT be redelivered:
            // the latch masks it and the count baseline records the depth it was
            // reported at, so the not-yet-drained kqueue knote cannot masquerade
            // as growth.
            assert_eq!(
                returned(h.call(22, [epfd, out_addr, 1, 0, 0, 0])),
                0,
                "round {round}: EPOLLET must not redeliver a still-unaccepted \
                 listener level"
            );

            // Drain to EAGAIN, exactly as an ET accept loop does.
            let fd = returned(accept_once(&mut h)) as i32;
            assert!(fd >= 0, "round {round}: accept must yield the connection");
            accepted.push(fd);
            assert_eq!(
                errno(accept_once(&mut h)),
                LINUX_EAGAIN.get(),
                "round {round}: listener must drain to EAGAIN"
            );

            latch_after_drain.push((round, listener_latch(&h)));
        }

        for client in clients {
            unsafe { libc::close(client) };
        }

        // The MECHANISM behind the deliveries above, asserted after the fact so
        // a regression reports the guest-visible stall first: the drain is what
        // re-arms the ET edge, so both the latch and the depth baseline must be
        // back to "nothing reported" and the next arrival is a fresh
        // `raw & !last_ready` edge at depth 1 again.
        for (round, latch) in latch_after_drain {
            assert_eq!(
                latch,
                (0, 0),
                "round {round}: an accept-drain must reset the listener ET read \
                 latch AND its readiness-count baseline"
            );
        }
    }

    #[test]
    fn epoll_et_write_eagain_after_partial_write_keeps_write_filter_armed() {
        let mut h = Harness::new();
        let epfd = returned(h.call(20, [0, 0, 0, 0, 0, 0])) as u64;

        let pair_addr = h.reserve(8);
        assert_eq!(
            returned(h.call(
                199,
                [
                    LINUX_AF_UNIX as u64,
                    LINUX_SOCK_STREAM as u64 | LINUX_O_NONBLOCK,
                    0,
                    pair_addr,
                    0,
                    0,
                ],
            )),
            0
        );
        let pair = h.memory.read_bytes(pair_addr, 8).unwrap();
        let writer = i32::from_le_bytes(pair[0..4].try_into().unwrap());

        let ev_addr = h.reserve(16);
        let mut ev = [0u8; 16];
        ev[0..4].copy_from_slice(&(LINUX_EPOLLOUT | LINUX_EPOLLET).to_le_bytes());
        ev[8..16].copy_from_slice(&(writer as u64).to_le_bytes());
        h.memory.write_bytes(ev_addr, &ev).unwrap();
        assert_eq!(
            returned(h.call(
                21,
                [epfd, LINUX_EPOLL_CTL_ADD, writer as u64, ev_addr, 0, 0,],
            )),
            0
        );

        let epoll_open = h.dispatcher.open_file(epfd as i32).expect("epoll fd");
        {
            let mut open = epoll_open.description.write();
            let OpenDescription::Epoll { interest, .. } = &mut *open else {
                panic!("epfd should be an epoll description");
            };
            let slot = interest.get_mut(&writer).expect("writer interest");
            slot.last_ready = LINUX_EPOLLOUT;
            slot.write_backpressured = false;
        }

        let write_request =
            SyscallRequest::new(64, SyscallArgs::from([writer as u64, MEM_BASE, 1, 0, 0, 0]));
        h.dispatcher
            .epoll_rearm_after_io(&write_request, &DispatchOutcome::Returned { value: 1 });
        {
            let open = epoll_open.description.read();
            let OpenDescription::Epoll { interest, .. } = &*open else {
                panic!("epfd should be an epoll description");
            };
            let slot = interest.get(&writer).expect("writer interest");
            assert_eq!(slot.last_ready & LINUX_EPOLLOUT, 0);
            assert!(!slot.write_backpressured);
        }

        h.dispatcher.epoll_rearm_after_io(
            &write_request,
            &DispatchOutcome::Errno {
                errno: LINUX_EAGAIN,
            },
        );
        {
            let open = epoll_open.description.read();
            let OpenDescription::Epoll { interest, .. } = &*open else {
                panic!("epfd should be an epoll description");
            };
            let slot = interest.get(&writer).expect("writer interest");
            assert!(
                slot.write_backpressured,
                "write EAGAIN after a partial nonblocking write must keep EPOLLET/EPOLLOUT armed"
            );
        }
    }

    #[test]
    fn epoll_close_rebinds_shared_host_fd_survivor() {
        use std::time::Duration;

        let mut h = Harness::new();
        let epfd = returned(h.call(20, [0, 0, 0, 0, 0, 0])) as u64;

        let pair_addr = h.reserve(8);
        assert_eq!(
            returned(h.call(
                199,
                [
                    LINUX_AF_UNIX as u64,
                    LINUX_SOCK_STREAM as u64 | LINUX_O_NONBLOCK,
                    0,
                    pair_addr,
                    0,
                    0,
                ],
            )),
            0
        );
        let pair = h.memory.read_bytes(pair_addr, 8).unwrap();
        let survivor = i32::from_le_bytes(pair[0..4].try_into().unwrap());
        let peer = i32::from_le_bytes(pair[4..8].try_into().unwrap());
        let closing_dup = returned(h.call(23, [survivor as u64, 0, 0, 0, 0, 0])) as i32;

        let ev_addr = h.reserve(16);
        let mut ev = [0u8; 16];
        ev[0..4].copy_from_slice(&(LINUX_EPOLLIN | LINUX_EPOLLET).to_le_bytes());
        ev[8..16].copy_from_slice(&(survivor as u64).to_le_bytes());
        h.memory.write_bytes(ev_addr, &ev).unwrap();
        assert_eq!(
            returned(h.call(
                21,
                [epfd, LINUX_EPOLL_CTL_ADD, survivor as u64, ev_addr, 0, 0],
            )),
            0
        );

        ev[8..16].copy_from_slice(&(closing_dup as u64).to_le_bytes());
        h.memory.write_bytes(ev_addr, &ev).unwrap();
        assert_eq!(
            returned(h.call(
                21,
                [epfd, LINUX_EPOLL_CTL_ADD, closing_dup as u64, ev_addr, 0, 0,],
            )),
            0
        );

        assert_eq!(returned(h.call(57, [closing_dup as u64, 0, 0, 0, 0, 0])), 0);
        {
            let epoll_open = h.dispatcher.open_file(epfd as i32).expect("epoll fd");
            let open = epoll_open.description.read();
            let OpenDescription::Epoll { interest, .. } = &*open else {
                panic!("epfd should be an epoll description");
            };
            assert!(interest.contains_key(&survivor));
            assert!(
                interest.contains_key(&closing_dup),
                "Linux retains a dup-keyed registration until the description's final fd closes"
            );
        }

        let byte_addr = h.put_bytes(b"x");
        assert_eq!(
            returned(h.call(64, [peer as u64, byte_addr, 1, 0, 0, 0])),
            1
        );

        let delivered_guest_fd = {
            let epoll_open = h.dispatcher.open_file(epfd as i32).expect("epoll fd");
            let open = epoll_open.description.read();
            let OpenDescription::Epoll { kqueue, .. } = &*open else {
                panic!("epfd should be an epoll description");
            };
            let mut events = Vec::new();
            let n = kqueue
                .with_mux(|mux| mux.wait(&mut events, Some(Duration::from_millis(100))))
                .expect("kqueue wait");
            assert!(n > 0, "peer write should wake the epoll instance");
            let io_tokens = events
                .iter()
                .filter(|event| event.readiness.read || event.readiness.write || event.eof)
                .map(|event| (event.token & 0xffff_ffff) as u32 as i32)
                .collect::<Vec<_>>();
            assert_eq!(io_tokens.len(), 1, "expected one routed IO readiness event");
            io_tokens[0]
        };

        assert_eq!(
            delivered_guest_fd, survivor,
            "close of a dup must rebind the shared host-fd registration to a surviving guest fd"
        );
        assert_eq!(returned(h.call(57, [survivor as u64, 0, 0, 0, 0, 0])), 0);
        let epoll_open = h.dispatcher.open_file(epfd as i32).expect("epoll fd");
        let open = epoll_open.description.read();
        let OpenDescription::Epoll { interest, .. } = &*open else {
            panic!("epfd should be an epoll description");
        };
        assert!(!interest.contains_key(&survivor));
        assert!(!interest.contains_key(&closing_dup));
    }

    #[test]
    fn unix_accept_unnamed_peer_writes_family_only_sockaddr() {
        let mut h = Harness::new();
        let listener = returned(h.call(
            198,
            [
                LINUX_AF_UNIX as u64,
                LINUX_SOCK_STREAM as u64 | LINUX_O_NONBLOCK,
                0,
                0,
                0,
                0,
            ],
        )) as i32;
        let client = returned(h.call(
            198,
            [
                LINUX_AF_UNIX as u64,
                LINUX_SOCK_STREAM as u64 | LINUX_O_NONBLOCK,
                0,
                0,
                0,
                0,
            ],
        )) as i32;

        let path = format!("/var/carrick-accept-{}", std::process::id());
        let mut sockaddr = vec![0u8; 2 + path.len() + 1];
        sockaddr[0..2].copy_from_slice(&(LINUX_AF_UNIX as u16).to_ne_bytes());
        sockaddr[2..2 + path.len()].copy_from_slice(path.as_bytes());
        let sockaddr_addr = h.put_bytes(&sockaddr);
        assert_eq!(
            returned(h.call(
                200,
                [
                    listener as u64,
                    sockaddr_addr,
                    sockaddr.len() as u64,
                    0,
                    0,
                    0
                ],
            )),
            0
        );
        assert_eq!(returned(h.call(201, [listener as u64, 1, 0, 0, 0, 0])), 0);
        assert_eq!(
            returned(h.call(
                203,
                [client as u64, sockaddr_addr, sockaddr.len() as u64, 0, 0, 0],
            )),
            0
        );

        let peer_addr = h.reserve(128);
        let peer_len_addr = h.reserve(4);
        h.memory
            .write_bytes(peer_len_addr, &128u32.to_ne_bytes())
            .unwrap();
        let accepted = returned(h.call(202, [listener as u64, peer_addr, peer_len_addr, 0, 0, 0]));
        assert!(
            accepted >= 0,
            "accept must return a guest fd, got {accepted}"
        );

        let peer_len = h.memory.read_bytes(peer_len_addr, 4).unwrap();
        assert_eq!(
            u32::from_ne_bytes(peer_len.try_into().unwrap()),
            2,
            "Linux reports only sa_family for an unnamed AF_UNIX peer"
        );
        let peer = h.memory.read_bytes(peer_addr, 2).unwrap();
        assert_eq!(
            u16::from_ne_bytes(peer.try_into().unwrap()),
            LINUX_AF_UNIX as u16
        );
    }

    /// GROUNDED REGRESSION GATE (Rust, in-tree, cross-platform: macOS kqueue +
    /// Linux epoll-emulation) for the epoll EPOLLET edge-loss hang. It drives the
    /// REAL `epoll_pwait`/`epoll_ctl`/`pipe2` handlers through the threaded
    /// dispatch path, mirroring the Go netpoller + os/exec pipe churn that hung
    /// `go build`: worker threads concurrently create a pipe, register the
    /// read-end EPOLLET in a SHARED epoll, write+close the write-end (EOF), and
    /// wait for a netpoller thread's `epoll_pwait` loop to report it. A pipe
    /// read-end at EOF MUST eventually be reported (EPOLLHUP/EPOLLIN); a lost edge
    /// ⇒ the worker times out ⇒ this test FAILS.
    ///
    /// ROOT CAUSE (fixed): `close(fd)` freed the fd number from `open_files` and
    /// only THEN detached it from epoll interest sets. In the window between, a
    /// sibling thread recycled that fd number and `epoll_ctl(ADD)`d it, and the
    /// late detach ripped out the NEW registration's interest — whose EPOLLET edge
    /// then never re-fired. Fixed by detaching BEFORE freeing the fd number (see
    /// `close` in dispatch/fs.rs). Routing is hardened with a generational udata
    /// handle (`EpollInterest::reg_gen`) against the residual drain-then-recycle
    /// ABA. Was RED on every run pre-fix (~3-5s); GREEN in ~0.1s after.
    #[cfg(unix)]
    #[test]
    fn epoll_et_pipe_eof_not_lost_under_concurrent_churn() {
        use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
        use std::time::{Duration, Instant};

        const NWORKERS: usize = 6;
        const TOTAL: usize = 600;
        const EPOLLIN: u32 = 0x1;
        const EPOLLHUP: u32 = 0x10;
        const EPOLLERR: u32 = 0x8;
        const EPOLLET: u32 = 0x8000_0000;
        const CTL_ADD: u64 = 1;
        const CTL_DEL: u64 = 2;
        const EV_STRIDE: u64 = 16; // aarch64 LinuxEpollEvent stride

        let dispatcher = SyscallDispatcher::with_rootfs(empty_rootfs());
        let reporter = CompatReporter::default();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1000));
        let futex = crate::thread::FutexTable::new();

        // Create the shared epoll instance up front.
        let epfd = {
            let mut mem = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
            let out = dispatcher
                .dispatch_threaded(
                    &dispatcher.capture_one_task_context().unwrap(),
                    SyscallRequest::new(20, SyscallArgs::from([0u64; 6])),
                    &mut mem,
                    &reporter,
                    crate::thread::ThreadId::synthetic_for_tests(1),
                    &registry,
                    &futex,
                )
                .expect("epoll_create1");
            returned(out) as u64
        };

        let eof_seen: Vec<AtomicBool> = (0..TOTAL).map(|_| AtomicBool::new(false)).collect();
        let next_slot = AtomicUsize::new(0);
        let active = AtomicUsize::new(NWORKERS);
        let stop = AtomicBool::new(false);
        let failed = AtomicI64::new(-1);

        let dispatcher = &dispatcher;
        let reporter = &reporter;
        let registry = &registry;
        let futex = &futex;
        let eof_seen = &eof_seen;
        let next_slot = &next_slot;
        let active = &active;
        let stop = &stop;
        let failed = &failed;

        std::thread::scope(|s| {
            // ---- netpoller ----
            s.spawn(move || {
                let mut mem = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
                let ev_buf = MEM_BASE + 0x800;
                let max = 32u64;
                while !stop.load(Ordering::Relaxed) {
                    let out = dispatcher
                        .dispatch_threaded(
                            &dispatcher.capture_one_task_context().unwrap(),
                            SyscallRequest::new(
                                22,
                                SyscallArgs::from([epfd, ev_buf, max, 50, 0, 0]),
                            ),
                            &mut mem,
                            reporter,
                            crate::thread::ThreadId::synthetic_for_tests(2),
                            registry,
                            futex,
                        )
                        .expect("epoll_pwait");
                    match out {
                        DispatchOutcome::Returned { value } if value > 0 => {
                            for i in 0..(value as u64) {
                                let off = ev_buf + i * EV_STRIDE;
                                let b = mem.read_bytes(off, 16).unwrap();
                                let events = u32::from_le_bytes(b[0..4].try_into().unwrap());
                                let data = u64::from_le_bytes(b[8..16].try_into().unwrap());
                                let slot = data as usize;
                                if events & (EPOLLHUP | EPOLLIN | EPOLLERR) != 0 && slot < TOTAL {
                                    eof_seen[slot].store(true, Ordering::Relaxed);
                                }
                            }
                        }
                        DispatchOutcome::Returned { .. } => {}
                        DispatchOutcome::WaitOnPollFds { fds, timeout, .. } => {
                            if let Some((fd, events)) = fds.first() {
                                let mut pfd = libc::pollfd {
                                    fd,
                                    events,
                                    revents: 0,
                                };
                                let ms =
                                    timeout.map(|d| d.as_millis().min(50) as i32).unwrap_or(50);
                                // SAFETY: one valid pollfd, bounded non-blocking wait.
                                unsafe {
                                    libc::poll(&mut pfd, 1, ms);
                                }
                            }
                        }
                        DispatchOutcome::WaitOnFds { timeout, .. } => {
                            let ms = timeout.map(|d| d.as_millis().min(50) as u64).unwrap_or(50);
                            std::thread::sleep(Duration::from_millis(ms));
                        }
                        _ => {}
                    }
                }
            });

            // ---- workers ----
            for w in 0..NWORKERS {
                s.spawn(move || {
                    let mut mem = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
                    let tid = crate::thread::ThreadId::synthetic_for_tests(100 + w as i32);
                    let pipe_out = MEM_BASE + 0x100;
                    let ev_in = MEM_BASE + 0x120;
                    let wbuf = MEM_BASE + 0x140;
                    mem.write_bytes(wbuf, b"x").unwrap();
                    let call =
                        |mem: &mut LinearMemory, num: u64, args: [u64; 6]| -> DispatchOutcome {
                            dispatcher
                                .dispatch_threaded(
                                    &dispatcher.capture_one_task_context().unwrap(),
                                    SyscallRequest::new(num, SyscallArgs::from(args)),
                                    mem,
                                    reporter,
                                    tid,
                                    registry,
                                    futex,
                                )
                                .expect("dispatch")
                        };
                    loop {
                        if stop.load(Ordering::Relaxed) || failed.load(Ordering::Relaxed) >= 0 {
                            break;
                        }
                        let slot = next_slot.fetch_add(1, Ordering::Relaxed);
                        if slot >= TOTAL {
                            break;
                        }
                        // pipe2(0): carrick makes the host ends non-blocking itself.
                        if !matches!(
                            call(&mut mem, 59, [pipe_out, 0, 0, 0, 0, 0]),
                            DispatchOutcome::Returned { value: 0 }
                        ) {
                            continue;
                        }
                        let fp = mem.read_bytes(pipe_out, 8).unwrap();
                        let rd = i32::from_le_bytes(fp[0..4].try_into().unwrap()) as u64;
                        let wr = i32::from_le_bytes(fp[4..8].try_into().unwrap()) as u64;
                        // epoll_ctl ADD rd, EPOLLIN|EPOLLET, data=slot
                        let mut ev = [0u8; 16];
                        ev[0..4].copy_from_slice(&(EPOLLIN | EPOLLET).to_le_bytes());
                        ev[8..16].copy_from_slice(&(slot as u64).to_le_bytes());
                        mem.write_bytes(ev_in, &ev).unwrap();
                        call(&mut mem, 21, [epfd, CTL_ADD, rd, ev_in, 0, 0]);
                        // write a byte, then close the write end (EOF).
                        call(&mut mem, 64, [wr, wbuf, 1, 0, 0, 0]);
                        call(&mut mem, 57, [wr, 0, 0, 0, 0, 0]);
                        // The read-end is now at EOF — the netpoller MUST report it.
                        let t0 = Instant::now();
                        while !eof_seen[slot].load(Ordering::Relaxed) {
                            if t0.elapsed() > Duration::from_secs(3) {
                                failed.store(slot as i64, Ordering::Relaxed);
                                stop.store(true, Ordering::Relaxed);
                                break;
                            }
                            std::thread::yield_now();
                        }
                        call(&mut mem, 21, [epfd, CTL_DEL, rd, 0, 0, 0]);
                        call(&mut mem, 57, [rd, 0, 0, 0, 0, 0]);
                    }
                    if active.fetch_sub(1, Ordering::Relaxed) == 1 {
                        stop.store(true, Ordering::Relaxed);
                    }
                });
            }
        });

        let f = failed.load(Ordering::Relaxed);
        assert!(
            f < 0,
            "epoll LOST the EOF edge for slot {f} under concurrent churn \
             (the Go-netpoller hang); native epoll never does this"
        );
    }

    /// FOCUSED regression gate for the close/reuse/detach ORDERING race that
    /// caused the edge-loss above. It isolates the exact mechanism: dedicated
    /// "recycler" threads `epoll_ctl(ADD)` a pipe read-end and immediately
    /// `close()` it with NO `EPOLL_CTL_DEL`, so `close`'s `detach_fd_from_epolls`
    /// is the sole remover AND the freed fd number is fed straight back to a
    /// victim's next `pipe2`. If `close` frees the fd number before detaching,
    /// the recycler's late detach rips out the victim's freshly-registered
    /// interest for that recycled fd and its EOF edge is lost. Distinct from the
    /// symmetric stress test above, which uses DEL+close; here close-detach is the
    /// only path under test. Was RED pre-fix; GREEN after detach-before-free.
    #[cfg(unix)]
    #[test]
    fn epoll_close_recycle_does_not_drop_interest() {
        use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
        use std::time::{Duration, Instant};

        const VICTIMS: usize = 4;
        const RECYCLERS: usize = 2;
        const TOTAL: usize = 400;
        const EPOLLIN: u32 = 0x1;
        const EPOLLHUP: u32 = 0x10;
        const EPOLLERR: u32 = 0x8;
        const EPOLLET: u32 = 0x8000_0000;
        const CTL_ADD: u64 = 1;
        const CTL_DEL: u64 = 2;
        const EV_STRIDE: u64 = 16;

        let dispatcher = SyscallDispatcher::with_rootfs(empty_rootfs());
        let reporter = CompatReporter::default();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1000));
        let futex = crate::thread::FutexTable::new();

        let epfd = {
            let mut mem = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
            let out = dispatcher
                .dispatch_threaded(
                    &dispatcher.capture_one_task_context().unwrap(),
                    SyscallRequest::new(20, SyscallArgs::from([0u64; 6])),
                    &mut mem,
                    &reporter,
                    crate::thread::ThreadId::synthetic_for_tests(1),
                    &registry,
                    &futex,
                )
                .expect("epoll_create1");
            returned(out) as u64
        };

        let eof_seen: Vec<AtomicBool> = (0..TOTAL).map(|_| AtomicBool::new(false)).collect();
        let next_slot = AtomicUsize::new(0);
        let active = AtomicUsize::new(VICTIMS);
        let stop = AtomicBool::new(false);
        let failed = AtomicI64::new(-1);

        let dispatcher = &dispatcher;
        let reporter = &reporter;
        let registry = &registry;
        let futex = &futex;
        let eof_seen = &eof_seen;
        let next_slot = &next_slot;
        let active = &active;
        let stop = &stop;
        let failed = &failed;

        std::thread::scope(|s| {
            // ---- netpoller ----
            s.spawn(move || {
                let mut mem = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
                let ev_buf = MEM_BASE + 0x800;
                let max = 32u64;
                while !stop.load(Ordering::Relaxed) {
                    let out = dispatcher
                        .dispatch_threaded(
                            &dispatcher.capture_one_task_context().unwrap(),
                            SyscallRequest::new(
                                22,
                                SyscallArgs::from([epfd, ev_buf, max, 50, 0, 0]),
                            ),
                            &mut mem,
                            reporter,
                            crate::thread::ThreadId::synthetic_for_tests(2),
                            registry,
                            futex,
                        )
                        .expect("epoll_pwait");
                    match out {
                        DispatchOutcome::Returned { value } if value > 0 => {
                            for i in 0..(value as u64) {
                                let off = ev_buf + i * EV_STRIDE;
                                let b = mem.read_bytes(off, 16).unwrap();
                                let events = u32::from_le_bytes(b[0..4].try_into().unwrap());
                                let data = u64::from_le_bytes(b[8..16].try_into().unwrap());
                                let slot = data as usize;
                                if events & (EPOLLHUP | EPOLLIN | EPOLLERR) != 0 && slot < TOTAL {
                                    eof_seen[slot].store(true, Ordering::Relaxed);
                                }
                            }
                        }
                        DispatchOutcome::Returned { .. } => {}
                        DispatchOutcome::WaitOnPollFds { fds, timeout, .. } => {
                            if let Some((fd, events)) = fds.first() {
                                let mut pfd = libc::pollfd {
                                    fd,
                                    events,
                                    revents: 0,
                                };
                                let ms =
                                    timeout.map(|d| d.as_millis().min(50) as i32).unwrap_or(50);
                                // SAFETY: one valid pollfd, bounded non-blocking wait.
                                unsafe {
                                    libc::poll(&mut pfd, 1, ms);
                                }
                            }
                        }
                        DispatchOutcome::WaitOnFds { timeout, .. } => {
                            let ms = timeout.map(|d| d.as_millis().min(50) as u64).unwrap_or(50);
                            std::thread::sleep(Duration::from_millis(ms));
                        }
                        _ => {}
                    }
                }
            });

            // ---- recyclers: ADD a read-end then close it (NO DEL) to churn fd
            // numbers through close()'s detach path while victims reuse them. ----
            for r in 0..RECYCLERS {
                s.spawn(move || {
                    let mut mem = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
                    let tid = crate::thread::ThreadId::synthetic_for_tests(200 + r as i32);
                    let pipe_out = MEM_BASE + 0x100;
                    let ev_in = MEM_BASE + 0x120;
                    let call =
                        |mem: &mut LinearMemory, num: u64, args: [u64; 6]| -> DispatchOutcome {
                            dispatcher
                                .dispatch_threaded(
                                    &dispatcher.capture_one_task_context().unwrap(),
                                    SyscallRequest::new(num, SyscallArgs::from(args)),
                                    mem,
                                    reporter,
                                    tid,
                                    registry,
                                    futex,
                                )
                                .expect("dispatch")
                        };
                    let mut ev = [0u8; 16];
                    ev[0..4].copy_from_slice(&(EPOLLIN | EPOLLET).to_le_bytes());
                    while !stop.load(Ordering::Relaxed) {
                        if !matches!(
                            call(&mut mem, 59, [pipe_out, 0, 0, 0, 0, 0]),
                            DispatchOutcome::Returned { value: 0 }
                        ) {
                            continue;
                        }
                        let fp = mem.read_bytes(pipe_out, 8).unwrap();
                        let rd = i32::from_le_bytes(fp[0..4].try_into().unwrap()) as u64;
                        let wr = i32::from_le_bytes(fp[4..8].try_into().unwrap()) as u64;
                        mem.write_bytes(ev_in, &ev).unwrap();
                        call(&mut mem, 21, [epfd, CTL_ADD, rd, ev_in, 0, 0]);
                        // close the read-end WITHOUT DEL: close()'s detach is the
                        // remover, and rd's number is now free for a victim's pipe2.
                        call(&mut mem, 57, [rd, 0, 0, 0, 0, 0]);
                        call(&mut mem, 57, [wr, 0, 0, 0, 0, 0]);
                    }
                });
            }

            // ---- victims ----
            for w in 0..VICTIMS {
                s.spawn(move || {
                    let mut mem = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
                    let tid = crate::thread::ThreadId::synthetic_for_tests(100 + w as i32);
                    let pipe_out = MEM_BASE + 0x100;
                    let ev_in = MEM_BASE + 0x120;
                    let wbuf = MEM_BASE + 0x140;
                    mem.write_bytes(wbuf, b"x").unwrap();
                    let call =
                        |mem: &mut LinearMemory, num: u64, args: [u64; 6]| -> DispatchOutcome {
                            dispatcher
                                .dispatch_threaded(
                                    &dispatcher.capture_one_task_context().unwrap(),
                                    SyscallRequest::new(num, SyscallArgs::from(args)),
                                    mem,
                                    reporter,
                                    tid,
                                    registry,
                                    futex,
                                )
                                .expect("dispatch")
                        };
                    loop {
                        if stop.load(Ordering::Relaxed) || failed.load(Ordering::Relaxed) >= 0 {
                            break;
                        }
                        let slot = next_slot.fetch_add(1, Ordering::Relaxed);
                        if slot >= TOTAL {
                            break;
                        }
                        if !matches!(
                            call(&mut mem, 59, [pipe_out, 0, 0, 0, 0, 0]),
                            DispatchOutcome::Returned { value: 0 }
                        ) {
                            continue;
                        }
                        let fp = mem.read_bytes(pipe_out, 8).unwrap();
                        let rd = i32::from_le_bytes(fp[0..4].try_into().unwrap()) as u64;
                        let wr = i32::from_le_bytes(fp[4..8].try_into().unwrap()) as u64;
                        let mut ev = [0u8; 16];
                        ev[0..4].copy_from_slice(&(EPOLLIN | EPOLLET).to_le_bytes());
                        ev[8..16].copy_from_slice(&(slot as u64).to_le_bytes());
                        mem.write_bytes(ev_in, &ev).unwrap();
                        call(&mut mem, 21, [epfd, CTL_ADD, rd, ev_in, 0, 0]);
                        call(&mut mem, 64, [wr, wbuf, 1, 0, 0, 0]);
                        call(&mut mem, 57, [wr, 0, 0, 0, 0, 0]);
                        let t0 = Instant::now();
                        while !eof_seen[slot].load(Ordering::Relaxed) {
                            if t0.elapsed() > Duration::from_secs(3) {
                                failed.store(slot as i64, Ordering::Relaxed);
                                stop.store(true, Ordering::Relaxed);
                                break;
                            }
                            std::thread::yield_now();
                        }
                        call(&mut mem, 21, [epfd, CTL_DEL, rd, 0, 0, 0]);
                        call(&mut mem, 57, [rd, 0, 0, 0, 0, 0]);
                    }
                    if active.fetch_sub(1, Ordering::Relaxed) == 1 {
                        stop.store(true, Ordering::Relaxed);
                    }
                });
            }
        });

        let f = failed.load(Ordering::Relaxed);
        assert!(
            f < 0,
            "epoll lost the EOF edge for slot {f}: a sibling close() recycled the \
             fd number and a detach-after-free dropped the victim's new interest"
        );
    }

    #[test]
    fn read_kernel_struct_accepts_unaligned_abi_reads_and_rejects_bad_pointers() {
        let mut memory = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
        let address = MEM_BASE + 3;
        let expected = LinuxTimespec::new(12, 34);
        memory.write_bytes(address, expected.abi_bytes()).unwrap();

        let actual: LinuxTimespec = read_kernel_struct(&memory, address).unwrap();
        let tv_sec = actual.tv_sec;
        let tv_nsec = actual.tv_nsec;
        assert_eq!((tv_sec, tv_nsec), (12, 34));

        assert_eq!(
            read_kernel_struct::<LinuxTimespec>(&memory, 0),
            Err(LINUX_EFAULT)
        );
        assert_eq!(
            read_kernel_struct::<LinuxTimespec>(&memory, MEM_BASE + MEM_LEN as u64 - 1),
            Err(LINUX_EFAULT)
        );
    }

    #[test]
    fn read_kernel_prefix_zero_fills_truncated_clone_args_and_rejects_overlarge_reads() {
        let mut memory = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
        let address = MEM_BASE + 5;
        let flags = LinuxCloneFlags::THREAD_MASK | LinuxCloneFlags::SETTLS.bits();
        memory.write_bytes(address, &flags.to_ne_bytes()).unwrap();

        let args: LinuxCloneArgs = read_kernel_prefix(&memory, address, 8).unwrap();
        let actual_flags = args.flags;
        let tls = args.tls;
        assert_eq!(actual_flags, flags);
        assert_eq!(tls, 0);

        assert_eq!(
            read_kernel_prefix::<LinuxCloneArgs>(
                &memory,
                address,
                <LinuxCloneArgs as KernelAbi>::ABI_SIZE + 1,
            ),
            Err(LINUX_EFAULT)
        );
    }

    #[test]
    fn clone_thread_requires_thread_bit_not_pthread_superset() {
        let mut h = Harness::new();
        let flags = LinuxCloneFlags::VM.bits()
            | LinuxCloneFlags::SIGHAND.bits()
            | LinuxCloneFlags::THREAD.bits()
            | LinuxCloneFlags::CHILD_CLEARTID.bits()
            | u64::from(crate::linux_abi::LINUX_SIGCHLD as u32);
        let child_tid = h.reserve(4);

        let outcome = h.call(SYS_CLONE, [flags, MEM_BASE + 0x800, 0, 0, child_tid, 0]);

        assert!(matches!(
            outcome,
            DispatchOutcome::CloneThread {
                child_tid_addr,
                clear_child_tid_addr,
                tls: None,
                parent_tid_addr: 0,
                ..
            } if child_tid_addr == 0 && clear_child_tid_addr == child_tid
        ));
    }

    #[test]
    fn clone_preserves_parent_and_tid_pointer_semantics_for_fork_path() {
        let mut h = Harness::new();
        let parent_tid = h.reserve(4);
        let child_tid = h.reserve(4);
        let flags = LinuxCloneFlags::PARENT.bits()
            | LinuxCloneFlags::PARENT_SETTID.bits()
            | LinuxCloneFlags::CHILD_SETTID.bits()
            | u64::from(crate::linux_abi::LINUX_SIGCHLD as u32);

        let outcome = h.call(SYS_CLONE, [flags, 0, parent_tid, 0, child_tid, 0]);

        assert!(matches!(
            outcome,
            DispatchOutcome::Fork {
                clone_parent: true,
                parent_tid_addr: Some(p),
                child_tid_addr: Some(c),
                ..
            } if p == parent_tid && c == child_tid
        ));
    }

    #[test]
    fn clone3_preserves_parent_and_tid_pointer_semantics_for_fork_path() {
        let mut h = Harness::new();
        let args_addr = h.reserve(<LinuxCloneArgs as KernelAbi>::ABI_SIZE);
        let parent_tid = h.reserve(4);
        let child_tid = h.reserve(4);
        let args = LinuxCloneArgs {
            flags: LinuxCloneFlags::PARENT.bits()
                | LinuxCloneFlags::PARENT_SETTID.bits()
                | LinuxCloneFlags::CHILD_SETTID.bits(),
            pidfd: 0,
            child_tid,
            parent_tid,
            exit_signal: u64::from(crate::linux_abi::LINUX_SIGCHLD as u32),
            stack: 0,
            stack_size: 0,
            tls: 0,
            set_tid: 0,
            set_tid_size: 0,
            cgroup: 0,
        };
        h.memory.write_bytes(args_addr, args.abi_bytes()).unwrap();

        let outcome = h.call(
            SYS_CLONE3,
            [
                args_addr,
                <LinuxCloneArgs as KernelAbi>::ABI_SIZE as u64,
                0,
                0,
                0,
                0,
            ],
        );

        assert!(matches!(
            outcome,
            DispatchOutcome::Fork {
                clone_parent: true,
                parent_tid_addr: Some(p),
                child_tid_addr: Some(c),
                ..
            } if p == parent_tid && c == child_tid
        ));
    }

    const AT_FDCWD: u64 = (-100i64) as u64;

    #[test]
    fn mkdirat_creates_overlay_dir_and_fstatat_sees_it() {
        let mut h = Harness::new();
        let path = h.put_str("/var/lib/apt/lists");
        let outcome = h.call(SYS_MKDIRAT, [AT_FDCWD, path, 0o755, 0, 0, 0]);
        assert_eq!(returned(outcome), 0);

        // fstatat must succeed and report a directory. The Linux stat
        // layout puts st_mode at bytes 16..20; bit S_IFDIR=0o040000.
        let statbuf = h.reserve(160);
        let path2 = h.put_str("/var/lib/apt/lists");
        let outcome = h.call(SYS_NEWFSTATAT, [AT_FDCWD, path2, statbuf, 0, 0, 0]);
        assert_eq!(returned(outcome), 0);
        let mode_bytes = h.memory.read_bytes(statbuf + 16, 4).unwrap();
        let mode = u32::from_le_bytes(mode_bytes.try_into().unwrap());
        assert_eq!(mode & 0o170000, 0o040000, "S_IFDIR not set in stat mode");
    }

    #[test]
    fn openat_o_creat_then_write_then_read_round_trips() {
        let mut h = Harness::new();
        // O_CREAT|O_WRONLY: writable, brand-new file inside an existing
        // rootfs directory.
        let path = h.put_str("/var/lib/apt/lock");
        let outcome = h.call(
            SYS_OPENAT,
            [AT_FDCWD, path, O_CREAT | O_WRONLY, 0o644, 0, 0],
        );
        let fd = returned(outcome) as u64;
        assert!(fd >= 3, "expected real fd, got {fd}");

        // Write four bytes.
        let payload = h.put_bytes(b"OKAY");
        let outcome = h.call(SYS_WRITE, [fd, payload, 4, 0, 0, 0]);
        assert_eq!(returned(outcome), 4);
        let outcome = h.call(SYS_CLOSE, [fd, 0, 0, 0, 0, 0]);
        assert_eq!(returned(outcome), 0);

        // Re-open O_RDONLY and read back.
        let path = h.put_str("/var/lib/apt/lock");
        let outcome = h.call(SYS_OPENAT, [AT_FDCWD, path, O_RDONLY, 0, 0, 0]);
        let fd = returned(outcome) as u64;
        let dest = h.reserve(16);
        let outcome = h.call(SYS_READ, [fd, dest, 16, 0, 0, 0]);
        assert_eq!(returned(outcome), 4);
        let bytes = h.memory.read_bytes(dest, 4).unwrap();
        assert_eq!(&bytes, b"OKAY");
    }

    #[test]
    fn unlinkat_on_rootfs_file_then_openat_returns_enoent() {
        let mut h = Harness::new();
        // /etc/motd lives in the rootfs.
        let path = h.put_str("/etc/motd");
        let outcome = h.call(SYS_UNLINKAT, [AT_FDCWD, path, 0, 0, 0, 0]);
        assert_eq!(returned(outcome), 0);

        let path = h.put_str("/etc/motd");
        let outcome = h.call(SYS_OPENAT, [AT_FDCWD, path, O_RDONLY, 0, 0, 0]);
        assert_eq!(errno(outcome), LINUX_ENOENT.get());
    }

    #[test]
    fn renameat_moves_overlay_backed_file() {
        let mut h = Harness::new();
        // Create a file in the overlay first.
        let path = h.put_str("/var/lib/apt/lock");
        let outcome = h.call(
            SYS_OPENAT,
            [AT_FDCWD, path, O_CREAT | O_WRONLY, 0o644, 0, 0],
        );
        let fd = returned(outcome) as u64;
        let payload = h.put_bytes(b"DATA");
        let _ = h.call(SYS_WRITE, [fd, payload, 4, 0, 0, 0]);
        let _ = h.call(SYS_CLOSE, [fd, 0, 0, 0, 0, 0]);

        let from = h.put_str("/var/lib/apt/lock");
        let to = h.put_str("/var/lib/apt/lock.new");
        let outcome = h.call(SYS_RENAMEAT, [AT_FDCWD, from, AT_FDCWD, to, 0, 0]);
        assert_eq!(returned(outcome), 0);

        // Source must now ENOENT, destination must read back the data.
        let path = h.put_str("/var/lib/apt/lock");
        let outcome = h.call(SYS_OPENAT, [AT_FDCWD, path, O_RDONLY, 0, 0, 0]);
        assert_eq!(errno(outcome), LINUX_ENOENT.get());

        let path = h.put_str("/var/lib/apt/lock.new");
        let outcome = h.call(SYS_OPENAT, [AT_FDCWD, path, O_RDONLY, 0, 0, 0]);
        let fd = returned(outcome) as u64;
        let dest = h.reserve(16);
        let outcome = h.call(SYS_READ, [fd, dest, 16, 0, 0, 0]);
        assert_eq!(returned(outcome), 4);
        let bytes = h.memory.read_bytes(dest, 4).unwrap();
        assert_eq!(&bytes, b"DATA");
    }

    /// Validates the systematic unknown-flag detector: when the guest
    /// passes a flag bit the dispatcher doesn't know about, the
    /// compat report must surface it as an `UnknownSyscallFlags`
    /// entry, regardless of whether the syscall ultimately returns
    /// success or EINVAL. The user explicitly asked for this loudness.
    #[test]
    fn unknown_pipe2_flag_is_recorded_in_compat_report() {
        let mut h = Harness::new();
        let buf = h.reserve(8);
        // Bit 0x80 (octal 0o200) is NOT one of O_CLOEXEC | O_NONBLOCK.
        // Send it through pipe2 — the handler returns EINVAL, and we
        // want the report to ALSO list the unknown bit so the operator
        // can fix it.
        const SYS_PIPE2: u64 = 59;
        let _ = h.call(SYS_PIPE2, [buf, 0x80, 0, 0, 0, 0]);

        // Finish the report and look for the entry.
        let report = std::mem::take(&mut h.reporter).finish();
        let entry = report
            .unknown_syscall_flags
            .iter()
            .find(|e| e.number == 59 && e.argument == 1)
            .expect("pipe2's unknown-flag bit 0x80 should appear in the report");
        assert!(entry.unknown_bits.contains("0x80"), "got {:?}", entry);
        assert_eq!(entry.count, 1);
        assert_eq!(entry.name, "pipe2");
    }

    /// Negative test: a syscall flag arg that has NO unknown bits set
    /// must NOT produce an UnknownSyscallFlags entry.
    #[test]
    fn known_pipe2_flag_is_silent() {
        let mut h = Harness::new();
        let buf = h.reserve(8);
        // O_CLOEXEC | O_NONBLOCK — both are in the supported mask.
        let _ = h.call(
            SYS_PIPE2,
            [buf, LINUX_O_CLOEXEC | LINUX_O_NONBLOCK, 0, 0, 0, 0],
        );
        let report = std::mem::take(&mut h.reporter).finish();
        assert!(
            report.unknown_syscall_flags.is_empty(),
            "no unknown bits should be reported; got {:?}",
            report.unknown_syscall_flags
        );
    }

    const SYS_PIPE2: u64 = 59;

    #[cfg(target_os = "macos")]
    #[test]
    fn host_syscall_result_translates_captured_host_errno() {
        use crate::dispatch::HostSyscallResult;
        use carrick_host_bsd::errno::linux_errno;

        carrick_portable::set_errno(libc::EINPROGRESS);
        let err = (-1i32).host_syscall_result().unwrap_err();
        assert_eq!(err.raw_errno(), libc::EINPROGRESS);
        assert_eq!(err.linux_errno(), linux_errno::EINPROGRESS);
        assert_ne!(err.linux_errno().get(), libc::EINPROGRESS);

        carrick_portable::set_errno(libc::EAGAIN);
        assert_eq!(
            (-1isize).host_syscall_result().unwrap_err().linux_errno(),
            linux_errno::EAGAIN
        );

        carrick_portable::set_errno(libc::ECONNREFUSED);
        assert_eq!(
            (-1i64).host_syscall_errno().unwrap_err(),
            linux_errno::ECONNREFUSED
        );

        assert_eq!(0i32.host_syscall_result().unwrap(), 0);
    }

    /// A MAP_SHARED futex word the dispatcher's software memory view can't
    /// translate (read fails) must still be read via the fork-coherent shared
    /// host pointer — never surfaced as EFAULT, which aborts glibc's futex code.
    /// Regression for the CPython multiprocessing SyncManager SIGABRT (a forked
    /// child's timed wait on a shared semaphore at the high mmap aperture).
    #[test]
    fn read_futex_word_falls_back_to_shared_mapping() {
        struct SharedOnly {
            word: u32,
        }
        impl GuestMemory for SharedOnly {
            fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
                Err(MemoryError::OutOfBounds { address, length })
            }
            fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
                Err(MemoryError::OutOfBounds {
                    address,
                    length: bytes.len(),
                })
            }
            fn shared_futex_location(
                &self,
                _guest_addr: u64,
            ) -> Option<carrick_guest_mem::SharedFutexLocation> {
                Some(carrick_guest_mem::SharedFutexLocation::Direct {
                    word: HostVa(&self.word as *const u32 as usize),
                    waiter_key: &self.word as *const u32 as usize,
                })
            }
        }
        // Software read fails, but the shared host pointer yields the word.
        let mem = SharedOnly { word: 0x00C0_FFEE };
        assert_eq!(read_futex_word(&mem, 0x0100_0160_0000), Ok(0x00C0_FFEE));

        // No shared mapping -> EFAULT propagates unchanged (no regression for
        // a genuinely bad private/anon address).
        let lin = LinearMemory::new(0x1000, vec![0u8; 8]);
        assert_eq!(read_futex_word(&lin, 0x9_9999_9999), Err(LINUX_EFAULT));
    }

    struct CountingMemory {
        base: u64,
        bytes: Vec<u8>,
        reads: std::cell::Cell<usize>,
        writes: std::cell::Cell<usize>,
        shared_futex_lookups: std::cell::Cell<usize>,
    }

    impl CountingMemory {
        fn new(base: u64, bytes: Vec<u8>) -> Self {
            Self {
                base,
                bytes,
                reads: std::cell::Cell::new(0),
                writes: std::cell::Cell::new(0),
                shared_futex_lookups: std::cell::Cell::new(0),
            }
        }
    }

    impl GuestMemory for CountingMemory {
        fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
            self.reads.set(self.reads.get() + 1);
            let offset = address
                .checked_sub(self.base)
                .ok_or(MemoryError::OutOfBounds { address, length })?;
            let offset = usize::try_from(offset)
                .map_err(|_| MemoryError::OutOfBounds { address, length })?;
            let end = offset
                .checked_add(length)
                .ok_or(MemoryError::OutOfBounds { address, length })?;
            if end > self.bytes.len() {
                return Err(MemoryError::OutOfBounds { address, length });
            }
            Ok(self.bytes[offset..end].to_vec())
        }

        fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            self.writes.set(self.writes.get() + 1);
            let offset = address
                .checked_sub(self.base)
                .ok_or(MemoryError::OutOfBounds {
                    address,
                    length: bytes.len(),
                })?;
            let offset = usize::try_from(offset).map_err(|_| MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            })?;
            let end = offset
                .checked_add(bytes.len())
                .ok_or(MemoryError::OutOfBounds {
                    address,
                    length: bytes.len(),
                })?;
            if end > self.bytes.len() {
                return Err(MemoryError::OutOfBounds {
                    address,
                    length: bytes.len(),
                });
            }
            self.bytes[offset..end].copy_from_slice(bytes);
            Ok(())
        }

        fn shared_futex_location(
            &self,
            _guest_addr: u64,
        ) -> Option<carrick_guest_mem::SharedFutexLocation> {
            self.shared_futex_lookups
                .set(self.shared_futex_lookups.get() + 1);
            None
        }
    }

    #[test]
    fn private_futex_wake_skips_shared_mapping_lookup() {
        let mut memory = CountingMemory::new(0x10000, vec![0u8; 0x1000]);
        memory.write_bytes(0x10800, &0u32.to_le_bytes()).unwrap();
        let reporter = CompatReporter::default();
        let futex = crate::thread::FutexTable::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1000));
        let request = SyscallRequest::new(
            98,
            SyscallArgs::from([
                0x10800,
                LINUX_FUTEX_WAKE | LinuxFutexFlags::PRIVATE.bits(),
                1,
                0,
                0,
                0,
            ]),
        );

        let outcome = dispatch_threaded_futex(
            request,
            &mut memory,
            &reporter,
            &futex,
            crate::thread::ThreadId::synthetic_for_tests(1001),
            &registry,
            None,
        );

        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
        assert_eq!(memory.shared_futex_lookups.get(), 0);
        assert!(crate::event_ring::contains_event(
            crate::event_ring::FUTEXWAKE,
            0x10800,
            0,
            0
        ));
    }

    #[test]
    fn non_private_futex_wake_checks_shared_mapping_lookup() {
        let mut memory = CountingMemory::new(0x10000, vec![0u8; 0x1000]);
        memory.write_bytes(0x10800, &0u32.to_le_bytes()).unwrap();
        let reporter = CompatReporter::default();
        let futex = crate::thread::FutexTable::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1000));
        let request = SyscallRequest::new(
            98,
            SyscallArgs::from([0x10800, LINUX_FUTEX_WAKE, 1, 0, 0, 0]),
        );

        let outcome = dispatch_threaded_futex(
            request,
            &mut memory,
            &reporter,
            &futex,
            crate::thread::ThreadId::synthetic_for_tests(1001),
            &registry,
            None,
        );

        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
        assert_eq!(memory.shared_futex_lookups.get(), 1);
    }

    /// Task 7 fix #4: a non-private `FUTEX_WAKE` whose word lives in a genuine
    /// `MAP_SHARED` mapping (`shared_futex_location` → `Some`) must be routed
    /// through the `PlatformFutex::shared_wake` seam — i.e. returned as a
    /// `DispatchOutcome::SharedFutexWake`, NOT a `Returned` from an inline
    /// `ulock::wake`. The loop then drives the backend wake (HVF __ulock / KVM
    /// SYS_futex), keeping the shared wait+wake pair on ONE seam. (Before the fix
    /// the dispatcher called `ulock::wake` directly, so `KvmFutex::shared_wake`
    /// was never reached on Linux.)
    #[test]
    fn shared_futex_wake_routes_through_platform_seam() {
        struct SharedWord {
            word: u32,
        }
        impl GuestMemory for SharedWord {
            fn read_bytes_raw(&self, _address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
                Ok(self.word.to_le_bytes()[..length.min(4)].to_vec())
            }
            fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
                Err(MemoryError::OutOfBounds {
                    address,
                    length: bytes.len(),
                })
            }
            fn shared_futex_location(
                &self,
                _guest_addr: u64,
            ) -> Option<carrick_guest_mem::SharedFutexLocation> {
                Some(carrick_guest_mem::SharedFutexLocation::Direct {
                    word: HostVa(&self.word as *const u32 as usize),
                    waiter_key: &self.word as *const u32 as usize,
                })
            }
        }
        let mut memory = SharedWord { word: 0 };
        let location = carrick_guest_mem::SharedFutexLocation::Direct {
            word: HostVa(&memory.word as *const u32 as usize),
            waiter_key: &memory.word as *const u32 as usize,
        };
        let reporter = CompatReporter::default();
        let futex = crate::thread::FutexTable::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1000));
        // Non-private FUTEX_WAKE (no PRIVATE flag) of up to 3 waiters.
        let request = SyscallRequest::new(
            98,
            SyscallArgs::from([0x10800, LINUX_FUTEX_WAKE, 3, 0, 0, 0]),
        );

        let outcome = dispatch_threaded_futex(
            request,
            &mut memory,
            &reporter,
            &futex,
            crate::thread::ThreadId::synthetic_for_tests(1001),
            &registry,
            None,
        );

        assert_eq!(
            outcome,
            DispatchOutcome::SharedFutexWake {
                location,
                waiter_key: location.waiter_key(),
                count: 3,
            },
            "a shared FUTEX_WAKE must defer to the PlatformFutex::shared_wake seam"
        );
    }

    /// On the LIVE multithreaded futex path (`dispatch_threaded_futex`), a present
    /// (non-NULL) `{tv_sec:0, tv_nsec:0}` relative `FUTEX_WAIT` timeout means
    /// "expire NOW" (ETIMEDOUT immediately), NOT "block forever" (the NULL-timeout
    /// case). Commit 519dd40f fixed this on the proc.rs `dispatch_normalized` path
    /// but the threaded path still collapsed `{0,0}` to `None`, parking forever.
    /// The parked `FutexWait` must carry `Some(Duration::ZERO)` (a deadline of
    /// `now`), never `None`.
    #[test]
    fn threaded_futex_wait_zero_but_present_timeout_parks_with_zero_deadline() {
        let mut memory = CountingMemory::new(0x10000, vec![0u8; 0x1000]);
        // Futex word == the expected value, so WAIT does not short-circuit to
        // EAGAIN and must consult the timeout.
        memory.write_bytes(0x10800, &7u32.to_le_bytes()).unwrap();
        // A present (non-NULL) relative timespec of {0, 0} at 0x10810.
        memory.write_bytes(0x10810, &[0u8; 16]).unwrap();
        let reporter = CompatReporter::default();
        let futex = crate::thread::FutexTable::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1000));
        // Private FUTEX_WAIT (no shared mapping) so the park stays in the
        // in-process parking-lot table and returns a `FutexWait` outcome.
        let request = SyscallRequest::new(
            98,
            SyscallArgs::from([
                0x10800,
                LINUX_FUTEX_WAIT | LinuxFutexFlags::PRIVATE.bits(),
                7,
                0x10810,
                0,
                0,
            ]),
        );

        let outcome = dispatch_threaded_futex(
            request,
            &mut memory,
            &reporter,
            &futex,
            crate::thread::ThreadId::synthetic_for_tests(1001),
            &registry,
            None,
        );

        match outcome {
            DispatchOutcome::FutexWait { timeout, .. } => assert_eq!(
                timeout,
                Some(std::time::Duration::ZERO),
                "a present {{0,0}} timeout must park with a zero deadline (expire now), \
                 not None (block forever)"
            ),
            other => panic!("expected a FutexWait park outcome, got {other:?}"),
        }
    }

    #[test]
    fn fresh_shared_anon_mmap_skips_zero_write() {
        let reporter = CompatReporter::default();
        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = CountingMemory::new(0x10000, vec![0u8; 0x1000]);

        let outcome = dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    222,
                    SyscallArgs::from([
                        0,
                        0x4000,
                        LINUX_PROT_READ | LINUX_PROT_WRITE,
                        LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                        u64::MAX,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap();

        assert_eq!(
            outcome,
            DispatchOutcome::Returned {
                value: crate::memory::LINUX_SHARED_FILE_BASE as i64
            }
        );
        assert_eq!(
            memory.writes.get(),
            0,
            "fresh MAP_SHARED|MAP_ANON should use the boot-zeroed shared aperture without materializing a zero buffer"
        );
        assert!(reporter.finish().unhandled_syscalls.is_empty());
    }

    // A `munmap`'d shared-anon slot that a later mmap recycles MUST be scrubbed
    // before reuse (no prior-tenant bytes leak into the new mapping). The scrub
    // runs `zero_anonymous_reuse` over the whole recycled HVF page, so the test
    // memory must actually be able to hold the scrubbed range: `CountingMemory`
    // is based at `LINUX_SHARED_FILE_BASE` with the full slot backed, otherwise
    // the scrub write faults `OutOfBounds` and the mmap fails ENOMEM.
    #[test]
    fn reused_shared_anon_mmap_zeroes_recycled_range() {
        let reporter = CompatReporter::default();
        let mut dispatcher = SyscallDispatcher::new();
        let mut memory =
            CountingMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, vec![0u8; 0x4000]);
        let mmap_args = SyscallArgs::from([
            0,
            0x4000,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
            u64::MAX,
            0,
        ]);

        assert_eq!(
            dispatcher
                .dispatch(
                    &dispatcher.capture_one_task_context().unwrap(),
                    SyscallRequest::new(222, mmap_args),
                    &mut memory,
                    &reporter
                )
                .unwrap(),
            DispatchOutcome::Returned {
                value: crate::memory::LINUX_SHARED_FILE_BASE as i64
            }
        );
        memory.writes.set(0);

        assert_eq!(
            dispatcher
                .dispatch(
                    &dispatcher.capture_one_task_context().unwrap(),
                    SyscallRequest::new(
                        215,
                        SyscallArgs::from([
                            crate::memory::LINUX_SHARED_FILE_BASE,
                            0x4000,
                            0,
                            0,
                            0,
                            0,
                        ]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { value: 0 }
        );
        memory.writes.set(0);

        assert_eq!(
            dispatcher
                .dispatch(
                    &dispatcher.capture_one_task_context().unwrap(),
                    SyscallRequest::new(222, mmap_args),
                    &mut memory,
                    &reporter
                )
                .unwrap(),
            DispatchOutcome::Returned {
                value: crate::memory::LINUX_SHARED_FILE_BASE as i64
            }
        );
        // The recycled slot is one HVF page (`HVF_PAGE_SIZE` = 0x4000) and the
        // scrub streams it through `zero_range_chunked` in 4 KiB `ZERO_CHUNK`
        // writes, so 0x4000 / 0x1000 = 4 raw writes cover it exactly once.
        assert_eq!(
            memory.writes.get(),
            4,
            "reused MAP_SHARED|MAP_ANON ranges must still be scrubbed before reuse"
        );
        assert!(reporter.finish().unhandled_syscalls.is_empty());
    }

    #[test]
    fn read_guest_c_string_reads_in_chunks_not_one_byte_at_a_time() {
        let mut bytes = vec![b'a'; 300];
        bytes.push(0);
        bytes.resize(512, 0);
        let memory = CountingMemory::new(0x4000, bytes);

        let value = read_guest_c_string(&memory, 0x4000).unwrap();

        assert_eq!(value.len(), 300);
        assert!(
            memory.reads.get() <= 3,
            "read_guest_c_string should chunk reads, not issue {} byte reads",
            memory.reads.get(),
        );
    }

    #[test]
    fn every_migrated_syscall_is_claimed_by_the_normalized_table() {
        let d = SyscallDispatcher::new();
        let mut mem = LinearMemory::new(0, vec![0u8; 4096]);
        let reporter = CompatReporter::default();
        // Numbers that used to live in the deleted legacy match. Each must now
        // be claimed by the normalized table (Some), never None.
        for nr in [
            5u64, 7, 8, 10, 11, 13, 14, 43, 44, 45, 74, 93, 151, 152, 159, 172, 173, 174, 175, 176,
            177, 178, 243, 269, 283, 293, 435,
        ] {
            let req = SyscallRequest::new(nr, SyscallArgs::from([0, 0, 0, 0, 0, 0]));
            assert!(
                d.dispatch_normalized(
                    &d.capture_one_task_context().unwrap(),
                    req,
                    &mut mem,
                    &reporter,
                    None
                )
                .is_some(),
                "syscall {nr} fell through the normalized table",
            );
        }
    }

    #[test]
    fn resolve_exec_path_absolutizes_relative_against_cwd() {
        let d = SyscallDispatcher::new();
        // Default cwd is "/": a relative exec path resolves against it. This is
        // the Go os/exec TestCommandRelativeName shape (cmd.Path="b/foo",
        // cmd.Dir="/").
        assert_eq!(d.resolve_exec_path("b/os_exec.test"), "/b/os_exec.test");
        // With a deeper cwd, the relative path joins onto it.
        d.set_cwd("/run/src/os/exec");
        assert_eq!(d.resolve_exec_path("./echo"), "/run/src/os/exec/echo");
        assert_eq!(d.resolve_exec_path("../x"), "/run/src/os/x");
        // Absolute paths are normalized but not cwd-joined.
        assert_eq!(d.resolve_exec_path("/bin/sh"), "/bin/sh");
        assert_eq!(d.resolve_exec_path("/bin/../bin/sh"), "/bin/sh");
    }

    #[test]
    fn unknown_syscall_returns_enosys_without_panicking() {
        let mut d = SyscallDispatcher::new();
        let mut mem = LinearMemory::new(0, vec![0u8; 4096]);
        let reporter = CompatReporter::default();
        // 999 is not a real aarch64 syscall and is not in the table.
        let req = SyscallRequest::new(999, SyscallArgs::from([0, 0, 0, 0, 0, 0]));
        let outcome = d
            .dispatch(
                &d.capture_one_task_context().unwrap(),
                req,
                &mut mem,
                &reporter,
            )
            .expect("must not error");
        assert_eq!(
            outcome,
            DispatchOutcome::Errno {
                errno: LINUX_ENOSYS
            }
        );
    }

    /// The dispatcher's `pty_table()` accessor must return the same
    /// `Arc`-wrapped table that was cloned into the `/dev` and `/dev/pts`
    /// mounts. Because all three hold clones of the same `Arc`, mutations
    /// through one pointer are visible through any other.
    #[test]
    fn dispatcher_shares_pty_table_with_dev_mounts() {
        let dispatcher = SyscallDispatcher::with_rootfs(empty_rootfs());
        // A freshly constructed dispatcher has an empty pty table.
        assert!(
            dispatcher.pty_table().lock().live_indices().is_empty(),
            "pty table should start empty"
        );
        // Confirm the Arc is genuinely shared: insert an entry directly into
        // the table and verify the dispatcher sees it through its accessor.
        let index = dispatcher
            .pty_table()
            .lock()
            .insert("dummy-slave".to_string(), 1234);
        assert_eq!(
            dispatcher.pty_table().lock().live_indices(),
            vec![index],
            "inserted index must be visible through the dispatcher accessor"
        );
    }

    #[test]
    fn dns_overrides_render_resolv_conf() {
        let spec = carrick_spec::NetworkNamespaceSpec {
            dns_servers: vec!["1.1.1.1".parse().unwrap(), "9.9.9.9".parse().unwrap()],
            dns_search: vec!["example.test".to_string()],
            dns_options: vec!["ndots:2".to_string()],
            ..Default::default()
        };

        let model = crate::network::model::LinuxNetworkModel::from_spec(&spec);
        let contents = String::from_utf8(resolv_conf_contents_for_network(&model)).unwrap();
        assert!(contents.contains("nameserver 1.1.1.1\n"));
        assert!(contents.contains("nameserver 9.9.9.9\n"));
        assert!(contents.contains("search example.test\n"));
        assert!(contents.contains("options ndots:2\n"));
    }

    #[test]
    fn with_network_mounts_sys_class_net_from_model() {
        let mut spec = carrick_spec::NetworkNamespaceSpec::bridge_default(
            Some("web".to_string()),
            Vec::new(),
            Vec::new(),
        );
        spec.attachments = vec![
            carrick_spec::NetworkAttachmentSpec::bridge_default(
                carrick_spec::BridgeId::new("front"),
                Some("web".to_string()),
                vec!["web-front".to_string()],
                Some(std::net::Ipv4Addr::new(172, 31, 0, 44)),
            ),
            carrick_spec::NetworkAttachmentSpec::bridge_default(
                carrick_spec::BridgeId::new("back"),
                Some("web".to_string()),
                vec!["web-back".to_string()],
                Some(std::net::Ipv4Addr::new(172, 32, 0, 44)),
            ),
        ];
        spec.bridge_id = spec.attachments[0].bridge_id.clone();
        spec.ipv4 = spec.attachments[0].ipv4;
        spec.gateway_v4 = spec.attachments[0].gateway_v4;
        let network = std::sync::Arc::new(crate::network::RuntimeNetwork::create(&spec).unwrap());
        let dispatcher = SyscallDispatcher::with_network(network);
        let sys = dispatcher.fs.vfs_mounts.resolve("/sys/class/net").unwrap();

        let names = sys
            .vfs
            .readdir("/sys/class/net")
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["lo", "eth0", "eth1"]);

        let eth1 = sys
            .vfs
            .open(
                "/sys/class/net/eth1/ifindex",
                crate::vfs::OpenFlags::default(),
                &crate::vfs::OpenContext::default(),
            )
            .unwrap();
        let crate::vfs::VfsHandle::Bytes { contents, .. } = eth1 else {
            panic!("model-backed /sys/class/net ifindex should open as bytes");
        };
        assert_eq!(String::from_utf8(contents).unwrap(), "3\n");
    }

    #[test]
    fn with_host_network_preserves_host_sys_class_net() {
        let default_dispatcher = SyscallDispatcher::new();
        let default_sys = default_dispatcher
            .fs
            .vfs_mounts
            .resolve("/sys/class/net")
            .unwrap();
        let expected = default_sys
            .vfs
            .readdir("/sys/class/net")
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect::<Vec<_>>();
        let network = std::sync::Arc::new(crate::network::RuntimeNetwork::host_default());
        let host_dispatcher = SyscallDispatcher::with_network(network);
        let host_sys = host_dispatcher
            .fs
            .vfs_mounts
            .resolve("/sys/class/net")
            .unwrap();

        let actual = host_sys
            .vfs
            .readdir("/sys/class/net")
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect::<Vec<_>>();

        assert_eq!(actual, expected);
    }

    /// The Linux errno constants we publish must match the
    /// asm-generic kernel headers. Pinned values from
    /// linux/include/uapi/asm-generic/errno{,-base}.h.
    #[test]
    fn linux_errno_constants_match_kernel_uapi() {
        use crate::dispatch::linux_errno::*;
        assert_eq!(EPERM.get(), 1);
        assert_eq!(ENOENT.get(), 2);
        assert_eq!(EAGAIN.get(), 11);
        assert_eq!(ENOMEM.get(), 12);
        assert_eq!(EFAULT.get(), 14);
        assert_eq!(EINVAL.get(), 22);
        assert_eq!(ESPIPE.get(), 29);
        assert_eq!(EDEADLK.get(), 35);
        assert_eq!(ENAMETOOLONG.get(), 36);
        assert_eq!(ENOSYS.get(), 38);
        assert_eq!(EINPROGRESS.get(), 115);
        assert_eq!(ETIMEDOUT.get(), 110);
        assert_eq!(ECONNREFUSED.get(), 111);
    }
}

#[cfg(test)]
mod rosetta_handshake_tests {
    use super::*;

    const BASE: u64 = 0x4000;

    fn mem() -> LinearMemory {
        LinearMemory::new(BASE, vec![0xABu8; 256])
    }

    #[test]
    fn non_rosetta_ioctl_passes_through() {
        // A normal ioctl (e.g. TCGETS=0x5401) is not claimed by the handshake.
        let mut m = mem();
        assert!(rosetta_handshake_ioctl(&mut m, 0x5401, BASE).is_none());
    }

    #[test]
    fn info_ioctl_returns_zero_and_zeroes_buffer() {
        // 0x80806123: size field = 0x80 (128). Not memcmp'd; success + zeroed.
        let mut m = mem();
        let outcome =
            rosetta_handshake_ioctl(&mut m, 0x80806123, BASE).expect("info ioctl must be handled");
        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
        let buf = m.read_bytes(BASE, 128).unwrap();
        assert!(buf.iter().all(|&b| b == 0), "info buffer must be zeroed");
    }

    #[test]
    fn license_ioctl_writes_blob_when_rosetta_present() {
        // 0x80456125: size field = 0x45 (69). When Rosetta is installed the
        // buffer is filled with its verification blob; either way it succeeds.
        let mut m = mem();
        let outcome = rosetta_handshake_ioctl(&mut m, 0x80456125, BASE)
            .expect("licence ioctl must be handled");
        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
        if crate::runtime::rosetta_license_blob().is_some() {
            let buf = m.read_bytes(BASE, 13).unwrap();
            assert_eq!(&buf, b"Our hard work");
        }
    }

    #[test]
    fn faulting_address_returns_efault() {
        // An out-of-bounds buffer address must surface EFAULT, not panic.
        let mut m = mem();
        let outcome = rosetta_handshake_ioctl(&mut m, 0x80806123, 0xDEAD_0000)
            .expect("info ioctl must be handled");
        assert_eq!(
            outcome,
            DispatchOutcome::Errno {
                errno: LINUX_EFAULT
            }
        );
    }
}

#[cfg(test)]
mod hvpatch_in_process_fork_tests {
    use super::*;

    fn fork_dispatcher(
        parent: &SyscallDispatcher,
        parent_tid: crate::thread::ThreadId,
        child_tid: crate::thread::ThreadId,
        parent_guest_pid: u32,
        child_guest_pid: u32,
    ) -> (SyscallDispatcher, crate::kernel::KernelContext) {
        let parent_context = parent.capture_one_task_context().unwrap();
        let plan =
            crate::kernel::ClonePlan::from_flags(carrick_abi::LinuxCloneFlags::empty()).unwrap();
        let child_context = parent_context
            .kernel()
            .reserve_fork(
                &parent_context,
                plan,
                "dispatcher-fork-test".to_owned(),
                None,
            )
            .unwrap()
            .prepare_reference(child_tid)
            .unwrap()
            .commit()
            .unwrap()
            .into_parts()
            .unwrap()
            .0;
        let child =
            parent.fork_clone_in_process(parent_tid, child_tid, parent_guest_pid, child_guest_pid);
        *child.kernel_binding.write() = child_context.task_binding();
        (child, child_context)
    }

    #[test]
    fn hvpatch_pi_futex_owner_uses_kernel_linux_tid() {
        let mut parent = SyscallDispatcher::new();
        parent.set_execution_backend(crate::page_profile::ExecutionBackend::HvPatch);
        let parent_context = parent.capture_one_task_context().unwrap();
        let parent_tid = parent_context.thread().registry_id();
        let child_registry_id = crate::thread::ThreadId::synthetic_for_tests(4101);
        let (child, child_context) =
            fork_dispatcher(&parent, parent_tid, child_registry_id, 41, 42);

        // HVPatch's host-thread registry id is execution machinery, not the
        // Linux-visible tid allocated by the authoritative kernel graph.
        let transport_tid = crate::thread::ThreadId::synthetic_for_tests(9101);
        let registry = crate::thread::ThreadRegistry::new(transport_tid);
        let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
        let address = 0x10800;
        write_u32(&mut memory, address, 0).unwrap();

        let outcome = child
            .dispatch_threaded(
                &child_context,
                SyscallRequest::new(
                    98,
                    SyscallArgs::from([
                        address,
                        LINUX_FUTEX_LOCK_PI | LINUX_FUTEX_PRIVATE_FLAG,
                        0,
                        0,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &CompatReporter::default(),
                transport_tid,
                &registry,
                &crate::thread::FutexTable::new(),
            )
            .unwrap();

        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
        assert_eq!(
            read_u32(&memory, address).unwrap(),
            u32::try_from(child_context.thread().key().tid.raw()).unwrap()
        );
    }

    #[test]
    fn dispatcher_fork_clone_splits_process_state_without_duping_descriptions() {
        let child_tid = crate::thread::ThreadId::synthetic_for_tests(4101);
        let parent = SyscallDispatcher::new();
        let parent_context = parent.capture_one_task_context().unwrap();
        let parent_tid = parent_context.thread().registry_id();
        let description =
            kernel_file_description(Arc::new(RwLock::new(OpenDescription::SyntheticFile {
                base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDWR),
                path: "/fork-clone".to_owned(),
                contents: b"payload".to_vec(),
                offset: 2,
            })));
        parent.captured_file_table().write_open_files().insert(
            3,
            OpenFile::new(Arc::clone(&description), crate::linux_abi::LINUX_FD_CLOEXEC),
        );
        parent.restore_signal_mask(
            &parent_context,
            parent_tid,
            carrick_abi::SigSet::EMPTY.with(12),
        );
        parent.mark_signal_pending(&parent_context, parent_tid, 15);
        parent.proc.lock().pdeathsig = 9;
        parent.proc.lock().membarrier_ready = u64::MAX;
        parent.mem.lock().brk_current = 0x1234_0000;

        let (child, child_context) = fork_dispatcher(&parent, parent_tid, child_tid, 41, 42);

        let child_file = child
            .captured_file_table()
            .read_open_files()
            .get(&3)
            .cloned()
            .unwrap();
        assert!(Arc::ptr_eq(&description, &child_file.description));
        assert_eq!(child_file.fd_flags, crate::linux_abi::LINUX_FD_CLOEXEC);
        assert_eq!(
            child.signal_mask_for(&child_context, child_tid).raw(),
            1 << 11
        );
        assert!(child_context.thread().signal_state().pending().is_empty());
        assert_eq!(child.proc.lock().pdeathsig, 0);
        assert_eq!(child.proc.lock().membarrier_ready, 0);
        assert_eq!(child.mem.lock().brk_current, 0x1234_0000);

        child.captured_file_table().write_open_files().remove(&3);
        child.mem.lock().brk_current = 0x5678_0000;
        assert!(
            parent
                .captured_file_table()
                .read_open_files()
                .contains_key(&3)
        );
        assert_eq!(parent.mem.lock().brk_current, 0x1234_0000);
    }

    #[test]
    fn hvpatch_exit_notification_observes_retired_inherited_pipe_writer() {
        let mut host_fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(host_fds.as_mut_ptr()) }, 0);
        let read_host_fd = host_fds[0];
        let write_host_fd = host_fds[1];

        let parent = SyscallDispatcher::new();
        parent.captured_file_table().write_open_files().insert(
            3,
            OpenFile::from_open_description(
                Arc::new(RwLock::new(OpenDescription::HostPipe {
                    host_fd: HostFdRef::new(read_host_fd),
                    is_read_end: true,
                    pipe_id: 1,
                    base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDONLY),
                    pty: None,
                    bidirectional: false,
                    write_kind: HostWriteKind::PipeLike,
                })),
                0,
            ),
        );
        parent.captured_file_table().write_open_files().insert(
            4,
            OpenFile::from_open_description(
                Arc::new(RwLock::new(OpenDescription::HostPipe {
                    host_fd: HostFdRef::new(write_host_fd),
                    is_read_end: false,
                    pipe_id: 1,
                    base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_WRONLY),
                    pty: None,
                    bidirectional: false,
                    write_kind: HostWriteKind::PipeLike,
                })),
                0,
            ),
        );
        for open_file in parent.captured_file_table().read_open_files().values() {
            retain_open_file(&open_file.description);
        }

        let parent_tid = crate::thread::ThreadId::synthetic_for_tests(5100);
        let child_tid = crate::thread::ThreadId::synthetic_for_tests(5101);
        let (child, child_context) = fork_dispatcher(&parent, parent_tid, child_tid, 51, 52);
        let parent_writer = parent
            .captured_file_table()
            .write_open_files()
            .remove(&4)
            .unwrap();
        parent.close_open_file_and_free_pty(&parent_writer);
        drop(parent_writer);

        let mut pollfd = libc::pollfd {
            fd: read_host_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut pollfd, 1, 0) }, 0);

        child_context
            .kernel()
            .exit_task_key_eventually_notifying(
                child_context.task().key(),
                crate::kernel::LinuxWaitStatus::from_wait_encoding(0),
                None,
                |_| {
                    child.retire_hvpatch_process_fds(&child_context);
                    pollfd.revents = 0;
                    assert_eq!(unsafe { libc::poll(&mut pollfd, 1, 0) }, 1);
                    assert_ne!(pollfd.revents & libc::POLLHUP, 0);
                },
            )
            .unwrap();

        pollfd.revents = 0;
        assert_eq!(unsafe { libc::poll(&mut pollfd, 1, 0) }, 1);
        assert_ne!(pollfd.revents & libc::POLLHUP, 0);
    }

    #[test]
    fn hvpatch_inherited_fd_close_is_not_the_last_logical_reference() {
        let dispatcher = SyscallDispatcher::new();
        let description = Arc::new(RwLock::new(OpenDescription::SyntheticFile {
            base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDONLY),
            path: "epoll-inherited-owner".to_owned(),
            contents: Vec::new(),
            offset: 0,
        }));
        let fd = dispatcher
            .install_fd_at_or_above(
                3,
                OpenFile::from_open_description(Arc::clone(&description), 0),
            )
            .unwrap();
        let parent_tid = crate::thread::ThreadId::synthetic_for_tests(5200);
        let child_tid = crate::thread::ThreadId::synthetic_for_tests(5201);
        let (child, _) = fork_dispatcher(&dispatcher, parent_tid, child_tid, 61, 62);

        let child_file = child.open_file(fd).unwrap();
        assert_eq!(description.read().fd_ref_count(), 2);
        assert!(!is_last_open_file_ref(&child_file));

        let child_file = child
            .captured_file_table()
            .write_open_files()
            .remove(&fd)
            .unwrap();
        child.close_open_file_and_free_pty(&child_file);
        assert_eq!(description.read().fd_ref_count(), 1);
        let parent_file = dispatcher.open_file(fd).unwrap();
        assert!(is_last_open_file_ref(&parent_file));
    }

    /// Linux epoll registrations attach to the monitored open-file
    /// description, not to one process's numeric fd slot.  After fork the
    /// parent and child share both descriptions.  If the child replaces its
    /// inherited monitored slot with dup3(), the parent's registration must
    /// survive until the parent's reference to the original description is
    /// closed.
    ///
    /// This is the reduced form of the HvPatch Go os/exec hang: the child fd
    /// shuffle replaced an inherited pipe slot and Carrick detached the shared
    /// epoll interest by guest-fd number after installing the replacement.
    #[cfg(unix)]
    #[test]
    fn final_target_close_detaches_epoll_owner_from_another_file_table() {
        const MEM_BASE: u64 = 0x5210_0000;
        const MEM_LEN: usize = 0x1000;

        let parent = SyscallDispatcher::new();
        let reporter = crate::compat::CompatReporter::default();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(5400));
        let futex = crate::thread::FutexTable::new();
        let mut memory = LinearMemory::new(MEM_BASE, vec![0; MEM_LEN]);
        let tid = crate::thread::ThreadId::synthetic_for_tests(5401);
        let call = |dispatcher: &SyscallDispatcher,
                    memory: &mut LinearMemory,
                    number: u64,
                    args: [u64; 6]| {
            dispatcher
                .dispatch_threaded(
                    &dispatcher.capture_one_task_context().unwrap(),
                    SyscallRequest::new(number, SyscallArgs::from(args)),
                    memory,
                    &reporter,
                    tid,
                    &registry,
                    &futex,
                )
                .expect("dispatch")
        };

        let epfd = match call(&parent, &mut memory, 20, [0; 6]) {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("epoll_create1 failed: {other:?}"),
        };
        let pipe_addr = MEM_BASE + 0x100;
        assert_eq!(
            call(&parent, &mut memory, 59, [pipe_addr, 0, 0, 0, 0, 0]),
            DispatchOutcome::Returned { value: 0 }
        );
        let pipe_fds = memory.read_bytes(pipe_addr, 8).unwrap();
        let read_fd = i32::from_le_bytes(pipe_fds[0..4].try_into().unwrap());
        let event_addr = MEM_BASE + 0x120;
        let mut event = [0_u8; 16];
        event[0..4].copy_from_slice(&LINUX_EPOLLIN.to_le_bytes());
        memory.write_bytes(event_addr, &event).unwrap();
        assert_eq!(
            call(
                &parent,
                &mut memory,
                21,
                [
                    epfd as u64,
                    LINUX_EPOLL_CTL_ADD,
                    read_fd as u64,
                    event_addr,
                    0,
                    0
                ],
            ),
            DispatchOutcome::Returned { value: 0 }
        );

        let target_description = parent
            .open_file(read_fd)
            .expect("parent target fd")
            .description;
        let epoll_description = parent.open_file(epfd).expect("parent epoll fd").description;
        let (_, _, _, _, owners) = target_description
            .snapshot_for_test(std::time::Instant::now() + std::time::Duration::from_secs(1))
            .expect("target reverse epoll snapshot");
        assert_eq!(owners, vec![(epoll_description.id(), read_fd)]);

        let (child, _) = fork_dispatcher(
            &parent,
            crate::thread::ThreadId::synthetic_for_tests(5401),
            crate::thread::ThreadId::synthetic_for_tests(5402),
            81,
            82,
        );
        assert_eq!(
            call(&child, &mut memory, 57, [epfd as u64, 0, 0, 0, 0, 0]),
            DispatchOutcome::Returned { value: 0 }
        );
        assert_eq!(
            call(&parent, &mut memory, 57, [read_fd as u64, 0, 0, 0, 0, 0]),
            DispatchOutcome::Returned { value: 0 }
        );
        assert_eq!(
            call(&child, &mut memory, 57, [read_fd as u64, 0, 0, 0, 0, 0]),
            DispatchOutcome::Returned { value: 0 }
        );

        let (_, _, _, _, owners) = target_description
            .snapshot_for_test(std::time::Instant::now() + std::time::Duration::from_secs(1))
            .expect("detached target snapshot");
        assert!(owners.is_empty());
        let epoll = parent.open_file(epfd).expect("parent epoll fd");
        let epoll = epoll.description.read();
        let OpenDescription::Epoll { interest, .. } = &*epoll else {
            panic!("epoll fd changed description kind");
        };
        assert!(
            !interest.contains_key(&read_fd),
            "final target close did not detach the epoll owner in another table"
        );
    }

    #[test]
    fn hvpatch_child_dup3_does_not_detach_parent_epoll_interest() {
        const MEM_BASE: u64 = 0x5200_0000;
        const MEM_LEN: usize = 0x1000;
        const EPOLLIN: u32 = 0x1;
        const EPOLLET: u32 = 0x8000_0000;

        let parent = SyscallDispatcher::new();
        let reporter = crate::compat::CompatReporter::default();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(5300));
        let futex = crate::thread::FutexTable::new();
        let mut memory = LinearMemory::new(MEM_BASE, vec![0; MEM_LEN]);
        let tid = crate::thread::ThreadId::synthetic_for_tests(5301);

        macro_rules! call {
            ($dispatcher:expr, $number:expr, $args:expr $(,)?) => {
                $dispatcher
                    .dispatch_threaded(
                        &$dispatcher.capture_one_task_context().unwrap(),
                        SyscallRequest::new($number, SyscallArgs::from($args)),
                        &mut memory,
                        &reporter,
                        tid,
                        &registry,
                        &futex,
                    )
                    .expect("dispatch")
            };
        }

        let epfd = match call!(&parent, 20, [0; 6]) {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("epoll_create1 failed: {other:?}"),
        };
        let pipe_addr = MEM_BASE + 0x100;
        assert_eq!(
            call!(&parent, 59, [pipe_addr, 0, 0, 0, 0, 0]),
            DispatchOutcome::Returned { value: 0 }
        );
        let pipe_fds = memory.read_bytes(pipe_addr, 8).unwrap();
        let read_fd = i32::from_le_bytes(pipe_fds[0..4].try_into().unwrap());
        let write_fd = i32::from_le_bytes(pipe_fds[4..8].try_into().unwrap());

        let event_addr = MEM_BASE + 0x120;
        let mut event = [0u8; 16];
        event[0..4].copy_from_slice(&(EPOLLIN | EPOLLET).to_le_bytes());
        event[8..16].copy_from_slice(&0xfeed_face_u64.to_le_bytes());
        memory.write_bytes(event_addr, &event).unwrap();
        assert_eq!(
            call!(
                &parent,
                21,
                [epfd as u64, 1, read_fd as u64, event_addr, 0, 0],
            ),
            DispatchOutcome::Returned { value: 0 }
        );

        let (child, _) = fork_dispatcher(
            &parent,
            crate::thread::ThreadId::synthetic_for_tests(5301),
            crate::thread::ThreadId::synthetic_for_tests(5302),
            71,
            72,
        );
        assert_eq!(
            call!(&child, 24, [write_fd as u64, read_fd as u64, 0, 0, 0, 0],),
            DispatchOutcome::Returned {
                value: read_fd as i64
            }
        );

        // Make `read_fd` name a child-only description, then close its final
        // logical reference. Numeric-only auto-detach used to remove the
        // parent's registration here even though the registered description
        // and the closing description are unrelated.
        let child_pipe_addr = MEM_BASE + 0x180;
        assert_eq!(
            call!(&child, 59, [child_pipe_addr, 0, 0, 0, 0, 0]),
            DispatchOutcome::Returned { value: 0 }
        );
        let child_pipe_fds = memory.read_bytes(child_pipe_addr, 8).unwrap();
        let child_read_fd = i32::from_le_bytes(child_pipe_fds[0..4].try_into().unwrap());
        let child_write_fd = i32::from_le_bytes(child_pipe_fds[4..8].try_into().unwrap());
        assert_eq!(
            call!(
                &child,
                24,
                [child_write_fd as u64, read_fd as u64, 0, 0, 0, 0],
            ),
            DispatchOutcome::Returned {
                value: read_fd as i64
            }
        );
        assert_eq!(
            call!(&child, 57, [child_read_fd as u64, 0, 0, 0, 0, 0]),
            DispatchOutcome::Returned { value: 0 }
        );
        assert_eq!(
            call!(&child, 57, [child_write_fd as u64, 0, 0, 0, 0, 0]),
            DispatchOutcome::Returned { value: 0 }
        );
        assert_eq!(
            call!(&child, 57, [read_fd as u64, 0, 0, 0, 0, 0]),
            DispatchOutcome::Returned { value: 0 }
        );

        let epoll = parent.open_file(epfd).expect("parent epoll fd");
        let epoll = epoll.description.read();
        let OpenDescription::Epoll { interest, .. } = &*epoll else {
            panic!("epoll fd changed description kind");
        };
        assert!(
            interest.contains_key(&read_fd),
            "child dup3 detached the parent's inherited epoll registration"
        );
        drop(epoll);

        // Drain the child-close wake before making the pipe readable.  The
        // parent's inherited registration must still arm the host
        // multiplexer: a level re-sample after the write would hide a deleted
        // knote/epoll entry, whereas polling the instance fd proves the wake
        // source itself survived the child's non-final close.
        let ready_addr = MEM_BASE + 0x1c0;
        assert_eq!(
            call!(&parent, 22, [epfd as u64, ready_addr, 1, 0, 0, 0]),
            DispatchOutcome::Returned { value: 0 }
        );
        let byte_addr = MEM_BASE + 0x1e0;
        memory.write_bytes(byte_addr, b"x").unwrap();
        assert_eq!(
            call!(&parent, 64, [write_fd as u64, byte_addr, 1, 0, 0, 0],),
            DispatchOutcome::Returned { value: 1 }
        );
        let epoll = parent.open_file(epfd).expect("parent epoll fd");
        let poll_fd = {
            let epoll = epoll.description.read();
            let OpenDescription::Epoll { kqueue, .. } = &*epoll else {
                panic!("epoll fd changed description kind");
            };
            kqueue.poll_fd()
        };
        let mut pollfd = libc::pollfd {
            fd: poll_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(
            unsafe { libc::poll(&mut pollfd, 1, 100) },
            1,
            "child non-final close deleted the parent's host epoll registration"
        );
        assert_ne!(pollfd.revents & libc::POLLIN, 0);
    }
}

#[cfg(test)]
mod container_policy_dispatch_tests {
    //! End-to-end tests for the launch-time container syscall policy at the
    //! dispatch-entry seam: deny hit, miss passthrough, unconfined opt-out
    //! (handlers stay honest ENOSYS), both dispatch paths, fork inheritance,
    //! and survival across the dispatcher's execve-time state resets.
    use super::*;
    use crate::compat::CompatReporter;
    use carrick_spec::SeccompPolicy;

    const SYS_ADD_KEY: u64 = 217;
    const SYS_REQUEST_KEY: u64 = 218;
    const SYS_KEYCTL: u64 = 219;
    const SYS_GETPID: u64 = 172;
    const MEM_BASE: u64 = 0x4000_0000;

    fn confined_dispatcher() -> SyscallDispatcher {
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.apply_seccomp_policy(SeccompPolicy::ContainerDefault);
        dispatcher
    }

    fn dispatch_one(dispatcher: &mut SyscallDispatcher, nr: u64) -> DispatchOutcome {
        let reporter = CompatReporter::default();
        let mut memory = LinearMemory::new(MEM_BASE, vec![0u8; 4096]);
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(nr, SyscallArgs([0; 6])),
                &mut memory,
                &reporter,
            )
            .expect("dispatch")
    }

    #[test]
    fn policy_denies_keyring_family_with_eperm_before_handler() {
        let mut dispatcher = confined_dispatcher();
        for nr in [SYS_ADD_KEY, SYS_REQUEST_KEY, SYS_KEYCTL] {
            assert_eq!(
                dispatch_one(&mut dispatcher, nr),
                DispatchOutcome::Errno { errno: LINUX_EPERM },
                "syscall {nr} must be policy-denied EPERM at dispatch entry"
            );
        }
    }

    #[test]
    fn policy_denial_reports_as_policy_not_unimplemented() {
        let dispatcher = confined_dispatcher();
        let reporter = CompatReporter::default();
        let mut memory = LinearMemory::new(MEM_BASE, vec![0u8; 4096]);
        let mut dispatcher = dispatcher;
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(SYS_ADD_KEY, SyscallArgs([0; 6])),
                &mut memory,
                &reporter,
            )
            .expect("dispatch");
        let report = reporter.snapshot();
        assert!(
            report
                .partial_syscalls
                .iter()
                .any(|e| e.name == "add_key" && e.reason.contains("container syscall policy")),
            "policy denial must surface as a policy event: {report:?}"
        );
        assert!(
            !report
                .unhandled_syscalls
                .iter()
                .any(|e| e.name == "add_key"),
            "policy denial must NOT count as an unimplemented handler: {report:?}"
        );
    }

    #[test]
    fn policy_miss_passes_through_to_handler() {
        let mut dispatcher = confined_dispatcher();
        // getpid is NOT in the deny table: the handler must run and answer.
        match dispatch_one(&mut dispatcher, SYS_GETPID) {
            DispatchOutcome::Returned { value } => assert!(value > 0, "getpid returned {value}"),
            other => panic!("getpid must reach its handler under the policy, got {other:?}"),
        }
    }

    #[test]
    fn unconfined_opt_out_keeps_handlers_honest_enosys() {
        // Unconfined (run-elf default / --security-opt seccomp=unconfined):
        // the keyring handlers keep their honest absent-backend ENOSYS — the
        // policy layer NEVER leaks into handler behavior.
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.apply_seccomp_policy(SeccompPolicy::Unconfined);
        for nr in [SYS_ADD_KEY, SYS_REQUEST_KEY, SYS_KEYCTL] {
            assert_eq!(
                dispatch_one(&mut dispatcher, nr),
                DispatchOutcome::Errno {
                    errno: LINUX_ENOSYS
                },
                "unconfined keyring syscall {nr} must stay honest ENOSYS"
            );
        }
        // And a fresh dispatcher (no policy applied at all) is unconfined too.
        let mut bare = SyscallDispatcher::new();
        assert_eq!(
            dispatch_one(&mut bare, SYS_ADD_KEY),
            DispatchOutcome::Errno {
                errno: LINUX_ENOSYS
            }
        );
    }

    #[test]
    fn policy_applies_on_threaded_dispatch_path_too() {
        let dispatcher = confined_dispatcher();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(2200));
        let reporter = CompatReporter::default();
        let mut memory = LinearMemory::new(MEM_BASE, vec![0u8; 4096]);
        let outcome = dispatcher
            .dispatch_threaded(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(SYS_KEYCTL, SyscallArgs([0; 6])),
                &mut memory,
                &reporter,
                registry.main_tid(),
                &registry,
                &crate::thread::FutexTable::new(),
            )
            .expect("threaded dispatch");
        assert_eq!(outcome, DispatchOutcome::Errno { errno: LINUX_EPERM });
    }

    #[test]
    fn threaded_sched_yield_reaches_the_vcpu_scheduler() {
        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(2201));
        let reporter = CompatReporter::default();
        let mut memory = LinearMemory::new(MEM_BASE, vec![0u8; 4096]);
        let outcome = dispatcher
            .dispatch_threaded(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(124, SyscallArgs([0; 6])),
                &mut memory,
                &reporter,
                registry.main_tid(),
                &registry,
                &crate::thread::FutexTable::new(),
            )
            .expect("threaded sched_yield dispatch");

        assert_eq!(outcome, DispatchOutcome::SchedulerYield);
    }

    #[test]
    fn policy_survives_execve_time_dispatcher_resets() {
        // carrick's guest execve keeps the dispatcher object and selectively
        // resets per-image state (signal handlers, executable path). The
        // policy must survive those resets — like a Linux seccomp filter
        // surviving execve.
        let mut dispatcher = confined_dispatcher();
        dispatcher.reset_signal_handlers_on_execve(&dispatcher.exact_signal_context_for_test());
        dispatcher.set_executable_path("/replaced/image".to_string());
        assert_eq!(
            dispatch_one(&mut dispatcher, SYS_ADD_KEY),
            DispatchOutcome::Errno { errno: LINUX_EPERM }
        );
    }

    #[test]
    fn policy_is_inherited_by_forked_children() {
        // The runtime's guest fork is a host fork: the child inherits the
        // dispatcher (and thus the policy table) via the process memory copy.
        // Prove it with a real fork — the child dispatches add_key and reports
        // the outcome through its exit code.
        let mut dispatcher = confined_dispatcher();
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            let denied = matches!(
                dispatch_one(&mut dispatcher, SYS_ADD_KEY),
                DispatchOutcome::Errno { errno } if errno == LINUX_EPERM
            );
            // SAFETY: _exit is async-signal-safe; no cleanup wanted post-fork.
            unsafe { libc::_exit(if denied { 0 } else { 1 }) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "forked child must inherit the deny table (status {status:#x})"
        );
    }

    #[test]
    fn docker_default_policy_keeps_identity_fast_path() {
        // The Docker default model never denies identity syscalls, so a
        // container run must NOT lose the EL1-shim fast path.
        let dispatcher = confined_dispatcher();
        assert!(dispatcher.identity_fast_path_enabled());
        // A guest seccomp filter still disables it, policy or not.
        dispatcher
            .seccomp
            .install(vec![crate::seccomp::SockFilter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: crate::seccomp::SECCOMP_RET_ALLOW,
            }])
            .expect("install guest seccomp filter");
        assert!(!dispatcher.identity_fast_path_enabled());
    }
}
