//! Filesystem syscall dispatch tests.
//!
//! Split out of the former tests/syscall_dispatch.rs monolith. Shared imports,
//! constants, and helpers live in tests/common/syscall_support.rs.

// clippy's allow-unwrap-in-tests heuristic does not cover helper functions in
// integration test crates. The no-panic gate targets production code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/syscall_support.rs"]
mod support;

#[cfg(target_os = "macos")]
use carrick_runtime::fs_backend::HostFsBackend;
use carrick_runtime::linux_abi::{LINUX_AT_FDCWD, LINUX_AT_REMOVEDIR, LINUX_O_CREAT, LINUX_O_RDWR};
use carrick_runtime::vfs::BindVfs;
use support::*;

#[test]
fn inotify_init_add_watch_read_dispatch_plumbing() {
    // The event mechanism itself is unit-tested against a real vnode in
    // src/inotify.rs; here we verify the syscall plumbing at the dispatch seam.
    // The in-memory backend has no host vnode, so watching an existing path is
    // ENOSPC (inotify watches require `--fs host`); we exercise the fd
    // lifecycle and the error paths.
    const IN_NONBLOCK: u64 = 0o4000;
    const IN_MODIFY: u64 = 0x2;
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"hi\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    // inotify_init1(IN_NONBLOCK) -> a fresh fd >= 3.
    let ifd = match run(
        &mut dispatcher,
        &mut memory,
        26,
        [IN_NONBLOCK, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => {
            assert!(value >= 3, "init1 fd {value}");
            value as u64
        }
        other => panic!("inotify_init1: {other:?}"),
    };

    // read with no events queued -> EAGAIN (11).
    assert_eq!(
        run(&mut dispatcher, &mut memory, 63, [ifd, 0x4100, 64, 0, 0, 0]),
        DispatchOutcome::Errno { errno: 11 }
    );

    // add_watch on an existing in-memory path -> ENOSPC (28): no host vnode.
    memory.write_bytes(0x4200, b"/etc/motd\0").unwrap();
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            27,
            [ifd, 0x4200, IN_MODIFY, 0, 0, 0]
        ),
        DispatchOutcome::Errno { errno: 28 }
    );

    // add_watch on a nonexistent path -> ENOENT (2).
    memory.write_bytes(0x4280, b"/no/such\0").unwrap();
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            27,
            [ifd, 0x4280, IN_MODIFY, 0, 0, 0]
        ),
        DispatchOutcome::Errno { errno: 2 }
    );

    // add_watch on an empty path -> ENOENT (2); unlike fstatat-style metadata
    // syscalls, inotify_add_watch has no AT_EMPTY_PATH form.
    memory.write_bytes(0x4300, b"\0").unwrap();
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            27,
            [ifd, 0x4300, IN_MODIFY, 0, 0, 0]
        ),
        DispatchOutcome::Errno { errno: 2 }
    );

    // rm_watch of an unknown wd -> EINVAL (22).
    assert_eq!(
        run(&mut dispatcher, &mut memory, 28, [ifd, 99, 0, 0, 0, 0]),
        DispatchOutcome::Errno { errno: 22 }
    );

    // add_watch / rm_watch on a non-inotify fd -> EINVAL (22).
    assert_eq!(
        run(&mut dispatcher, &mut memory, 28, [0, 1, 0, 0, 0, 0]),
        DispatchOutcome::Errno { errno: 22 }
    );
}

#[test]
fn inotify_add_watch_under_bind_mount_uses_host_vnode() {
    const IN_NONBLOCK: u64 = 0o4000;
    const IN_MODIFY: u64 = 0x2;
    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-bindwatch")).unwrap();
    std::fs::write(
        scratch.path().join("nodejs-bindwatch/watch_file"),
        b"watch payload",
    )
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-bindwatch/watch_file\0")
        .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    let ifd = match run(
        &mut dispatcher,
        &mut memory,
        26,
        [IN_NONBLOCK, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("inotify_init1: {other:?}"),
    };
    match run(
        &mut dispatcher,
        &mut memory,
        27,
        [ifd, 0x4000, IN_MODIFY, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => assert!(value >= 1, "watch descriptor {value}"),
        other => panic!("inotify_add_watch: {other:?}"),
    }
    std::fs::write(
        scratch.path().join("nodejs-bindwatch/watch_file"),
        b"changed payload",
    )
    .unwrap();
    match run(&mut dispatcher, &mut memory, 63, [ifd, 0x4100, 64, 0, 0, 0]) {
        DispatchOutcome::Returned { value } => assert!(value >= 16, "inotify bytes {value}"),
        other => panic!("inotify read after bind write: {other:?}"),
    }
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn bind_mount_cwd_relative_stat_open_mkdir_and_inotify_use_host_tree() {
    const IN_NONBLOCK: u64 = 0o4000;
    const IN_MODIFY: u64 = 0x2;
    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-bindcwd")).unwrap();
    std::fs::write(
        scratch.path().join("nodejs-bindcwd/watch_file"),
        b"watch payload",
    )
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x800]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-bindcwd\0")
        .unwrap();
    memory.write_bytes(0x4040, b"child\0").unwrap();
    memory.write_bytes(0x4060, b"child/file.txt\0").unwrap();
    memory.write_bytes(0x4080, b".\0").unwrap();
    memory.write_bytes(0x40a0, b"watch_file\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    assert_eq!(
        run(&mut dispatcher, &mut memory, 49, [0x4000, 0, 0, 0, 0, 0],),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            34,
            [LINUX_AT_FDCWD, 0x4040, 0o755, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(scratch.path().join("nodejs-bindcwd/child").is_dir());
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            56,
            [
                LINUX_AT_FDCWD,
                0x4060,
                LINUX_O_CREAT | LINUX_O_RDWR,
                0o644,
                0,
                0,
            ],
        ),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 57, [3, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(
        scratch
            .path()
            .join("nodejs-bindcwd/child/file.txt")
            .is_file()
    );

    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            79,
            [LINUX_AT_FDCWD, 0x4060, 0x4200, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4200);
    assert_eq!(stat.st_mode & LINUX_S_IFMT, LINUX_S_IFREG);

    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            291,
            [
                LINUX_AT_FDCWD,
                0x4080,
                0,
                LINUX_STATX_BASIC_STATS as u64,
                0x4300,
                0,
            ],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let statx = read_statx(&memory, 0x4300);
    assert_eq!(statx.stx_mode as u32 & LINUX_S_IFMT, LINUX_S_IFDIR);

    let ifd = match run(
        &mut dispatcher,
        &mut memory,
        26,
        [IN_NONBLOCK, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("inotify_init1: {other:?}"),
    };
    match run(
        &mut dispatcher,
        &mut memory,
        27,
        [ifd, 0x40a0, IN_MODIFY, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => assert!(value >= 1, "file wd {value}"),
        other => panic!("relative inotify_add_watch file: {other:?}"),
    }
    match run(
        &mut dispatcher,
        &mut memory,
        27,
        [ifd, 0x4080, IN_MODIFY, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => assert!(value >= 1, "dir wd {value}"),
        other => panic!("relative inotify_add_watch cwd: {other:?}"),
    }
    std::fs::write(
        scratch.path().join("nodejs-bindcwd/watch_file"),
        b"changed payload",
    )
    .unwrap();
    match run(&mut dispatcher, &mut memory, 63, [ifd, 0x4400, 64, 0, 0, 0]) {
        DispatchOutcome::Returned { value } => assert!(value >= 16, "inotify bytes {value}"),
        other => panic!("relative inotify read after bind write: {other:?}"),
    }

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn bind_mount_directory_inotify_reports_child_file_write_name() {
    const IN_NONBLOCK: u64 = 0o4000;
    const IN_MODIFY: u64 = 0x2;
    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-binddirwatch")).unwrap();
    std::fs::write(
        scratch.path().join("nodejs-binddirwatch/watch_file"),
        b"watch payload",
    )
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-binddirwatch\0")
        .unwrap();
    memory.write_bytes(0x4040, b".\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    assert_eq!(
        run(&mut dispatcher, &mut memory, 49, [0x4000, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    let ifd = match run(
        &mut dispatcher,
        &mut memory,
        26,
        [IN_NONBLOCK, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("inotify_init1: {other:?}"),
    };
    match run(
        &mut dispatcher,
        &mut memory,
        27,
        [ifd, 0x4040, IN_MODIFY, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => assert!(value >= 1, "dir wd {value}"),
        other => panic!("directory inotify_add_watch: {other:?}"),
    }
    std::fs::write(
        scratch.path().join("nodejs-binddirwatch/watch_file"),
        b"changed payload",
    )
    .unwrap();
    match run(
        &mut dispatcher,
        &mut memory,
        63,
        [ifd, 0x4100, 128, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => assert!(value >= 28, "inotify bytes {value}"),
        other => panic!("directory inotify read after child write: {other:?}"),
    }
    let event = memory.read_bytes(0x4100, 32).unwrap();
    let name_len = u32::from_ne_bytes(event[12..16].try_into().unwrap()) as usize;
    assert!(name_len >= "watch_file\0".len(), "name len {name_len}");
    assert_eq!(&event[16..16 + "watch_file".len()], b"watch_file");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn getdents64_lists_rootfs_directory_entries() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x500]);
    memory.write_bytes(0x4000, b"/etc\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(61, SyscallArgs::from([3, 0x4100, 0x100, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value } = outcome else {
        panic!("expected getdents64 success, got {outcome:?}");
    };
    // A real Linux directory lists `.` and `..` first, then its entries, so the
    // listing is the three records ., .., motd.
    assert!(value as usize > LINUX_DIRENT64_HEADER_SIZE + "motd".len());

    let dirent = memory.read_bytes(0x4100, value as usize).unwrap();
    // Parse every dirent64 record and collect (name, d_type).
    let mut entries: Vec<(String, u8)> = Vec::new();
    let mut off = 0usize;
    while off < dirent.len() {
        let (header, _) = LinuxDirent64Header::read_from_prefix(&dirent[off..]).unwrap();
        let reclen = header.d_reclen as usize;
        assert!(reclen > 0 && off + reclen <= dirent.len());
        let name_start = off + LINUX_DIRENT64_HEADER_SIZE;
        let name_end = dirent[name_start..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| name_start + offset)
            .unwrap();
        entries.push((
            String::from_utf8_lossy(&dirent[name_start..name_end]).into_owned(),
            header.d_type,
        ));
        off += reclen;
    }
    assert!(
        entries
            .iter()
            .any(|(n, t)| n == "." && *t == 4u8 /* DT_DIR */)
    );
    assert!(
        entries
            .iter()
            .any(|(n, t)| n == ".." && *t == 4u8 /* DT_DIR */)
    );
    assert!(
        entries
            .iter()
            .any(|(n, t)| n == "motd" && *t == LINUX_DT_REG)
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(61, SyscallArgs::from([3, 0x4100, 0x100, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
}

#[test]
fn linkat_reports_eexist_enoent_and_links_into_writable_overlay() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"linkat fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/missing\0").unwrap();
    memory.write_bytes(0x4040, b"/etc/new-link\0").unwrap();
    memory.write_bytes(0x4060, b"\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    37,
                    SyscallArgs::from(
                        [(-100_i64) as u64, 0x4000, (-100_i64) as u64, 0x4000, 0, 0,]
                    ),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 17 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    37,
                    SyscallArgs::from(
                        [(-100_i64) as u64, 0x4000, (-100_i64) as u64, 0x4040, 0, 0,]
                    ),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // Hard-linking an existing file to a new name lands in the writable
        // overlay (the backend's hard_link), so it succeeds rather than
        // reporting the obsolete read-only EROFS.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    37,
                    SyscallArgs::from(
                        [(-100_i64) as u64, 0x4020, (-100_i64) as u64, 0x4040, 0, 0,]
                    ),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    37,
                    SyscallArgs::from(
                        [(-100_i64) as u64, 0x4000, (-100_i64) as u64, 0x4060, 0, 0,]
                    ),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    37,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4000,
                        (-100_i64) as u64,
                        0x4040,
                        0xdead,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn symlinkat_bootstrap_reports_eexist_for_known_links_and_erofs_for_new_paths() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"symlinkat fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"target\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4040, b"/etc/new-link\0").unwrap();
    memory.write_bytes(0x4060, b"\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    36,
                    SyscallArgs::from([0x4000, (-100_i64) as u64, 0x4020, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 17 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    36,
                    SyscallArgs::from([0x4000, (-100_i64) as u64, 0x4040, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 30 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    36,
                    SyscallArgs::from([0x4060, (-100_i64) as u64, 0x4040, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    36,
                    SyscallArgs::from([0x4000, (-100_i64) as u64, 0x4060, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn renameat_renames_known_sources_into_overlay_and_enoent_otherwise() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"renameat fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/motd.bak\0").unwrap();
    memory.write_bytes(0x4040, b"/etc/missing\0").unwrap();
    memory.write_bytes(0x4060, b"\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    38,
                    SyscallArgs::from(
                        [(-100_i64) as u64, 0x4000, (-100_i64) as u64, 0x4020, 0, 0,]
                    ),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // Renaming an existing rootfs file copies it up into the writable
        // overlay and renames there, so it succeeds rather than the obsolete
        // read-only EROFS.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    38,
                    SyscallArgs::from(
                        [(-100_i64) as u64, 0x4040, (-100_i64) as u64, 0x4020, 0, 0,]
                    ),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    38,
                    SyscallArgs::from(
                        [(-100_i64) as u64, 0x4060, (-100_i64) as u64, 0x4020, 0, 0,]
                    ),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    38,
                    SyscallArgs::from(
                        [(-100_i64) as u64, 0x4000, (-100_i64) as u64, 0x4060, 0, 0,]
                    ),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn unlinkat_removes_files_on_overlay_and_validates_directory_kind() {
    const AT_REMOVEDIR: u64 = 0x200;
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar_with_links(
        [
            ("etc/motd", b"unlinkat fixture\n".as_slice()),
            ("etc/conf.d/.gitkeep", b"".as_slice()),
        ],
        [],
    ))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/conf.d\0").unwrap();
    memory.write_bytes(0x4040, b"/etc/missing\0").unwrap();
    memory.write_bytes(0x4060, b"\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    // unlinkat(AT_REMOVEDIR) on a regular file is ENOTDIR (checked while motd
    // still exists, before the destructive unlink below).
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    35,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, AT_REMOVEDIR, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 20 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    35,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // Unlinking an existing file records a whiteout/tombstone in the
        // writable overlay and succeeds, instead of the obsolete read-only
        // EROFS.
        DispatchOutcome::Returned { value: 0 }
    );
    // unlinkat without AT_REMOVEDIR on a directory is EISDIR.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    35,
                    SyscallArgs::from([(-100_i64) as u64, 0x4020, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 21 }
    );
    // rmdir of a non-empty directory (/etc/conf.d holds .gitkeep) is ENOTEMPTY,
    // matching real Linux on the writable overlay (no longer read-only EROFS).
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    35,
                    SyscallArgs::from([(-100_i64) as u64, 0x4020, AT_REMOVEDIR, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 39 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    35,
                    SyscallArgs::from([(-100_i64) as u64, 0x4040, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    35,
                    SyscallArgs::from([(-100_i64) as u64, 0x4060, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    35,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0xdead, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn mknodat_returns_eexist_for_known_paths_and_creates_in_overlay_otherwise() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"mknodat fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/new-node\0").unwrap();
    memory.write_bytes(0x4040, b"\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    33,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0o100644, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 17 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    33,
                    SyscallArgs::from([(-100_i64) as u64, 0x4020, 0o100644, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // mknod with an S_IFREG (regular-file) mode on a new path materialises
        // an empty file in the writable overlay and succeeds, rather than the
        // obsolete read-only EROFS.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    33,
                    SyscallArgs::from([(-100_i64) as u64, 0x4040, 0o100644, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn mkdirat_returns_eexist_for_known_paths_and_creates_in_overlay_otherwise() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"mkdirat fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/new-dir\0").unwrap();
    memory.write_bytes(0x4040, b"\0").unwrap();
    memory.write_bytes(0x4060, b"/proc/self/maps\0").unwrap();
    memory.write_bytes(0x4080, b"relative/dir\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    34,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0o755, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 17 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    34,
                    SyscallArgs::from([(-100_i64) as u64, 0x4060, 0o755, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 17 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    34,
                    SyscallArgs::from([(-100_i64) as u64, 0x4020, 0o755, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // mkdir on a new path under an existing parent creates the directory in
        // the writable overlay and succeeds, rather than the obsolete EROFS.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    34,
                    SyscallArgs::from([(-100_i64) as u64, 0x4040, 0o755, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(34, SyscallArgs::from([99, 0x4080, 0o755, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn mkdirat_under_bind_mount_creates_host_directory_for_openat_children() {
    let scratch = tempfile::TempDir::new().unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/tmp/nodejs-bindcp\0").unwrap();
    memory
        .write_bytes(0x4020, b"/tmp/nodejs-bindcp/test\0")
        .unwrap();
    memory
        .write_bytes(0x4060, b"/tmp/nodejs-bindcp/test/file.txt\0")
        .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    34,
                    SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, 0o700, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    34,
                    SyscallArgs::from([LINUX_AT_FDCWD, 0x4020, 0o755, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(scratch.path().join("nodejs-bindcp/test").is_dir());

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([
                        LINUX_AT_FDCWD,
                        0x4060,
                        LINUX_O_CREAT | LINUX_O_RDWR,
                        0o644,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert!(scratch.path().join("nodejs-bindcp/test/file.txt").is_file());
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(57, SyscallArgs::from([3, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(35, SyscallArgs::from([LINUX_AT_FDCWD, 0x4060, 0, 0, 0, 0]),),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(!scratch.path().join("nodejs-bindcp/test/file.txt").exists());
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    35,
                    SyscallArgs::from([LINUX_AT_FDCWD, 0x4020, LINUX_AT_REMOVEDIR, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(!scratch.path().join("nodejs-bindcp/test").exists());
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn bind_mount_create_stamps_guest_owner_on_files_and_directories() {
    let scratch = tempfile::TempDir::new().unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-bindowner\0")
        .unwrap();
    memory
        .write_bytes(0x4040, b"/tmp/nodejs-bindowner/file.txt\0")
        .unwrap();
    memory
        .write_bytes(0x4080, b"/tmp/nodejs-bindowner/dir\0")
        .unwrap();

    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    assert_eq!(
        run(&mut dispatcher, &mut memory, 144, [1001, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 146, [1000, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            34,
            [LINUX_AT_FDCWD, 0x4000, 0o755, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            34,
            [LINUX_AT_FDCWD, 0x4080, 0o755, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            56,
            [
                LINUX_AT_FDCWD,
                0x4040,
                LINUX_O_CREAT | LINUX_O_RDWR,
                0o644,
                0,
                0,
            ],
        ),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 57, [3, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );

    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            79,
            [LINUX_AT_FDCWD, 0x4040, 0x4100, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let file_stat = read_stat(&memory, 0x4100);
    let file_uid = file_stat.st_uid;
    let file_gid = file_stat.st_gid;
    assert_eq!(file_uid, 1000);
    assert_eq!(file_gid, 1001);

    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            79,
            [LINUX_AT_FDCWD, 0x4080, 0x4200, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let dir_stat = read_stat(&memory, 0x4200);
    let dir_uid = dir_stat.st_uid;
    let dir_gid = dir_stat.st_gid;
    assert_eq!(dir_uid, 1000);
    assert_eq!(dir_gid, 1001);

    assert!(scratch.path().join("nodejs-bindowner/file.txt").is_file());
    assert!(scratch.path().join("nodejs-bindowner/dir").is_dir());
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn bind_mount_directory_inotify_reports_created_child_name() {
    const IN_NONBLOCK: u64 = 0o4000;
    const IN_MODIFY: u64 = 0x2;
    const IN_CREATE: u64 = 0x100;
    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-bindcreate")).unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-bindcreate/watch_dir")).unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x800]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-bindcreate/watch_dir\0")
        .unwrap();
    memory
        .write_bytes(0x4040, b"/tmp/nodejs-bindcreate/watch_dir/fsevent-0\0")
        .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    let ifd = match run(
        &mut dispatcher,
        &mut memory,
        26,
        [IN_NONBLOCK, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("inotify_init1: {other:?}"),
    };
    let wd = match run(
        &mut dispatcher,
        &mut memory,
        27,
        [ifd, 0x4000, IN_MODIFY | IN_CREATE, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("directory inotify_add_watch: {other:?}"),
    };
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            56,
            [
                LINUX_AT_FDCWD,
                0x4040,
                LINUX_O_CREAT | LINUX_O_RDWR,
                0o644,
                0,
                0,
            ],
        ),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 57, [4, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );

    let n = match run(
        &mut dispatcher,
        &mut memory,
        63,
        [ifd, 0x4200, 128, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as usize,
        other => panic!("directory inotify read after child create: {other:?}"),
    };
    assert!(n >= 28, "inotify bytes {n}");
    let event = memory.read_bytes(0x4200, n).unwrap();
    let got_wd = i32::from_ne_bytes(event[0..4].try_into().unwrap());
    assert_eq!(got_wd, wd);
    let name_len = u32::from_ne_bytes(event[12..16].try_into().unwrap()) as usize;
    assert!(name_len >= "fsevent-0\0".len(), "name len {name_len}");
    let name = &event[16..16 + "fsevent-0".len()];
    assert_eq!(name, b"fsevent-0");

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn host_overlay_directory_inotify_reports_created_child_name() {
    const IN_NONBLOCK: u64 = 0o4000;
    const IN_MODIFY: u64 = 0x2;
    const IN_CREATE: u64 = 0x100;
    let scratch_root = tempfile::TempDir::new().unwrap();
    let backend = HostFsBackend::new_in(scratch_root.path()).unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x800]);
    memory.write_bytes(0x4000, b"/nodejs-hostcreate\0").unwrap();
    memory
        .write_bytes(0x4040, b"/nodejs-hostcreate/watch_dir\0")
        .unwrap();
    memory
        .write_bytes(0x4080, b"/nodejs-hostcreate/watch_dir/fsevent-0\0")
        .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            34,
            [LINUX_AT_FDCWD, 0x4000, 0o755, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            34,
            [LINUX_AT_FDCWD, 0x4040, 0o755, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );

    let ifd = match run(
        &mut dispatcher,
        &mut memory,
        26,
        [IN_NONBLOCK, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("inotify_init1: {other:?}"),
    };
    let wd = match run(
        &mut dispatcher,
        &mut memory,
        27,
        [ifd, 0x4040, IN_MODIFY | IN_CREATE, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("directory inotify_add_watch: {other:?}"),
    };
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            56,
            [
                LINUX_AT_FDCWD,
                0x4080,
                LINUX_O_CREAT | LINUX_O_RDWR,
                0o644,
                0,
                0,
            ],
        ),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 57, [4, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );

    let n = match run(
        &mut dispatcher,
        &mut memory,
        63,
        [ifd, 0x4200, 128, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as usize,
        other => panic!("directory inotify read after child create: {other:?}"),
    };
    assert!(n >= 28, "inotify bytes {n}");
    let event = memory.read_bytes(0x4200, n).unwrap();
    let got_wd = i32::from_ne_bytes(event[0..4].try_into().unwrap());
    assert_eq!(got_wd, wd);
    let name_len = u32::from_ne_bytes(event[12..16].try_into().unwrap()) as usize;
    assert!(name_len >= "fsevent-0\0".len(), "name len {name_len}");
    let name = &event[16..16 + "fsevent-0".len()];
    assert_eq!(name, b"fsevent-0");

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn bind_mount_repeated_relative_stat_after_guest_mkdir_uses_host_tree() {
    let scratch = tempfile::TempDir::new().unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x800]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-bindstat\0")
        .unwrap();
    memory.write_bytes(0x4040, b"test_dir\0").unwrap();

    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    assert_eq!(
        run(&mut dispatcher, &mut memory, 144, [1001, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 146, [1000, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            34,
            [LINUX_AT_FDCWD, 0x4000, 0o755, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 49, [0x4000, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            34,
            [LINUX_AT_FDCWD, 0x4040, 0o755, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(scratch.path().join("nodejs-bindstat/test_dir").is_dir());

    for _ in 0..300 {
        assert_eq!(
            run(
                &mut dispatcher,
                &mut memory,
                79,
                [LINUX_AT_FDCWD, 0x4040, 0x4200, 0, 0, 0],
            ),
            DispatchOutcome::Returned { value: 0 }
        );
        let stat = read_stat(&memory, 0x4200);
        let mode = stat.st_mode;
        let uid = stat.st_uid;
        let gid = stat.st_gid;
        assert_eq!(mode & LINUX_S_IFMT, LINUX_S_IFDIR);
        assert_eq!(uid, 1000);
        assert_eq!(gid, 1001);
    }

    for _ in 0..300 {
        assert_eq!(
            run(
                &mut dispatcher,
                &mut memory,
                291,
                [
                    LINUX_AT_FDCWD,
                    0x4040,
                    0,
                    LINUX_STATX_BASIC_STATS as u64,
                    0x4380,
                    0,
                ],
            ),
            DispatchOutcome::Returned { value: 0 }
        );
        let statx = read_statx(&memory, 0x4380);
        let mode = statx.stx_mode;
        let uid = statx.stx_uid;
        let gid = statx.stx_gid;
        assert_eq!(mode as u32 & LINUX_S_IFMT, LINUX_S_IFDIR);
        assert_eq!(uid, 1000);
        assert_eq!(gid, 1001);
    }

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn renameat_under_bind_mount_moves_host_entries() {
    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-bindmv")).unwrap();
    std::fs::write(
        scratch.path().join("nodejs-bindmv/old.txt"),
        b"rename payload",
    )
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-bindmv/old.txt\0")
        .unwrap();
    memory
        .write_bytes(0x4040, b"/tmp/nodejs-bindmv/new.txt\0")
        .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    38,
                    SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, LINUX_AT_FDCWD, 0x4040, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(!scratch.path().join("nodejs-bindmv/old.txt").exists());
    assert_eq!(
        std::fs::read(scratch.path().join("nodejs-bindmv/new.txt")).unwrap(),
        b"rename payload"
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn symlinkat_and_readlinkat_under_bind_mount_use_host_tree() {
    let scratch = tempfile::TempDir::new().unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"target-name\0").unwrap();
    memory.write_bytes(0x4020, b"/tmp/nodejs-bindln\0").unwrap();
    memory
        .write_bytes(0x4060, b"/tmp/nodejs-bindln/link\0")
        .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    34,
                    SyscallArgs::from([LINUX_AT_FDCWD, 0x4020, 0o755, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    36,
                    SyscallArgs::from([0x4000, LINUX_AT_FDCWD, 0x4060, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        std::fs::read_link(scratch.path().join("nodejs-bindln/link")).unwrap(),
        std::path::PathBuf::from("target-name")
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    78,
                    SyscallArgs::from([LINUX_AT_FDCWD, 0x4060, 0x4100, 64, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 11 }
    );
    assert_eq!(memory.read_bytes(0x4100, 11).unwrap(), b"target-name");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn linkat_and_unlinkat_under_bind_mount_use_host_tree() {
    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-bindhard")).unwrap();
    std::fs::write(
        scratch.path().join("nodejs-bindhard/source.txt"),
        b"hard payload",
    )
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-bindhard/source.txt\0")
        .unwrap();
    memory
        .write_bytes(0x4040, b"/tmp/nodejs-bindhard/linked.txt\0")
        .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    37,
                    SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, LINUX_AT_FDCWD, 0x4040, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        std::fs::read(scratch.path().join("nodejs-bindhard/linked.txt")).unwrap(),
        b"hard payload"
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(35, SyscallArgs::from([LINUX_AT_FDCWD, 0x4040, 0, 0, 0, 0]),),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(!scratch.path().join("nodejs-bindhard/linked.txt").exists());
    assert!(scratch.path().join("nodejs-bindhard/source.txt").exists());
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}
