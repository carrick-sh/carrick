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
use carrick_runtime::fs_backend::{FsBackend, HostFsBackend};
use support::*;

#[test]
fn cwd_and_access_syscalls_use_rootfs_state() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc\0").unwrap();
    memory.write_bytes(0x4010, b"motd\0").unwrap();
    memory.write_bytes(0x4020, b"/\0").unwrap();
    memory.write_bytes(0x4030, b"//..\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(17, SyscallArgs::from([0x4100, 16, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // Linux getcwd(2) returns the length of the filled buffer including the
        // terminating NUL ("/\0" -> 2), not the buffer address.
        DispatchOutcome::Returned { value: 2 }
    );
    assert_eq!(memory.read_bytes(0x4100, 2).unwrap(), b"/\0");

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(49, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(dispatcher.cwd(), "/etc");

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(17, SyscallArgs::from([0x4100, 16, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // "/etc\0" -> 5 bytes filled (length, not address).
        DispatchOutcome::Returned { value: 5 }
    );
    assert_eq!(memory.read_bytes(0x4100, 5).unwrap(), b"/etc\0");

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    48,
                    SyscallArgs::from([(-100_i64) as u64, 0x4010, 4, 0, 0, 0]),
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
                    48,
                    SyscallArgs::from([(-100_i64) as u64, 0x4010, 2, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // W_OK on an existing file: the overlay is writable and the guest is
        // root, so this succeeds (it used to report EACCES under the obsolete
        // read-only rootfs model).
        DispatchOutcome::Returned { value: 0 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4010, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4200, 64, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 18 }
    );
    assert_eq!(
        memory.read_bytes(0x4200, 18).unwrap(),
        b"rootfs says hello\n"
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(49, SyscallArgs::from([0x4020, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(dispatcher.cwd(), "/");
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(49, SyscallArgs::from([0x4030, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(dispatcher.cwd(), "/");
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
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(50, SyscallArgs::from([4, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(dispatcher.cwd(), "/etc");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn faccessat2_supports_bootstrap_access_flags_and_fd_checks() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar_with_links(
        [("etc/motd", b"rootfs says hello\n".as_slice())],
        [("etc/motd-link", "motd")],
    ))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/motd-link\0").unwrap();
    memory.write_bytes(0x4040, b"/proc/cpuinfo\0").unwrap();
    memory.write_bytes(0x4060, b"\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    439,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4000,
                        LINUX_R_OK,
                        LINUX_AT_EACCESS,
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
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    439,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4000,
                        LINUX_W_OK,
                        LINUX_AT_EACCESS,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // The rootfs is backed by a writable overlay and the guest runs as root
        // (root bypasses DAC write checks), so W_OK on an existing file succeeds
        // just as it does on a real overlayfs mounted by root.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    439,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4020,
                        LINUX_X_OK,
                        LINUX_AT_SYMLINK_NOFOLLOW,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // motd-link points at the 0o644 regular file "motd": even as root,
        // X_OK on a regular file with no execute bit set returns EACCES, which
        // is exactly what real Linux does.
        DispatchOutcome::Errno {
            errno: LinuxErrno::new(13)
        }
    );
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
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    439,
                    SyscallArgs::from([3, 0x4060, LINUX_R_OK, LINUX_AT_EMPTY_PATH, 0, 0]),
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
                    439,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4040,
                        LINUX_R_OK,
                        LINUX_AT_EACCESS,
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
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    439,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 8, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LinuxErrno::new(22)
        }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    439,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, LINUX_R_OK, 0x80, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LinuxErrno::new(22)
        }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn statfs_writes_packed_linux_statfs_for_rootfs_path() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(43, SyscallArgs::from([0x4000, 0x4100, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let statfs = read_statfs(&memory, 0x4100);
    let fs_type = statfs.f_type;
    let block_size = statfs.f_bsize;
    let name_len = statfs.f_namelen;
    assert_eq!(fs_type, LINUX_OVERLAYFS_SUPER_MAGIC);
    assert_eq!(block_size, 4096);
    assert!(name_len >= 255);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn fstatfs_writes_packed_linux_statfs_for_open_fd() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
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
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(44, SyscallArgs::from([3, 0x4100, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let statfs = read_statfs(&memory, 0x4100);
    let fs_type = statfs.f_type;
    let free_blocks = statfs.f_bfree;
    assert_eq!(fs_type, LINUX_OVERLAYFS_SUPER_MAGIC);
    assert!(free_blocks > 0);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn newfstatat_and_fstat_write_typed_linux_stat() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x500]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    79,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4100, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4100);
    let mode = stat.st_mode;
    let size = stat.st_size;
    assert_eq!(mode & LINUX_S_IFMT, LINUX_S_IFREG);
    assert_eq!(mode & 0o777, 0o644);
    assert_eq!(size, 18);

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
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(80, SyscallArgs::from([3, 0x4200, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4200);
    let mode = stat.st_mode;
    let size = stat.st_size;
    assert_eq!(mode & LINUX_S_IFMT, LINUX_S_IFREG);
    assert_eq!(size, 18);

    memory.write_bytes(0x4300, b"/etc\0").unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    79,
                    SyscallArgs::from([(-100_i64) as u64, 0x4300, 0x4400, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4400);
    let mode = stat.st_mode;
    assert_eq!(mode & LINUX_S_IFMT, LINUX_S_IFDIR);
}

#[test]
fn statx_writes_basic_rootfs_fd_and_symlink_metadata() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar_with_links(
        [("etc/motd", b"rootfs says hello\n".as_slice())],
        [("etc/motd-link", "motd")],
    ))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x700]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/motd-link\0").unwrap();
    memory.write_bytes(0x4040, b"\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    291,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4000,
                        0,
                        LINUX_STATX_BASIC_STATS as u64,
                        0x4100,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let statx = read_statx(&memory, 0x4100);
    let mask = statx.stx_mask;
    let blksize = statx.stx_blksize;
    let mode = statx.stx_mode;
    let nlink = statx.stx_nlink;
    let uid = statx.stx_uid;
    let gid = statx.stx_gid;
    let size = statx.stx_size;
    let blocks = statx.stx_blocks;
    assert_eq!(mask & LINUX_STATX_BASIC_STATS, LINUX_STATX_BASIC_STATS);
    assert_eq!(blksize, 4096);
    assert_eq!(mode as u32 & LINUX_S_IFMT, LINUX_S_IFREG);
    assert_eq!(mode as u32 & 0o777, 0o644);
    assert_eq!(nlink, 1);
    assert_eq!(uid, 0);
    assert_eq!(gid, 0);
    assert_eq!(size, 18);
    assert_eq!(blocks, 1);

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
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    291,
                    SyscallArgs::from([
                        3,
                        0x4040,
                        LINUX_AT_EMPTY_PATH,
                        LINUX_STATX_BASIC_STATS as u64,
                        0x4200,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let statx = read_statx(&memory, 0x4200);
    let mode = statx.stx_mode;
    let size = statx.stx_size;
    assert_eq!(mode as u32 & LINUX_S_IFMT, LINUX_S_IFREG);
    assert_eq!(size, 18);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    291,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4020,
                        LINUX_AT_SYMLINK_NOFOLLOW,
                        LINUX_STATX_BASIC_STATS as u64,
                        0x4300,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let statx = read_statx(&memory, 0x4300);
    let mode = statx.stx_mode;
    let size = statx.stx_size;
    assert_eq!(mode as u32 & LINUX_S_IFMT, LINUX_S_IFLNK);
    assert_eq!(size, 4);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    291,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4000,
                        0,
                        LINUX_STATX_RESERVED,
                        0x4400,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LinuxErrno::new(22)
        }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    291,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4000,
                        0x80,
                        LINUX_STATX_BASIC_STATS as u64,
                        0x4400,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LinuxErrno::new(22)
        }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    291,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4000,
                        0,
                        LINUX_STATX_BASIC_STATS as u64,
                        0x5000,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LinuxErrno::new(14)
        }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn host_stat_following_symlink_reports_target_inode() {
    let scratch = tempfile::TempDir::new().unwrap();
    let dir =
        cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority()).unwrap();
    let backend = HostFsBackend::from_existing_dir(dir);
    backend.make_dir("/tmp").unwrap();
    backend.make_dir("/target").unwrap();
    backend.symlink("/target", "/tmp/link").unwrap();

    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let reporter = CompatReporter::default();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x600]);
    memory.write_bytes(0x4000, b"/target\0").unwrap();
    memory.write_bytes(0x4020, b"/tmp/link\0").unwrap();

    for (path_addr, stat_addr, flags) in [
        (0x4000, 0x4100, 0),
        (0x4020, 0x4200, 0),
        (0x4020, 0x4300, LINUX_AT_SYMLINK_NOFOLLOW),
    ] {
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(
                        79,
                        SyscallArgs::from([(-100_i64) as u64, path_addr, stat_addr, flags, 0, 0,]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { value: 0 }
        );
    }

    let target = read_stat(&memory, 0x4100);
    let followed_link = read_stat(&memory, 0x4200);
    let link = read_stat(&memory, 0x4300);
    assert_eq!(target.st_mode & LINUX_S_IFMT, LINUX_S_IFDIR);
    assert_eq!(followed_link.st_mode & LINUX_S_IFMT, LINUX_S_IFDIR);
    assert_eq!(link.st_mode & LINUX_S_IFMT, LINUX_S_IFLNK);
    let target_ino = target.st_ino;
    let followed_link_ino = followed_link.st_ino;
    let link_ino = link.st_ino;
    assert_eq!(target_ino, followed_link_ino);
    assert_ne!(target_ino, link_ino);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(49, SyscallArgs::from([0x4020, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
}

fn assert_fstat_and_statx_empty_path_agree(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut LinearMemory,
    reporter: &CompatReporter,
    fd: i32,
    expected_mode_type: u32,
) {
    let stat_addr = 0x7000;
    let statx_addr = 0x7200;
    memory.write_bytes(0x7400, b"\0").unwrap();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(80, SyscallArgs::from([fd as u64, stat_addr, 0, 0, 0, 0])),
                memory,
                reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    291,
                    SyscallArgs::from([
                        fd as u64,
                        0x7400,
                        LINUX_AT_EMPTY_PATH,
                        LINUX_STATX_BASIC_STATS as u64,
                        statx_addr,
                        0,
                    ]),
                ),
                memory,
                reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    let stat = read_stat(memory, stat_addr);
    let statx = read_statx(memory, statx_addr);
    let stat_mode = stat.st_mode;
    let stat_size = stat.st_size;
    let stat_nlink = stat.st_nlink;
    let stat_uid = stat.st_uid;
    let stat_gid = stat.st_gid;
    let stat_blocks = stat.st_blocks;
    let statx_mode = statx.stx_mode;
    let statx_size = statx.stx_size;
    let statx_nlink = statx.stx_nlink;
    let statx_uid = statx.stx_uid;
    let statx_gid = statx.stx_gid;
    let statx_blocks = statx.stx_blocks;
    assert_eq!(stat_mode, statx_mode as u32, "fd {fd} mode");
    assert_eq!(stat_mode & LINUX_S_IFMT, expected_mode_type, "fd {fd} type");
    assert_eq!(stat_size as u64, statx_size, "fd {fd} size");
    assert_eq!(stat_nlink, statx_nlink, "fd {fd} nlink");
    assert_eq!(stat_uid, statx_uid, "fd {fd} uid");
    assert_eq!(stat_gid, statx_gid, "fd {fd} gid");
    assert_eq!(stat_blocks as u64, statx_blocks, "fd {fd} blocks");
}

#[test]
fn fstat_and_statx_empty_path_agree_for_anonymous_fd_kinds() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x4000]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let eventfd = dispatcher
        .dispatch(
            SyscallRequest::new(19, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: eventfd } = eventfd else {
        panic!("expected eventfd2 success, got {eventfd:?}");
    };

    let timerfd = dispatcher
        .dispatch(
            SyscallRequest::new(85, SyscallArgs::from([1, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: timerfd } = timerfd else {
        panic!("expected timerfd_create success, got {timerfd:?}");
    };

    let epoll = dispatcher
        .dispatch(
            SyscallRequest::new(20, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: epoll } = epoll else {
        panic!("expected epoll_create1 success, got {epoll:?}");
    };

    let pipe_addr = 0x7600;
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(59, SyscallArgs::from([pipe_addr, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let pipe = read_fd_pair(&memory, pipe_addr);

    let socket = dispatcher
        .dispatch(
            SyscallRequest::new(
                198,
                SyscallArgs::from([
                    LINUX_AF_INET as u64,
                    (LINUX_SOCK_STREAM | LINUX_SOCK_NONBLOCK) as u64,
                    0,
                    0,
                    0,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: socket } = socket else {
        panic!("expected socket success, got {socket:?}");
    };

    for fd in [eventfd, timerfd, epoll] {
        assert_fstat_and_statx_empty_path_agree(
            &mut dispatcher,
            &mut memory,
            &reporter,
            fd as i32,
            0,
        );
    }
    for fd in [pipe.read_fd, pipe.write_fd] {
        assert_fstat_and_statx_empty_path_agree(
            &mut dispatcher,
            &mut memory,
            &reporter,
            fd,
            LINUX_S_IFIFO,
        );
    }
    assert_fstat_and_statx_empty_path_agree(
        &mut dispatcher,
        &mut memory,
        &reporter,
        socket as i32,
        LINUX_S_IFSOCK,
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

// ── fstat on a pty fd reports S_IFCHR ─────────────────────────────────────────

#[test]
fn fstat_pty_reports_char_device() {
    // A pty master is a character device (S_IFCHR = 0o020000), not a pipe
    // (S_IFIFO). fstat(2) on the master fd must report the S_IFCHR type bits.
    //
    // LinuxStat layout (aarch64):
    //   offset 0  : st_dev  (u64, 8 bytes)
    //   offset 8  : st_ino  (u64, 8 bytes)
    //   offset 16 : st_mode (u32, 4 bytes)  ← we check this
    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/dev/ptmx\0").unwrap();
    let reporter = CompatReporter::default();

    // openat(AT_FDCWD, "/dev/ptmx", O_RDWR=2) → master fd.
    let master = match dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 2, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap()
    {
        DispatchOutcome::Returned { value } => value as u64,
        o => panic!("open /dev/ptmx failed: {:?}", o),
    };

    // fstat(master, statbuf) — syscall 80.
    let statbuf = 0x4100u64;
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(80, SyscallArgs::from([master, statbuf, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 },
        "fstat on pty master must succeed"
    );

    // st_mode is at offset 16; read 4 bytes and check the S_IFMT bits.
    let mode_bytes = memory.read_bytes(statbuf + 16, 4).unwrap();
    let mode = u32::from_le_bytes([mode_bytes[0], mode_bytes[1], mode_bytes[2], mode_bytes[3]]);
    assert_eq!(
        mode & LINUX_S_IFMT,
        LINUX_S_IFCHR,
        "fstat on pty master must report S_IFCHR, got mode {:o}",
        mode
    );
}

#[test]
fn faccessat2_dotdot_after_missing_intermediate_returns_enoent() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "work/.keep",
        b"".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"abc/..\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);
    dispatcher.set_cwd("/work");

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    439,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4000,
                        LINUX_X_OK,
                        LINUX_AT_EACCESS,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LinuxErrno::new(2)
        }
    );
}

#[test]
fn x86_stat_writes_x8664_stat_layout() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "usr/local/go/bin/go",
        b"stub".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x500]);
    memory.write_bytes(0x4000, b"/usr/local/go\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    CARRICK_PRIVATE_X86_STAT,
                    SyscallArgs::from([0x4000, 0x4100, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_x8664_stat(&memory, 0x4100);
    let mode = stat.st_mode;
    let nlink = stat.st_nlink;
    assert_eq!(mode & LINUX_S_IFMT, LINUX_S_IFDIR);
    assert_eq!(mode & 0o777, 0o755);
    assert_eq!(nlink, 2);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    CARRICK_PRIVATE_X86_LSTAT,
                    SyscallArgs::from([0x4000, 0x4180, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_x8664_stat(&memory, 0x4180);
    let mode = stat.st_mode;
    assert_eq!(mode & LINUX_S_IFMT, LINUX_S_IFDIR);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    CARRICK_PRIVATE_X86_NEWFSTATAT,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x41c0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_x8664_stat(&memory, 0x41c0);
    let mode = stat.st_mode;
    assert_eq!(mode & LINUX_S_IFMT, LINUX_S_IFDIR);

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
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    CARRICK_PRIVATE_X86_FSTAT,
                    SyscallArgs::from([3, 0x4200, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_x8664_stat(&memory, 0x4200);
    let mode = stat.st_mode;
    assert_eq!(mode & LINUX_S_IFMT, LINUX_S_IFDIR);
}
