use carrick::compat::{CompatReporter, SyscallArgs};
use carrick::dispatch::{
    Aarch64SyscallFrame, DispatchOutcome, GuestMemory, LinearMemory, SyscallDispatcher,
    SyscallRequest,
};
use carrick::elf::SegmentPerms;
use carrick::linux_abi::{
    LINUX_DIRENT64_HEADER_SIZE, LINUX_DT_REG, LINUX_S_IFDIR, LINUX_S_IFMT, LINUX_S_IFREG,
    LinuxDirent64Header, LinuxRlimit, LinuxStat, LinuxUtsname,
};
use carrick::memory::{AddressSpace, LINUX_HEAP_BASE, LINUX_HEAP_SIZE, LINUX_MMAP_BASE};
use carrick::rootfs::{LayerSource, RootFs};
use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;
use zerocopy::FromBytes;

#[test]
fn write_syscall_reads_guest_memory_and_writes_stdout() {
    let mut memory = LinearMemory::new(0x4000, b"hello from linux\n".to_vec());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(64, SyscallArgs::from([1, 0x4000, 17, 0, 0, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Returned { value: 17 });
    assert_eq!(dispatcher.stdout(), b"hello from linux\n");
    assert!(dispatcher.stderr().is_empty());

    let report = reporter.finish();
    assert!(report.unhandled_syscalls.is_empty());
}

#[test]
fn write_syscall_rejects_bad_guest_pointer_with_efault() {
    let mut memory = LinearMemory::new(0x4000, b"short".to_vec());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(64, SyscallArgs::from([1, 0x5000, 5, 0, 0, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Errno { errno: 14 });
    assert!(dispatcher.stdout().is_empty());
}

#[test]
fn exit_syscall_requests_process_exit() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(93, SyscallArgs::from([42, 0, 0, 0, 0, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Exit { code: 42 });
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn exit_group_syscall_requests_process_exit() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(94, SyscallArgs::from([7, 0, 0, 0, 0, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Exit { code: 7 });
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn unknown_syscall_returns_enosys_and_records_report_entry() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(9999, SyscallArgs::from([1, 2, 3, 4, 5, 6])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Errno { errno: 38 });
    let report = reporter.finish();
    assert_eq!(report.unhandled_syscalls[0].number, 9999);
    assert_eq!(report.unhandled_syscalls[0].name, "unknown");
    assert_eq!(report.unhandled_syscalls[0].count, 1);
}

#[test]
fn syscall_request_can_be_built_from_aarch64_register_frame() {
    let frame = Aarch64SyscallFrame {
        x0: 1,
        x1: 0x4000,
        x2: 17,
        x3: 0,
        x4: 0,
        x5: 0,
        x8: 64,
    };

    assert_eq!(
        SyscallRequest::from_aarch64_frame(frame),
        SyscallRequest::new(64, SyscallArgs::from([1, 0x4000, 17, 0, 0, 0]))
    );
}

#[test]
fn linear_memory_bounds_reads() {
    let mut memory = LinearMemory::new(0x1000, b"abcdef".to_vec());

    assert_eq!(memory.read_bytes(0x1002, 3).unwrap(), b"cde");
    assert!(memory.read_bytes(0x1004, 3).is_err());
    memory.write_bytes(0x1001, b"XY").unwrap();
    assert_eq!(memory.read_bytes(0x1000, 4).unwrap(), b"aXYd");
    assert!(memory.write_bytes(0x1005, b"YZ").is_err());
}

#[test]
fn openat_read_close_round_trip_through_rootfs_fd() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    let opened = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &mut reporter,
        )
        .unwrap();
    assert_eq!(opened, DispatchOutcome::Returned { value: 3 });

    let read = dispatcher
        .dispatch(
            SyscallRequest::new(63, SyscallArgs::from([3, 0x4100, 64, 0, 0, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();
    assert_eq!(read, DispatchOutcome::Returned { value: 18 });
    assert_eq!(
        memory.read_bytes(0x4100, 18).unwrap(),
        b"rootfs says hello\n"
    );

    let closed = dispatcher
        .dispatch(
            SyscallRequest::new(57, SyscallArgs::from([3, 0, 0, 0, 0, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();
    assert_eq!(closed, DispatchOutcome::Returned { value: 0 });
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn openat_missing_rootfs_file_returns_enoent() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, b"/missing\0".to_vec());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &mut reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Errno { errno: 2 });
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

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
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(17, SyscallArgs::from([0x4100, 16, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0x4100 }
    );
    assert_eq!(memory.read_bytes(0x4100, 2).unwrap(), b"/\0");

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(49, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
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
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0x4100 }
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
                &mut reporter,
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
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 13 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4010, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4200, 64, 0, 0, 0])),
                &mut memory,
                &mut reporter,
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
                &mut reporter,
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
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(50, SyscallArgs::from([4, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(dispatcher.cwd(), "/etc");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn lseek_repositions_rootfs_file_reads() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x300]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(62, SyscallArgs::from([3, 7, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 7 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(memory.read_bytes(0x4100, 4).unwrap(), b"says");
}

#[test]
fn readlinkat_reads_rootfs_symlink_target_without_nul() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar_with_links(
        [("lib/ld-musl-aarch64.so.1", b"loader".as_slice())],
        [("lib/ld-linux-aarch64.so.1", "ld-musl-aarch64.so.1")],
    ))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0xff; 0x200]);
    memory
        .write_bytes(0x4000, b"/lib/ld-linux-aarch64.so.1\0")
        .unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                78,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4100, 64, 0, 0]),
            ),
            &mut memory,
            &mut reporter,
        )
        .unwrap();

    let target = b"ld-musl-aarch64.so.1";
    assert_eq!(
        outcome,
        DispatchOutcome::Returned {
            value: target.len() as i64
        }
    );
    assert_eq!(memory.read_bytes(0x4100, target.len()).unwrap(), target);
    assert_eq!(
        memory.read_bytes(0x4100 + target.len() as u64, 1).unwrap(),
        [0xff]
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn readlinkat_reports_synthetic_proc_self_exe() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "bin/app",
        b"app".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0xff; 0x200]);
    memory.write_bytes(0x4000, b"/proc/self/exe\0").unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs_and_executable(rootfs, "/bin/app");

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                78,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4100, 64, 0, 0]),
            ),
            &mut memory,
            &mut reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Returned { value: 8 });
    assert_eq!(memory.read_bytes(0x4100, 8).unwrap(), b"/bin/app");
    assert_eq!(memory.read_bytes(0x4108, 1).unwrap(), [0xff]);
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
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    79,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4100, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
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
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(80, SyscallArgs::from([3, 0x4200, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
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
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4400);
    let mode = stat.st_mode;
    assert_eq!(mode & LINUX_S_IFMT, LINUX_S_IFDIR);
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
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(61, SyscallArgs::from([3, 0x4100, 0x100, 0, 0, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value } = outcome else {
        panic!("expected getdents64 success, got {outcome:?}");
    };
    assert!(value as usize >= LINUX_DIRENT64_HEADER_SIZE + "motd".len() + 1);

    let dirent = memory.read_bytes(0x4100, value as usize).unwrap();
    let (header, _) = LinuxDirent64Header::read_from_prefix(&dirent).unwrap();
    let reclen = header.d_reclen;
    let dtype = header.d_type;
    assert_eq!(reclen as usize, value as usize);
    assert_eq!(dtype, LINUX_DT_REG);
    let name_start = LINUX_DIRENT64_HEADER_SIZE;
    let name_end = dirent[name_start..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|offset| name_start + offset)
        .unwrap();
    assert_eq!(&dirent[name_start..name_end], b"motd");

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(61, SyscallArgs::from([3, 0x4100, 0x100, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
}

#[test]
fn brk_tracks_heap_within_runtime_arena() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(214, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_HEAP_BASE as i64
        }
    );

    let next = LINUX_HEAP_BASE + 0x1000;
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(214, SyscallArgs::from([next, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: next as i64 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    214,
                    SyscallArgs::from([LINUX_HEAP_BASE + LINUX_HEAP_SIZE + 1, 0, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: next as i64 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn process_identity_syscalls_return_bootstrap_ids() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let pid = std::process::id() as i64;

    for (number, expected) in [
        (172, pid),
        (173, 1),
        (174, 0),
        (175, 0),
        (176, 0),
        (177, 0),
        (178, pid),
    ] {
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(number, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                    &mut memory,
                    &mut reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { value: expected }
        );
    }
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn set_tid_address_and_robust_list_are_bootstrap_successes() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let pid = std::process::id() as i64;

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(96, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: pid }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(99, SyscallArgs::from([0x4000, 24, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn uname_writes_packed_linux_utsname() {
    let mut memory = LinearMemory::new(0x4000, vec![0; core::mem::size_of::<LinuxUtsname>()]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(160, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let utsname = read_utsname(&memory, 0x4000);
    assert_eq!(linux_c_string(utsname.sysname), "Linux");
    assert_eq!(linux_c_string(utsname.machine), "aarch64");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn prlimit64_writes_packed_rlimit() {
    let mut memory = LinearMemory::new(0x4000, vec![0; core::mem::size_of::<LinuxRlimit>()]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(261, SyscallArgs::from([0, 3, 0, 0x4000, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let rlimit = read_rlimit(&memory, 0x4000);
    let current = rlimit.rlim_cur;
    let maximum = rlimit.rlim_max;
    assert_eq!(current, maximum);
    assert!(current > 0);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn getrandom_fills_guest_buffer() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 32]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(278, SyscallArgs::from([0x4000, 16, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 16 }
    );
    assert!(
        memory
            .read_bytes(0x4000, 16)
            .unwrap()
            .iter()
            .any(|byte| *byte != 0)
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn rt_signal_stubs_zero_old_state() {
    let mut memory = LinearMemory::new(0x4000, vec![0xff; 0x200]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(135, SyscallArgs::from([0, 0, 0x4000, 8, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(memory.read_bytes(0x4000, 8).unwrap(), [0; 8]);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(134, SyscallArgs::from([2, 0, 0x4010, 8, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(
        memory
            .read_bytes(0x4010, 32)
            .unwrap()
            .iter()
            .all(|byte| *byte == 0)
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn mmap_maps_file_bytes_into_guest_memory_arena() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "lib/libc.so",
        b"0123456789abcdef".as_slice(),
    )]))])
    .unwrap();
    let mut memory = AddressSpace::from_segments(
        0,
        [
            (0x4000, rw_perms(), b"/lib/libc.so\0".to_vec(), 0x100),
            (LINUX_MMAP_BASE, rwx_perms(), Vec::new(), 0x4000),
        ],
    )
    .unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(222, SyscallArgs::from([0, 4, 1, 0x02, 3, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_MMAP_BASE as i64
        }
    );
    assert_eq!(memory.read_bytes(LINUX_MMAP_BASE, 4).unwrap(), b"0123");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn mmap_anonymous_fixed_mapping_zeroes_guest_memory_and_mprotect_munmap_are_noops() {
    let mut memory = AddressSpace::from_segments(
        0,
        [(LINUX_MMAP_BASE, rwx_perms(), b"dirty".to_vec(), 0x4000)],
    )
    .unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    222,
                    SyscallArgs::from([LINUX_MMAP_BASE, 5, 3, 0x12 | 0x20, (-1_i64) as u64, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_MMAP_BASE as i64
        }
    );
    assert_eq!(
        memory.read_bytes(LINUX_MMAP_BASE, 5).unwrap(),
        b"\0\0\0\0\0"
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(226, SyscallArgs::from([LINUX_MMAP_BASE, 5, 1, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(215, SyscallArgs::from([LINUX_MMAP_BASE, 5, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

fn read_stat(memory: &impl GuestMemory, address: u64) -> LinuxStat {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxStat>())
        .unwrap();
    let (stat, _) = LinuxStat::read_from_prefix(&bytes).unwrap();
    stat
}

fn read_utsname(memory: &impl GuestMemory, address: u64) -> LinuxUtsname {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxUtsname>())
        .unwrap();
    let (utsname, _) = LinuxUtsname::read_from_prefix(&bytes).unwrap();
    utsname
}

fn read_rlimit(memory: &impl GuestMemory, address: u64) -> LinuxRlimit {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxRlimit>())
        .unwrap();
    let (rlimit, _) = LinuxRlimit::read_from_prefix(&bytes).unwrap();
    rlimit
}

fn linux_c_string<const N: usize>(field: [u8; N]) -> String {
    let end = field.iter().position(|byte| *byte == 0).unwrap_or(N);
    String::from_utf8(field[..end].to_vec()).unwrap()
}

fn rw_perms() -> SegmentPerms {
    SegmentPerms {
        read: true,
        write: true,
        execute: false,
    }
}

fn rwx_perms() -> SegmentPerms {
    SegmentPerms {
        read: true,
        write: true,
        execute: true,
    }
}

fn gzip_tar<const N: usize>(files: [(&str, &[u8]); N]) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (path, contents) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, contents).unwrap();
        }
        builder.finish().unwrap();
    }

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

fn gzip_tar_with_links<const N: usize, const M: usize>(
    files: [(&str, &[u8]); N],
    links: [(&str, &str); M],
) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (path, contents) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, contents).unwrap();
        }
        for (path, target) in links {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header.set_cksum();
            builder.append_link(&mut header, path, target).unwrap();
        }
        builder.finish().unwrap();
    }

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}
