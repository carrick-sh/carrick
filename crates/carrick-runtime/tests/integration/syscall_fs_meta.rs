//! Filesystem syscall dispatch tests.
//!
//! Split out of the former tests/syscall_dispatch.rs monolith. Shared imports,
//! constants, and helpers live in tests/common/syscall_support.rs.

// clippy's allow-unwrap-in-tests heuristic does not cover helper functions in
// integration test crates. The no-panic gate targets production code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/syscall_support.rs"]
mod support;

use carrick_runtime::linux_abi::{LINUX_AT_FDCWD, LINUX_EFBIG, LINUX_O_CREAT, LINUX_O_RDWR};
use carrick_runtime::vfs::{BindVfs, MAX_IN_MEMORY_FILE_SIZE};
use support::*;

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
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                78,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4100, 64, 0, 0]),
            ),
            &mut memory,
            &reporter,
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
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs_and_executable(rootfs, "/bin/app");

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                78,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4100, 64, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Returned { value: 8 });
    assert_eq!(memory.read_bytes(0x4100, 8).unwrap(), b"/bin/app");
    assert_eq!(memory.read_bytes(0x4108, 1).unwrap(), [0xff]);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn proc_self_magic_links_readlink_and_lstat() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "bin/app",
        b"app".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0xff; 0x600]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs_and_executable(rootfs, "/bin/app");

    // readlink /proc/self/cwd → the working dir ("/" by default).
    memory.write_bytes(0x4000, b"/proc/self/cwd\0").unwrap();
    let out = dispatcher
        .dispatch(
            SyscallRequest::new(
                78,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4100, 64, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(out, DispatchOutcome::Returned { value: 1 });
    assert_eq!(memory.read_bytes(0x4100, 1).unwrap(), b"/");

    // readlink /proc/self → the caller's (numeric) pid, even though it is
    // modeled as a traversable directory.
    memory.write_bytes(0x4000, b"/proc/self\0").unwrap();
    let out = dispatcher
        .dispatch(
            SyscallRequest::new(
                78,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4200, 64, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: n } = out else {
        panic!("readlink /proc/self: {out:?}");
    };
    let pid = String::from_utf8(memory.read_bytes(0x4200, n as usize).unwrap()).unwrap();
    assert!(
        !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()),
        "/proc/self should readlink to a pid, got {pid:?}"
    );

    // lstat /proc/self/exe → an existing S_IFLNK (was ENOENT before).
    memory.write_bytes(0x4000, b"/proc/self/exe\0").unwrap();
    let out = dispatcher
        .dispatch(
            SyscallRequest::new(
                79,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4300, 0x100, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(
        out,
        DispatchOutcome::Returned { value: 0 },
        "lstat exe: {out:?}"
    );
    let st = read_stat(&memory, 0x4300);
    assert_eq!(
        st.st_mode & LINUX_S_IFMT,
        LINUX_S_IFLNK,
        "/proc/self/exe should lstat as a symlink"
    );
}

#[test]
fn proc_self_fd_readlink_synthesizes_anon_inode_target() {
    // An fd with no backing path (here an eventfd) must readlink to the
    // anon_inode:[…] target Linux shows, not an empty string.
    let mut memory = LinearMemory::new(0x4000, vec![0xff; 0x400]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // eventfd2(0, 0) = syscall 19.
    let DispatchOutcome::Returned { value: fd } = dispatcher
        .dispatch(
            SyscallRequest::new(19, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap()
    else {
        panic!("eventfd2 should succeed");
    };

    let path = format!("/proc/self/fd/{fd}\0");
    memory.write_bytes(0x4000, path.as_bytes()).unwrap();
    let out = dispatcher
        .dispatch(
            SyscallRequest::new(
                78,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4100, 64, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: n } = out else {
        panic!("readlink /proc/self/fd/{fd}: {out:?}");
    };
    let target = String::from_utf8(memory.read_bytes(0x4100, n as usize).unwrap()).unwrap();
    assert_eq!(target, "anon_inode:[eventfd]");
}

#[test]
fn dev_fd_opens_descriptor_like_proc_self_fd() {
    // /dev/fd is a symlink to /proc/self/fd on Linux; bash process substitution
    // (`cat <(...)`) passes /dev/fd/N to the spawned command, which open()s it to
    // dup the pipe. carrick had no /dev/fd at all → ENOENT, breaking process
    // substitution and the libuv conformance harness. open(/dev/fd/N) must dup
    // fd N (works for an anon/pipe fd with no backing path), exactly like
    // open(/proc/self/fd/N).
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // eventfd2(0,0) → a non-stdio fd with no backing path (the process-sub case).
    let DispatchOutcome::Returned { value: efd } = dispatcher
        .dispatch(
            SyscallRequest::new(19, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap()
    else {
        panic!("eventfd2 should succeed");
    };

    let path = format!("/dev/fd/{efd}\0");
    memory.write_bytes(0x4000, path.as_bytes()).unwrap();
    // openat(AT_FDCWD, "/dev/fd/{efd}", O_RDONLY)
    let out = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: dup_fd } = out else {
        panic!("open(/dev/fd/{efd}) should dup the descriptor, got {out:?}");
    };
    assert!(dup_fd >= 3, "expected a fresh fd, got {dup_fd}");
    assert_ne!(dup_fd, efd, "open(/dev/fd/N) must return a NEW fd");
}

#[test]
fn proc_self_fd_directory_lists_open_fds() {
    // `ls /proc/self/fd` / `for fd in /proc/self/fd/*`: opendir + getdents must
    // enumerate the guest's open fds as symlink entries.
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x4000]);
    memory.write_bytes(0x4000, b"/proc/self/fd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // eventfd2(0, 0) = syscall 19 → a non-stdio fd that must appear in the list.
    let DispatchOutcome::Returned { value: efd } = dispatcher
        .dispatch(
            SyscallRequest::new(19, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap()
    else {
        panic!("eventfd2 should succeed");
    };

    // openat(AT_FDCWD, "/proc/self/fd", O_RDONLY) — a directory open.
    let open = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: dirfd } = open else {
        panic!("opendir /proc/self/fd: {open:?}");
    };

    // getdents64(dirfd, buf, count) = syscall 61.
    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                61,
                SyscallArgs::from([dirfd as u64, 0x4400, 0x1000, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value } = outcome else {
        panic!("getdents64 /proc/self/fd: {outcome:?}");
    };
    assert!(value > 0, "getdents should return entries");

    let dirent = memory.read_bytes(0x4400, value as usize).unwrap();
    let mut names: Vec<String> = Vec::new();
    let mut off = 0usize;
    while off < dirent.len() {
        let (header, _) = LinuxDirent64Header::read_from_prefix(&dirent[off..]).unwrap();
        let reclen = header.d_reclen as usize;
        if reclen == 0 {
            break;
        }
        let name_start = off + LINUX_DIRENT64_HEADER_SIZE;
        let name_end = dirent[name_start..]
            .iter()
            .position(|b| *b == 0)
            .map(|p| name_start + p)
            .unwrap();
        names.push(String::from_utf8_lossy(&dirent[name_start..name_end]).into_owned());
        off += reclen;
    }
    // The eventfd and the stdio fds must be listed.
    assert!(
        names.contains(&efd.to_string()),
        "/proc/self/fd should list the eventfd {efd}: {names:?}"
    );
    for stdio in ["0", "1", "2"] {
        assert!(
            names.iter().any(|n| n == stdio),
            "/proc/self/fd should list stdio {stdio}: {names:?}"
        );
    }
}

#[test]
fn proc_self_auxv_refreshes_when_image_state_is_updated() {
    // execve now re-applies the new image's /proc state via the same setters; a
    // second set_auxv_image (as a fresh image would trigger) must be reflected,
    // not stuck on the first image's auxv.
    let read_auxv = |dispatcher: &mut SyscallDispatcher, memory: &mut LinearMemory| -> Vec<u8> {
        let reporter = CompatReporter::default();
        memory.write_bytes(0x4000, b"/proc/self/auxv\0").unwrap();
        let DispatchOutcome::Returned { value: fd } = dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                memory,
                &reporter,
            )
            .unwrap()
        else {
            panic!("open /proc/self/auxv");
        };
        let DispatchOutcome::Returned { value: n } = dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([fd as u64, 0x4400, 0x400, 0, 0, 0])),
                memory,
                &reporter,
            )
            .unwrap()
        else {
            panic!("read /proc/self/auxv");
        };
        memory.read_bytes(0x4400, n as usize).unwrap().to_vec()
    };

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    let mut dispatcher = SyscallDispatcher::new();

    dispatcher.set_auxv_image(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(
        read_auxv(&mut dispatcher, &mut memory),
        vec![1, 2, 3, 4, 5, 6, 7, 8]
    );

    // A subsequent image (the execve refresh) replaces it.
    dispatcher.set_auxv_image(vec![9, 10, 11, 12]);
    assert_eq!(read_auxv(&mut dispatcher, &mut memory), vec![9, 10, 11, 12]);
}

#[test]
fn proc_self_fdinfo_renders_pos_flags_ino() {
    // proc_pid_fdinfo(5): pos/flags/mnt_id/ino for an fd. libuv/Node read the
    // octal flags to recover an inherited fd's O_NONBLOCK/append/access mode.
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let DispatchOutcome::Returned { value: efd } = dispatcher
        .dispatch(
            SyscallRequest::new(19, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap()
    else {
        panic!("eventfd2 should succeed");
    };

    let path = format!("/proc/self/fdinfo/{efd}\0");
    memory.write_bytes(0x4000, path.as_bytes()).unwrap();
    let open = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: fd } = open else {
        panic!("open /proc/self/fdinfo/{efd}: {open:?}");
    };
    let read = dispatcher
        .dispatch(
            SyscallRequest::new(63, SyscallArgs::from([fd as u64, 0x4400, 0x400, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: nbytes } = read else {
        panic!("read fdinfo: {read:?}");
    };
    let content = String::from_utf8(memory.read_bytes(0x4400, nbytes as usize).unwrap()).unwrap();
    for label in ["pos:\t", "flags:\t0", "mnt_id:\t", "ino:\t"] {
        assert!(
            content.contains(label),
            "fdinfo missing {label:?}: {content:?}"
        );
    }

    // A closed/unopened fd's fdinfo is ENOENT.
    memory
        .write_bytes(0x4000, b"/proc/self/fdinfo/4242\0")
        .unwrap();
    let missing = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(missing, DispatchOutcome::Errno { errno: 2 });
}

#[test]
fn openat_reads_synthetic_proc_maps_and_cpuinfo() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    memory.write_bytes(0x4000, b"/proc/self/maps\0").unwrap();
    memory.write_bytes(0x4040, b"/proc/cpuinfo\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

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
    let maps_read = dispatcher
        .dispatch(
            SyscallRequest::new(63, SyscallArgs::from([3, 0x4100, 0x400, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: maps_len } = maps_read else {
        panic!("expected /proc/self/maps read success, got {maps_read:?}");
    };
    let maps = String::from_utf8(memory.read_bytes(0x4100, maps_len as usize).unwrap()).unwrap();
    assert!(maps.contains(" r-xp "));
    assert!(maps.contains("/proc/self/exe"));
    assert!(maps.contains("[heap]"));
    assert!(maps.ends_with('\n'));

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4040, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    let cpuinfo_read = dispatcher
        .dispatch(
            SyscallRequest::new(63, SyscallArgs::from([4, 0x4500, 0x200, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: cpuinfo_len } = cpuinfo_read else {
        panic!("expected /proc/cpuinfo read success, got {cpuinfo_read:?}");
    };
    let cpuinfo =
        String::from_utf8(memory.read_bytes(0x4500, cpuinfo_len as usize).unwrap()).unwrap();
    assert!(cpuinfo.contains("processor\t: 0"));
    assert!(cpuinfo.contains("CPU architecture: 8"));
    assert!(cpuinfo.contains("Features\t:"));

    let report = reporter.finish();
    assert!(report.unhandled_syscalls.is_empty());
    assert!(report.proc_read_unimplemented.is_empty());
}

#[test]
fn synthetic_proc_surface_serves_common_process_and_system_files() {
    let paths: [(&str, &[u8]); 20] = [
        ("/proc/cmdline", b"BOOT_IMAGE="),
        ("/proc/diskstats", b""),
        ("/proc/filesystems", b"overlay"),
        ("/proc/loadavg", b"0.00"),
        ("/proc/meminfo", b"MemTotal:"),
        ("/proc/mounts", b"overlay / overlay"),
        ("/proc/partitions", b"major minor"),
        ("/proc/stat", b"cpu  "),
        ("/proc/uptime", b" "),
        ("/proc/version", b"Linux version"),
        ("/proc/self/auxv", &[0u8; 16]),
        ("/proc/self/cmdline", b"/proc/self/exe"),
        ("/proc/self/comm", b"exe"),
        ("/proc/self/limits", b"Max open files"),
        ("/proc/self/mounts", b"overlay / overlay"),
        ("/proc/self/statm", b"0 0"),
        ("/proc/self/status", b"Name:\texe"),
        ("/proc/sys/kernel/osrelease", b"carrick"),
        // --net=host contract: /proc/sys/kernel/hostname is the live host short
        // name (guest_hostname(), in lockstep with uname nodename), NOT a fixed
        // string. Derive from the single source of truth so any host name passes;
        // it falls back to "carrick" when the host has no usable name.
        (
            "/proc/sys/kernel/hostname",
            carrick_runtime::execute::guest_hostname().as_bytes(),
        ),
        // boot_id is now a random v4 UUID (was an all-zero sentinel); the only
        // value-stable marker is the version-4 nibble at the 3rd group.
        ("/proc/sys/kernel/random/boot_id", b"-4"),
    ];

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let path_address = 0x4000_u64;
    let read_buffer = 0x4400_u64;
    let read_len_max = 0xC00_u64;
    for (next_fd, (path, expected_substr)) in (3_i64..).zip(paths) {
        let path_bytes: Vec<u8> = path.bytes().chain([0]).collect();
        memory.write_bytes(path_address, &path_bytes).unwrap();
        let open = dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, path_address, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap();
        assert_eq!(
            open,
            DispatchOutcome::Returned { value: next_fd },
            "expected fd {next_fd} for {path}, got {open:?}"
        );
        let read = dispatcher
            .dispatch(
                SyscallRequest::new(
                    63,
                    SyscallArgs::from([next_fd as u64, read_buffer, read_len_max, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap();
        let DispatchOutcome::Returned { value: read_len } = read else {
            panic!("expected read success for {path}, got {read:?}");
        };
        let bytes = memory.read_bytes(read_buffer, read_len as usize).unwrap();
        if expected_substr.is_empty() {
            assert_eq!(
                bytes.len(),
                0,
                "{path} expected empty file, got {} bytes",
                bytes.len()
            );
        } else {
            let found = bytes
                .windows(expected_substr.len())
                .any(|window| window == expected_substr);
            assert!(
                found,
                "{path} did not contain {expected_substr:?}: {bytes:?}"
            );
        }
    }

    let report = reporter.finish();
    assert!(report.proc_read_unimplemented.is_empty());
    assert!(report.unhandled_syscalls.is_empty());
}

#[test]
fn synthetic_proc_files_write_regular_packed_stat_records() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    memory.write_bytes(0x4000, b"/proc/cpuinfo\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

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
    assert_eq!(mode & 0o777, 0o444);
    assert!(size > 0);

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
    let fd_stat = read_stat(&memory, 0x4200);
    let fd_mode = fd_stat.st_mode;
    let fd_size = fd_stat.st_size;
    assert_eq!(fd_mode & LINUX_S_IFMT, LINUX_S_IFREG);
    assert_eq!(fd_mode & 0o777, 0o444);
    assert_eq!(fd_size, size);

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn proc_self_oom_score_adj_is_writable() {
    // systemd/runc write oom_score_adj at startup; carrick accepts-and-ignores
    // the write (no EACCES on open, no EBADF on write) so they don't warn.
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    memory
        .write_bytes(0x4000, b"/proc/self/oom_score_adj\0")
        .unwrap();
    memory.write_bytes(0x4200, b"-1000\n").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // openat(AT_FDCWD, path, O_WRONLY) — must NOT EACCES.
    let open = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 1, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: fd } = open else {
        panic!("oom_score_adj should open O_WRONLY, got {open:?}");
    };
    // write(fd, "-1000\n", 6) — accepted, returns the byte count.
    let write = dispatcher
        .dispatch(
            SyscallRequest::new(64, SyscallArgs::from([fd as u64, 0x4200, 6, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(write, DispatchOutcome::Returned { value: 6 });
}

#[test]
fn missing_proc_file_records_compat_report_entry() {
    // /proc/self/sched is unserved by carrick (and ENOENT in the Docker oracle
    // too), so it stands in as a still-unimplemented proc path for the
    // compat-report wiring.
    let mut memory = LinearMemory::new(0x4000, b"/proc/self/sched\0".to_vec());
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Errno { errno: 2 });
    let report = reporter.finish();
    assert!(report.unhandled_syscalls.is_empty());
    assert_eq!(report.proc_read_unimplemented[0].path, "/proc/self/sched");
    assert_eq!(report.proc_read_unimplemented[0].count, 1);
}

#[test]
fn synthetic_sys_surface_serves_common_cpu_and_mm_files() {
    let ncpu = carrick_runtime::host_facts::logical_cpu_count();
    let cpu_range = if ncpu <= 1 {
        b"0\n".to_vec()
    } else {
        format!("0-{}\n", ncpu - 1).into_bytes()
    };
    let kernel_max = format!("{}\n", ncpu.max(1) - 1).into_bytes();
    let paths: Vec<(&str, Vec<u8>)> = vec![
        ("/sys/devices/system/cpu/online", cpu_range.clone()),
        ("/sys/devices/system/cpu/possible", cpu_range.clone()),
        ("/sys/devices/system/cpu/present", cpu_range),
        ("/sys/devices/system/cpu/kernel_max", kernel_max),
        ("/sys/devices/system/cpu/cpu0/online", b"1\n".to_vec()),
        (
            "/sys/devices/system/cpu/cpu0/topology/physical_package_id",
            b"0\n".to_vec(),
        ),
        (
            "/sys/devices/system/cpu/cpu0/topology/core_id",
            b"0\n".to_vec(),
        ),
        (
            "/sys/devices/system/cpu/cpu0/topology/thread_siblings_list",
            b"0\n".to_vec(),
        ),
        (
            "/sys/devices/system/cpu/cpu0/topology/core_siblings_list",
            b"0\n".to_vec(),
        ),
        (
            "/sys/devices/system/cpu/cpufreq/policy0/scaling_cur_freq",
            b"2400000\n".to_vec(),
        ),
        (
            "/sys/devices/system/cpu/cpufreq/policy0/scaling_max_freq",
            b"2400000\n".to_vec(),
        ),
        (
            "/sys/devices/system/cpu/cpufreq/policy0/scaling_min_freq",
            b"600000\n".to_vec(),
        ),
        (
            "/sys/kernel/mm/transparent_hugepage/enabled",
            b"always [madvise] never\n".to_vec(),
        ),
        (
            "/sys/kernel/mm/transparent_hugepage/defrag",
            b"always defer defer+madvise [madvise] never\n".to_vec(),
        ),
        (
            "/sys/kernel/random/uuid",
            b"00000000-0000-4000-8000-000000000000\n".to_vec(),
        ),
        (
            "/sys/kernel/random/boot_id",
            b"00000000-0000-4000-8000-000000000000\n".to_vec(),
        ),
        ("/sys/fs/cgroup/cgroup.controllers", b"\n".to_vec()),
    ];

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let path_address = 0x4000_u64;
    let read_buffer = 0x4400_u64;
    let read_len_max = 0xC00_u64;
    for (next_fd, (path, expected)) in (3_i64..).zip(paths) {
        let path_bytes: Vec<u8> = path.bytes().chain([0]).collect();
        memory.write_bytes(path_address, &path_bytes).unwrap();
        let open = dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, path_address, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap();
        assert_eq!(
            open,
            DispatchOutcome::Returned { value: next_fd },
            "expected fd {next_fd} for {path}, got {open:?}"
        );
        let read = dispatcher
            .dispatch(
                SyscallRequest::new(
                    63,
                    SyscallArgs::from([next_fd as u64, read_buffer, read_len_max, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap();
        let DispatchOutcome::Returned { value: read_len } = read else {
            panic!("expected read success for {path}, got {read:?}");
        };
        let bytes = memory.read_bytes(read_buffer, read_len as usize).unwrap();
        assert_eq!(
            bytes.as_slice(),
            expected.as_slice(),
            "{path} content mismatch: got {bytes:?}"
        );
    }

    let report = reporter.finish();
    assert!(report.sys_read_unimplemented.is_empty());
    assert!(report.proc_read_unimplemented.is_empty());
    assert!(report.unhandled_syscalls.is_empty());
}

#[test]
fn missing_sys_file_records_compat_report_entry() {
    let mut memory = LinearMemory::new(
        0x4000,
        b"/sys/devices/virtual/dmi/id/product_uuid\0".to_vec(),
    );
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Errno { errno: 2 });
    let report = reporter.finish();
    assert!(report.unhandled_syscalls.is_empty());
    assert_eq!(
        report.sys_read_unimplemented[0].path,
        "/sys/devices/virtual/dmi/id/product_uuid"
    );
    assert_eq!(report.sys_read_unimplemented[0].count, 1);
}

#[test]
fn fchown_and_fchownat_succeed_on_writable_overlay_and_validate_args() {
    const AT_EMPTY_PATH: u64 = 0x1000;
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"fchown fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/missing\0").unwrap();
    memory.write_bytes(0x4040, b"\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(55, SyscallArgs::from([1, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // The rootfs is backed by a writable overlay (tmpfs-like; owner/mode are
        // not tracked) and the guest runs as root, so fchown is accepted as a
        // no-op success rather than the obsolete read-only-rootfs EROFS.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(55, SyscallArgs::from([99, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    54,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // fchownat on an existing path: no-op success on the writable overlay.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    54,
                    SyscallArgs::from([(-100_i64) as u64, 0x4020, 0, 0, 0, 0]),
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
                    54,
                    SyscallArgs::from([(-100_i64) as u64, 0x4040, 0, 0, 0, 0]),
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
                SyscallRequest::new(54, SyscallArgs::from([3, 0x4040, 0, 0, AT_EMPTY_PATH, 0]),),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // fchownat(AT_EMPTY_PATH) on an open fd: no-op success on the overlay.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    54,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0xdead, 0]),
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
fn fchmod_and_fchmodat_succeed_on_writable_overlay_and_validate_args() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"fchmod fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/missing\0").unwrap();
    memory.write_bytes(0x4040, b"\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(52, SyscallArgs::from([1, 0o644, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // Writable overlay + root guest: fchmod succeeds (no-op on the
        // tmpfs-like backend) instead of the obsolete read-only EROFS.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(52, SyscallArgs::from([99, 0o644, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    53,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0o644, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // fchmodat on an existing path applies to the writable overlay backend
        // and succeeds.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    53,
                    SyscallArgs::from([(-100_i64) as u64, 0x4020, 0o644, 0, 0, 0]),
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
                    53,
                    SyscallArgs::from([(-100_i64) as u64, 0x4040, 0o644, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    // The fchmodat syscall (nr 53) is SYSCALL_DEFINE3 in Linux and IGNORES
    // the 4th register, so a non-zero flags value must NOT fail. glibc leaves
    // AT_SYMLINK_NOFOLLOW (0x100) there — `apt-get update` issues exactly
    // fchmodat(AT_FDCWD, path, 0644, 0x100) on every downloaded index, and the
    // real kernel succeeds. (We previously returned EINVAL here, which made
    // every apt download chmod fail.)
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    53,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0o644, 0x100, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    // fchmodat2 (452) with a real flags argument also applies the mode.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    452,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0o600, 0x100, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn chmod_and_fchmod_under_bind_mount_update_host_mode() {
    use std::os::unix::fs::PermissionsExt;

    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-bindchmod")).unwrap();
    let host_file = scratch.path().join("nodejs-bindchmod/file.txt");
    std::fs::write(&host_file, b"chmod payload").unwrap();
    std::fs::set_permissions(&host_file, std::fs::Permissions::from_mode(0o644)).unwrap();

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-bindchmod/file.txt\0")
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
        run(
            &mut dispatcher,
            &mut memory,
            53,
            [LINUX_AT_FDCWD, 0x4000, 0o600, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        std::fs::metadata(&host_file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            79,
            [LINUX_AT_FDCWD, 0x4000, 0x4100, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4100);
    assert_eq!(stat.st_mode & 0o777, 0o600);

    let fd = match run(
        &mut dispatcher,
        &mut memory,
        56,
        [LINUX_AT_FDCWD, 0x4000, LINUX_O_RDWR, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("openat bind file: {other:?}"),
    };
    assert_eq!(
        run(&mut dispatcher, &mut memory, 52, [fd, 0o640, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        std::fs::metadata(&host_file).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 80, [fd, 0x4200, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4200);
    assert_eq!(stat.st_mode & 0o777, 0o640);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn utimensat_under_bind_mount_updates_host_times() {
    use std::os::unix::fs::MetadataExt;

    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-bindutime")).unwrap();
    let host_file = scratch.path().join("nodejs-bindutime/file.txt");
    std::fs::write(&host_file, b"utime payload").unwrap();

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x600]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-bindutime/file.txt\0")
        .unwrap();
    let times = 0x4100;
    write_linux_timespec(&mut memory, times, 123, 456);
    write_linux_timespec(&mut memory, times + 16, 789, 12);

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
        run(
            &mut dispatcher,
            &mut memory,
            88,
            [LINUX_AT_FDCWD, 0x4000, times, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let host_meta = std::fs::metadata(&host_file).unwrap();
    assert_eq!(host_meta.atime(), 123);
    assert_eq!(host_meta.mtime(), 789);

    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            79,
            [LINUX_AT_FDCWD, 0x4000, 0x4200, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4200);
    let st_atime = stat.st_atime;
    let st_mtime = stat.st_mtime;
    assert_eq!(st_atime, 123);
    assert_eq!(st_mtime, 789);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn non_root_chown_under_bind_mount_to_root_returns_eperm() {
    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-bindchown")).unwrap();
    std::fs::write(
        scratch.path().join("nodejs-bindchown/file.txt"),
        b"chown payload",
    )
    .unwrap();

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-bindchown/file.txt\0")
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
        run(&mut dispatcher, &mut memory, 146, [1000, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            54,
            [LINUX_AT_FDCWD, 0x4000, 0, 0, 0, 0],
        ),
        DispatchOutcome::Errno { errno: 1 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn root_chown_under_bind_mount_records_guest_owner_without_host_chown() {
    use std::os::unix::fs::MetadataExt;

    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-bindrootchown")).unwrap();
    let host_file = scratch.path().join("nodejs-bindrootchown/file.txt");
    std::fs::write(&host_file, b"root chown payload").unwrap();
    let host_before = std::fs::metadata(&host_file).unwrap();

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x300]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-bindrootchown/file.txt\0")
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
        run(
            &mut dispatcher,
            &mut memory,
            54,
            [LINUX_AT_FDCWD, 0x4000, 1000, 1001, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );

    let host_after = std::fs::metadata(&host_file).unwrap();
    assert_eq!(host_after.uid(), host_before.uid());
    assert_eq!(host_after.gid(), host_before.gid());

    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            79,
            [LINUX_AT_FDCWD, 0x4000, 0x4100, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4100);
    let stat_uid = stat.st_uid;
    let stat_gid = stat.st_gid;
    assert_eq!(stat_uid, 1000);
    assert_eq!(stat_gid, 1001);

    let fd = match run(
        &mut dispatcher,
        &mut memory,
        56,
        [LINUX_AT_FDCWD, 0x4000, LINUX_O_RDWR, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("openat bind file: {other:?}"),
    };
    assert_eq!(
        run(&mut dispatcher, &mut memory, 55, [fd, 1002, 1003, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 80, [fd, 0x4200, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4200);
    let stat_uid = stat.st_uid;
    let stat_gid = stat.st_gid;
    assert_eq!(stat_uid, 1002);
    assert_eq!(stat_gid, 1003);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn fchownat_at_empty_path_records_owner_like_fchown() {
    // M7: fchownat(fd, "", uid, gid, AT_EMPTY_PATH) must record the owner of the
    // fd's file (was: a no-op success that never called set_owner). Verified via
    // fstat through a bind mount, like the fchown test above.
    use std::os::unix::fs::MetadataExt;
    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(scratch.path().join("emptypathchown")).unwrap();
    let host_file = scratch.path().join("emptypathchown/file.txt");
    std::fs::write(&host_file, b"empty-path chown payload").unwrap();
    let host_before = std::fs::metadata(&host_file).unwrap();

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x500]);
    memory
        .write_bytes(0x4000, b"/tmp/emptypathchown/file.txt\0")
        .unwrap();
    memory.write_bytes(0x4300, b"\0").unwrap(); // the empty pathname
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

    // openat the bind file -> fd.
    let fd = match run(
        &mut dispatcher,
        &mut memory,
        56,
        [LINUX_AT_FDCWD, 0x4000, LINUX_O_RDWR, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("openat: {other:?}"),
    };

    // fchownat(fd, ""@0x4300, 1500, 1501, AT_EMPTY_PATH).
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            54,
            [fd, 0x4300, 1500, 1501, LINUX_AT_EMPTY_PATH, 0]
        ),
        DispatchOutcome::Returned { value: 0 }
    );

    // The host file's real owner is untouched (carrick records a guest-visible
    // owner via xattr, not a host chown).
    let host_after = std::fs::metadata(&host_file).unwrap();
    assert_eq!(host_after.uid(), host_before.uid());

    // fstat(fd) reports the guest-visible owner we just set.
    assert_eq!(
        run(&mut dispatcher, &mut memory, 80, [fd, 0x4200, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4200);
    let (uid, gid) = (stat.st_uid, stat.st_gid);
    assert_eq!(
        uid, 1500,
        "fchownat(AT_EMPTY_PATH) must record the owner uid"
    );
    assert_eq!(
        gid, 1501,
        "fchownat(AT_EMPTY_PATH) must record the owner gid"
    );
}

#[test]
fn utimensat_sets_times_on_writable_overlay_and_validates_timestamps() {
    const UTIME_NOW: i64 = (1 << 30) - 1;
    const UTIME_OMIT: i64 = (1 << 30) - 2;

    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"utimensat fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/missing\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    let now_pair = 0x4100;
    write_linux_timespec(&mut memory, now_pair, 0, UTIME_NOW);
    write_linux_timespec(&mut memory, now_pair + 16, 0, UTIME_NOW);
    let omit_pair = 0x4140;
    write_linux_timespec(&mut memory, omit_pair, 0, UTIME_OMIT);
    write_linux_timespec(&mut memory, omit_pair + 16, 0, 1_000_000_001);
    let valid_pair = 0x4180;
    write_linux_timespec(&mut memory, valid_pair, 123, 456);
    write_linux_timespec(&mut memory, valid_pair + 16, 789, 12);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    88,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, valid_pair, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // Setting explicit atime/mtime on an existing file persists to the
        // writable overlay backend (no-op on the in-memory backend) and
        // succeeds, instead of the obsolete read-only EROFS.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    88,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, now_pair, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // UTIME_NOW on an existing file: success on the writable overlay.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    88,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // NULL times (set both to now) on an existing file: success.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    88,
                    SyscallArgs::from([(-100_i64) as u64, 0x4020, 0, 0, 0, 0]),
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
                    88,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, valid_pair, 0xdead, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    88,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, omit_pair, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(88, SyscallArgs::from([(-100_i64) as u64, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 14 }
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
                SyscallRequest::new(88, SyscallArgs::from([3, 0, valid_pair, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // futimens form (pathname == NULL with a valid open fd): success on the
        // writable overlay rather than the obsolete read-only EROFS.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(88, SyscallArgs::from([99, 0, valid_pair, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn truncate_bootstrap_returns_erofs_for_known_paths_and_enoent_for_missing() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([
        ("etc/motd", b"truncate fixture\n".as_slice()),
        ("etc/dir/.gitkeep", b"".as_slice()),
    ]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/dir\0").unwrap();
    memory.write_bytes(0x4040, b"/etc/missing\0").unwrap();
    memory.write_bytes(0x4060, b"\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(45, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 30 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(45, SyscallArgs::from([0x4020, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 21 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(45, SyscallArgs::from([0x4040, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(45, SyscallArgs::from([0x4060, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(45, SyscallArgs::from([0x4000, (-1_i64) as u64, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn xattr_family_dispatches_per_target_on_in_memory_backend() {
    // The xattr family is fully wired (no longer a blanket ENOTSUP stub):
    // path/fd targets are resolved BEFORE the attribute store is consulted.
    // Linux resolves the path first for every *xattr syscall, so a path that
    // does not exist is ENOENT — for set/get/list AND remove alike (Docker
    // linux/arm64 debian:stable: set/get/list/removexattr on a missing path
    // all return errno 2). The fd-variants validate the fd first and report
    // EBADF for an unopened descriptor. The real `user.*` round-trip on an
    // existing file is exercised against the host backend by the conformance
    // suite; here we pin the in-memory dispatch ordering.
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"user.test\0").unwrap();
    memory.write_bytes(0x4040, b"data").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // Path-variants set/get/list (5,6 set; 8,9 get; 11,12 list) and the
    // remove*xattr path variants (14,15) all resolve the path first; /etc/motd
    // is absent on the bare in-memory backend, so each is ENOENT. Args:
    // (path, name, value, size).
    for number in [5, 6, 8, 9, 11, 12, 14, 15] {
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(
                        number,
                        SyscallArgs::from([0x4000, 0x4020, 0x4040, 4, 0, 0]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Errno { errno: 2 },
            "path-variant xattr syscall {number} on a missing path should be ENOENT"
        );
    }

    // Fd-variants (7 fsetxattr, 10 fgetxattr, 13 flistxattr) validate the fd
    // before anything else: an unopened fd is EBADF.
    // 16 fremovexattr is also an fd variant: the unopened fd 0x4000 is
    // validated before path resolution, so EBADF wins.
    for number in [7, 10, 13, 16] {
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(
                        number,
                        SyscallArgs::from([0x4000, 0x4020, 0x4040, 4, 0, 0]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Errno { errno: 9 },
            "fd-variant syscall {number} should return EBADF for an unopened fd"
        );
    }

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn fallocate_grows_open_files_on_writable_overlay_and_validates_arguments() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"fallocate fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(47, SyscallArgs::from([1, 0, 0, 4096, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 29 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(47, SyscallArgs::from([999, 0, 0, 4096, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(47, SyscallArgs::from([1, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(47, SyscallArgs::from([1, 0xdead, 0, 4096, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(47, SyscallArgs::from([1, 0, (-1_i64) as u64, 4096, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, LINUX_O_RDWR, 0, 0, 0]),
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
                SyscallRequest::new(47, SyscallArgs::from([3, 0, 0, 4096, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // fallocate on an open regular file grows it in the writable overlay
        // (in-memory backend resizes the cached bytes) and succeeds, instead of
        // the obsolete read-only EROFS.
        DispatchOutcome::Returned { value: 0 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn ftruncate_bootstrap_rejects_streams_and_read_only_rootfs_fds() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"ftruncate fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(46, SyscallArgs::from([1, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(46, SyscallArgs::from([2, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(46, SyscallArgs::from([99, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(46, SyscallArgs::from([1, (-1_i64) as u64, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
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
                SyscallRequest::new(46, SyscallArgs::from([3, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn ftruncate_rejects_unbounded_in_memory_file_growth() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"/big\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4000,
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

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    46,
                    SyscallArgs::from([3, MAX_IN_MEMORY_FILE_SIZE + 1, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: LINUX_EFBIG }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

/// A guest must be able to OVERRIDE the synthetic, single-file `/etc/services`
/// injection: kaniko's image-unpack `unlink(/etc/services)`s to lay down the
/// base image's copy, and many workloads rewrite `/etc/resolv.conf`. The
/// injected mount is read-only, so before the fix an unlink/write returned
/// EROFS/EACCES. After the fix a guest mutation DETACHES the injection so the
/// path falls through to the writable overlay — the guest's version wins, and a
/// delete-without-recreate makes the path ENOENT. An untouched injection still
/// serves as the fallback default.
#[test]
fn guest_can_override_synthetic_etc_services_via_unlink_then_recreate() {
    const LINUX_O_RDONLY: u64 = 0;
    // A rootfs whose /etc is a real directory (so the overlay can create the new
    // /etc/services after the injection is detached) — exactly the kaniko
    // `--fs host` scratch shape, where /etc already exists.
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs motd\n".as_slice(),
    )]))])
    .unwrap();
    // The macOS host's /etc/services is many KB and opens with a comment banner,
    // so the read buffer (at 0x8000) must be large enough to capture an smtp
    // entry. Path is at 0x4000, the new-contents scratch at 0x4100.
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x20000]);
    memory.write_bytes(0x4000, b"/etc/services\0").unwrap();
    memory
        .write_bytes(0x4100, b"carrick-test 9999/tcp\n")
        .unwrap();
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

    // Control: WITHOUT any mutation, /etc/services reads the synthetic
    // injection (the common case still works). The macOS host's services file
    // (or carrick's built-in fallback) always lists smtp.
    let fd = match run(
        &mut dispatcher,
        &mut memory,
        56,
        [LINUX_AT_FDCWD, 0x4000, LINUX_O_RDONLY, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("control openat read: {other:?}"),
    };
    let n = match run(
        &mut dispatcher,
        &mut memory,
        63,
        [fd, 0x8000, 0x10000, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as usize,
        other => panic!("control read: {other:?}"),
    };
    let injected = memory.read_bytes(0x8000, n).unwrap();
    assert!(
        String::from_utf8_lossy(&injected).contains("smtp"),
        "control: synthetic /etc/services must list smtp, got {n} bytes"
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 57, [fd, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );

    // unlinkat("/etc/services"): before the fix this routed to the read-only
    // EtcServicesVfs and returned EROFS (30). After the fix the injection is
    // detached and the unlink succeeds (0).
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            35,
            [LINUX_AT_FDCWD, 0x4000, 0, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 },
        "unlinkat(/etc/services) of an overridable injection must succeed"
    );

    // After unlink without recreate, the path is gone: openat read → ENOENT (2),
    // not the synthetic injection.
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            56,
            [LINUX_AT_FDCWD, 0x4000, LINUX_O_RDONLY, 0, 0, 0],
        ),
        DispatchOutcome::Errno { errno: 2 },
        "after unlink the detached injection must be ENOENT, not the synthetic file"
    );
    // newfstatat agrees: ENOENT.
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            79,
            [LINUX_AT_FDCWD, 0x4000, 0x4300, 0, 0, 0],
        ),
        DispatchOutcome::Errno { errno: 2 },
        "stat after unlink must be ENOENT"
    );

    // Recreate /etc/services with NEW contents via O_CREAT|O_WRONLY, write,
    // close — this lands in the writable overlay, not the synthetic mount.
    let fd = match run(
        &mut dispatcher,
        &mut memory,
        56,
        [
            LINUX_AT_FDCWD,
            0x4000,
            LINUX_O_CREAT | LINUX_O_WRONLY,
            0o644,
            0,
            0,
        ],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("recreate openat O_CREAT|O_WRONLY: {other:?}"),
    };
    assert_eq!(
        run(&mut dispatcher, &mut memory, 64, [fd, 0x4100, 22, 0, 0, 0]),
        DispatchOutcome::Returned { value: 22 },
        "write of new /etc/services contents must succeed"
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 57, [fd, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );

    // Re-open for read: the overlay's NEW contents win, NOT the synthetic file.
    let fd = match run(
        &mut dispatcher,
        &mut memory,
        56,
        [LINUX_AT_FDCWD, 0x4000, LINUX_O_RDONLY, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("reopen read after recreate: {other:?}"),
    };
    let n = match run(
        &mut dispatcher,
        &mut memory,
        63,
        [fd, 0x8000, 0x10000, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as usize,
        other => panic!("read after recreate: {other:?}"),
    };
    assert_eq!(
        memory.read_bytes(0x8000, n).unwrap(),
        b"carrick-test 9999/tcp\n",
        "after override+recreate the overlay contents must win over the injection"
    );
}
