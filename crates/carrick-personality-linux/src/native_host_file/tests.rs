use super::*;
use carrick_core_abi::host_file::HostFileRequestView;

/// User memory at a fixed base; anything outside it faults.
struct Memory {
    base: u64,
    bytes: Vec<u8>,
    writable: bool,
    /// Resident but not yet writable: a page whose copy-on-write share is
    /// unbroken, or a read-only mapping. Writing it needs a supply.
    read_only: core::ops::Range<u64>,
}
impl HostFileUser for Memory {
    fn copy_in(&mut self, dst: &mut [u8], src: u64) -> bool {
        let Some(start) = src.checked_sub(self.base) else {
            return false;
        };
        let start = start as usize;
        match self.bytes.get(start..start + dst.len()) {
            Some(bytes) => {
                dst.copy_from_slice(bytes);
                true
            }
            None => false,
        }
    }
    fn writable(&mut self, dst: u64, len: usize) -> usize {
        if !self.writable {
            return 0;
        }
        let end = self.base + self.bytes.len() as u64;
        let len = (end.saturating_sub(dst) as usize).min(len);
        if dst < self.read_only.end && dst + len as u64 > self.read_only.start {
            return self.read_only.start.saturating_sub(dst) as usize;
        }
        len
    }
}

const BASE: u64 = 0x10000;
const TABLE: [u64; 3] = [9, 1, 2];

/// Resident memory is whole pages, like real user mappings: a path copy may
/// read up to its terminator's page end.
fn memory(bytes: &[u8]) -> Memory {
    let mut bytes = bytes.to_vec();
    bytes.resize(bytes.len().div_ceil(4096).max(1) * 4096, 0);
    Memory {
        base: BASE,
        bytes,
        writable: true,
        read_only: 0..0,
    }
}

/// Descriptors: 0 pipe, 1 host stdout, 3 host file (read-only), 4 eventfd.
fn caller(fd: i32) -> Option<NativeDescriptor> {
    Some(match fd {
        0 => NativeDescriptor::InZone(InZoneKind::Pipe(
            carrick_syscall_abi::LinuxPipeIdentity::new(1, 1),
        )),
        1 => NativeDescriptor::HostBacked {
            access: DescriptionAccess::ReadWrite,
        },
        3 => NativeDescriptor::HostBacked {
            access: DescriptionAccess::ReadOnly,
        },
        4 => NativeDescriptor::InZone(InZoneKind::EventFd),
        _ => NativeDescriptor::Absent,
    })
}

fn run(call: HostFileCall, user: &mut Memory) -> Option<HostFileStage> {
    run_releasing(call, user, &[], &mut 0)
}

/// Stage with `retired` sources pending in the caller's reservation owner;
/// `popped` counts how many staging took.
fn run_releasing(
    call: HostFileCall,
    user: &mut Memory,
    retired: &[host_file::MapSourceReply],
    popped: &mut usize,
) -> Option<HostFileStage> {
    let mut resolve = caller;
    let mut releases = |out: &mut [host_file::MapSourceReply]| {
        let taken = retired.len().min(out.len());
        out[..taken].copy_from_slice(&retired[..taken]);
        *popped += taken;
        taken
    };
    let mut namespace = NativeNamespace {
        table: TABLE,
        resolve: &mut resolve,
        releases: &mut releases,
    };
    stage(call, &mut namespace, user)
}

fn returned(errno: LinuxErrno) -> Option<HostFileStage> {
    Some(HostFileStage::Returned(SyscallResult::from_errno(errno)))
}

fn request(stage: Option<HostFileStage>) -> (Box<[u8]>, Option<HostFileOutput>, bool) {
    match stage {
        Some(HostFileStage::Request {
            record,
            output,
            resolves_path,
            ..
        }) => (record, output, resolves_path),
        other => panic!("expected a host request, got {other:?}"),
    }
}

#[test]
fn mutation_decode_and_staging_keep_the_canonical_arguments_and_wire_shape() {
    let mut user = memory(b"source\0target\0");
    for (number, args, op, input, path) in [
        (
            34,
            [LINUX_AT_FDCWD as u64, BASE, 0o755, 0, 0, 0],
            HostFileOp::Mkdirat,
            b"source".as_slice(),
            true,
        ),
        (
            35,
            [LINUX_AT_FDCWD as u64, BASE, 0x200, 0, 0, 0],
            HostFileOp::Unlinkat,
            b"source".as_slice(),
            true,
        ),
        (
            36,
            [BASE, LINUX_AT_FDCWD as u64, BASE + 7, 0, 0, 0],
            HostFileOp::Symlinkat,
            b"source\0target".as_slice(),
            true,
        ),
        (
            37,
            [
                LINUX_AT_FDCWD as u64,
                BASE,
                LINUX_AT_FDCWD as u64,
                BASE + 7,
                0x400,
                0,
            ],
            HostFileOp::Linkat,
            b"source\0target".as_slice(),
            true,
        ),
        (
            38,
            [
                LINUX_AT_FDCWD as u64,
                BASE,
                LINUX_AT_FDCWD as u64,
                BASE + 7,
                0xff,
                0,
            ],
            HostFileOp::Renameat,
            b"source\0target".as_slice(),
            true,
        ),
        (
            276,
            [
                LINUX_AT_FDCWD as u64,
                BASE,
                LINUX_AT_FDCWD as u64,
                BASE + 7,
                1,
                0,
            ],
            HostFileOp::Renameat,
            b"source\0target".as_slice(),
            true,
        ),
        (
            88,
            [LINUX_AT_FDCWD as u64, BASE, 0, 0, 0, 0],
            HostFileOp::Utimensat,
            b"source".as_slice(),
            true,
        ),
        (
            88,
            [1, 0, 0, 0, 0, 0],
            HostFileOp::SetFdTimes,
            b"".as_slice(),
            false,
        ),
        (
            45,
            [BASE, 123, 0, 0, 0, 0],
            HostFileOp::Truncate,
            b"source".as_slice(),
            true,
        ),
        (
            46,
            [1, 123, 0, 0, 0, 0],
            HostFileOp::Ftruncate,
            b"".as_slice(),
            false,
        ),
    ] {
        let call = HostFileCall::decode(CanonicalNr::new(number), &args).unwrap();
        assert!(call.uses_child_mutation_venue());
        let (mut bytes, output, resolves_path) = request(run(call, &mut user));
        assert_eq!(output, None);
        assert_eq!(resolves_path, path);
        let view = HostFileRequestView::parse(&mut bytes).unwrap();
        assert_eq!(view.header().table, TABLE);
        assert_eq!(view.header().op, op);
        assert_eq!(view.input(), input);
        assert_eq!(view.output_capacity(), 0);
        if matches!(op, HostFileOp::Truncate | HostFileOp::Ftruncate) {
            assert_eq!(view.header().args, [123, 0, 0, 0]);
        }
    }
    assert!(
        !HostFileCall::Write {
            fd: 1,
            buf: BASE,
            count: 1
        }
        .uses_child_mutation_venue()
    );
}

#[test]
fn mutation_argument_errors_precede_copy_and_keep_source_dirfd_priority() {
    let mut user = memory(b"\0target\0");
    for call in [
        HostFileCall::Unlinkat {
            dirfd: LINUX_AT_FDCWD,
            path: u64::MAX,
            flags: 1,
        },
        HostFileCall::Linkat {
            olddirfd: LINUX_AT_FDCWD,
            oldpath: u64::MAX,
            newdirfd: LINUX_AT_FDCWD,
            newpath: u64::MAX,
            flags: 1,
        },
        HostFileCall::Renameat {
            olddirfd: LINUX_AT_FDCWD,
            oldpath: u64::MAX,
            newdirfd: LINUX_AT_FDCWD,
            newpath: u64::MAX,
            flags: 3,
        },
        HostFileCall::Utimensat {
            dirfd: LINUX_AT_FDCWD,
            path: u64::MAX,
            times: u64::MAX,
            flags: 1,
        },
        HostFileCall::Truncate {
            path: u64::MAX,
            length: u64::MAX,
        },
        HostFileCall::Ftruncate {
            fd: 999,
            length: u64::MAX,
        },
    ] {
        assert_eq!(
            run(call, &mut user),
            returned(carrick_syscall_abi::LINUX_EINVAL)
        );
    }
    let link = |olddirfd, oldpath| HostFileCall::Linkat {
        olddirfd,
        oldpath,
        newdirfd: 999,
        newpath: BASE + 1,
        flags: 0,
    };
    assert_eq!(
        run(link(LINUX_AT_FDCWD, BASE), &mut user),
        returned(carrick_syscall_abi::LINUX_ENOENT)
    );
    assert_eq!(
        run(link(0, BASE + 1), &mut user),
        returned(carrick_syscall_abi::LINUX_ENOTDIR)
    );
    assert_eq!(
        run(
            HostFileCall::Utimensat {
                dirfd: LINUX_AT_FDCWD,
                path: BASE + 1,
                times: BASE + 4096,
                flags: 0,
            },
            &mut user
        ),
        Some(HostFileStage::Fault {
            address: BASE + 4096,
            access: Access::Read
        })
    );
}

#[test]
fn mutation_pair_staging_has_a_fixed_two_path_copy_and_record_budget() {
    struct Counted {
        memory: Memory,
        calls: usize,
        copied: usize,
    }
    impl HostFileUser for Counted {
        fn copy_in(&mut self, dst: &mut [u8], src: u64) -> bool {
            self.calls += 1;
            self.copied += dst.len();
            self.memory.copy_in(dst, src)
        }
        fn writable(&mut self, dst: u64, len: usize) -> usize {
            self.memory.writable(dst, len)
        }
    }
    for length in [1, LINUX_PATH_MAX - 1] {
        for offset in [0, 1, 4095] {
            let target = 3 * LINUX_PATH_MAX + offset;
            let mut bytes = vec![0; 6 * LINUX_PATH_MAX];
            bytes[offset..offset + length].fill(b'x');
            bytes[target..target + length].fill(b'y');
            let mut user = Counted {
                memory: memory(&bytes),
                calls: 0,
                copied: 0,
            };
            let mut resolve = caller;
            let mut namespace = NativeNamespace {
                table: TABLE,
                resolve: &mut resolve,
                releases: &mut |_| 0,
            };
            let (mut record, output, _) = request(stage(
                HostFileCall::Symlinkat {
                    target: BASE + offset as u64,
                    dirfd: LINUX_AT_FDCWD,
                    path: BASE + target as u64,
                },
                &mut namespace,
                &mut user,
            ));
            assert!(user.calls <= 4, "two page-bounded copies per path");
            assert!(user.copied <= 2 * LINUX_PATH_MAX);
            if offset == 0 {
                assert_eq!(user.calls, 2);
                assert_eq!(user.copied, 2 * LINUX_PATH_MAX);
            }
            assert_eq!(
                HostFileRequestView::parse(&mut record)
                    .unwrap()
                    .input()
                    .len(),
                2 * length + 1
            );
            assert_eq!(output, None);
        }
    }
    let mut user = memory(&[b'x'; LINUX_PATH_MAX]);
    assert_eq!(
        run(
            HostFileCall::Mkdirat {
                dirfd: LINUX_AT_FDCWD,
                path: BASE,
                mode: 0o755
            },
            &mut user
        ),
        returned(carrick_syscall_abi::LINUX_ENAMETOOLONG)
    );
}

#[test]
fn in_zone_objects_never_build_a_host_request() {
    let mut user = memory(b"hello\0");
    for call in [
        HostFileCall::Write {
            fd: 0,
            buf: BASE,
            count: 5,
        },
        HostFileCall::Writev {
            fd: 0,
            iov: BASE,
            iovcnt: 1,
        },
        HostFileCall::Read {
            fd: 4,
            buf: BASE,
            count: 8,
        },
    ] {
        assert_eq!(
            run(call, &mut user),
            Some(HostFileStage::InRing),
            "{call:?} on an in-zone object must stay in ring"
        );
    }
    // Linux answers these for a pipe without any host involvement.
    assert_eq!(
        run(
            HostFileCall::Lseek {
                fd: 0,
                offset: 0,
                whence: 1
            },
            &mut user
        ),
        returned(carrick_syscall_abi::LINUX_ESPIPE)
    );
    assert_eq!(
        run(
            HostFileCall::Pread {
                fd: 0,
                buf: BASE,
                count: 1,
                offset: 0
            },
            &mut user
        ),
        returned(carrick_syscall_abi::LINUX_ESPIPE)
    );
    assert_eq!(
        run(
            HostFileCall::Ioctl {
                fd: 0,
                request: carrick_syscall_abi::LINUX_TCGETS,
                arg: BASE,
            },
            &mut user
        ),
        returned(carrick_syscall_abi::LINUX_ENOTTY)
    );
    assert_eq!(
        run(
            HostFileCall::Getdents64 {
                fd: 0,
                dirp: BASE,
                count: 64
            },
            &mut user
        ),
        returned(carrick_syscall_abi::LINUX_ENOTDIR)
    );
}

/// A request outside the host ioctl allowlist on a host-backed stdio
/// descriptor is left UNROUTED (a counted ENOSYS), never a served ENOTTY:
/// TIOCGPGRP, TCSBRK and FIOASYNC are job-control requests a terminal
/// answers, and ENOTTY would both be wrong and hide the gap from the
/// ring-first counters.
#[test]
fn a_non_allowlisted_ioctl_on_host_stdio_stays_unrouted() {
    let mut user = memory(b"");
    for request in [
        0x540F_u64, /* TIOCGPGRP */
        0x5409,     /* TCSBRK */
        0x5452,     /* FIOASYNC */
    ] {
        assert_eq!(
            run(
                HostFileCall::Ioctl {
                    fd: 1,
                    request,
                    arg: BASE,
                },
                &mut user
            ),
            None,
            "ioctl {request:#x} on host stdout must not be served"
        );
    }
}

/// Linux answers `fstat` on a pipe, an eventfd or an epoll instance from the
/// object itself: the ring returns the record the dispatcher reports for
/// that kind (one shared `LinuxStatFields`), never a host request.
#[test]
fn in_zone_fstat_is_answered_in_ring_with_the_shared_record() {
    let mut user = memory(b"");
    let stat = |fields: &carrick_syscall_abi::LinuxStatFields| -> Box<[u8]> {
        zerocopy::IntoBytes::as_bytes(&carrick_syscall_abi::LinuxStat::from_fields(fields)).into()
    };
    let output = HostFileOutput::bytes(BASE, LINUX_STAT_BYTES);
    let pipe = run(
        HostFileCall::Fstat {
            fd: 0,
            statbuf: BASE,
            layout: StatLayout::Generic,
        },
        &mut user,
    );
    assert_eq!(
        pipe,
        Some(HostFileStage::InRingReply {
            output,
            bytes: stat(&carrick_syscall_abi::LinuxPipeIdentity::new(1, 1).stat_fields()),
        })
    );
    let Some(HostFileStage::InRingReply { bytes, .. }) = pipe else {
        unreachable!()
    };
    let mode = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    assert_eq!(
        mode & 0o170000,
        carrick_syscall_abi::LINUX_S_IFIFO,
        "S_IFIFO"
    );
    assert_eq!(
        run(
            HostFileCall::Fstat {
                fd: 4,
                statbuf: BASE,
                layout: StatLayout::Generic
            },
            &mut user
        ),
        Some(HostFileStage::InRingReply {
            output,
            bytes: stat(&carrick_syscall_abi::LinuxStatFields::CARRICK_EVENTFD),
        })
    );
    // statx(fd, "", AT_EMPTY_PATH) on a pipe: the statx encoding of the
    // same record.
    let mut empty = memory(b"\0");
    assert_eq!(
        run(
            HostFileCall::Statx {
                dirfd: 0,
                path: BASE,
                flags: u64::from(LINUX_AT_EMPTY_PATH),
                mask: 0x7ff,
                buf: BASE + 0x100,
            },
            &mut empty
        ),
        Some(HostFileStage::InRingReply {
            output: HostFileOutput::bytes(BASE + 0x100, LINUX_STATX_BYTES),
            bytes: zerocopy::IntoBytes::as_bytes(&carrick_syscall_abi::LinuxStatx::from_fields(
                &carrick_syscall_abi::LinuxPipeIdentity::new(1, 1).stat_fields()
            ))
            .into(),
        })
    );
    // An unwritable buffer still asks for write supply first.
    user.writable = false;
    assert_eq!(
        run(
            HostFileCall::Fstat {
                fd: 0,
                statbuf: BASE,
                layout: StatLayout::Generic
            },
            &mut user
        ),
        Some(HostFileStage::Fault {
            address: BASE,
            access: Access::Write
        })
    );
}

#[test]
fn host_backed_write_stages_the_callers_bytes_and_table() {
    let mut user = memory(b"hello");
    let (mut record, output, resolves_path) = request(run(
        HostFileCall::Write {
            fd: 1,
            buf: BASE,
            count: 5,
        },
        &mut user,
    ));
    assert_eq!(output, None);
    assert!(!resolves_path, "a descriptor write needs no path authority");
    let view = HostFileRequestView::parse(&mut record).unwrap();
    assert_eq!(view.header().op, HostFileOp::Write);
    assert_eq!(view.header().table, TABLE);
    assert_eq!(view.header().fd, 1);
    assert_eq!(view.input(), b"hello");
}

#[test]
fn writev_gathers_vectors_and_bad_descriptors_stay_in_ring() {
    // Two iovecs at BASE pointing at "ab" and "cde".
    let mut bytes = vec![0u8; 0x30];
    bytes[0..8].copy_from_slice(&(BASE + 0x20).to_le_bytes());
    bytes[8..16].copy_from_slice(&2u64.to_le_bytes());
    bytes[16..24].copy_from_slice(&(BASE + 0x22).to_le_bytes());
    bytes[24..32].copy_from_slice(&3u64.to_le_bytes());
    bytes[0x20..0x25].copy_from_slice(b"abcde");
    let mut user = memory(&bytes);
    let call = |fd| HostFileCall::Writev {
        fd,
        iov: BASE,
        iovcnt: 2,
    };
    let (mut record, ..) = request(run(call(1), &mut user));
    assert_eq!(
        HostFileRequestView::parse(&mut record).unwrap().input(),
        b"abcde"
    );
    assert_eq!(
        run(call(9), &mut user),
        returned(carrick_syscall_abi::LINUX_EBADF)
    );
    assert_eq!(
        run(call(3), &mut user),
        returned(carrick_syscall_abi::LINUX_EBADF),
        "a read-only description refuses writes"
    );
    assert_eq!(
        run(
            HostFileCall::Writev {
                fd: 1,
                iov: BASE,
                iovcnt: LINUX_UIO_MAXIOV + 1
            },
            &mut user
        ),
        returned(carrick_syscall_abi::LINUX_EINVAL)
    );
}

#[test]
fn path_calls_stage_the_path_and_need_path_authority() {
    let mut user = memory(b"/etc/ld.so.cache\0");
    let (mut record, output, resolves_path) = request(run(
        HostFileCall::Openat {
            dirfd: LINUX_AT_FDCWD,
            path: BASE,
            flags: 0o2_000_000,
            mode: 0,
        },
        &mut user,
    ));
    assert!(resolves_path, "openat resolves with the caller's authority");
    assert_eq!(output, None);
    let view = HostFileRequestView::parse(&mut record).unwrap();
    assert_eq!(view.header().op, HostFileOp::Openat);
    assert_eq!(
        view.header().table,
        TABLE,
        "the new fd lands in the caller's table"
    );
    assert_eq!(view.header().args[0], 0o2_000_000);
    assert_eq!(view.input(), b"/etc/ld.so.cache");

    // An in-zone or absent dirfd is answered in ring. A host-backed
    // descriptor is carried with the request for the carrier to pin.
    let mut relative = memory(b"libc.so.6\0");
    let openat = |dirfd| HostFileCall::Openat {
        dirfd,
        path: BASE,
        flags: 0,
        mode: 0,
    };
    assert_eq!(
        run(openat(0), &mut relative),
        returned(carrick_syscall_abi::LINUX_ENOTDIR)
    );
    assert_eq!(
        run(openat(9), &mut relative),
        returned(carrick_syscall_abi::LINUX_EBADF)
    );
    let (mut relative_record, _, _) = request(run(openat(3), &mut relative));
    let relative_view = HostFileRequestView::parse(&mut relative_record).unwrap();
    assert_eq!(relative_view.header().fd, 3);
    assert_eq!(relative_view.input(), b"libc.so.6");
    let mut empty = memory(b"\0");
    assert_eq!(
        run(openat(LINUX_AT_FDCWD), &mut empty),
        returned(carrick_syscall_abi::LINUX_ENOENT)
    );
}

#[test]
fn empty_path_stat_names_the_descriptor() {
    let mut user = memory(b"\0");
    let (mut record, output, resolves_path) = request(run(
        HostFileCall::Newfstatat {
            dirfd: 3,
            path: BASE,
            statbuf: BASE + 0x100,
            flags: u64::from(LINUX_AT_EMPTY_PATH),
            layout: StatLayout::Generic,
        },
        &mut user,
    ));
    assert!(!resolves_path);
    assert_eq!(
        output,
        Some(HostFileOutput::bytes(BASE + 0x100, LINUX_STAT_BYTES))
    );
    let view = HostFileRequestView::parse(&mut record).unwrap();
    assert_eq!(view.header().op, HostFileOp::Fstat);
    assert_eq!(view.header().fd, 3);
    // Without AT_EMPTY_PATH an empty path is ENOENT, never a descriptor stat.
    assert_eq!(
        run(
            HostFileCall::Newfstatat {
                dirfd: 3,
                path: BASE,
                statbuf: BASE,
                flags: 0,
                layout: StatLayout::Generic
            },
            &mut user
        ),
        returned(carrick_syscall_abi::LINUX_ENOENT)
    );
}

#[test]
fn unreadable_input_requests_fault_supply_first_and_long_paths_fail() {
    let mut user = memory(b"");
    assert_eq!(
        run(
            HostFileCall::Write {
                fd: 1,
                buf: 0x9000,
                count: 1
            },
            &mut user
        ),
        Some(HostFileStage::Fault {
            address: 0x9000,
            access: Access::Read
        })
    );
    let mut long = memory(&vec![b'a'; LINUX_PATH_MAX + 8]);
    assert_eq!(
        run(
            HostFileCall::Faccessat {
                dirfd: LINUX_AT_FDCWD,
                path: BASE,
                mode: 0,
                flags: 0
            },
            &mut long
        ),
        returned(carrick_syscall_abi::LINUX_ENAMETOOLONG)
    );
}

#[test]
fn completion_copies_output_only_on_success() {
    let mut user = memory(&[0u8; 4]);
    let (mut record, output, _) = request(run(
        HostFileCall::Read {
            fd: 3,
            buf: BASE,
            count: 4,
        },
        &mut user,
    ));
    HostFileRequestView::parse(&mut record)
        .unwrap()
        .reply(3, b"abc")
        .unwrap();
    let mut copied = Vec::new();
    let result = complete(&record, output, &mut |address, bytes| {
        copied.push((address, bytes.to_vec()));
        true
    });
    assert_eq!(result, SyscallResult::new(3));
    assert_eq!(copied, vec![(BASE, b"abc".to_vec())]);
    // No reply (refused or cancelled service) never copies anything.
    let (record, output, _) = request(run(
        HostFileCall::Read {
            fd: 3,
            buf: BASE,
            count: 4,
        },
        &mut user,
    ));
    assert_eq!(
        complete(&record, output, &mut |_, _| panic!("no output")),
        SyscallResult::from_errno(carrick_syscall_abi::LINUX_EIO)
    );
}

#[test]
fn x86_fstat_completes_the_canonical_reply_in_x86_layout() {
    // #1714: x86_64 `fstat` writes a 144-byte record whose st_nlink/st_mode
    // order differs from the canonical one the carrier replies with.
    let mut user = memory(&[0u8; X8664_STAT_BYTES]);
    let (mut record, output, _) = request(run(
        HostFileCall::Fstat {
            fd: 3,
            statbuf: BASE,
            layout: StatLayout::X8664,
        },
        &mut user,
    ));
    let output = output.expect("fstat has output");
    assert_eq!(output.len, X8664_STAT_BYTES);
    let view = HostFileRequestView::parse(&mut record).unwrap();
    assert_eq!(view.output_capacity(), LINUX_STAT_BYTES);
    let fields = carrick_syscall_abi::LinuxStatFields {
        ino: 7,
        mode: 0o100644,
        nlink: 2,
        uid: 1,
        gid: 3,
        rdev: 0,
        size: 30,
        blocks: None,
        atime: (1, 2),
        mtime: (3, 4),
        ctime: (5, 6),
    };
    view.reply(
        0,
        zerocopy::IntoBytes::as_bytes(&carrick_syscall_abi::LinuxStat::from_fields(&fields)),
    )
    .unwrap();
    let mut copied = Vec::new();
    let result = complete(&record, Some(output), &mut |address, bytes| {
        copied.push((address, bytes.to_vec()));
        true
    });
    assert_eq!(result, SyscallResult::new(0));
    let expected =
        zerocopy::IntoBytes::as_bytes(&carrick_syscall_abi::LinuxX8664Stat::from_fields(&fields))
            .to_vec();
    assert_eq!(copied, vec![(BASE, expected)]);
    // A reply that is not one canonical record is EIO, never a partial copy.
    let (mut record, output, _) = request(run(
        HostFileCall::Fstat {
            fd: 3,
            statbuf: BASE,
            layout: StatLayout::X8664,
        },
        &mut user,
    ));
    HostFileRequestView::parse(&mut record)
        .unwrap()
        .reply(0, b"short")
        .unwrap();
    assert_eq!(
        complete(&record, output, &mut |_, _| panic!("no output")),
        SyscallResult::from_errno(carrick_syscall_abi::LINUX_EIO)
    );
}

#[test]
fn unwritable_output_requests_write_supply_before_crossing() {
    let mut user = memory(b"");
    user.writable = false;
    assert_eq!(
        run(
            HostFileCall::Fstat {
                fd: 1,
                statbuf: BASE + 8,
                layout: StatLayout::Generic
            },
            &mut user
        ),
        Some(HostFileStage::Fault {
            address: BASE + 8,
            access: Access::Write
        })
    );
    // A buffer whose tail runs past the resident range faults at the tail.
    let mut user = memory(b"");
    assert_eq!(
        run(
            HostFileCall::Read {
                fd: 3,
                buf: BASE + 4096 - 2,
                count: 8
            },
            &mut user
        ),
        Some(HostFileStage::Fault {
            address: BASE + 4096,
            access: Access::Write
        })
    );
}

#[test]
fn private_file_mmap_stages_a_byte_source_request_with_its_exact_key() {
    let mut user = memory(b"");
    let key = NativeMapKey {
        address: 0,
        length: 8192,
        prot: 1,
        flags: LINUX_MAP_PRIVATE,
        fd: 3,
        offset: 4096,
    };
    let Some(HostFileStage::Request {
        mut record,
        output,
        resolves_path,
        map,
        ..
    }) = run(HostFileCall::MapPrivate(key), &mut user)
    else {
        panic!("a host file mapping crosses for its byte source");
    };
    assert_eq!((output, resolves_path, map), (None, false, Some(key)));
    let view = HostFileRequestView::parse(&mut record).unwrap();
    assert_eq!(view.header().op, HostFileOp::MapPrivate);
    assert_eq!(view.header().args[0], 4096);
    assert!(view.input().is_empty(), "nothing retired, nothing released");

    // The owner's retired sources ride the next mapping request; a refused
    // call (an in-zone descriptor) pops none of them.
    let source = |token: u64| host_file::MapSourceReply {
        handle: core::num::NonZeroU64::new(token).unwrap(),
        generation: core::num::NonZeroU64::MIN,
    };
    let retired = [source(5), source(6)];
    let mut popped = 0;
    assert_eq!(
        run_releasing(
            HostFileCall::MapPrivate(NativeMapKey { fd: 0, ..key }),
            &mut user,
            &retired,
            &mut popped
        ),
        returned(carrick_syscall_abi::LINUX_ENODEV)
    );
    assert_eq!(popped, 0, "a call answered in ring releases nothing");
    let Some(HostFileStage::Request { mut record, .. }) = run_releasing(
        HostFileCall::MapPrivate(key),
        &mut user,
        &retired,
        &mut popped,
    ) else {
        panic!("a host file mapping crosses");
    };
    let view = HostFileRequestView::parse(&mut record).unwrap();
    assert_eq!(
        host_file::MapSourceReply::decode_releases(view.input())
            .unwrap()
            .collect::<Vec<_>>(),
        retired
    );
    // A pipe has no mmap; an unaligned offset or empty length is EINVAL.
    assert_eq!(
        run(
            HostFileCall::MapPrivate(NativeMapKey { fd: 0, ..key }),
            &mut user
        ),
        returned(carrick_syscall_abi::LINUX_ENODEV)
    );
    assert_eq!(
        run(
            HostFileCall::MapPrivate(NativeMapKey { offset: 1, ..key }),
            &mut user
        ),
        returned(carrick_syscall_abi::LINUX_EINVAL)
    );
    // Decoding claims only private file mappings.
    let args = |flags| [0, 4096, 1, flags, 3, 0];
    assert!(matches!(
        HostFileCall::decode(LINUX_NR_MMAP, &args(LINUX_MAP_PRIVATE)),
        Some(HostFileCall::MapPrivate(_))
    ));
    assert_eq!(
        HostFileCall::decode(LINUX_NR_MMAP, &args(LINUX_MAP_SHARED)),
        None
    );
    assert_eq!(
        HostFileCall::decode(
            LINUX_NR_MMAP,
            &args(LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS)
        ),
        None
    );
}

#[test]
fn unserved_epoll_reads_do_not_prepare_output() {
    let mut user = memory(&[]);
    user.writable = false;
    let mut resolve = |_| Some(NativeDescriptor::InZone(InZoneKind::Epoll));
    let mut releases = |_: &mut [host_file::MapSourceReply]| 0;
    let mut namespace = NativeNamespace {
        table: TABLE,
        resolve: &mut resolve,
        releases: &mut releases,
    };
    assert!(matches!(
        stage(
            HostFileCall::Read {
                fd: 0,
                buf: BASE,
                count: 1
            },
            &mut namespace,
            &mut user
        ),
        Some(HostFileStage::InRing)
    ));
}

/// A staged write carries its writer's own file-size limit; other records
/// keep their arguments and never ask for the limit.
#[test]
fn write_records_carry_the_writers_file_size_limit() {
    let staged = |op: HostFileOp, args: [u64; 4]| {
        let mut record = vec![0u8; record_len(3, 0).unwrap()];
        host_file::encode(
            &mut record,
            HostFileHeader {
                op,
                table: [1, 2, 3],
                fd: 4,
                flags: 0,
                args,
            },
            b"abc",
            0,
        )
        .unwrap();
        record
    };
    for limit in [u64::MAX, 4096, 0] {
        let mut write = staged(HostFileOp::Write, [0; 4]);
        stamp_write_file_size_limit::<()>(&mut write, || Ok(limit)).unwrap();
        let view = host_file::HostFileRequestView::parse(&mut write).unwrap();
        assert_eq!(view.header().args, [limit, 0, 0, 0]);
        assert_eq!(view.input(), b"abc");
        for op in [HostFileOp::Truncate, HostFileOp::Ftruncate] {
            let mut resize = staged(op, [123, 0, 0, 0]);
            stamp_write_file_size_limit::<()>(&mut resize, || Ok(limit)).unwrap();
            let view = HostFileRequestView::parse(&mut resize).unwrap();
            assert_eq!(view.header().args, [123, limit, 0, 0]);
        }
    }
    let mut open = staged(HostFileOp::Openat, [0o1101, 0o644, 0, 0]);
    stamp_write_file_size_limit::<()>(&mut open, || panic!("an open has no file-size stamp"))
        .unwrap();
    let view = host_file::HostFileRequestView::parse(&mut open).unwrap();
    assert_eq!(view.header().args, [0o1101, 0o644, 0, 0]);
}

/// #1392: a ring chdir stages one chdir lookup (a `Newfstatat` whose reply
/// area has room for a name) and copies nothing back to user memory; the
/// ring reads the directory spelling from the reply.
#[test]
fn chdir_stages_one_lookup_and_reads_the_directory_from_its_reply() {
    let mut user = memory(b"sub\0");
    let Some(HostFileStage::Request {
        mut record,
        output,
        resolves_path,
        map,
        chdir,
    }) = run(HostFileCall::Chdir { path: BASE }, &mut user)
    else {
        panic!("chdir crosses for its lookup");
    };
    assert_eq!(
        (output, resolves_path, map, chdir),
        (None, true, None, true)
    );
    let view = HostFileRequestView::parse(&mut record).unwrap();
    assert_eq!(view.header().op, HostFileOp::Newfstatat);
    assert_eq!(view.header().fd, LINUX_AT_FDCWD);
    assert_eq!(view.input(), b"sub");
    assert_eq!(view.output_capacity(), CHDIR_REPLY_BYTES);

    let mut stat = carrick_syscall_abi::LinuxStat::from_fields(
        &carrick_syscall_abi::LinuxPipeIdentity::new(1, 1).stat_fields(),
    );
    stat.st_mode = carrick_syscall_abi::LINUX_S_IFDIR | 0o755;
    let mut reply = zerocopy::IntoBytes::as_bytes(&stat).to_vec();
    reply.extend_from_slice(b"/tmp/sub");
    view.reply(0, &reply).unwrap();
    assert_eq!(
        chdir_target(&record).unwrap().as_bytes(),
        b"/tmp/sub",
        "the carrier's canonical spelling becomes the cwd"
    );

    // An empty path is ENOENT in ring; a failed lookup's errno is the
    // result; a reply that is not a directory never becomes a cwd.
    let mut empty = memory(b"\0");
    assert_eq!(
        run(HostFileCall::Chdir { path: BASE }, &mut empty),
        returned(carrick_syscall_abi::LINUX_ENOENT)
    );
    let (mut failed, ..) = request(run(HostFileCall::Chdir { path: BASE }, &mut user));
    HostFileRequestView::parse(&mut failed)
        .unwrap()
        .reply(carrick_syscall_abi::LINUX_ENOTDIR.guest_retval(), &[])
        .unwrap();
    assert_eq!(
        chdir_target(&failed).map(|_| ()),
        Err(SyscallResult::from_errno(
            carrick_syscall_abi::LINUX_ENOTDIR
        ))
    );
    let (mut file, ..) = request(run(HostFileCall::Chdir { path: BASE }, &mut user));
    stat.st_mode = carrick_syscall_abi::LINUX_S_IFREG | 0o644;
    let mut reply = zerocopy::IntoBytes::as_bytes(&stat).to_vec();
    reply.extend_from_slice(b"/tmp/file");
    HostFileRequestView::parse(&mut file)
        .unwrap()
        .reply(0, &reply)
        .unwrap();
    assert!(chdir_target(&file).is_err());
}

/// #2206: a child's `fchdir` of a host-backed descriptor stages the chdir
/// lookup of that descriptor, completed exactly as `chdir`'s. Only a fork
/// descendant stages it; an in-zone object is never a directory and a
/// closed number is EBADF, both in ring.
#[test]
fn fchdir_stages_one_descriptor_lookup_for_a_descendant() {
    let call = HostFileCall::decode(crate::crossing::nr::FCHDIR, &[3, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(call, HostFileCall::Fchdir { fd: 3 });
    assert!(call.uses_child_mutation_venue());
    let mut user = memory(b"");
    let Some(HostFileStage::Request {
        mut record,
        output,
        resolves_path,
        map,
        chdir,
    }) = run(call, &mut user)
    else {
        panic!("fchdir of a host-backed descriptor crosses for its lookup");
    };
    assert_eq!(
        (output, resolves_path, map, chdir),
        (None, true, None, true),
        "the caller's access context authorizes the search check"
    );
    let view = HostFileRequestView::parse(&mut record).unwrap();
    assert_eq!(view.header().op, HostFileOp::Fchdir);
    assert_eq!(view.header().fd, 3);
    assert_eq!(view.header().table, TABLE);
    assert_eq!(view.input(), b"");
    assert_eq!(view.output_capacity(), CHDIR_REPLY_BYTES);

    for (fd, errno) in [
        (0, carrick_syscall_abi::LINUX_ENOTDIR),
        (4, carrick_syscall_abi::LINUX_ENOTDIR),
        (2, carrick_syscall_abi::LINUX_EBADF),
        (-1, carrick_syscall_abi::LINUX_EBADF),
    ] {
        assert_eq!(
            run(HostFileCall::Fchdir { fd }, &mut user),
            returned(errno),
            "fd {fd}"
        );
    }
}

/// #1392: a path record is re-staged with its caller's access context
/// leading the input; a descriptor record is left exactly as staged.
#[test]
fn access_context_leads_only_path_records() {
    let fs = crate::task_fs::TaskFs {
        cwd: crate::task_fs::TaskPath::new(b"/tmp").unwrap(),
        root: None,
    };
    let mut access = Vec::new();
    fs.encode_access(&crate::identity::TaskCredentials::ROOT, 0o022, &mut access)
        .unwrap();
    let mut user = memory(b"rel\0");
    let (record, ..) = request(run(
        HostFileCall::Openat {
            dirfd: LINUX_AT_FDCWD,
            path: BASE,
            flags: 0,
            mode: 0,
        },
        &mut user,
    ));
    let mut stamped = stamp_access_context(&record, &access).unwrap();
    let view = HostFileRequestView::parse(&mut stamped).unwrap();
    let (context, path) = host_file::AccessContext::decode(view.input()).unwrap();
    assert_eq!((context.cwd, path), (&b"/tmp"[..], &b"rel"[..]));
    assert_eq!(view.header().op, HostFileOp::Openat);

    let mut write = memory(b"data");
    let (record, ..) = request(run(
        HostFileCall::Write {
            fd: 1,
            buf: BASE,
            count: 4,
        },
        &mut write,
    ));
    assert_eq!(&*stamp_access_context(&record, &access).unwrap(), &*record);
}

fn pollfds(entries: &[(i32, i16)]) -> Vec<u8> {
    entries
        .iter()
        .flat_map(|&(fd, events)| {
            let mut entry = [0u8; host_file::POLLFD_BYTES];
            entry[..4].copy_from_slice(&fd.to_le_bytes());
            entry[4..6].copy_from_slice(&events.to_le_bytes());
            // A stale revents the guest left behind travels unchanged; the
            // carrier overwrites it.
            entry[6..].copy_from_slice(&0x7fffi16.to_le_bytes());
            entry
        })
        .collect()
}

/// `ppoll(fds, nfds, timeout, NULL)` with the pollfd array at `BASE` and a
/// timespec, when given, right after it.
fn ppoll(entries: &[(i32, i16)], timespec: Option<(i64, i64)>) -> (HostFileCall, Memory) {
    let mut bytes = pollfds(entries);
    let timeout = timespec.map_or(0, |(seconds, nanoseconds)| {
        let address = BASE + bytes.len() as u64;
        bytes.extend_from_slice(&seconds.to_le_bytes());
        bytes.extend_from_slice(&nanoseconds.to_le_bytes());
        address
    });
    (
        HostFileCall::Ppoll {
            fds: BASE,
            nfds: entries.len() as u64,
            timeout,
            sigmask: 0,
        },
        memory(&bytes),
    )
}

#[test]
fn ppoll_decodes_its_four_routing_arguments() {
    assert_eq!(
        HostFileCall::decode(crate::crossing::nr::PPOLL, &[BASE, 3, 0x20, 0x30, 8, 0]),
        Some(HostFileCall::Ppoll {
            fds: BASE,
            nfds: 3,
            timeout: 0x20,
            sigmask: 0x30,
        })
    );
}

#[test]
fn ppoll_over_host_stdio_stages_one_readiness_snapshot() {
    // Rust std's startup shape: fds 0-2, no events, zero timeout. Here fd 1
    // is host stdout and fd 7 is absent (the carrier reports POLLNVAL).
    let entries = [(1, 0), (-1, 0x1), (7, 0)];
    let (call, mut user) = ppoll(&entries, Some((0, 0)));
    let (mut record, output, resolves_path) = request(run(call, &mut user));
    assert!(!resolves_path);
    assert_eq!(
        output,
        Some(HostFileOutput::bytes(
            BASE,
            entries.len() * host_file::POLLFD_BYTES
        ))
    );
    let view = HostFileRequestView::parse(&mut record).unwrap();
    assert_eq!(view.header().op, HostFileOp::Poll);
    assert_eq!(view.header().table, TABLE);
    assert_eq!(view.header().args[0], host_file::PollWait::Snapshot.raw());
    assert_eq!(view.input(), pollfds(&entries));
    assert_eq!(view.output_capacity(), view.input().len());
}

#[test]
fn ppoll_that_would_wait_marks_its_snapshot_may_wait() {
    for timespec in [None, Some((0, 1)), Some((5, 0))] {
        let (call, mut user) = ppoll(&[(1, 0x4)], timespec);
        let (mut record, _, _) = request(run(call, &mut user));
        let view = HostFileRequestView::parse(&mut record).unwrap();
        assert_eq!(
            view.header().args[0],
            host_file::PollWait::MayWait.raw(),
            "{timespec:?}"
        );
    }
}

#[test]
fn ppoll_sets_the_carrier_cannot_answer_whole_keep_their_route() {
    // A mixed set (fd 0 is an in-zone pipe) needs the ring's wait (#1051).
    let (call, mut user) = ppoll(&[(1, 0x4), (0, 0x1)], Some((0, 0)));
    assert_eq!(run(call, &mut user), None);
    // No host-backed member: nothing for the carrier to observe.
    let (call, mut user) = ppoll(&[(7, 0x1), (-1, 0)], Some((0, 0)));
    assert_eq!(run(call, &mut user), None);
    // A signal mask is installed by the ring's wait, not by a snapshot.
    let (call, mut user) = ppoll(&[(1, 0x4)], Some((0, 0)));
    let HostFileCall::Ppoll {
        fds, nfds, timeout, ..
    } = call
    else {
        unreachable!()
    };
    let masked = HostFileCall::Ppoll {
        fds,
        nfds,
        timeout,
        sigmask: BASE,
    };
    assert_eq!(run(masked, &mut user), None);
    // More entries than one record carries.
    let huge = HostFileCall::Ppoll {
        fds: BASE,
        nfds: (HOST_FILE_CHUNK_BYTES / host_file::POLLFD_BYTES) as u64 + 1,
        timeout: 0,
        sigmask: 0,
    };
    assert_eq!(run(huge, &mut user), None);
    // A contended namespace keeps the route too.
    let (call, mut user) = ppoll(&[(1, 0x4)], Some((0, 0)));
    let mut resolve = |_| None;
    let mut releases = |_: &mut [host_file::MapSourceReply]| 0;
    let mut namespace = NativeNamespace {
        table: TABLE,
        resolve: &mut resolve,
        releases: &mut releases,
    };
    assert_eq!(stage(call, &mut namespace, &mut user), None);
}

#[test]
fn ppoll_arrays_need_readable_input_and_writable_output_before_crossing() {
    let (_, mut user) = ppoll(&[(1, 0x4)], None);
    let unreadable = HostFileCall::Ppoll {
        fds: BASE - 4096,
        nfds: 1,
        timeout: 0,
        sigmask: 0,
    };
    assert_eq!(
        run(unreadable, &mut user),
        Some(HostFileStage::Fault {
            address: BASE - 4096,
            access: Access::Read,
        })
    );
    let (call, mut user) = ppoll(&[(1, 0x4)], None);
    user.writable = false;
    assert_eq!(
        run(call, &mut user),
        Some(HostFileStage::Fault {
            address: BASE,
            access: Access::Write,
        })
    );
}

/// The input bytes a staged write request carries.
fn write_input(mut record: Box<[u8]>) -> Vec<u8> {
    let view = HostFileRequestView::parse(&mut record).unwrap();
    assert_eq!(view.header().op, HostFileOp::Write);
    view.input().to_vec()
}

/// The staged prefix of a write the user read stopped at `address`.
fn prefix_at(stage: Option<HostFileStage>, address: u64) -> Vec<u8> {
    let stage = stage.expect("a host-backed write is staged");
    assert_eq!(stage.fault(), Some((address, Access::Read)), "{stage:?}");
    match stage.refused() {
        HostFileStage::Request {
            record,
            output: None,
            resolves_path: false,
            map: None,
            chdir: false,
        } => write_input(record),
        other => panic!("a refused supply writes the prefix, got {other:?}"),
    }
}

#[test]
fn write_fault_after_a_readable_prefix_keeps_the_prefix() {
    // #1954: a buffer readable for 16 bytes, then unmapped. Linux's write
    // returns 16; the gather must not discard the copied prefix.
    let mut bytes = vec![0u8; 4096];
    bytes[4080..].copy_from_slice(b"0123456789abcdef");
    let mut user = memory(&bytes);
    let staged = run(
        HostFileCall::Write {
            fd: 1,
            buf: BASE + 4080,
            count: 0x100001,
        },
        &mut user,
    );
    assert_eq!(prefix_at(staged, BASE + 4096), b"0123456789abcdef");
}

#[test]
fn write_fault_with_no_readable_byte_is_efault_after_refused_supply() {
    let mut user = memory(b"");
    let staged = run(
        HostFileCall::Write {
            fd: 1,
            buf: BASE + 4096,
            count: 8,
        },
        &mut user,
    )
    .unwrap();
    assert_eq!(
        staged,
        HostFileStage::Fault {
            address: BASE + 4096,
            access: Access::Read
        }
    );
    assert_eq!(
        Some(staged.refused()),
        returned(carrick_syscall_abi::LINUX_EFAULT)
    );
}

#[test]
fn write_fault_supplied_then_retried_writes_every_byte() {
    // A valid but non-resident page: the ring supplies the exact faulting
    // page and retries the call, which then gathers the whole buffer.
    let mut user = memory(&[b'a'; 4096]);
    let call = HostFileCall::Write {
        fd: 1,
        buf: BASE + 4088,
        count: 16,
    };
    assert_eq!(prefix_at(run(call, &mut user), BASE + 4096), b"aaaaaaaa");
    user.bytes.extend_from_slice(&[b'b'; 4096]);
    let (record, ..) = request(run(call, &mut user));
    assert_eq!(write_input(record), b"aaaaaaaabbbbbbbb");
}

#[test]
fn writev_fault_in_a_later_vector_keeps_the_earlier_bytes() {
    // iov[0] "abcde" is readable; iov[1] starts 3 bytes before the end of
    // the resident page and runs past it; iov[2] is never reached.
    let mut bytes = vec![0u8; 4096];
    let vector = |bytes: &mut Vec<u8>, at: usize, base: u64, len: u64| {
        bytes[at..at + 8].copy_from_slice(&base.to_le_bytes());
        bytes[at + 8..at + 16].copy_from_slice(&len.to_le_bytes());
    };
    vector(&mut bytes, 0, BASE + 0x100, 5);
    vector(&mut bytes, 16, BASE + 4093, 8);
    vector(&mut bytes, 32, BASE + 0x100, 5);
    bytes[0x100..0x105].copy_from_slice(b"abcde");
    bytes[4093..].copy_from_slice(b"xyz");
    let mut user = memory(&bytes);
    let writev = |iov, iovcnt| HostFileCall::Writev { fd: 1, iov, iovcnt };
    assert_eq!(
        prefix_at(run(writev(BASE, 3), &mut user), BASE + 4096),
        b"abcdexyz"
    );
    // A fault at the start of a later vector keeps every earlier vector.
    vector(&mut user.bytes, 16, 0x900000, 4);
    assert_eq!(
        prefix_at(run(writev(BASE, 3), &mut user), 0x900000),
        b"abcde"
    );
    // An unreadable first vector or vector array copies nothing: EFAULT.
    vector(&mut user.bytes, 0, 0x900000, 4);
    assert_eq!(
        run(writev(BASE, 3), &mut user),
        Some(HostFileStage::Fault {
            address: 0x900000,
            access: Access::Read
        })
    );
    assert_eq!(
        run(writev(BASE + 4096 - 16, 2), &mut user),
        Some(HostFileStage::Fault {
            address: BASE + 4096,
            access: Access::Read
        })
    );
}

#[test]
fn readlink_decodes_and_bounds_the_output_without_a_nul() {
    let decode = |size| {
        HostFileCall::decode(
            crate::crossing::nr::READLINKAT,
            &[(-100i64) as u64, BASE, BASE + 512, size, 0, 0],
        )
        .unwrap()
    };
    let mut user = memory(b"/proc/self/exe\0");
    for size in [0, u64::MAX, 0x80000000] {
        assert_eq!(
            run(decode(size), &mut user),
            returned(carrick_syscall_abi::LINUX_EINVAL)
        );
    }
    let (mut record, output, path) = request(run(decode(3), &mut user));
    assert!(path);
    let view = HostFileRequestView::parse(&mut record).unwrap();
    assert_eq!(view.header().op, HostFileOp::Readlinkat);
    assert_eq!(view.output_capacity(), 3);
    view.reply(3, b"/bi").unwrap();
    let mut copied = Vec::new();
    assert_eq!(
        complete(&record, output, &mut |address, bytes| {
            assert_eq!(address, BASE + 512);
            copied.extend_from_slice(bytes);
            true
        })
        .raw(),
        3
    );
    assert_eq!(copied, b"/bi");
}

#[test]
fn readlink_validates_only_the_bytes_returned_by_the_link() {
    let mut user = memory(b"/proc/self/exe\0");
    let call = HostFileCall::Readlinkat {
        dirfd: carrick_fd_core::Fd(LINUX_AT_FDCWD),
        path: carrick_guest_arch::UserVa::new(BASE),
        buf: carrick_guest_arch::UserVa::new(BASE + 4090),
        bufsiz: ReadlinkSize(8192),
    };
    // The target fits in the mapped prefix. Linux never accesses the unused
    // tail of bufsiz, even when that tail crosses into unmapped memory.
    let (mut record, output, _) = request(run(call, &mut user));
    HostFileRequestView::parse(&mut record)
        .unwrap()
        .reply(3, b"/bi")
        .unwrap();
    assert_eq!(
        complete(&record, output, &mut |address, bytes| {
            user.writable(address, bytes.len()) == bytes.len()
        })
        .raw(),
        3
    );
}

#[test]
fn a_decoded_call_the_venue_does_not_admit_keeps_its_crossing_output_stage() {
    use crate::crossing::HostCrossingSet;
    // The root's AT_FDCWD readlinkat keeps its crossing output preparation.
    let (path, out) = (0x7000_0000u64, 0x7000_1000u64);
    let args = [LINUX_AT_FDCWD as u64, path, out, 64, 0, 0];
    let decoded = HostFileCall::decode(crate::crossing::nr::READLINKAT, &args).unwrap();
    assert_eq!(
        admit_or_cross(
            HostCrossingSet::X86,
            carrick_guest_arch::NativeOrdinal::new(267),
            crate::crossing::nr::READLINKAT,
            &args,
            ServiceOrigin::Initial,
            |_| false,
            |_, _| 0,
        ),
        Err(Some(HostFileStage::PrepareOutput { address: out })),
    );
    // The child's own retained service stages the same call before copyout.
    let mut visited = false;
    assert_eq!(
        admit_or_cross(
            HostCrossingSet::X86,
            carrick_guest_arch::NativeOrdinal::new(267),
            crate::crossing::nr::READLINKAT,
            &args,
            ServiceOrigin::Descendant,
            |_| false,
            |_, _| {
                visited = true;
                0
            },
        ),
        Ok(decoded),
    );
    assert!(!visited, "descendant copyout is checked after service");
    // Once the page is writable the crossing runs as it is.
    assert_eq!(
        admit_or_cross(
            HostCrossingSet::X86,
            carrick_guest_arch::NativeOrdinal::new(267),
            crate::crossing::nr::READLINKAT,
            &args,
            ServiceOrigin::Initial,
            |_| false,
            |_, len| len,
        ),
        Err(None)
    );
    // An admitted call is the venue's to stage; nothing is prepared for it.
    let openat = [LINUX_AT_FDCWD as u64, path, 0, 0, 0, 0];
    assert!(matches!(
        admit_or_cross(
            HostCrossingSet::X86,
            carrick_guest_arch::NativeOrdinal::new(257),
            crate::crossing::nr::OPENAT,
            &openat,
            ServiceOrigin::Initial,
            |_| false,
            |_, _| 0,
        ),
        Ok(HostFileCall::Openat { .. })
    ));
}

#[test]
fn crossing_preparation_visits_each_optional_gettimeofday_record() {
    use crate::crossing::HostCrossingSet;
    let args = [BASE, BASE + 4096, 0, 0, 0, 0];
    let mut visited = Vec::new();
    let stage = crossing_output_stage(
        HostCrossingSet::Aarch64,
        crate::crossing::nr::GETTIMEOFDAY,
        &args,
        |address, length| {
            visited.push((address, length));
            if address == BASE { length } else { 0 }
        },
    );
    assert_eq!(visited, [(BASE, 16), (BASE + 4096, 8)]);
    assert_eq!(
        stage,
        Some(HostFileStage::PrepareOutput {
            address: BASE + 4096
        })
    );
    // Null timeval is legal; it must not hide an untouched timezone record.
    assert_eq!(
        crossing_output_stage(
            HostCrossingSet::Aarch64,
            crate::crossing::nr::GETTIMEOFDAY,
            &[0, BASE, 0, 0, 0, 0],
            |_, _| 0,
        ),
        Some(HostFileStage::PrepareOutput { address: BASE })
    );
    assert_eq!(
        crossing_output_stage(
            HostCrossingSet::Aarch64,
            crate::crossing::nr::GETTIMEOFDAY,
            &[0; 6],
            |_, _| panic!("absent outputs must not probe guest memory"),
        ),
        None
    );
}

/// Production crossing preparation, including untouched destinations and the
/// second nullable copy_file_range offset. This does not execute a host effect.
#[test]
fn direct_range_crossings_prepare_every_output_before_host_effect() {
    use crate::crossing::{HostCrossingSet, nr};
    let out = BASE + 4096;
    for set in [HostCrossingSet::Aarch64, HostCrossingSet::X86] {
        let event_bytes = if set == HostCrossingSet::X86 { 12 } else { 16 };
        for (canonical, args, expected) in [
            (nr::GETRANDOM, [out, 32, 0, 0, 0, 0], vec![(out, 32)]),
            (nr::STATX, [3, BASE, 0, 0, out, 0], vec![(out, 256)]),
            (
                nr::COPY_FILE_RANGE,
                [3, out, 4, out + 4096, 32, 0],
                vec![(out, 8), (out + 4096, 8)],
            ),
            (nr::COPY_FILE_RANGE, [3, 0, 4, out, 32, 0], vec![(out, 8)]),
            (
                nr::EPOLL_PWAIT2,
                [3, out, 2, 0, 0, 0],
                vec![(out, 2 * event_bytes)],
            ),
            (
                nr::EPOLL_PWAIT,
                [3, out, 2, 0, 0, 0],
                vec![(out, 2 * event_bytes)],
            ),
        ] {
            if !set.is_allowed(canonical) {
                continue;
            }
            let mut visited = Vec::new();
            assert_eq!(
                crossing_output_stage(set, canonical, &args, |address, length| {
                    visited.push((address, length));
                    length
                }),
                None
            );
            assert_eq!(visited, expected, "{set:?} {canonical:?}");
            for &(untouched, _) in &expected {
                assert_eq!(
                    crossing_output_stage(set, canonical, &args, |address, length| {
                        if address == untouched { 0 } else { length }
                    }),
                    Some(HostFileStage::PrepareOutput { address: untouched }),
                    "{set:?} {canonical:?}"
                );
            }
        }
    }
}

#[test]
fn epoll_crossing_array_uses_signed_count_and_exact_isa_stride() {
    use crate::crossing::{HostCrossingSet, nr};
    for (set, stride) in [
        (HostCrossingSet::Aarch64, 16u64),
        (HostCrossingSet::X86, 12),
    ] {
        let out = BASE + 4096 - stride;
        assert_eq!(
            crossing_output_stage(
                set,
                nr::EPOLL_PWAIT,
                &[3, out, 1, 0, 0, 0],
                |address, length| (BASE + 4096 - address).min(length as u64) as usize
            ),
            None
        );
        for count in [0, u32::MAX as u64, i32::MAX as u64] {
            assert_eq!(
                crossing_output_stage(
                    set,
                    nr::EPOLL_PWAIT,
                    &[3, out, count, 0, 0, 0],
                    |_, _| panic!("invalid event count must not prepare memory")
                ),
                None
            );
        }
    }
}

#[test]
fn remaining_direct_crossings_prepare_fixed_and_byte_count_outputs() {
    use crate::crossing::{HostCrossingSet, nr};
    let out = BASE + 4096;
    for set in [HostCrossingSet::Aarch64, HostCrossingSet::X86] {
        for (canonical, args, bytes) in [
            (nr::READ, [3, out, 32, 0, 0, 0], 32),
            (nr::PREAD64, [3, out, 32, 0, 0, 0], 32),
            (nr::GETDENTS64, [3, out, 32, 0, 0, 0], 32),
            (nr::SENDFILE, [4, 3, out, 32, 0, 0], 8),
            (nr::FSTAT, [3, out, 0, 0, 0, 0], 128),
            (nr::NEWFSTATAT, [3, BASE, out, 0, 0, 0], 128),
            (nr::TIMERFD_SETTIME, [3, 0, BASE, out, 0, 0], 32),
            (nr::TIMERFD_GETTIME, [3, out, 0, 0, 0, 0], 32),
            (nr::CLOCK_GETRES, [1, out, 0, 0, 0, 0], 16),
            (nr::TIMES, [out, 0, 0, 0, 0, 0], 32),
            (nr::SOCKETPAIR, [1, 1, 0, out, 0, 0], 8),
            (nr::NANOSLEEP, [BASE, out, 0, 0, 0, 0], 16),
            (nr::CLOCK_NANOSLEEP, [1, 0, BASE, out, 0, 0], 16),
        ] {
            if !set.is_allowed(canonical) {
                continue;
            }
            let mut visited = Vec::new();
            assert_eq!(
                crossing_output_stage(set, canonical, &args, |address, length| {
                    visited.push((address, length));
                    length
                }),
                None
            );
            assert_eq!(visited, [(out, bytes)], "{set:?} {canonical:?}");
            assert_eq!(
                crossing_output_stage(set, canonical, &args, |_, _| 0),
                Some(HostFileStage::PrepareOutput { address: out })
            );
        }
    }
    for (canonical, args) in [
        (
            carrick_syscall_abi::CanonicalNr::new(carrick_syscall_abi::CARRICK_PRIVATE_X86_FSTAT),
            [3, out, 0, 0, 0, 0],
        ),
        (
            carrick_syscall_abi::CanonicalNr::new(
                carrick_syscall_abi::CARRICK_PRIVATE_X86_NEWFSTATAT,
            ),
            [3, BASE, out, 0, 0, 0],
        ),
    ] {
        let mut visited = Vec::new();
        assert_eq!(
            crossing_output_stage(HostCrossingSet::X86, canonical, &args, |address, length| {
                visited.push((address, length));
                length
            }),
            None
        );
        assert_eq!(visited, [(out, 144)]);
    }
    assert_eq!(
        crossing_output_stage(
            HostCrossingSet::Aarch64,
            nr::CLOCK_NANOSLEEP,
            &[1, 1, BASE, out, 0, 0],
            |_, _| panic!("absolute sleeps have no remainder")
        ),
        None
    );
}

/// #231 (apt's chmod/chown): `fchmod`/`fchown` of a host-backed descriptor
/// and a path's `fchmodat`/`fchmodat2`/`fchownat` stage the four
/// metadata-mutation records, each carrying the caller's access context
/// (its credentials decide EPERM). `fchmodat`'s fourth register is ignored,
/// as Linux ignores it; `chown`'s -1 owner and group keep their 32-bit
/// spelling.
#[test]
fn chmod_and_chown_stage_their_records_with_the_callers_authority() {
    let mut user = memory(b"source\0");
    let at = LINUX_AT_FDCWD as u64;
    let unchanged = u64::MAX;
    let nofollow = carrick_syscall_abi::LINUX_AT_SYMLINK_NOFOLLOW;
    for (number, args, op, fd, flags, words, input) in [
        (
            52,
            [3, 0o104755, 0, 0, 0, 0],
            HostFileOp::Fchmod,
            3,
            0,
            [0o4755, 0, 0, 0],
            b"".as_slice(),
        ),
        (
            55,
            [1, unchanged, 7, 0, 0, 0],
            HostFileOp::Fchown,
            1,
            0,
            [u64::from(u32::MAX), 7, 0, 0],
            b"".as_slice(),
        ),
        (
            53,
            [at, BASE, 0o644, nofollow, 0, 0],
            HostFileOp::Fchmodat,
            LINUX_AT_FDCWD,
            0,
            [0o644, 0, 0, 0],
            b"source".as_slice(),
        ),
        (
            452,
            [at, BASE, 0o600, nofollow, 0, 0],
            HostFileOp::Fchmodat,
            LINUX_AT_FDCWD,
            nofollow as u32,
            [0o600, 0, 0, 0],
            b"source".as_slice(),
        ),
        (
            54,
            [at, BASE, 0, unchanged, nofollow, 0],
            HostFileOp::Fchownat,
            LINUX_AT_FDCWD,
            nofollow as u32,
            [0, u64::from(u32::MAX), 0, 0],
            b"source".as_slice(),
        ),
    ] {
        let call = HostFileCall::decode(CanonicalNr::new(number), &args).unwrap();
        let (mut bytes, output, resolves_path) = request(run(call, &mut user));
        assert_eq!(output, None);
        assert!(resolves_path, "{op:?} carries the caller's access context");
        let view = HostFileRequestView::parse(&mut bytes).unwrap();
        let header = view.header();
        assert_eq!(
            (
                header.op,
                header.fd,
                header.flags,
                header.args,
                header.table
            ),
            (op, fd, flags, words, TABLE)
        );
        assert_eq!(view.input(), input);
        // The path calls are the child's mutation venue; the descriptor
        // calls follow the descriptor, also for the run root.
        assert_eq!(
            call.uses_child_mutation_venue(),
            matches!(op, HostFileOp::Fchmodat | HostFileOp::Fchownat)
        );
        assert!(call.admitted_for(ServiceOrigin::Descendant, |_| false));
        assert_eq!(
            call.admitted_for(ServiceOrigin::Initial, |_| false),
            matches!(op, HostFileOp::Fchmod | HostFileOp::Fchown)
        );
        assert!(!call.admitted_for(ServiceOrigin::Initial, |_| true));
    }
}

/// The ring answers what Linux answers before any file is touched: EBADF
/// for a closed descriptor and for `fchmod`/`fchown` of an O_PATH one,
/// EINVAL for an unknown `fchmodat2`/`fchownat` flag, ENOENT for an empty
/// path. `fchownat(fd, "", AT_EMPTY_PATH)` is the descriptor's own chown,
/// which an O_PATH descriptor allows. An in-zone object keeps its route.
#[test]
fn chmod_and_chown_answer_linux_errors_in_ring() {
    let mut user = memory(b"\0");
    let ebadf = returned(carrick_syscall_abi::LINUX_EBADF);
    let path_fd = |fd: i32| {
        Some(match fd {
            5 => NativeDescriptor::HostBacked {
                access: DescriptionAccess::Path,
            },
            other => return caller(other),
        })
    };
    let staged = |call: HostFileCall, user: &mut Memory| {
        let mut resolve = path_fd;
        let mut releases = |_: &mut [host_file::MapSourceReply]| 0;
        stage(
            call,
            &mut NativeNamespace {
                table: TABLE,
                resolve: &mut resolve,
                releases: &mut releases,
            },
            user,
        )
    };
    for fd in [999, 5] {
        assert_eq!(
            staged(HostFileCall::Fchmod { fd, mode: 0 }, &mut user),
            ebadf
        );
        let chown = HostFileCall::Fchown {
            fd,
            owner: 0,
            group: 0,
        };
        assert_eq!(staged(chown, &mut user), ebadf);
    }
    assert_eq!(
        staged(HostFileCall::Fchmod { fd: 0, mode: 0 }, &mut user),
        None
    );
    let einval = returned(carrick_syscall_abi::LINUX_EINVAL);
    let chmodat = |path, flags| HostFileCall::Fchmodat {
        dirfd: LINUX_AT_FDCWD,
        path,
        mode: 0o600,
        flags,
    };
    let chownat = |dirfd, flags| HostFileCall::Fchownat {
        dirfd,
        path: BASE,
        owner: 0,
        group: 0,
        flags,
    };
    assert_eq!(staged(chmodat(u64::MAX, 0x200), &mut user), einval);
    assert_eq!(staged(chownat(LINUX_AT_FDCWD, 0x200), &mut user), einval);
    assert_eq!(
        staged(chmodat(BASE, 0), &mut user),
        returned(carrick_syscall_abi::LINUX_ENOENT)
    );
    assert_eq!(
        staged(chownat(LINUX_AT_FDCWD, 0), &mut user),
        returned(carrick_syscall_abi::LINUX_ENOENT)
    );
    let empty = u64::from(LINUX_AT_EMPTY_PATH);
    let (mut bytes, _, _) = request(staged(chownat(5, empty), &mut user));
    let view = HostFileRequestView::parse(&mut bytes).unwrap();
    assert_eq!(
        (view.header().op, view.header().fd),
        (HostFileOp::Fchown, 5)
    );
    let (mut bytes, _, _) = request(staged(chownat(LINUX_AT_FDCWD, empty), &mut user));
    let view = HostFileRequestView::parse(&mut bytes).unwrap();
    assert_eq!(
        (view.header().op, view.input()),
        (HostFileOp::Fchownat, &b"."[..])
    );
    assert_eq!(staged(chownat(999, empty), &mut user), ebadf);
}

/// A host network socket descriptor (#231): fd 1 is host-backed.
const SOCKET_FD: u64 = 1;

/// Stage a socket call and stamp its caller, as the ring's service does.
fn socket_record(user: &mut Memory, canonical: CanonicalNr, args: [u64; 6]) -> Box<[u8]> {
    let call = SocketCall::decode(canonical, &args).expect("a socket call");
    let (record, output, _) = request(run(HostFileCall::Socket(call), user));
    assert_eq!(output.map(|output| output.layout), Some(OutputLayout::Net));
    stamp_net_caller(
        &record,
        &host_file::NetCaller {
            task: carrick_sched_core::process::TaskKey {
                id: carrick_sched_core::process::TaskId::from_registry_allocation(
                    core::num::NonZeroI32::new(5).unwrap(),
                ),
                serial: carrick_sched_core::process::TaskSerial::from_raw_u64(3).unwrap(),
            },
            ns_pid: core::num::NonZeroU32::new(5).unwrap(),
            ids: host_file::AccessIds {
                ruid: 1000,
                euid: 1000,
                suid: 1000,
                fsuid: 1000,
                rgid: 1000,
                egid: 1000,
                sgid: 1000,
                fsgid: 1000,
            },
            cap_effective: 0,
        },
    )
    .expect("the caller fits the record")
}

/// The carrier's reply to a socket record: `result`, the socket's facts and
/// no written extent beyond each output segment's empty one.
fn serve_socket(record: &mut [u8], result: i64, facts: host_file::NetTransferFacts) {
    let (_, input, _) = host_file::request_parts(record).unwrap();
    let call = socket::staged_call(input).unwrap();
    let empty: Vec<(u32, &[u8])> = call
        .segments()
        .iter()
        .filter(|segment| segment.output)
        .map(|_| (0, &[][..]))
        .collect();
    let output = if result < 0 {
        Vec::new()
    } else {
        host_file::NetCall::encode_written(facts, &empty)
    };
    HostFileRequestView::parse(record)
        .unwrap()
        .reply(result, &output)
        .unwrap();
}

const STREAM: host_file::NetTransferFacts = host_file::NetTransferFacts {
    stream: true,
    blocking: true,
};

/// #2414 review P0-1: a send keeps its caller's whole extent. Its first
/// record stages one record's range and the call's length, and the ring's
/// continuation moves the rest record by record: a blocking stream send
/// continues past a short record (the host's send buffer was full) until
/// every byte moved, from the byte after the last one moved. A non-blocking
/// one stops at a short record, a datagram never continues, a signal stops
/// the call with what it moved, and an error answers the bytes moved, or
/// itself when none moved. Red before the fix: staging clipped the call to
/// 61440 bytes and nothing continued it.
#[test]
fn a_socket_send_keeps_its_whole_extent_across_records() {
    use crate::native_host_file::socket::NetTransferStep;
    const LEN: usize = 200_000;
    let mut user = memory(&vec![7u8; LEN]);
    let first = socket_record(
        &mut user,
        crate::crossing::nr::SENDTO,
        [SOCKET_FD, BASE, LEN as u64, 0, 0, 0],
    );
    let (_, input, _) = host_file::request_parts(&first).unwrap();
    let call = socket::staged_call(input).unwrap();
    assert_eq!(call.args[2], LEN as u64, "the call keeps its whole length");
    assert_eq!(
        call.segments()[0].len as usize,
        host_file::NET_TRANSFER_MAX_BYTES
    );

    let step = |record: &[u8], result: i64, done: NetTransfer, interrupted: bool| {
        net_transfer_step(record, SyscallResult::new(result), done, interrupted).unwrap()
    };
    // A blocking stream send whose first record moved its whole range.
    let mut served = first.clone();
    serve_socket(&mut served, 65_536, STREAM);
    let NetTransferStep::Next {
        transfer,
        address,
        len,
        send: true,
    } = step(&served, 65_536, NetTransfer::default(), false)
    else {
        panic!("a blocking stream send continues")
    };
    assert_eq!(
        (transfer.done(), address, len),
        (65_536, BASE + 65_536, 65_536)
    );
    let (second, output) =
        net_transfer_record(&served, address, len, Some(&vec![7u8; len])).unwrap();
    assert_eq!(output.layout, OutputLayout::Net);
    let (_, input, _) = host_file::request_parts(&second).unwrap();
    let (caller, _) = host_file::NetCaller::split(input).unwrap();
    assert_eq!(caller.ids.euid, 1000, "the caller stays the call's");
    let call = socket::staged_call(input).unwrap();
    assert_eq!(
        call.args,
        [SOCKET_FD, BASE + 65_536, (LEN - 65_536) as u64, 0, 0, 0]
    );
    // A short record (a full send buffer) continues from its last byte.
    let mut short = second.clone();
    serve_socket(&mut short, 1_000, STREAM);
    let NetTransferStep::Next {
        transfer, address, ..
    } = step(&short, 1_000, transfer, false)
    else {
        panic!("a blocking stream send continues past a short record")
    };
    assert_eq!((transfer.done(), address), (66_536, BASE + 66_536));
    // ... but a non-blocking one returns what moved.
    let nonblocking = host_file::NetTransferFacts {
        stream: true,
        blocking: false,
    };
    let mut short = second.clone();
    serve_socket(&mut short, 1_000, nonblocking);
    assert_eq!(
        step(&short, 1_000, transfer, false),
        NetTransferStep::Complete(SyscallResult::new(66_536 + 1_000))
    );
    // A signal stops the call with what it moved.
    let mut interrupted = second.clone();
    serve_socket(&mut interrupted, 65_536, STREAM);
    assert_eq!(
        step(&interrupted, 65_536, transfer, true),
        NetTransferStep::Complete(SyscallResult::new(66_536 + 65_536))
    );
    // An error after progress answers the progress; before it, the error.
    let epipe = carrick_syscall_abi::LINUX_EPIPE.guest_retval();
    let mut failed = second.clone();
    serve_socket(&mut failed, epipe, STREAM);
    assert_eq!(
        step(&failed, epipe, transfer, false),
        NetTransferStep::Complete(SyscallResult::new(66_536))
    );
    let mut failed = first.clone();
    serve_socket(&mut failed, epipe, STREAM);
    assert_eq!(
        step(&failed, epipe, NetTransfer::default(), false),
        NetTransferStep::Complete(SyscallResult::new(epipe))
    );
    // A datagram is one record: it never continues.
    let datagram = host_file::NetTransferFacts {
        stream: false,
        blocking: true,
    };
    let mut sent = first.clone();
    serve_socket(&mut sent, 65_536, datagram);
    assert_eq!(
        step(&sent, 65_536, NetTransfer::default(), false),
        NetTransferStep::Complete(SyscallResult::new(65_536))
    );
    // A transfer's next record never repeats or skips a byte.
    assert!(net_transfer_record(&served, BASE, len, Some(&vec![7u8; len])).is_none());
    assert!(net_transfer_record(&served, BASE + 65_537, len, Some(&vec![7u8; len])).is_none());
}

/// #2414 review P0-1: a receive keeps its caller's whole extent. Its first
/// record holds any datagram whole; a MSG_WAITALL receive on a blocking
/// stream socket continues until its buffer is full, the stream ends (a
/// record of 0) or a signal stops it; a plain receive, a peek and a
/// non-blocking MSG_WAITALL answer their first record. The rest of a
/// MSG_WAITALL buffer is proven writable before the first record crosses.
#[test]
fn a_socket_receive_continues_only_for_msg_waitall_on_a_blocking_stream() {
    use crate::native_host_file::socket::NetTransferStep;
    const LEN: usize = 200_000;
    const WAITALL: u64 = 0x100;
    let mut user = memory(&vec![0u8; LEN]);
    let waitall = socket_record(
        &mut user,
        crate::crossing::nr::RECVFROM,
        [SOCKET_FD, BASE, LEN as u64, WAITALL, 0, 0],
    );
    let step = |record: &[u8], result: i64, facts| {
        let mut served = record.to_vec();
        serve_socket(&mut served, result, facts);
        net_transfer_step(
            &served,
            SyscallResult::new(result),
            NetTransfer::default(),
            false,
        )
        .unwrap()
    };
    let NetTransferStep::Next {
        transfer,
        address,
        len,
        send: false,
    } = step(&waitall, 40_000, STREAM)
    else {
        panic!("a blocking MSG_WAITALL stream receive continues")
    };
    assert_eq!(
        (transfer.done(), address, len),
        (40_000, BASE + 40_000, 65_536)
    );
    let mut served = waitall.to_vec();
    serve_socket(&mut served, 40_000, STREAM);
    let (next, output) = net_transfer_record(&served, address, len, None).unwrap();
    let (_, input, _) = host_file::request_parts(&next).unwrap();
    let call = socket::staged_call(input).unwrap();
    assert_eq!(
        call.args,
        [
            SOCKET_FD,
            BASE + 40_000,
            (LEN - 40_000) as u64,
            WAITALL,
            0,
            0
        ]
    );
    assert!(call.segments()[0].output && !call.segments()[0].input);
    assert_eq!(
        output.len,
        host_file::NetCall::output_capacity(call.segments())
    );
    // The end of the stream ends the call.
    assert_eq!(
        step(&waitall, 0, STREAM),
        NetTransferStep::Complete(SyscallResult::new(0))
    );
    // Non-blocking, a datagram, a plain receive and a peek answer at once.
    for (flags, facts) in [
        (
            WAITALL,
            host_file::NetTransferFacts {
                stream: true,
                blocking: false,
            },
        ),
        (
            WAITALL,
            host_file::NetTransferFacts {
                stream: false,
                blocking: true,
            },
        ),
        (0, STREAM),
        (WAITALL | 0x2, STREAM),
    ] {
        let record = socket_record(
            &mut user,
            crate::crossing::nr::RECVFROM,
            [SOCKET_FD, BASE, LEN as u64, flags, 0, 0],
        );
        assert_eq!(
            step(&record, 40_000, facts),
            NetTransferStep::Complete(SyscallResult::new(40_000)),
            "flags {flags:#x}, {facts:?}"
        );
    }
    // A MSG_WAITALL buffer that is not all writable faults before anything
    // is received: the ring supplies it first.
    let mut short = memory(&vec![0u8; 70_000]);
    let call = SocketCall::decode(
        crate::crossing::nr::RECVFROM,
        &[SOCKET_FD, BASE, LEN as u64, WAITALL, 0, 0],
    )
    .unwrap();
    assert!(matches!(
        run(HostFileCall::Socket(call), &mut short),
        Some(HostFileStage::Fault {
            access: Access::Write,
            ..
        })
    ));
}

/// #2414 review P0-1: a send's whole extent is proven readable before its
/// first record crosses, so the continuation's later records copy it in
/// without a fault of their own; a datagram's single record carries all of
/// a 65000-byte datagram.
#[test]
fn a_socket_send_proves_its_whole_extent_readable_and_holds_a_datagram() {
    let mut short = memory(&vec![0u8; 70_000]);
    let call = SocketCall::decode(
        crate::crossing::nr::SENDTO,
        &[SOCKET_FD, BASE, 200_000, 0, 0, 0],
    )
    .unwrap();
    assert!(matches!(
        run(HostFileCall::Socket(call), &mut short),
        Some(HostFileStage::Fault {
            address,
            access: Access::Read,
        }) if address == BASE + 73_728
    ));
    let mut user = memory(&vec![1u8; 65_000]);
    let record = socket_record(
        &mut user,
        crate::crossing::nr::SENDTO,
        [SOCKET_FD, BASE, 65_000, 0, 0, 0],
    );
    let (_, input, _) = host_file::request_parts(&record).unwrap();
    let call = socket::staged_call(input).unwrap();
    assert_eq!(call.args[2], 65_000);
    assert_eq!(call.segments()[0].len, 65_000);
}

/// A Linux `struct mmsghdr` (its leading `struct msghdr`, then `msg_len`).
fn msghdr(
    name: u64,
    namelen: u32,
    iov: u64,
    iovlen: u64,
    control: u64,
    controllen: u64,
) -> Vec<u8> {
    let mut header = vec![0u8; carrick_syscall_abi::LINUX_MMSGHDR_BYTES];
    header[..8].copy_from_slice(&name.to_le_bytes());
    header[8..12].copy_from_slice(&namelen.to_le_bytes());
    header[16..24].copy_from_slice(&iov.to_le_bytes());
    header[24..32].copy_from_slice(&iovlen.to_le_bytes());
    header[32..40].copy_from_slice(&control.to_le_bytes());
    header[40..48].copy_from_slice(&controllen.to_le_bytes());
    header
}

fn iovec(base: u64, len: u64) -> Vec<u8> {
    [base.to_le_bytes(), len.to_le_bytes()].concat()
}

/// Lay `parts` out at their offsets in one buffer of `len` bytes.
fn laid_out(len: usize, parts: &[(usize, &[u8])]) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    for (at, part) in parts {
        bytes[*at..*at + part.len()].copy_from_slice(part);
    }
    bytes
}

fn socket_stage(
    user: &mut Memory,
    canonical: CanonicalNr,
    args: [u64; 6],
) -> Option<HostFileStage> {
    let call = SocketCall::decode(canonical, &args).expect("a socket call");
    run(HostFileCall::Socket(call), user)
}

/// The arguments and segment table a staged socket request carries.
fn staged_net(stage: Option<HostFileStage>) -> ([u64; 6], Vec<host_file::NetSegment>) {
    let (record, output, _) = request(stage);
    assert_eq!(output.map(|output| output.layout), Some(OutputLayout::Net));
    let (_, input, _) = host_file::request_parts(&record).unwrap();
    let call = host_file::NetCall::decode(input).expect("a staged socket call");
    (call.args, call.segments().to_vec())
}

fn net_segment(address: u64, len: u32, input: bool, output: bool) -> host_file::NetSegment {
    host_file::NetSegment {
        address,
        len,
        input,
        output,
    }
}

const MSG_DONTWAIT: u64 = 0x40;

/// #2418 review P0-1: a received message's header, and a batched sent
/// one's `msg_len`, are written back after the call moved its data. A
/// header on a page whose copy-on-write share is unbroken (or a read-only
/// one) is supplied writable before the crossing, as every other output
/// range is; a refused supply is EFAULT before any datagram moved. Red
/// before: the header was declared output unchecked, the carrier sent or
/// consumed the datagram and completion answered EFAULT after it.
#[test]
fn a_message_header_linux_writes_back_is_supplied_writable_before_the_crossing() {
    use crate::crossing::nr;
    // Page 0: the header. Page 1: its iovec, buffer and name.
    let bytes = laid_out(
        8192,
        &[
            (0, &msghdr(BASE + 4096 + 512, 16, BASE + 4096, 1, 0, 0)),
            (4096, &iovec(BASE + 4096 + 64, 32)),
        ],
    );
    let mut user = memory(&bytes);
    user.read_only = BASE..BASE + 4096;
    let fault = |user: &mut Memory, canonical, args| {
        socket_stage(user, canonical, args).and_then(|stage| stage.fault())
    };
    // recvmsg and recvmmsg write msg_namelen first; sendmmsg writes msg_len.
    let header = [SOCKET_FD, BASE, 0, 0, 0, 0];
    assert_eq!(
        fault(&mut user, nr::RECVMSG, header),
        Some((BASE + 8, Access::Write))
    );
    let batch = [SOCKET_FD, BASE, 1, MSG_DONTWAIT, 0, 0];
    assert_eq!(
        fault(&mut user, nr::RECVMMSG, batch),
        Some((BASE + 8, Access::Write))
    );
    assert_eq!(
        fault(&mut user, nr::SENDMMSG, batch),
        Some((BASE + 56, Access::Write))
    );
    assert_eq!(
        socket_stage(&mut user, nr::RECVMSG, header).map(HostFileStage::refused),
        returned(carrick_syscall_abi::LINUX_EFAULT)
    );
    // sendmsg writes nothing back: its read-only header crosses.
    staged_net(socket_stage(&mut user, nr::SENDMSG, header));
    // Supplied: every call crosses.
    user.read_only = 0..0;
    staged_net(socket_stage(&mut user, nr::RECVMSG, header));
    staged_net(socket_stage(&mut user, nr::RECVMMSG, batch));
    staged_net(socket_stage(&mut user, nr::SENDMMSG, batch));
}

/// #2418 re-review P0: `sendmsg` takes three arguments, so a libc wrapper
/// leaves the sixth syscall register (`%r9`, `x5`) as whatever it held. The
/// staged request carries the carrier's "data not staged" marker in that
/// slot (`NET_MESSAGE_UNSTAGED_ARG`), so a stale register value must never
/// reach the carrier on a message that WAS staged: a 1 on a datagram socket
/// answered EMSGSIZE and any other non-zero value a counted ENOSYS for a
/// healthy `sendmsg`. Red before: the slot kept the caller's register.
#[test]
fn a_staged_message_call_never_forwards_the_callers_stale_sixth_register() {
    use crate::crossing::nr;
    let bytes = laid_out(
        8192,
        &[
            (0, &msghdr(0, 0, BASE + 4096, 1, 0, 0)),
            (4096, &iovec(BASE + 4096 + 64, 32)),
        ],
    );
    for stale in [1, 0xdead_beef, u64::MAX] {
        for canonical in [nr::SENDMSG, nr::RECVMSG] {
            let mut user = memory(&bytes);
            let (args, _) = staged_net(socket_stage(
                &mut user,
                canonical,
                [SOCKET_FD, BASE, 0, 0, 0, stale],
            ));
            assert_eq!(
                args[host_file::NET_MESSAGE_UNSTAGED_ARG],
                0,
                "{canonical:?} with a stale sixth register {stale:#x}"
            );
        }
    }
}

/// #2418 review P0-2 and P1-1: ancillary data is not staged. A message
/// call with a non-zero `msg_controllen`, either way and whatever
/// `msg_control` holds, is a counted refusal: Linux's control messages
/// (and its EFAULT for a NULL buffer) are not answered by a guess, and no
/// guest length sizes a carrier allocation. A control pointer with no
/// length carries nothing and crosses. Red before: a receive's control
/// buffer crossed with its unclamped length, and a send's NULL control
/// buffer with a length was sent as if it had none.
#[test]
fn message_control_data_is_a_counted_refusal_in_either_direction() {
    use crate::crossing::nr;
    let iov = iovec(BASE + 0x200, 32);
    for (control, controllen) in [
        (BASE + 0x400, 64),
        (BASE + 0x400, 0x7fff_fff0),
        (BASE + 0x400, 0x1_0000_0000),
        (0, 64),
    ] {
        let header = msghdr(0, 0, BASE + 0x100, 1, control, controllen);
        let mut user = memory(&laid_out(4096, &[(0, &header), (0x100, &iov)]));
        for (canonical, args) in [
            (nr::RECVMSG, [SOCKET_FD, BASE, 0, 0, 0, 0]),
            (nr::SENDMSG, [SOCKET_FD, BASE, 0, 0, 0, 0]),
            (nr::RECVMMSG, [SOCKET_FD, BASE, 1, MSG_DONTWAIT, 0, 0]),
            (nr::SENDMMSG, [SOCKET_FD, BASE, 1, 0, 0, 0]),
        ] {
            assert_eq!(
                socket_stage(&mut user, canonical, args),
                None,
                "{canonical:?} with msg_control {control:#x}, msg_controllen {controllen:#x}"
            );
        }
    }
    let header = msghdr(0, 0, BASE + 0x100, 1, BASE + 0x400, 0);
    let mut user = memory(&laid_out(4096, &[(0, &header), (0x100, &iov)]));
    for canonical in [nr::RECVMSG, nr::SENDMSG] {
        let (_, segments) = staged_net(socket_stage(
            &mut user,
            canonical,
            [SOCKET_FD, BASE, 0, 0, 0, 0],
        ));
        assert!(
            segments
                .iter()
                .all(|segment| segment.address != BASE + 0x400),
            "{segments:?}"
        );
    }
}

/// #2418 review P0-3: Linux's `sendmmsg` and `recvmmsg` move their entries
/// in order and stop at the first that fails; once one moved, the call
/// answers the count moved. A later entry whose header, iovecs or ranges
/// fault stages the entries before it behind a supply of the faulting
/// page: a supplied page retries the whole batch, a refused one moves the
/// staged prefix. Red before: the refused supply answered EFAULT and moved
/// nothing.
#[test]
fn a_later_batch_entry_that_faults_moves_the_entries_before_it() {
    use crate::crossing::nr;
    // sendmmsg: entry 0 is the resident page's last 64 bytes, entry 1 is
    // on the next, unmapped page.
    let bytes = laid_out(
        4096,
        &[
            (4096 - 64, &msghdr(0, 0, BASE + 0x100, 1, 0, 0)),
            (0x100, &iovec(BASE + 0x200, 7)),
            (0x200, b"A-query"),
        ],
    );
    let mut user = memory(&bytes);
    let args = [SOCKET_FD, BASE + 4096 - 64, 2, 0x4000, 0, 0];
    let stage = socket_stage(&mut user, nr::SENDMMSG, args).unwrap();
    assert_eq!(stage.fault(), Some((BASE + 4096, Access::Read)));
    let (staged, segments) = staged_net(Some(stage.refused()));
    assert_eq!(staged[2], 1, "a refused supply sends entry 0 alone");
    assert!(segments.iter().all(|segment| segment.address < BASE + 4096));
    user.bytes.resize(8192, 0);
    assert_eq!(
        staged_net(socket_stage(&mut user, nr::SENDMMSG, args)).0[2],
        2
    );

    // recvmmsg: entry 1's buffer is on a page not yet writable.
    let bytes = laid_out(
        8192,
        &[
            (0, &msghdr(0, 0, BASE + 0x100, 1, 0, 0)),
            (64, &msghdr(0, 0, BASE + 0x110, 1, 0, 0)),
            (0x100, &iovec(BASE + 0x200, 32)),
            (0x110, &iovec(BASE + 4096, 32)),
        ],
    );
    let mut user = memory(&bytes);
    user.read_only = BASE + 4096..BASE + 8192;
    let args = [SOCKET_FD, BASE, 2, MSG_DONTWAIT, 0, 0];
    let stage = socket_stage(&mut user, nr::RECVMMSG, args).unwrap();
    assert_eq!(stage.fault(), Some((BASE + 4096, Access::Write)));
    assert_eq!(staged_net(Some(stage.refused())).0[2], 1);
    user.read_only = 0..0;
    assert_eq!(
        staged_net(socket_stage(&mut user, nr::RECVMMSG, args)).0[2],
        2
    );
    // An unreadable first entry moves nothing: EFAULT once refused.
    let stage = socket_stage(
        &mut user,
        nr::RECVMMSG,
        [SOCKET_FD, BASE + 8192, 2, 0, 0, 0],
    );
    assert_eq!(
        stage.map(HostFileStage::refused),
        returned(carrick_syscall_abi::LINUX_EFAULT)
    );
}

/// #2418 review P0-4: a `recvmmsg` crosses only as Linux's whole call.
/// One whose entries do not all fit one record (their buffers, or their
/// segments) is refused whole, never cut to fewer entries that leave
/// datagrams queued; a timeout, which Linux checks between datagrams and
/// writes back, is refused before the descriptor is looked up (Linux
/// validates it first); and `vlen` is the `unsigned int` Linux reads. Red
/// before: the batch was cut short, the timeout crossed unhonoured, and a
/// count in the register's upper half read past the caller's array.
#[test]
fn a_receive_batch_is_staged_whole_or_refused() {
    use crate::crossing::nr;
    // Two 40000-byte buffers: entry 1 does not fit the data range left.
    let bytes = laid_out(
        0x1000 + 80_000,
        &[
            (0, &msghdr(0, 0, BASE + 0x100, 1, 0, 0)),
            (64, &msghdr(0, 0, BASE + 0x110, 1, 0, 0)),
            (0x100, &iovec(BASE + 0x1000, 40_000)),
            (0x110, &iovec(BASE + 0x1000 + 40_000, 40_000)),
        ],
    );
    let mut user = memory(&bytes);
    assert_eq!(
        socket_stage(
            &mut user,
            nr::RECVMMSG,
            [SOCKET_FD, BASE, 2, MSG_DONTWAIT, 0, 0]
        ),
        None
    );
    // One entry's buffer holds any datagram whole.
    let one = [SOCKET_FD, BASE, 1, MSG_DONTWAIT, 0, 0];
    assert_eq!(
        staged_net(socket_stage(&mut user, nr::RECVMMSG, one)).0[2],
        1
    );
    // A timeout, even on a closed descriptor.
    for fd in [SOCKET_FD, 7] {
        assert_eq!(
            socket_stage(
                &mut user,
                nr::RECVMMSG,
                [fd, BASE, 1, MSG_DONTWAIT, BASE + 0x200, 0]
            ),
            None
        );
    }

    // A hundred one-byte entries: more segments than one record holds.
    let mut parts = Vec::new();
    let headers: Vec<Vec<u8>> = (0..100u64)
        .map(|entry| msghdr(0, 0, BASE + 0x2000 + 16 * entry, 1, 0, 0))
        .collect();
    let iovecs: Vec<Vec<u8>> = (0..100u64)
        .map(|entry| iovec(BASE + 0x3000 + entry, 1))
        .collect();
    for (entry, (header, iov)) in headers.iter().zip(&iovecs).enumerate() {
        parts.push((64 * entry, header.as_slice()));
        parts.push((0x2000 + 16 * entry, iov.as_slice()));
    }
    let mut user = memory(&laid_out(0x4000, &parts));
    assert_eq!(
        socket_stage(
            &mut user,
            nr::RECVMMSG,
            [SOCKET_FD, BASE, 100, MSG_DONTWAIT, 0, 0]
        ),
        None
    );

    // vlen is an unsigned int: the upper half of its register is not the
    // count. The one entry is the resident page's last; past it is unmapped.
    let bytes = laid_out(
        4096,
        &[
            (4096 - 64, &msghdr(0, 0, BASE + 0x100, 1, 0, 0)),
            (0x100, &iovec(BASE + 0x200, 32)),
        ],
    );
    let mut user = memory(&bytes);
    let msgvec = BASE + 4096 - 64;
    for canonical in [nr::RECVMMSG, nr::SENDMMSG] {
        let (args, _) = staged_net(socket_stage(
            &mut user,
            canonical,
            [SOCKET_FD, msgvec, (1 << 32) | 1, MSG_DONTWAIT, 0, 0],
        ));
        assert_eq!(args[2], 1, "{canonical:?}");
        let (args, segments) = staged_net(socket_stage(
            &mut user,
            canonical,
            [SOCKET_FD, msgvec, 1 << 32, MSG_DONTWAIT, 0, 0],
        ));
        assert_eq!((args[2], segments.len()), (0, 0), "{canonical:?}");
    }
}

/// #2418 review P0-5: a message call declares as output exactly the
/// header fields Linux writes back (a received message's `msg_namelen`
/// when it has a name, `msg_controllen` and `msg_flags`; a batched
/// message's `msg_len`), so completion never copies back the rest of the
/// header (`msg_iov`, `msg_control`, padding) from the snapshot staging
/// took. Output ranges that overlap one another have no single answer a
/// copy-back can give and are refused. Red before: the whole header was
/// one output segment.
#[test]
fn a_message_header_declares_only_the_fields_linux_writes_back() {
    use crate::crossing::nr;
    let header = msghdr(BASE + 0x300, 28, BASE + 0x100, 1, 0, 0);
    let mut user = memory(&laid_out(
        4096,
        &[(0, &header), (0x100, &iovec(BASE + 0x200, 32))],
    ));
    let (_, segments) = staged_net(socket_stage(
        &mut user,
        nr::RECVMSG,
        [SOCKET_FD, BASE, 0, 0, 0, 0],
    ));
    assert_eq!(
        segments,
        [
            net_segment(BASE, 56, true, false),
            net_segment(BASE + 8, 4, false, true),
            net_segment(BASE + 40, 8, false, true),
            net_segment(BASE + 48, 4, false, true),
            net_segment(BASE + 0x100, 16, true, false),
            net_segment(BASE + 0x200, 32, false, true),
            net_segment(BASE + 0x300, 28, false, true),
        ]
    );
    let (_, segments) = staged_net(socket_stage(
        &mut user,
        nr::RECVMMSG,
        [SOCKET_FD, BASE, 1, MSG_DONTWAIT, 0, 0],
    ));
    assert_eq!(
        segments[..5],
        [
            net_segment(BASE, 64, true, false),
            net_segment(BASE + 8, 4, false, true),
            net_segment(BASE + 40, 8, false, true),
            net_segment(BASE + 48, 4, false, true),
            net_segment(BASE + 56, 4, false, true),
        ]
    );
    let (_, segments) = staged_net(socket_stage(
        &mut user,
        nr::SENDMMSG,
        [SOCKET_FD, BASE, 1, 0, 0, 0],
    ));
    assert_eq!(
        segments,
        [
            net_segment(BASE, 64, true, false),
            net_segment(BASE + 56, 4, false, true),
            net_segment(BASE + 0x100, 16, true, false),
            net_segment(BASE + 0x200, 32, true, false),
            net_segment(BASE + 0x300, 28, true, false),
        ]
    );
    // Two buffers over one range, or a buffer over the header: refused.
    for overlapping in [
        [iovec(BASE + 0x200, 32), iovec(BASE + 0x210, 32)].concat(),
        [iovec(BASE + 0x200, 32), iovec(BASE, 32)].concat(),
    ] {
        let header = msghdr(BASE + 0x300, 28, BASE + 0x100, 2, 0, 0);
        let mut user = memory(&laid_out(4096, &[(0, &header), (0x100, &overlapping)]));
        assert_eq!(
            socket_stage(&mut user, nr::RECVMSG, [SOCKET_FD, BASE, 0, 0, 0, 0]),
            None
        );
    }
}

/// #2418 review P0-5: the errors Linux answers for a message header
/// before it moves anything: more than `UIO_MAXIOV` iovecs is EMSGSIZE, a
/// negative `msg_namelen` with a name is EINVAL (without a name it is
/// ignored), and iovec lengths whose sum overflows an `ssize_t` are
/// EINVAL. A send reads at most a `struct sockaddr_storage` of its name.
#[test]
fn message_header_errors_and_name_lengths_answer_as_linux() {
    use crate::crossing::nr;
    let stage = |header: &[u8], iovecs: &[u8], canonical| {
        let mut user = memory(&laid_out(8192, &[(0, header), (0x100, iovecs)]));
        socket_stage(&mut user, canonical, [SOCKET_FD, BASE, 0, 0, 0, 0])
    };
    let one = iovec(BASE + 0x1000, 8);
    for canonical in [nr::SENDMSG, nr::RECVMSG] {
        assert_eq!(
            stage(&msghdr(0, 0, BASE + 0x100, 1025, 0, 0), &one, canonical),
            returned(carrick_syscall_abi::LINUX_EMSGSIZE),
            "{canonical:?}"
        );
        assert_eq!(
            stage(
                &msghdr(BASE + 0x800, 0x8000_0000, BASE + 0x100, 1, 0, 0),
                &one,
                canonical
            ),
            returned(carrick_syscall_abi::LINUX_EINVAL),
            "{canonical:?}"
        );
        staged_net(stage(
            &msghdr(0, 0x8000_0000, BASE + 0x100, 1, 0, 0),
            &one,
            canonical,
        ));
        let overflowing = [
            iovec(BASE + 0x1000, i64::MAX as u64),
            iovec(BASE + 0x1000, 1),
        ]
        .concat();
        assert_eq!(
            stage(
                &msghdr(0, 0, BASE + 0x100, 2, 0, 0),
                &overflowing,
                canonical
            ),
            returned(carrick_syscall_abi::LINUX_EINVAL),
            "{canonical:?}"
        );
    }
    let (_, segments) = staged_net(stage(
        &msghdr(BASE + 0x800, 200, BASE + 0x100, 1, 0, 0),
        &one,
        nr::SENDMSG,
    ));
    assert_eq!(
        segments.last(),
        Some(&net_segment(BASE + 0x800, 128, true, false))
    );
}

/// #2418 review P0-5: a `sendmsg` or `sendmmsg` that fails EPIPE owes its
/// caller SIGPIPE unless the call passed `MSG_NOSIGNAL`, as `send` does;
/// a receive never does.
#[test]
fn a_message_send_that_fails_epipe_owes_sigpipe_unless_msg_nosignal() {
    use crate::crossing::nr;
    let bytes = laid_out(
        4096,
        &[
            (0, &msghdr(0, 0, BASE + 0x100, 1, 0, 0)),
            (0x100, &iovec(BASE + 0x200, 4)),
        ],
    );
    let epipe = carrick_syscall_abi::LINUX_EPIPE.guest_retval();
    for (canonical, flags, args, owed) in [
        (nr::SENDMSG, 0, [SOCKET_FD, BASE, 0, 0, 0, 0], true),
        (
            nr::SENDMSG,
            0x4000,
            [SOCKET_FD, BASE, 0x4000, 0, 0, 0],
            false,
        ),
        (nr::SENDMMSG, 0, [SOCKET_FD, BASE, 1, 0, 0, 0], true),
        (
            nr::SENDMMSG,
            0x4000,
            [SOCKET_FD, BASE, 1, 0x4000, 0, 0],
            false,
        ),
        (nr::RECVMSG, 0, [SOCKET_FD, BASE, 0, 0, 0, 0], false),
    ] {
        let mut user = memory(&bytes);
        let mut record = socket_record(&mut user, canonical, args).into_vec();
        serve_socket(&mut record, epipe, STREAM);
        assert_eq!(
            sigpipe_on_epipe(&record),
            owed,
            "{canonical:?} with flags {flags:#x}"
        );
    }
}
