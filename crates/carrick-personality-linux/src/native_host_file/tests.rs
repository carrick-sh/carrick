use super::*;
use carrick_core_abi::host_file::HostFileRequestView;

/// User memory at a fixed base; anything outside it faults.
struct Memory {
    base: u64,
    bytes: Vec<u8>,
    writable: bool,
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
        (end.saturating_sub(dst) as usize).min(len)
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
    }
}

/// Descriptors: 0 pipe, 1 host stdout, 3 host file (read-only), 4 eventfd.
fn caller(fd: i32) -> Option<NativeDescriptor> {
    Some(match fd {
        0 => NativeDescriptor::InZone(InZoneKind::Pipe),
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
                request: 0x5401
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

/// Linux answers `fstat` on a pipe, an eventfd or an epoll instance from the
/// object itself: the ring returns the record the dispatcher reports for
/// that kind (one shared `LinuxStatFields`), never a host request.
#[test]
fn in_zone_fstat_is_answered_in_ring_with_the_shared_record() {
    let mut user = memory(b"");
    let stat = |fields: &carrick_syscall_abi::LinuxStatFields| -> Box<[u8]> {
        zerocopy::IntoBytes::as_bytes(&carrick_syscall_abi::LinuxStat::from_fields(fields)).into()
    };
    let output = HostFileOutput {
        address: BASE,
        len: LINUX_STAT_BYTES,
    };
    let pipe = run(
        HostFileCall::Fstat {
            fd: 0,
            statbuf: BASE,
        },
        &mut user,
    );
    assert_eq!(
        pipe,
        Some(HostFileStage::InRingReply {
            output,
            bytes: stat(&carrick_syscall_abi::LinuxStatFields::CARRICK_PIPE),
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
                statbuf: BASE
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
            output: HostFileOutput {
                address: BASE + 0x100,
                len: LINUX_STATX_BYTES,
            },
            bytes: zerocopy::IntoBytes::as_bytes(&carrick_syscall_abi::LinuxStatx::from_fields(
                &carrick_syscall_abi::LinuxStatFields::CARRICK_PIPE
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
                statbuf: BASE
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

    // A relative path through an in-zone or absent dirfd is answered in ring;
    // through a host directory it is a later slice (counted ENOSYS).
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
    assert_eq!(
        run(openat(3), &mut relative),
        returned(carrick_syscall_abi::LINUX_ENOSYS)
    );
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
        },
        &mut user,
    ));
    assert!(!resolves_path);
    assert_eq!(
        output,
        Some(HostFileOutput {
            address: BASE + 0x100,
            len: LINUX_STAT_BYTES
        })
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
                flags: 0
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
fn unwritable_output_requests_write_supply_before_crossing() {
    let mut user = memory(b"");
    user.writable = false;
    assert_eq!(
        run(
            HostFileCall::Fstat {
                fd: 1,
                statbuf: BASE + 8
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
