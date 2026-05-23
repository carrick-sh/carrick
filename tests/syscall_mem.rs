//! Memory-management syscall dispatch tests.
//!
//! Split out of the former tests/syscall_dispatch.rs monolith. Shared imports,
//! constants, and helpers live in tests/common/syscall_support.rs.

#[path = "common/syscall_support.rs"]
mod support;

use support::*;

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
fn brk_tracks_heap_within_runtime_arena() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(214, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
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
                &reporter,
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
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: next as i64 }
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
                SyscallRequest::new(222, SyscallArgs::from([0, 4, 1, 0x02, 3, 0])),
                &mut memory,
                &reporter,
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
fn mmap_anonymous_reservations_fit_in_runtime_arena() {
    let mut memory = AddressSpace::from_segments(
        0,
        [(LINUX_MMAP_BASE, rwx_perms(), Vec::new(), LINUX_MMAP_SIZE)],
    )
    .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let map_private_anonymous = 0x02 | 0x20;
    let reservations = [
        128 * 1024,
        256 * 1024,
        1024 * 1024,
        8 * 1024 * 1024,
        64 * 1024 * 1024,
        512 * 1024 * 1024,
    ];

    let mut expected = LINUX_MMAP_BASE;
    for length in reservations {
        let outcome = dispatcher
            .dispatch(
                SyscallRequest::new(
                    222,
                    SyscallArgs::from([0, length, 0, map_private_anonymous, (-1_i64) as u64, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap();
        assert_eq!(
            outcome,
            DispatchOutcome::Returned {
                value: expected as i64
            }
        );
        expected += length;
    }

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn mmap_rejects_unknown_map_flag_bits() {
    const LINUX_EINVAL: i32 = 22;
    let mut memory = AddressSpace::from_segments(
        0,
        [(LINUX_MMAP_BASE, rwx_perms(), Vec::new(), LINUX_MMAP_SIZE)],
    )
    .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let map_private_anonymous = 0x02 | 0x20;
    let unknown_flag = 1u64 << 47;

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    222,
                    SyscallArgs::from([
                        0,
                        0x1000,
                        0,
                        map_private_anonymous | unknown_flag,
                        (-1_i64) as u64,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL
        }
    );
}

#[test]
fn mmap_unsupported_prot_none_hint_does_not_consume_bump_space() {
    let mut memory = AddressSpace::from_segments(
        0,
        [(LINUX_MMAP_BASE, rwx_perms(), Vec::new(), LINUX_MMAP_SIZE)],
    )
    .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let map_private_anonymous = 0x02 | 0x20;

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    222,
                    SyscallArgs::from([
                        LINUX_MMAP_BASE + LINUX_MMAP_SIZE + 0x1000,
                        64 * 1024 * 1024,
                        0,
                        map_private_anonymous,
                        (-1_i64) as u64,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 12 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    222,
                    SyscallArgs::from([0, 0x1000, 0, map_private_anonymous, (-1_i64) as u64, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_MMAP_BASE as i64
        }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn mmap_without_hint_uses_next_page_granular_address() {
    let mut memory = AddressSpace::from_segments(
        0,
        [(LINUX_MMAP_BASE, rwx_perms(), Vec::new(), LINUX_MMAP_SIZE)],
    )
    .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let map_private_anonymous = 0x02 | 0x20;

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    222,
                    SyscallArgs::from([
                        0,
                        128 * 1024,
                        0,
                        map_private_anonymous,
                        (-1_i64) as u64,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_MMAP_BASE as i64
        }
    );

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                222,
                SyscallArgs::from([
                    0,
                    64 * 1024 * 1024 + 4 * 1024 * 1024,
                    0,
                    map_private_anonymous,
                    (-1_i64) as u64,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();

    let DispatchOutcome::Returned { value } = outcome else {
        panic!("large reservation failed: {outcome:?}");
    };
    assert_eq!(value as u64, LINUX_MMAP_BASE + 128 * 1024);

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn mmap_non_fixed_hint_does_not_overlap_existing_bump_allocation() {
    let mut memory = AddressSpace::from_segments(
        0,
        [(LINUX_MMAP_BASE, rwx_perms(), Vec::new(), LINUX_MMAP_SIZE)],
    )
    .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let map_private_anonymous = 0x02 | 0x20;

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    222,
                    SyscallArgs::from([0, 0x2000, 0, map_private_anonymous, (-1_i64) as u64, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_MMAP_BASE as i64
        }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    222,
                    SyscallArgs::from([
                        LINUX_MMAP_BASE + 0x1000,
                        0x1000,
                        0,
                        map_private_anonymous,
                        (-1_i64) as u64,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: (LINUX_MMAP_BASE + 0x2000) as i64
        }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn mm_lock_msync_mincore_stubs_validate_args_and_succeed() {
    const MS_SYNC: u64 = 0x04;
    const MS_ASYNC: u64 = 0x01;
    const MCL_CURRENT: u64 = 0x01;
    let mut memory =
        AddressSpace::from_segments(0, [(LINUX_MMAP_BASE, rwx_perms(), b"".to_vec(), 0x4000)])
            .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    227,
                    SyscallArgs::from([LINUX_MMAP_BASE, 0x1000, MS_SYNC, 0, 0, 0]),
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
                    227,
                    SyscallArgs::from([LINUX_MMAP_BASE, 0x1000, MS_SYNC | MS_ASYNC, 0, 0, 0]),
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
                    227,
                    SyscallArgs::from([0xdead_0000, 0x1000, MS_SYNC, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 12 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    228,
                    SyscallArgs::from([LINUX_MMAP_BASE, 0x1000, 0, 0, 0, 0]),
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
                SyscallRequest::new(229, SyscallArgs::from([LINUX_MMAP_BASE, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(230, SyscallArgs::from([MCL_CURRENT, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(230, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(231, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    let vec_addr = LINUX_MMAP_BASE + 0x2000;
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    232,
                    SyscallArgs::from([LINUX_MMAP_BASE, 0x4000, vec_addr, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let pages_present = memory.read_bytes(vec_addr, 1).unwrap();
    assert_eq!(pages_present[0], 1);

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn mremap_bootstrap_accepts_shrinking_and_rejects_growth_with_enomem() {
    const MREMAP_MAYMOVE: u64 = 0x01;
    let mut memory =
        AddressSpace::from_segments(0, [(LINUX_MMAP_BASE, rwx_perms(), b"".to_vec(), 0x4000)])
            .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    216,
                    SyscallArgs::from([LINUX_MMAP_BASE, 0x4000, 0x2000, MREMAP_MAYMOVE, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_MMAP_BASE as i64,
        }
    );
    // Growing a mapping that cannot extend in place: with MREMAP_MAYMOVE,
    // Linux relocates the mapping to a fresh region rather than failing.
    // The bump allocator hands out the start of the mmap arena (which is
    // still at LINUX_MMAP_BASE in this fixture) and copies the old bytes
    // across. (Without MREMAP_MAYMOVE this would be ENOMEM — see below.)
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    216,
                    SyscallArgs::from([LINUX_MMAP_BASE, 0x1000, 0x8000, MREMAP_MAYMOVE, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_MMAP_BASE as i64,
        }
    );
    // Growing WITHOUT MREMAP_MAYMOVE when the mapping cannot extend in
    // place must fail with ENOMEM, matching Linux mremap(2).
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    216,
                    SyscallArgs::from([LINUX_MMAP_BASE, 0x1000, 0x8000, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 12 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    216,
                    SyscallArgs::from([LINUX_MMAP_BASE, 0x1000, 0, 0, 0, 0]),
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
                    216,
                    SyscallArgs::from([LINUX_MMAP_BASE, 0x1000, 0x2000, 0xdead, 0, 0]),
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
                    216,
                    SyscallArgs::from([0x1000, 0x1000, 0x2000, MREMAP_MAYMOVE, 0, 0]),
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
fn mmap_anonymous_fixed_mapping_zeroes_guest_memory_and_mprotect_munmap_are_noops() {
    let mut memory = AddressSpace::from_segments(
        0,
        [(LINUX_MMAP_BASE, rwx_perms(), b"dirty".to_vec(), 0x4000)],
    )
    .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    222,
                    SyscallArgs::from([LINUX_MMAP_BASE, 5, 3, 0x12 | 0x20, (-1_i64) as u64, 0]),
                ),
                &mut memory,
                &reporter,
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
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(215, SyscallArgs::from([LINUX_MMAP_BASE, 5, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn madvise_accepts_common_advice_for_mapped_ranges() {
    let mut memory = AddressSpace::from_segments(
        0,
        [(LINUX_MMAP_BASE, rwx_perms(), b"dirty".to_vec(), 0x4000)],
    )
    .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    233,
                    SyscallArgs::from([LINUX_MMAP_BASE, 0x1000, LINUX_MADV_DONTNEED, 0, 0, 0]),
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
                    233,
                    SyscallArgs::from([LINUX_MMAP_BASE, 0x1000, LINUX_MADV_WILLNEED, 0, 0, 0]),
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
                    233,
                    SyscallArgs::from([LINUX_MMAP_BASE + 1, 0x1000, 0, 0, 0, 0])
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
                    233,
                    SyscallArgs::from([LINUX_MMAP_BASE, 0x1000, 999, 0, 0, 0])
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
                    233,
                    SyscallArgs::from([LINUX_MMAP_BASE + 0x8000, 0x1000, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 12 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}
