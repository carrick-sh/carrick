//! Stat and statx record serialization and flag validation helpers.

use carrick_abi::{
    KernelAbi, LINUX_AT_EACCESS, LINUX_AT_EMPTY_PATH, LINUX_AT_NO_AUTOMOUNT,
    LINUX_AT_SYMLINK_NOFOLLOW, LINUX_EFAULT, LINUX_PAGE_SIZE, LINUX_S_IFDIR, LINUX_S_IFLNK,
    LINUX_S_IFMT, LINUX_S_IFREG, LinuxStat, LinuxStatx, LinuxStatxTimestamp, LinuxX8664Stat,
};
pub(crate) use carrick_abi::{
    LINUX_AT_STATX_DONT_SYNC, LINUX_AT_STATX_FORCE_SYNC, LINUX_STATX_BASIC_STATS,
    LINUX_STATX_RESERVED,
};
use carrick_guest_mem::{
    CurrentMmMemory, GuestVa, GuestWriteRange, MemoryError, MemoryPrepareError, UserMemoryVenue,
};

use super::{
    DispatchOutcome, RootFsMetadata, StatRecord, blocks_512, linux_dev_major, linux_dev_minor,
    write_kernel_struct, write_kernel_struct_raw,
};

/// An already captured Linux stat result. Only the three bounded ABI layouts
/// can construct this output; no fd, path, borrowed source or memory permit
/// survives a wait. Moving the output transfers its completion custody.
#[derive(Debug, PartialEq, Eq)]
pub struct StatCopyout {
    address: GuestVa,
    record: CapturedStat,
}

#[derive(Debug, PartialEq, Eq)]
enum CapturedStat {
    Aarch64(LinuxStat),
    X8664(LinuxX8664Stat),
    Statx(LinuxStatx),
}

const _: () = {
    assert!(LinuxStat::ABI_SIZE <= carrick_el1_abi::MM_PORTAL_MAX_BYTES as usize);
    assert!(LinuxX8664Stat::ABI_SIZE <= carrick_el1_abi::MM_PORTAL_MAX_BYTES as usize);
    assert!(LinuxStatx::ABI_SIZE <= carrick_el1_abi::MM_PORTAL_MAX_BYTES as usize);
};

impl StatCopyout {
    /// Complete the captured record once, or return its owned dependency.
    /// PREPARE validates the entire record before infallible COMMIT, including
    /// a record crossing a page boundary. Temporary refusal is never EFAULT.
    pub fn resume(self, memory: &mut impl CurrentMmMemory) -> DispatchOutcome {
        let bytes = match &self.record {
            CapturedStat::Aarch64(stat) => stat.abi_bytes(),
            CapturedStat::X8664(stat) => stat.abi_bytes(),
            CapturedStat::Statx(stat) => stat.abi_bytes(),
        };
        let Some(range) = GuestWriteRange::new(self.address, bytes.len()) else {
            return DispatchOutcome::errno(LINUX_EFAULT);
        };
        match memory.prepare_write(&[range]) {
            Ok(prepared) => {
                prepared.commit(&[bytes]);
                DispatchOutcome::Returned { value: 0 }
            }
            Err(MemoryPrepareError::Fault(MemoryError::OutOfBounds { .. })) => {
                DispatchOutcome::errno(LINUX_EFAULT)
            }
            Err(dependency) => DispatchOutcome::OwnerStatCopyout {
                output: Box::new(self),
                dependency,
            },
        }
    }
}

pub(crate) fn linux_statx_flags_are_supported(flags: u64) -> bool {
    const SUPPORTED: u64 = LINUX_AT_SYMLINK_NOFOLLOW
        | LINUX_AT_EMPTY_PATH
        | LINUX_AT_NO_AUTOMOUNT
        | LINUX_AT_STATX_FORCE_SYNC
        | LINUX_AT_STATX_DONT_SYNC;
    let sync = flags & (LINUX_AT_STATX_FORCE_SYNC | LINUX_AT_STATX_DONT_SYNC);
    flags & !SUPPORTED == 0 && sync != (LINUX_AT_STATX_FORCE_SYNC | LINUX_AT_STATX_DONT_SYNC)
}

pub(crate) fn linux_access_flags_are_supported(flags: u64) -> bool {
    const SUPPORTED: u64 = LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EACCESS | LINUX_AT_EMPTY_PATH;
    flags & !SUPPORTED == 0
}

pub(super) fn write_stat_record(
    memory: &mut impl CurrentMmMemory,
    statbuf: u64,
    record: &StatRecord,
) -> DispatchOutcome {
    let size = record.size_usize();
    let blocks = record
        .blocks
        .map(|b| b as i64)
        .unwrap_or_else(|| blocks_512(size));
    let stat = LinuxStat {
        st_dev: 1,
        st_ino: record.ino,
        st_mode: record.mode,
        st_nlink: record.nlink,
        st_uid: record.uid.raw(),
        st_gid: record.gid.raw(),
        st_rdev: record.rdev,
        __pad1: 0,
        st_size: record.size as i64,
        st_blksize: 4096,
        __pad2: 0,
        st_blocks: blocks,
        st_atime: record.atime.0,
        st_atime_nsec: record.atime.1 as u64,
        st_mtime: record.mtime.0,
        st_mtime_nsec: record.mtime.1 as u64,
        st_ctime: record.ctime.0,
        st_ctime_nsec: record.ctime.1 as u64,
        __unused4: 0,
        __unused5: 0,
    };

    if memory.user_memory_venue() == UserMemoryVenue::Owner {
        return StatCopyout {
            address: GuestVa(statbuf),
            record: CapturedStat::Aarch64(stat),
        }
        .resume(memory);
    }
    if write_kernel_struct_raw(memory, statbuf, &stat).is_err() {
        DispatchOutcome::Errno {
            errno: LINUX_EFAULT,
        }
    } else {
        DispatchOutcome::Returned { value: 0 }
    }
}

pub(super) fn write_x8664_stat_record(
    memory: &mut impl CurrentMmMemory,
    statbuf: u64,
    record: &StatRecord,
) -> DispatchOutcome {
    let size = record.size_usize();
    let blocks = record
        .blocks
        .map(|b| b as i64)
        .unwrap_or_else(|| blocks_512(size));
    let stat = LinuxX8664Stat {
        st_dev: 1,
        st_ino: record.ino,
        st_nlink: record.nlink as u64,
        st_mode: record.mode,
        st_uid: record.uid.raw(),
        st_gid: record.gid.raw(),
        __pad0: 0,
        st_rdev: record.rdev,
        st_size: record.size as i64,
        st_blksize: 4096,
        st_blocks: blocks,
        st_atime: record.atime.0,
        st_atime_nsec: record.atime.1,
        st_mtime: record.mtime.0,
        st_mtime_nsec: record.mtime.1,
        st_ctime: record.ctime.0,
        st_ctime_nsec: record.ctime.1,
        __reserved: [0; 3],
    };

    if memory.user_memory_venue() == UserMemoryVenue::Owner {
        return StatCopyout {
            address: GuestVa(statbuf),
            record: CapturedStat::X8664(stat),
        }
        .resume(memory);
    }
    if write_kernel_struct_raw(memory, statbuf, &stat).is_err() {
        DispatchOutcome::Errno {
            errno: LINUX_EFAULT,
        }
    } else {
        DispatchOutcome::Returned { value: 0 }
    }
}

/// Build a [`RealStat`](carrick_vfs::fs_backend::RealStat) from a live `libc::stat`
/// (e.g. an `fstat` of a host fd) carrying the REAL on-disk values: the true
/// file type (so a symlink stat'd with `AT_SYMLINK_NOFOLLOW` reports S_IFLNK)
/// and the real `st_nlink` (a true hard link reports more than 1). An fd-based
/// stat then reports the SAME real size/kind/times as the path-based
/// `real_stat` that statx/newfstatat use.
pub(super) fn real_stat_from_libc(st: &libc::stat) -> carrick_vfs::fs_backend::RealStat {
    use carrick_vfs::rootfs::RootFsEntryKind;
    let kind = match st.st_mode as u32 & LINUX_S_IFMT {
        m if m == LINUX_S_IFDIR => RootFsEntryKind::Directory,
        m if m == LINUX_S_IFLNK => RootFsEntryKind::Symlink,
        _ => RootFsEntryKind::File,
    };
    carrick_vfs::fs_backend::RealStat {
        kind,
        ino: st.st_ino,
        nlink: st.st_nlink as u32,
        mode: st.st_mode as u32 & 0o7777,
        uid: carrick_abi::NsUid::ROOT,
        gid: carrick_abi::NsGid::ROOT,
        size: st.st_size as u64,
        blocks: Some(st.st_blocks.max(0) as u64),
        atime: (st.st_atime, carrick_portable::stat_atime_nsec(st)),
        mtime: (st.st_mtime, carrick_portable::stat_mtime_nsec(st)),
        ctime: (st.st_ctime, carrick_portable::stat_ctime_nsec(st)),
    }
}

/// Build and write a `statx` record from a real backing stat.
pub(crate) fn write_statx_real(
    memory: &mut impl CurrentMmMemory,
    statxbuf: u64,
    real: &carrick_vfs::fs_backend::RealStat,
) -> DispatchOutcome {
    write_statx_record(memory, statxbuf, &StatRecord::from_real(real))
}

pub(crate) fn write_statx(
    memory: &mut impl CurrentMmMemory,
    statxbuf: u64,
    metadata: &RootFsMetadata,
) -> DispatchOutcome {
    write_statx_record(memory, statxbuf, &StatRecord::from_metadata(metadata))
}

pub(super) fn write_statx_record(
    memory: &mut impl CurrentMmMemory,
    statxbuf: u64,
    record: &StatRecord,
) -> DispatchOutcome {
    let zero_time = LinuxStatxTimestamp::zero();
    let stx_ts = |t: (i64, i64)| LinuxStatxTimestamp {
        tv_sec: t.0,
        tv_nsec: t.1 as u32,
        __reserved: 0,
    };
    let size = record.size_usize();
    let blocks = record.blocks.unwrap_or_else(|| blocks_512(size) as u64);
    let statx = LinuxStatx {
        stx_mask: LINUX_STATX_BASIC_STATS,
        stx_blksize: LINUX_PAGE_SIZE as u32,
        stx_attributes: 0,
        stx_nlink: record.nlink,
        stx_uid: record.uid.raw(),
        stx_gid: record.gid.raw(),
        stx_mode: record.mode as u16,
        __spare0: [0; 1],
        stx_ino: record.ino,
        stx_size: record.size,
        stx_blocks: blocks,
        stx_attributes_mask: 0,
        stx_atime: stx_ts(record.atime),
        stx_btime: zero_time,
        stx_ctime: stx_ts(record.ctime),
        stx_mtime: stx_ts(record.mtime),
        stx_rdev_major: linux_dev_major(record.rdev),
        stx_rdev_minor: linux_dev_minor(record.rdev),
        stx_dev_major: 0,
        stx_dev_minor: 1,
        stx_mnt_id: 1,
        stx_dio_mem_align: 0,
        stx_dio_offset_align: 0,
        stx_subvol: 0,
        stx_atomic_write_unit_min: 0,
        stx_atomic_write_unit_max: 0,
        stx_atomic_write_segments_max: 0,
        stx_dio_read_offset_align: 0,
        stx_atomic_write_unit_max_opt: 0,
        __spare2: [0; 1],
        __spare3: [0; 8],
    };
    if memory.user_memory_venue() == UserMemoryVenue::Owner {
        return StatCopyout {
            address: GuestVa(statxbuf),
            record: CapturedStat::Statx(statx),
        }
        .resume(memory);
    }
    write_kernel_struct(memory, statxbuf, &statx)
}

pub(crate) fn write_synthetic_statx(
    memory: &mut impl CurrentMmMemory,
    statxbuf: u64,
    path: &str,
    size: usize,
) -> DispatchOutcome {
    write_synthetic_statx_mode(memory, statxbuf, path, size, LINUX_S_IFREG | 0o444)
}

pub(crate) fn write_synthetic_statx_mode(
    memory: &mut impl CurrentMmMemory,
    statxbuf: u64,
    path: &str,
    size: usize,
    mode: u32,
) -> DispatchOutcome {
    write_statx_record(memory, statxbuf, &StatRecord::synthetic(path, size, mode))
}

#[cfg(test)]
mod owner_copyout_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use carrick_el1_abi::{El1MmHandle, PortalOwnerWait, PortalWaitCause, ReservationMm};
    use carrick_guest_mem::{GuestMemory, PreparedGuestWrite};
    use std::num::NonZeroU64;

    struct WaitingMemory {
        wait: Option<PortalOwnerWait>,
        fault: bool,
        bytes: Vec<u8>,
        preparations: Vec<usize>,
    }
    struct Permit<'a>(&'a mut [u8]);
    impl PreparedGuestWrite for Permit<'_> {
        fn commit(self: Box<Self>, outputs: &[&[u8]]) {
            assert_eq!(outputs.len(), 1);
            assert_eq!(self.0.len(), outputs[0].len());
            self.0.copy_from_slice(outputs[0]);
        }
    }
    impl WaitingMemory {
        fn new(cause: PortalWaitCause) -> Self {
            // SAFETY: the fixture models this exact owner and producer revision.
            let wait = unsafe {
                PortalOwnerWait::from_owner(
                    El1MmHandle::from_admitted_owner(
                        NonZeroU64::new(1).unwrap(),
                        ReservationMm::new(2).unwrap(),
                        NonZeroU64::new(3).unwrap(),
                    ),
                    cause,
                    7,
                )
            };
            Self {
                wait: Some(wait),
                fault: false,
                bytes: vec![0xa5; 512],
                preparations: Vec::new(),
            }
        }
    }
    impl GuestMemory for WaitingMemory {
        fn user_memory_venue(&self) -> UserMemoryVenue {
            UserMemoryVenue::Owner
        }
        fn prepare_write(
            &mut self,
            ranges: &[GuestWriteRange],
        ) -> Result<Box<dyn PreparedGuestWrite + '_>, MemoryPrepareError> {
            assert_eq!(ranges.len(), 1);
            let range = ranges[0];
            self.preparations.push(range.len());
            if let Some(wait) = self.wait.take() {
                return Err(MemoryPrepareError::OwnerWait(wait));
            }
            if self.fault {
                return Err(MemoryPrepareError::Fault(MemoryError::OutOfBounds {
                    address: range.address().raw(),
                    length: range.len(),
                }));
            }
            let offset = (range.address().raw() - 0x1000) as usize;
            Ok(Box::new(Permit(
                &mut self.bytes[offset..offset + range.len()],
            )))
        }
        fn read_bytes_raw(&self, _: u64, _: usize) -> Result<Vec<u8>, MemoryError> {
            Err(MemoryError::Unsupported)
        }
        fn write_bytes_raw(&mut self, _: u64, _: &[u8]) -> Result<(), MemoryError> {
            panic!("admitted stat output bypassed its prepared permit")
        }
    }
    impl CurrentMmMemory for WaitingMemory {}

    type Writer = fn(&mut WaitingMemory, u64, &StatRecord) -> DispatchOutcome;
    const WRITERS: [Writer; 3] = [
        write_stat_record,
        write_x8664_stat_record,
        write_statx_record,
    ];

    #[test]
    fn stat_copyout_retains_owner_wait_instead_of_efault() {
        for cause in [
            PortalWaitCause::Editor,
            PortalWaitCause::Gate,
            PortalWaitCause::Reservations,
        ] {
            for writer in WRITERS {
                let mut record = StatRecord::synthetic("/captured", 12345, LINUX_S_IFREG | 0o644);
                let mut memory = WaitingMemory::new(cause);
                let wait = memory.wait.unwrap();
                let outcome = writer(&mut memory, 0x1000, &record);
                let DispatchOutcome::OwnerStatCopyout {
                    output,
                    dependency: MemoryPrepareError::OwnerWait(actual),
                } = outcome
                else {
                    panic!("stat copyout flattened {cause:?}: {outcome:?}");
                };
                assert_eq!(actual, wait);
                assert!(memory.bytes.iter().all(|&byte| byte == 0xa5));
                assert_eq!(memory.preparations.len(), 1);
                // The source can change while waiting; completion owns the
                // original serialized record rather than another lookup.
                record.size = 98765;
                assert_eq!(record.size, 98765);
                assert_eq!(
                    (*output).resume(&mut memory),
                    DispatchOutcome::Returned { value: 0 }
                );
                assert_eq!(memory.preparations.len(), 2);
                let size_offset = if memory.preparations[0] == LinuxStatx::ABI_SIZE {
                    40
                } else {
                    48
                };
                assert_eq!(
                    u64::from_le_bytes(
                        memory.bytes[size_offset..size_offset + 8]
                            .try_into()
                            .unwrap()
                    ),
                    12345
                );
                assert!(
                    memory
                        .preparations
                        .iter()
                        .all(|&length| length <= LinuxStatx::ABI_SIZE)
                );
            }
        }
    }

    #[test]
    fn stat_copyout_revalidates_destination_after_owner_wait() {
        for writer in WRITERS {
            let record = StatRecord::synthetic("/captured", 12345, LINUX_S_IFREG | 0o644);
            let mut memory = WaitingMemory::new(PortalWaitCause::Editor);
            let DispatchOutcome::OwnerStatCopyout { output, .. } =
                writer(&mut memory, 0x1000, &record)
            else {
                panic!("missing captured output");
            };
            memory.fault = true;
            assert_eq!(
                (*output).resume(&mut memory),
                DispatchOutcome::errno(LINUX_EFAULT)
            );
            assert!(memory.bytes.iter().all(|&byte| byte == 0xa5));
            memory.wait = None;
            assert_eq!(
                writer(&mut memory, u64::MAX - 1, &record),
                DispatchOutcome::errno(LINUX_EFAULT)
            );
        }
    }

    #[test]
    fn fstat_copyout_keeps_the_original_record_after_fd_reuse() {
        use crate::dispatch::{
            OpenDescription, OpenDescriptionBase, SyscallDispatcher, SyscallRequest,
        };
        use carrick_observability::compat::{CompatReporter, SyscallArgs};
        let mut dispatcher = SyscallDispatcher::new();
        let install = |dispatcher: &SyscallDispatcher, length: usize| {
            let outcome = dispatcher.install_fd(
                OpenDescription::SyntheticFile {
                    base: OpenDescriptionBase::new(carrick_abi::LINUX_O_RDONLY),
                    path: "/captured".into(),
                    contents: vec![0; length],
                    offset: 0,
                },
                0,
            );
            let DispatchOutcome::Returned { value } = outcome else {
                panic!("install file: {outcome:?}");
            };
            value as u64
        };
        let fd = install(&dispatcher, 12345);
        let mut memory = WaitingMemory::new(PortalWaitCause::Gate);
        let context = dispatcher.capture_one_task_context().unwrap();
        let reporter = CompatReporter::default();
        let outcome = dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(
                    carrick_abi::syscall::nr::FSTAT.raw(),
                    SyscallArgs::from([fd, 0x1000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap();
        let DispatchOutcome::OwnerStatCopyout { output, .. } = outcome else {
            panic!("fstat did not retain output: {outcome:?}");
        };
        assert_eq!(
            dispatcher
                .dispatch(
                    &context,
                    SyscallRequest::new(
                        carrick_abi::syscall::nr::CLOSE.raw(),
                        SyscallArgs::from([fd, 0, 0, 0, 0, 0])
                    ),
                    &mut memory,
                    &reporter
                )
                .unwrap(),
            DispatchOutcome::Returned { value: 0 }
        );
        assert_eq!(install(&dispatcher, 98765), fd);
        assert_eq!(
            (*output).resume(&mut memory),
            DispatchOutcome::Returned { value: 0 }
        );
        assert_eq!(
            i64::from_le_bytes(memory.bytes[48..56].try_into().unwrap()),
            12345
        );
    }
}
