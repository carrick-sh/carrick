//! Stat and statx record serialization and flag validation helpers.

use carrick_abi::{
    LINUX_AT_EACCESS, LINUX_AT_EMPTY_PATH, LINUX_AT_NO_AUTOMOUNT, LINUX_AT_SYMLINK_NOFOLLOW,
    LINUX_S_IFDIR, LINUX_S_IFLNK, LINUX_S_IFMT, LINUX_S_IFREG, LinuxStat, LinuxStatx,
    LinuxX8664Stat,
};
pub(crate) use carrick_abi::{
    LINUX_AT_STATX_DONT_SYNC, LINUX_AT_STATX_FORCE_SYNC, LINUX_STATX_RESERVED,
};
use carrick_guest_mem::CurrentMmMemory;

use super::copyout::copyout_record;
use super::{DispatchOutcome, RootFsMetadata, StatRecord, blocks_512};

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
    context: &crate::kernel::KernelContext,
    memory: &mut impl CurrentMmMemory,
    statbuf: u64,
    record: &StatRecord,
) -> DispatchOutcome {
    copyout_record(
        context,
        memory,
        statbuf,
        &linux_stat(record),
        DispatchOutcome::Returned { value: 0 },
    )
}

/// The Linux `struct stat` for one record: the single encoding shared by the
/// dispatcher's copyout and the native host-file venue's reply.
pub(super) fn linux_stat(record: &StatRecord) -> LinuxStat {
    LinuxStat::from_fields(&record.linux_fields())
}

pub(super) fn write_x8664_stat_record(
    context: &crate::kernel::KernelContext,
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

    copyout_record(
        context,
        memory,
        statbuf,
        &stat,
        DispatchOutcome::Returned { value: 0 },
    )
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
    context: &crate::kernel::KernelContext,
    memory: &mut impl CurrentMmMemory,
    statxbuf: u64,
    real: &carrick_vfs::fs_backend::RealStat,
) -> DispatchOutcome {
    write_statx_record(context, memory, statxbuf, &StatRecord::from_real(real))
}

pub(crate) fn write_statx(
    context: &crate::kernel::KernelContext,
    memory: &mut impl CurrentMmMemory,
    statxbuf: u64,
    metadata: &RootFsMetadata,
) -> DispatchOutcome {
    write_statx_record(
        context,
        memory,
        statxbuf,
        &StatRecord::from_metadata(metadata),
    )
}

pub(super) fn write_statx_record(
    context: &crate::kernel::KernelContext,
    memory: &mut impl CurrentMmMemory,
    statxbuf: u64,
    record: &StatRecord,
) -> DispatchOutcome {
    copyout_record(
        context,
        memory,
        statxbuf,
        &linux_statx(record),
        DispatchOutcome::Returned { value: 0 },
    )
}

/// The Linux `struct statx` for one record: the single encoding shared by
/// the dispatcher's copyout and the native host-file venue's reply.
pub(super) fn linux_statx(record: &StatRecord) -> LinuxStatx {
    LinuxStatx::from_fields(&record.linux_fields())
}

pub(crate) fn write_synthetic_statx(
    context: &crate::kernel::KernelContext,
    memory: &mut impl CurrentMmMemory,
    statxbuf: u64,
    path: &str,
    size: usize,
) -> DispatchOutcome {
    write_synthetic_statx_mode(context, memory, statxbuf, path, size, LINUX_S_IFREG | 0o444)
}

pub(crate) fn write_synthetic_statx_mode(
    context: &crate::kernel::KernelContext,
    memory: &mut impl CurrentMmMemory,
    statxbuf: u64,
    path: &str,
    size: usize,
    mode: u32,
) -> DispatchOutcome {
    write_statx_record(
        context,
        memory,
        statxbuf,
        &StatRecord::synthetic(path, size, mode),
    )
}
